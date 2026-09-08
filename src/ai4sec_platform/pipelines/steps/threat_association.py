from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.threats import linkage
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult

log = logging.getLogger(__name__)


@dataclass
class AssetAssociationStep:
    """逐资产跑 AI 关联并幂等落盘(evidence + payload assoc_status + threat_links)。

    参数(经 POST /api/runs params 传入):
      - asset_ids: list[int] | None  显式清单(给了即用它,忽略 scope/sample_size)
      - scope: 'sample'(默认,按来源优先级挑前 N) | 'all'(全部未 linked)
      - sample_size: int = 30
      - force: bool = False   True 时已 linked 资产也重跑(先删旧 evidence 再覆写)

    单条失败记日志继续,不中断整批(诚实标记,规则不决策)。
    """
    name: str = "asset_association"
    step_type: str = "llm_association"
    model_profile: str = "configured_model"

    def run(self, context: PipelineContext) -> StepResult:
        params = context.params
        try:
            asset_ids = params.get("asset_ids")
            if asset_ids is not None and not isinstance(asset_ids, list):
                asset_ids = None
            scope = str(params.get("scope") or "sample")
            sample_size = int(params.get("sample_size") or 30)
            force = bool(params.get("force") or False)
        except (TypeError, ValueError):
            scope, sample_size, force = "sample", 30, False

        ids = linkage.select_batch_assets(
            context.conn,
            asset_ids=asset_ids,
            scope=scope,
            sample_size=sample_size,
            force=force,
        )

        processed = linked = orphan = failed = 0
        for asset_id in ids:
            try:
                result = linkage.run_asset_association(
                    context.conn, asset_id=asset_id, force=force, run_id=context.run_id
                )
            except Exception as exc:  # noqa: BLE001 - 单条失败不中断整批
                failed += 1
                log.warning("[asset_association] asset=%s failed: %s", asset_id, exc)
            else:
                processed += 1
                if result.get("status") == "error":
                    failed += 1
                else:
                    associations = (result.get("associations") or {}).get("associations") or []
                    if associations:
                        linked += 1
                    else:
                        orphan += 1
            # 心跳 + 逐条进度, 供 GET /api/runs/{id} 轮询 + 看门狗判活
            _update_item_progress(
                context,
                step_name=self.name,
                completed=processed + failed,
                total=len(ids),
                linked=linked,
                orphan=orphan,
                failed=failed,
            )

        repo.create_quality_audit(
            context.conn,
            domain="threats",
            audit_type="asset_association",
            status="pass" if linked else ("warn" if processed else "error"),
            score=min(1.0, linked / max(1, processed)),
            summary=f"资产关联批跑:共 {len(ids)} 个,成功 {processed} 个,关联 {linked} 个,孤立 {orphan} 个,失败 {failed} 个。",
            details={"scope": scope, "sample_size": sample_size, "force": force, "processed": processed, "linked": linked, "orphan": orphan, "failed": failed},
        )
        return StepResult(metrics={
            "selected": len(ids),
            "processed": processed,
            "linked": linked,
            "orphan": orphan,
            "failed": failed,
        })


def _update_item_progress(context: PipelineContext, *, step_name: str, completed: int, total: int, **counts: int) -> None:
    """逐条把 item_progress 写回 pipeline_runs.summary_json(与 vulnerability_discovery 同款心跳)。"""
    if not context.run_id:
        return
    row = context.conn.execute(
        "SELECT summary_json FROM pipeline_runs WHERE run_id = ?", (context.run_id,)
    ).fetchone()
    if not row:
        return
    summary = repo.loads(row["summary_json"], {}) or {}
    summary["item_progress"] = {"step": step_name, "completed": completed, "total": total, **counts}
    summary["last_progress_at"] = utc_now()
    context.conn.execute(
        "UPDATE pipeline_runs SET summary_json = ? WHERE run_id = ?",
        (repo.dumps(summary), context.run_id),
    )
