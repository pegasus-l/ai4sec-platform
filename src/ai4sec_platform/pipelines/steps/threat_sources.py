from __future__ import annotations

import sys
from dataclasses import dataclass

from ai4sec_platform.domains.threats import source_registry
from ai4sec_platform.domains.threats.adapters.huawei_sources import (
    DEFAULT_ASCENDHUB_TARGETS,
    DEFAULT_LIVE_ORGS,
    _collect_repo_records,
    _collect_live_assets,
    _requested_sources,
    load_huawei_sources,
)
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.sources.registry import SourceRegistry


def _fresh(manual: list[dict], builtin: list[dict], key: str) -> list[dict]:
    """人工目标里剔掉内建已有的(用户在页面上加了本来就内建的,不去重就会重复采两遍)。"""
    seen = {str(item.get(key) or "") for item in builtin}
    return [item for item in manual if str(item.get(key) or "") not in seen]


def merge_manual_targets(conn, params: dict) -> dict:
    """把「数据源页」人工添加的采集目标并进 params(2026-10-08 领导反馈 #5)。

    约定:**显式传入的 params 优先**。pipeline 里写死了 orgs/ascendhub_targets 就按它跑,
    只有没给时才 = 代码内建默认值 + 库里启用的人工目标 —— 这样既让页面上的添加"下一轮就生效",
    又不改变任何既有 pipeline 的行为(不传参数的调用完全等价于改动前)。
    """
    try:
        extra = source_registry.load_collect_params(conn)
    except Exception:  # 建表/库异常不能拖垮采集主流程
        return params
    if not extra.get("orgs") and not extra.get("ascendhub_targets"):
        return params
    merged = dict(params)
    # 人工添加的排在内建前面(2026-10-09):原来追加在末尾,一旦采集侧还有截断(日常档的
    # 「只采前 N 个」),新加的目标永远轮不到,页面上显示"启用"却采不到,很难排查。
    # 采集侧现在默认不截断,这里再保证一次顺序,免得以后重新引入上限时又踩同一个坑。
    if extra["orgs"] and not merged.get("orgs"):
        merged["orgs"] = [*_fresh(extra["orgs"], DEFAULT_LIVE_ORGS, "org"), *DEFAULT_LIVE_ORGS]
    if extra["ascendhub_targets"] and not merged.get("ascendhub_targets"):
        merged["ascendhub_targets"] = [
            *_fresh(extra["ascendhub_targets"], DEFAULT_ASCENDHUB_TARGETS, "hub_id"),
            *DEFAULT_ASCENDHUB_TARGETS,
        ]
    return merged


@dataclass
class CollectHuaweiSourcesStep:
    name: str = "collect_huawei_sources"
    step_type: str = "collect_sources"

    def run(self, context: PipelineContext) -> StepResult:
        params = merge_manual_targets(context.conn, context.params)

        # Always use live path with incremental DB writes — cache path had no incremental progress
        # and refresh_source_cache=true means cache is re-fetched anyway (cache files are pointless)
        registry = SourceRegistry()
        requested = _requested_sources(params)
        records: list[dict] = []
        artifacts = []

        # 1. Repos (the big one — 25 orgs × multiple pages)
        if "repos" in requested:
            print("[collect] Fetching repos from GitCode/AtomGit...", file=sys.stderr, flush=True)
            repo_records = _collect_repo_records(registry, params)
            for record in repo_records:
                records.append(record)
                # Write each source record as a raw_artifact immediately
                art = context.artifact_store.write_json(
                    context.conn, run_id=context.run_id,
                    artifact_type="huawei_source_records",
                    name=f"threats/{record.get('source', 'unknown')}.json",
                    data={"records": [record], "params": params},
                )
                artifacts.append(art)
                context.conn.commit()
                print(f"[collect] {record.get('source')}: {len(record.get('items') or [])} items written", file=sys.stderr, flush=True)

        # 2. Assets (firmware, ascendhub, mirrors, openx)
        asset_records = _collect_live_assets(registry, params, requested_sources=requested)
        if isinstance(asset_records, list):
            for record in asset_records:
                if isinstance(record, dict):
                    records.append(record)
                    art = context.artifact_store.write_json(
                        context.conn, run_id=context.run_id,
                        artifact_type="huawei_source_records",
                        name=f"threats/{record.get('source', 'unknown')}.json",
                        data={"records": [record], "params": params},
                    )
                    artifacts.append(art)
                    context.conn.commit()
                    print(f"[collect] {record.get('source')}: {len(record.get('items') or [])} items written", file=sys.stderr, flush=True)
        elif isinstance(asset_records, dict):
            records.append(asset_records)
            art = context.artifact_store.write_json(
                context.conn, run_id=context.run_id,
                artifact_type="huawei_source_records",
                name=f"threats/{asset_records.get('source', 'unknown')}.json",
                data={"records": [asset_records], "params": params},
            )
            artifacts.append(art)
            context.conn.commit()
            print(f"[collect] {asset_records.get('source')}: {len(asset_records.get('items') or [])} items written", file=sys.stderr, flush=True)

        context.outputs["huawei_source_records"] = records
        metrics = self._metrics(records)
        print(f"[collect] Done. {metrics['items']} total items from {metrics['sources']} sources", file=sys.stderr, flush=True)
        return StepResult(metrics=metrics, artifacts=artifacts)

    def _write_records(self, context: PipelineContext, records: list[dict]) -> list:
        artifacts = []
        artifact = context.artifact_store.write_json(
            context.conn, run_id=context.run_id,
            artifact_type="huawei_source_records",
            name="threats/huawei_source_records.json",
            data={"records": records, "params": context.params},
        )
        artifacts.append(artifact)
        org_security_materials = _items(records, "org_security_materials")
        if org_security_materials:
            org_artifact = context.artifact_store.write_json(
                context.conn, run_id=context.run_id,
                artifact_type="huawei_org_security_materials",
                name="threats/huawei_org_security_materials.json",
                data={"items": org_security_materials, "params": context.params},
            )
            artifacts.append(org_artifact)
        return artifacts

    def _metrics(self, records: list[dict]) -> dict:
        return {
            "sources": len(records),
            "items": sum(len(record.get("items") or []) for record in records),
            "items_by_source": {record.get("source", "unknown"): len(record.get("items") or []) for record in records},
        }


def _items(records: list[dict], source: str) -> list[dict]:
    for record in records:
        if record.get("source") == source:
            return record.get("items") or []
    return []
