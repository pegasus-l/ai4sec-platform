"""威胁分析·资产↔代码仓 AI 关联 —— 共享判定例程。

把原先只存在于 app/api/threats.py 单资产端点的逻辑抽到 domain 层,
供「单点 ai-associate」与「批跑 pipeline」共用,杜绝两套 prompt/候选检索漂移。

写盘(幂等,复用现有 repo 层):
  - evidence_items(evidence_type='asset_association') ← 保留为最新一条(force 重跑先删旧)
  - asset payload merge: ai_association / assoc_status(linked|orphan)/ assoc_at / assoc_link_count
  - threat_links 边表 upsert(method='llm',按 (asset_id, repo_id, method) 幂等)

诚实标记原则:LLM 失败或解析失败 → 不伪造边,资产落 orphan,reason 留给人工。
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.models.router import LLMRouter

log = logging.getLogger(__name__)

DOMAIN = "threats"
_REPO_POOL_LIMIT = 800  # 候选检索池上限(与原端点一致)
_CANDIDATE_CAP = 30  # 候选仓上限(与原端点一致)
_VALID_CONFIDENCES = ("direct", "inferred", "weak")

# 抽样优先级:固件/镜像/昇腾镜像仓等最有真信号的来源排前,便于第一轮人工验收
_SOURCE_PRIORITY = ("firmware", "ascendhub", "openx", "mirror")


def _asset_association_prompt() -> str:
    """(从 app/api/threats.py 原样迁移,保持单点/批跑行为一致)"""
    return """
你是华为开源生态分析专家。我给你一个资产信息和一批候选代码仓库，请判断哪些仓库和这个资产有关联。

关联类型：
- direct: 资产直接包含或依赖该仓库的代码（如固件包里有该仓库的 .so 文件）
- inferred: 通过产品线/生态链路推断关联（如 Atlas 固件 → CANN 仓库，因为 CANN 是 Atlas 的软件栈）
- weak: 间接关联（如镜像站包含该仓库的软件包）

如果没有关联，返回空数组。

输出 JSON：
{
  "associations": [
    {"repo_id": "仓库ID", "repo_name": "org/name", "confidence": "direct|inferred|weak", "reason": "关联理由"}
  ],
  "summary": "一句话总结关联情况"
}
""".strip()


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _extract_output(output: Any) -> tuple[list[dict[str, Any]], str]:
    """从 complete_json 返回里稳健取 associations/summary(兼容包装结构)。"""
    out = output if isinstance(output, dict) else {}
    result = _as_dict(out.get("result")) or out
    associations = out.get("associations") or result.get("associations") or []
    if not isinstance(associations, list):
        associations = []
    summary = out.get("summary") or result.get("summary") or "已完成关联分析。"
    return [a for a in associations if isinstance(a, dict)], str(summary)


def _asset_features(asset: dict[str, Any]) -> tuple[str, str, str, str]:
    """(asset_name, asset_source, asset_desc, asset_model) —— 字段口径与原端点一致。"""
    payload = asset.get("payload") or {}
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    name = asset.get("title", "")
    source = str(payload.get("source", ""))
    desc = str(raw.get("msg") or raw.get("description") or raw.get("softwareExplain") or "")
    model = str(raw.get("modelName") or raw.get("displayName") or raw.get("name") or raw.get("repoName") or "")
    return name, source, desc, model


def _candidate_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, title, summary FROM domain_items "
        "WHERE domain = ? AND item_type = 'target' LIMIT ?",
        (DOMAIN, _REPO_POOL_LIMIT),
    ).fetchall()
    return [repo.row_to_dict(row) for row in rows]


def _pick_candidates(
    conn: sqlite3.Connection, words: set[str]
) -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]]]:
    """word-overlap 命中池内仓,上限 30;无命中回退 score top10。返回 (candidates, by_id)。"""
    candidates: list[dict[str, Any]] = []
    by_id: dict[int, dict[str, Any]] = {}
    for rdata in _candidate_rows(conn):
        text = (rdata.get("title", "") + " " + rdata.get("summary", "")).lower()
        if any(word in text for word in words):
            rid = int(rdata["id"])
            candidates.append({
                "repo_id": rid,
                "repo_name": rdata.get("title", ""),
                "repo_summary": (rdata.get("summary", "") or "")[:100],
            })
            by_id[rid] = rdata
        if len(candidates) >= _CANDIDATE_CAP:
            break
    if not candidates:
        top = conn.execute(
            "SELECT id, title, summary FROM domain_items "
            "WHERE domain = ? AND item_type = 'target' ORDER BY COALESCE(score, 0) DESC LIMIT 10",
            (DOMAIN,),
        ).fetchall()
        for rr in top:
            d = repo.row_to_dict(rr)
            rid = int(d["id"])
            candidates.append({
                "repo_id": rid,
                "repo_name": d.get("title", ""),
                "repo_summary": (d.get("summary", "") or "")[:100],
            })
            by_id[rid] = d
    return candidates, by_id


def _normalize_valid(associations: list[dict[str, Any]], by_id: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    """只保留 repo_id 确在候选集内、且未重复的条目,补齐 confidence/reason 默认值。"""
    valid: list[dict[str, Any]] = []
    seen: set[int] = set()
    for assoc in associations:
        try:
            rid = int(assoc.get("repo_id"))
        except (TypeError, ValueError):
            continue
        if rid not in by_id or rid in seen:
            continue
        seen.add(rid)
        conf = assoc.get("confidence")
        if conf not in _VALID_CONFIDENCES:
            conf = "inferred"
        valid.append({
            "repo_id": rid,
            "repo_name": assoc.get("repo_name") or by_id[rid].get("title", ""),
            "confidence": conf,
            "reason": str(assoc.get("reason") or "")[:500],
        })
    return valid


def _materialize_links(conn: sqlite3.Connection, asset_id: int, associations: list[dict[str, Any]]) -> None:
    """把一批(已校验)关联写进 threat_links(method='llm',按 (asset,repo,method) 幂等)。

    llm 判定的边一律落边表,人工状态列保留(none)。repo_id 非法/查无此仓由 FK 兜底。
    """
    for assoc in associations:
        try:
            rid = int(assoc.get("repo_id"))
        except (TypeError, ValueError):
            continue
        conf = assoc.get("confidence")
        if conf not in _VALID_CONFIDENCES:
            conf = "inferred"
        repo.upsert_threat_link(
            conn,
            asset_id=asset_id,
            repo_id=rid,
            confidence=conf,
            reason=str(assoc.get("reason") or "")[:500],
            rel_type="related",
            method="llm",
        )


def _merge_assoc_status(conn: sqlite3.Connection, asset_id: int, payload: dict[str, Any], evidence_payload: dict[str, Any]) -> None:
    """旧数据兜底:有 evidence/ai_association 但缺 assoc_status 的资产,派生补齐三态,保持口径统一。"""
    if payload.get("assoc_status"):
        return
    assocs = evidence_payload.get("associations") or []
    payload.setdefault("assoc_status", "linked" if isinstance(assocs, list) and assocs else "orphan")
    payload.setdefault("assoc_link_count", len(assocs) if isinstance(assocs, list) else 0)
    payload.setdefault("assoc_at", evidence_payload.get("reviewed_at", ""))
    repo.update_domain_item(conn, item_id=asset_id, payload=payload)
    conn.commit()


def run_asset_association(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    force: bool = False,
    run_id: str | None = None,
) -> dict[str, Any]:
    """对单个资产跑一遍 AI 关联并幂等落盘。

    force=False 且已有最新 asset_association evidence 时直接返回缓存(与原端点一致)。
    force=True 先删旧 evidence 再重跑,threat_links 按 (asset_id, repo_id, method) upsert 覆写。
    """
    row = conn.execute(
        "SELECT * FROM domain_items WHERE id = ? AND domain = ? AND item_type = 'asset'",
        (asset_id, DOMAIN),
    ).fetchone()
    if not row:
        return {"item_id": asset_id, "status": "error", "error": "asset not found"}
    asset = repo.row_to_dict(row)
    payload = asset.get("payload") or {}
    if not isinstance(payload, dict):
        payload = _as_dict(payload)

    if not force:
        existing = conn.execute(
            "SELECT * FROM evidence_items WHERE domain_item_id = ? AND evidence_type = 'asset_association' ORDER BY id DESC LIMIT 1",
            (asset_id,),
        ).fetchone()
        if existing:
            edata = repo.row_to_dict(existing)
            ep = edata.get("payload") or {}
            if not isinstance(ep, dict):
                ep = _as_dict(ep)
            if not payload.get("ai_association"):
                _merge_assoc_status(conn, asset_id, payload, ep)
            # 幂等回放:老数据只写 evidence/ai_association、未落 threat_links,
            # 命中缓存时把关联补成边,保证边表与 evidence 永远一致。
            _materialize_links(conn, asset_id, ep.get("associations") or [])
            if not payload.get("assoc_link_count"):
                payload["assoc_link_count"] = len(ep.get("associations") or [])
                payload["assoc_status"] = payload.get("assoc_status") or ("linked" if ep.get("associations") else "orphan")
                repo.update_domain_item(conn, item_id=asset_id, payload=payload)
            conn.commit()
            return {"item_id": asset_id, "status": "cached", "associations": ep}

    asset_name, asset_source, asset_desc, asset_model = _asset_features(asset)
    words: set[str] = set()
    for word in (f"{asset_name} {asset_model} {asset_desc}").lower().replace("/", " ").replace("-", " ").replace("_", " ").split():
        if len(word) >= 3:
            words.add(word)

    candidates, by_id = _pick_candidates(conn, words)
    llm_payload = {
        "asset_name": asset_name,
        "asset_type": asset_source,
        "asset_model": asset_model,
        "asset_description": asset_desc[:300],
        "candidate_repos": [
            {"repo_id": str(c["repo_id"]), "repo_name": c["repo_name"], "repo_summary": c["repo_summary"]}
            for c in candidates
        ],
    }

    output = LLMRouter().complete_json(
        profile="configured_model", prompt=_asset_association_prompt(), payload=llm_payload
    )
    if run_id:
        try:
            repo.create_model_call(
                conn,
                run_id=run_id,
                agent_name="asset_association",
                model_profile="configured_model",
                provider=(output or {}).get("provider", "configured_model") if isinstance(output, dict) else "configured_model",
                status="success",
                input_payload={"asset_id": asset_id, "payload": llm_payload},
                output_payload=output,
            )
        except Exception as exc:  # noqa: BLE001 - 记录不阻断
            log.warning("model_call 记录失败 asset=%s: %s", asset_id, exc)

    raw_associations, summary = _extract_output(output)
    valid = _normalize_valid(raw_associations, by_id)
    association_data = {
        "associations": valid,
        "summary": summary,
        "reviewed_at": datetime.now().isoformat(),
    }

    # 先删旧 evidence,保证「最新一条=最近一次 run」,幂等重跑不堆积
    conn.execute(
        "DELETE FROM evidence_items WHERE domain_item_id = ? AND evidence_type = 'asset_association'",
        (asset_id,),
    )
    repo.create_evidence(
        conn,
        domain=DOMAIN,
        domain_item_id=asset_id,
        evidence_type="asset_association",
        title="AI 资产关联分析",
        content=summary,
        source_url=asset.get("source_url") or "",
        confidence=None,
        payload=association_data,
    )

    payload["ai_association"] = association_data
    payload["assoc_status"] = "linked" if valid else "orphan"
    payload["assoc_at"] = datetime.now().isoformat()
    payload["assoc_link_count"] = len(valid)
    repo.update_domain_item(conn, item_id=asset_id, payload=payload)

    _materialize_links(conn, asset_id, valid)
    conn.commit()
    return {"item_id": asset_id, "status": "success", "associations": association_data}


def _source_rank(source: str) -> int:
    low = source.lower()
    for i, key in enumerate(_SOURCE_PRIORITY):
        if key in low:
            return i
    return len(_SOURCE_PRIORITY)


def select_batch_assets(
    conn: sqlite3.Connection,
    *,
    asset_ids: list[int] | None = None,
    scope: str = "sample",
    sample_size: int = 30,
    force: bool = False,
) -> list[int]:
    """选出批跑目标资产 id 列表。

    - asset_ids 给了就用它(显式清单,通常前端按 id 传);
    - scope='all': 全部「无有效边」资产(status ∈ None/orphan,或 linked 但无 threat_links 边的陈旧数据);
    - scope='sample'(默认): 按来源优先级(firmware/ascendhub/openx/mirror 靠前)
      挑前 sample_size 个无有效边资产,便于第一轮人工验质量。
    force=True 时连已有边的 linked 资产也纳入重跑。
    """
    if asset_ids:
        return [int(a) for a in asset_ids]

    # 已落边才算真 linked:只写 evidence/ai_association 但没边的陈旧资产视为未跑,纳入批跑
    edged: set[int] = set()
    if not force:
        for (aid,) in conn.execute("SELECT DISTINCT asset_id FROM threat_links").fetchall():
            edged.add(int(aid))

    rows = conn.execute(
        "SELECT id, source, payload_json FROM domain_items WHERE domain = ? AND item_type = 'asset' ORDER BY id",
        (DOMAIN,),
    ).fetchall()
    wanted: list[tuple[int, str]] = []
    for row in rows:
        payload = repo.loads(row["payload_json"], {})
        status = payload.get("assoc_status")
        if not force and status == "linked" and int(row["id"]) in edged:
            continue
        wanted.append((int(row["id"]), str(row["source"] or "")))
    if scope == "all":
        return [w[0] for w in wanted]
    wanted.sort(key=lambda w: _source_rank(w[1]))
    return [w[0] for w in wanted[: max(0, int(sample_size))]]
