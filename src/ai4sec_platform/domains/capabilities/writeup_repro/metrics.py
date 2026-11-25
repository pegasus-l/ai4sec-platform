"""T5.3:复利指标 —— 回答"经验沉淀到底有没有用"。

三个问题, 每个都要能给出数字:

1. **recipe 复用有没有发生**:命中次数、强/弱各多少(强弱口径见 ``recipes.match_strength``);
2. **复用了是不是更省**:命中的任务与没命中的任务, 在**耗时**与**工具调用数**上差多少。
   这是唯一能验证"省了试错"的实测口径 —— 注意它是**相关性**, 不是因果: 命中的任务可能本来就更简单;
3. **规律沉淀得怎么样**:pattern 总数、可溯源(``from_repro``)的比例、回测通过率。

另外单列一个"spec 阶段出局率":原文写不清导致根本没进执行的比例 —— 它是当前最大的产能瓶颈,
放进同一张表里, 免得只看"复现成功率"误判系统健康度。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

VERDICTS = ("success", "partial", "cannot_repro", "failed", "blocked")


def _now() -> str:
    return f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


def _mean(values: list[float]) -> float | None:
    clean = [float(v) for v in values if isinstance(v, (int, float))]
    return round(sum(clean) / len(clean), 1) if clean else None


def _verdict(evidence: dict[str, Any]) -> dict[str, Any]:
    reuse = evidence.get("recipe_reuse") or {}
    return {
        "used": bool(reuse.get("used")),
        "strength": str(reuse.get("strength") or ("weak" if reuse.get("used") else "")),
        "recipe_key": str(reuse.get("recipe_key") or ""),
    }


def summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """把库里的任务 / recipe / pattern 压成一张复利指标表。"""
    rows = conn.execute(
        "SELECT id, status, verdict, failure_reason, duration_seconds, tool_calls, evidence_json"
        " FROM writeup_repro_tasks"
    ).fetchall()

    by_verdict: dict[str, int] = {}
    by_status: dict[str, int] = {}
    spec_stage = 0
    buckets: dict[str, dict[str, list[float]]] = {
        "none": {"duration": [], "calls": []},
        "weak": {"duration": [], "calls": []},
        "strong": {"duration": [], "calls": []},
    }
    reused_keys: dict[str, int] = {}
    hits = {"total": 0, "strong": 0, "weak": 0}

    for row in rows:
        item = dict(row)
        status = str(item.get("status") or "")
        by_status[status] = by_status.get(status, 0) + 1
        verdict = str(item.get("verdict") or "")
        if verdict:
            by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        if status == "cannot_repro" and str(item.get("failure_reason") or "") == "article_incomplete":
            spec_stage += 1

        try:
            evidence = json.loads(item.get("evidence_json") or "{}")
        except (TypeError, ValueError):
            evidence = {}
        reuse = _verdict(evidence if isinstance(evidence, dict) else {})
        bucket = reuse["strength"] if reuse["used"] else "none"
        if bucket not in buckets:
            bucket = "weak"
        if reuse["used"]:
            hits["total"] += 1
            hits["strong" if bucket == "strong" else "weak"] += 1
            key = reuse["recipe_key"]
            if key:
                reused_keys[key] = reused_keys.get(key, 0) + 1
        buckets[bucket]["duration"].append(item.get("duration_seconds") or 0)
        buckets[bucket]["calls"].append(item.get("tool_calls") or 0)

    recipes = conn.execute(
        "SELECT recipe_key, material_id, degraded, fingerprint_json FROM writeup_repro_recipes"
    ).fetchall()
    non_degraded = sum(1 for r in recipes if not int(dict(r).get("degraded") or 0))

    patterns = conn.execute(
        "SELECT provenance, backtest_status FROM writeup_repro_patterns"
    ).fetchall()
    provenance: dict[str, int] = {}
    backtest: dict[str, int] = {}
    for row in patterns:
        item = dict(row)
        prov = str(item.get("provenance") or "")
        provenance[prov] = provenance.get(prov, 0) + 1
        status = str(item.get("backtest_status") or "pending")
        backtest[status] = backtest.get(status, 0) + 1
    traceable = sum(count for prov, count in provenance.items() if prov == "from_repro")

    executed = sum(1 for row in rows if str(dict(row).get("status")) in VERDICTS)

    return {
        "generated_at": _now(),
        "tasks": {
            "total": len(rows),
            "executed": executed,
            "by_status": by_status,
            "by_verdict": by_verdict,
            # 原文写不清、根本没进执行的比例 —— 最大的产能瓶颈, 必须和成功率并排看。
            "spec_stage_dropped": spec_stage,
            "spec_stage_rate": round(spec_stage / executed, 3) if executed else None,
        },
        "reuse": {
            "hits": hits,
            "by_bucket": {
                name: {
                    "tasks": len(data["duration"]),
                    "avg_duration_seconds": _mean(data["duration"]),
                    "avg_tool_calls": _mean(data["calls"]),
                }
                for name, data in buckets.items()
            },
            "top_recipes": sorted(
                ({"recipe_key": key, "times": count} for key, count in reused_keys.items()),
                key=lambda item: item["times"], reverse=True,
            )[:5],
        },
        "recipes": {
            "total": len(recipes),
            "non_degraded": non_degraded,
            "materials": len({int(dict(r).get("material_id") or 0) for r in recipes}),
        },
        "patterns": {
            "total": len(patterns),
            "traceable": traceable,
            "traceable_rate": round(traceable / len(patterns), 3) if patterns else None,
            "by_provenance": provenance,
            "backtest": backtest,
        },
        "note": (
            "复用耗时差是相关性不是因果: 命中的任务可能本来就更简单。"
            "强弱口径见 recipes.match_strength —— 它是启发式, 只用于提示谨慎。"
        ),
    }
