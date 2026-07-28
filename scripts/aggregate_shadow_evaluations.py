from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


FUNNEL_STAGES = (
    "search_candidates",
    "crawl_success",
    "content_extracted",
    "material_accepted",
    "events",
    "knowledge",
)


def aggregate_reports(report_paths: list[Path], excluded_run_ids: set[str]) -> dict[str, Any]:
    reports = [json.loads(path.read_text(encoding="utf-8")) for path in report_paths]
    included_reports = [report for report in reports if report["run_id"] not in excluded_run_ids]
    funnel = Counter()
    decisions = Counter()
    failures: dict[str, Counter[str]] = {
        "crawl": Counter(),
        "content_extraction": Counter(),
        "material_review": Counter(),
    }
    timing = Counter()
    model_calls = Counter()

    for report in included_reports:
        funnel.update({item["stage"]: int(item["count"]) for item in report.get("funnel") or []})
        decisions.update(report.get("review_decisions") or {})
        for category, items in (report.get("failures") or {}).items():
            if category in failures:
                failures[category].update({item["reason"]: int(item["count"]) for item in items})
        for metrics in (report.get("timing") or {}).values():
            timing["duration_ms"] += int(metrics.get("duration_ms") or 0)
        report_model_calls = report.get("model_calls") or {}
        for key in ("success", "failure", "latency_ms"):
            model_calls[key] += int(report_model_calls.get(key) or 0)

    candidates = funnel["search_candidates"]
    pages = candidates
    return {
        "production_writes": False,
        "included_run_ids": [report["run_id"] for report in included_reports],
        "excluded_run_ids": sorted(excluded_run_ids),
        "excluded_reason": "Early runs with interrupted or known-degraded model execution are excluded from benchmark rates.",
        "funnel": [{"stage": stage, "count": funnel[stage]} for stage in FUNNEL_STAGES],
        "quality": {
            "crawl_success_rate": _rate(funnel["crawl_success"], pages),
            "content_extracted_rate": _rate(funnel["content_extracted"], pages),
            "review_accept_rate": _rate(decisions["accept"], sum(decisions.values())),
        },
        "review_decisions": dict(decisions),
        "failures": {category: _top(items) for category, items in failures.items()},
        "timing": {
            "total_stage_duration_ms": timing["duration_ms"],
            "note": "Durations are summed across stages and runs; model stages run concurrently within a batch.",
        },
        "model_calls": {
            "count": int(model_calls["success"] + model_calls["failure"]),
            "success": int(model_calls["success"]),
            "failure": int(model_calls["failure"]),
            "latency_ms": int(model_calls["latency_ms"]),
            "estimated_cost": None,
        },
        "sampling": {
            "requires_human_labels": True,
            "precision": None,
            "recall": None,
        },
    }


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def _top(counter: Counter[str], limit: int = 10) -> list[dict[str, Any]]:
    return [{"reason": reason, "count": count} for reason, count in counter.most_common(limit)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate vulnerability shadow evaluation artifacts.")
    parser.add_argument("--report", action="append", required=True, type=Path, help="Per-run evaluation JSON path.")
    parser.add_argument("--exclude-run", action="append", default=[], help="Run ID excluded from benchmark metrics.")
    parser.add_argument("--output", required=True, type=Path, help="Output JSON path.")
    args = parser.parse_args()

    report = aggregate_reports(args.report, set(args.exclude_run))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
