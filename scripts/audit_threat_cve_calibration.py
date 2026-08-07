from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


COORDINATION_PROJECTS = {
    "release-management",
    "security",
    "security-committee",
    "cve-manager",
}


def load_rows(paths: Iterable[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        for org, org_data in (payload.get("orgs") or {}).items():
            for project, project_data in (org_data.get("projects") or {}).items():
                for finding in project_data.get("cves") or []:
                    if finding.get("cve_id"):
                        rows.append({"org": org, "project": project, **finding, "artifact": str(path)})
    return rows


def classify(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_project_cve: Counter[tuple[str, str, str]] = Counter()
    for row in rows:
        cve_id = str(row["cve_id"])
        project_key = (str(row["org"]), str(row["project"]), cve_id)
        by_cve[cve_id].append(row)
        by_project_cve[project_key] += 1

    fanout = {
        cve_id: sorted({(str(row["org"]), str(row["project"])) for row in findings})
        for cve_id, findings in by_cve.items()
    }
    coordination_rows = [
        row for row in rows if str(row["project"]).lower() in COORDINATION_PROJECTS
    ]
    duplicate_groups = [
        {"org": org, "project": project, "cve_id": cve_id, "rows": count}
        for (org, project, cve_id), count in sorted(by_project_cve.items())
        if count > 1
    ]
    high_fanout = [
        {"cve_id": cve_id, "fanout": len(projects), "projects": projects}
        for cve_id, projects in sorted(fanout.items(), key=lambda item: (-len(item[1]), item[0]))
        if len(projects) >= 4
    ]
    return {
        "rows": len(rows),
        "unique_cves": len(by_cve),
        "source_types": dict(Counter(str(row.get("source_type") or "unknown") for row in rows)),
        "coordination_rows": len(coordination_rows),
        "coordination_projects": dict(Counter(str(row["project"]) for row in coordination_rows)),
        "duplicate_groups": duplicate_groups,
        "multi_project_cves": sum(len(projects) > 1 for projects in fanout.values()),
        "fanout_distribution": dict(Counter(len(projects) for projects in fanout.values())),
        "high_fanout": high_fanout,
        "review_policy": {
            "coordination_rows": "do not treat as direct project vulnerability without component evidence",
            "duplicate_groups": "deduplicate within the same org/project/CVE before persistence",
            "high_fanout": "manual review; shared dependency is not automatically a false positive",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit threat CVE associations from scout artifacts")
    parser.add_argument("artifacts", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = classify(load_rows(args.artifacts))
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
