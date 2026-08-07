from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


CVE_API = "https://cveawg.mitre.org/api/cve/{cve_id}"
COMPONENT_RE = re.compile(
    r"漏洞归属组件[:：]\s*(.*?)(?:漏洞归属的版本|漏洞归属分支|CVSS)",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


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


def extract_declared_component(description: str) -> str:
    match = COMPONENT_RE.search(" ".join((description or "").split()))
    if not match:
        return ""
    component = URL_RE.sub("", match.group(1)).strip(" ,:：[]()")
    return component[:160]


def authoritative_products(payload: dict[str, Any]) -> list[str]:
    products = {
        str(affected.get("product") or "").strip()
        for affected in ((payload.get("containers") or {}).get("cna") or {}).get("affected") or []
        if str(affected.get("product") or "").strip()
    }
    return sorted(products)


def compare_component(declared: str, products: list[str]) -> str:
    if not declared:
        return "component_missing"
    if not products:
        return "authority_missing"
    declared_tokens = _tokens(declared)
    for product in products:
        product_tokens = _tokens(product)
        if declared_tokens & product_tokens:
            return "authoritative_match"
        declared_compact = _compact(declared)
        product_compact = _compact(product)
        if declared_compact and product_compact and (
            declared_compact in product_compact or product_compact in declared_compact
        ):
            return "authoritative_match"
    return "component_mismatch"


def build_report(
    rows: list[dict[str, Any]],
    authorities: dict[str, dict[str, Any]],
    *,
    min_fanout: int = 5,
) -> dict[str, Any]:
    projects_by_cve: dict[str, set[tuple[str, str]]] = defaultdict(set)
    rows_by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        cve_id = str(row["cve_id"])
        projects_by_cve[cve_id].add((str(row["org"]), str(row["project"])))
        rows_by_cve[cve_id].append(row)

    findings = []
    status_counts: dict[str, int] = defaultdict(int)
    for cve_id, projects in sorted(projects_by_cve.items(), key=lambda item: (-len(item[1]), item[0])):
        if len(projects) < min_fanout:
            continue
        authority = authorities.get(cve_id) or {}
        products = authoritative_products(authority)
        associations = []
        seen: set[tuple[str, str, str]] = set()
        for row in rows_by_cve[cve_id]:
            key = (str(row["org"]), str(row["project"]), str(row.get("source_url") or ""))
            if key in seen:
                continue
            seen.add(key)
            declared = extract_declared_component(str(row.get("description") or ""))
            status = compare_component(declared, products)
            status_counts[status] += 1
            associations.append(
                {
                    "org": key[0],
                    "project": key[1],
                    "declared_component": declared,
                    "status": status,
                    "source_type": row.get("source_type") or "",
                    "source_url": key[2],
                }
            )
        findings.append(
            {
                "cve_id": cve_id,
                "fanout": len(projects),
                "authority_state": (authority.get("cveMetadata") or {}).get("state") or "",
                "authoritative_products": products,
                "associations": associations,
            }
        )
    return {
        "reviewed_cves": len(findings),
        "reviewed_associations": sum(len(item["associations"]) for item in findings),
        "status_counts": dict(sorted(status_counts.items())),
        "findings": findings,
        "policy": {
            "authoritative_match": "retain as a shared-dependency or direct-project candidate",
            "component_mismatch": "retain evidence, require review, and exclude from direct project risk",
            "component_missing": "retain evidence and require review",
            "authority_missing": "do not reject automatically; retry authority lookup later",
        },
    }


def load_authorities(cve_ids: Iterable[str], cache_dir: Path, *, offline: bool = False) -> dict[str, dict[str, Any]]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    result: dict[str, dict[str, Any]] = {}
    for cve_id in sorted(set(cve_ids)):
        cache_path = cache_dir / f"{cve_id}.json"
        if cache_path.is_file():
            result[cve_id] = json.loads(cache_path.read_text(encoding="utf-8"))
            continue
        if offline:
            result[cve_id] = {}
            continue
        request = Request(CVE_API.format(cve_id=cve_id), headers={"User-Agent": "ai4sec-platform-cve-audit/1.0"})
        try:
            with urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
            result[cve_id] = {}
            continue
        cache_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result[cve_id] = payload
    return result


def _tokens(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", value.lower()) if len(token) >= 3}


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare high-fanout threat CVEs with CVE.org products")
    parser.add_argument("artifacts", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache-dir", type=Path, default=Path("output/cache/cve-authority"))
    parser.add_argument("--min-fanout", type=int, default=5)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()

    rows = load_rows(args.artifacts)
    projects_by_cve: dict[str, set[tuple[str, str]]] = defaultdict(set)
    for row in rows:
        projects_by_cve[str(row["cve_id"])].add((str(row["org"]), str(row["project"])))
    selected = [cve_id for cve_id, projects in projects_by_cve.items() if len(projects) >= args.min_fanout]
    authorities = load_authorities(selected, args.cache_dir, offline=args.offline)
    report = build_report(rows, authorities, min_fanout=args.min_fanout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
