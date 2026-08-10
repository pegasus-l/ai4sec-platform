from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


CVE_API = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
COMPONENT_RE = re.compile(
    r"漏洞归属组件[:：]\s*(.*?)(?:漏洞归属的版本|漏洞归属分支|CVSS)",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


def validate_high_fanout_cves(
    scout: dict[str, Any],
    *,
    cache_dir: Path,
    mode: str = "cache",
    min_fanout: int = 5,
    limit: int = 25,
    refresh: bool = False,
) -> dict[str, Any]:
    if mode not in {"cache", "live"}:
        raise ValueError("CVE authority mode must be cache or live")
    findings = _findings_by_cve(scout)
    selected = [
        cve_id
        for cve_id, rows in sorted(findings.items(), key=lambda item: (-len(_projects(item[1])), item[0]))
        if len(_projects(rows)) >= min_fanout
    ][: max(0, limit)]
    status_counts: Counter[str] = Counter()
    cache_hits = 0
    live_requests = 0
    cache_dir.mkdir(parents=True, exist_ok=True)
    for associations in findings.values():
        for association in associations:
            finding = association["finding"]
            cve_id = str(finding.get("cve_id") or "").upper()
            description_cves = extract_description_cve_ids(str(finding.get("description") or ""))
            if description_cves and cve_id not in description_cves:
                finding["authority_validation"] = {
                    "status": "identifier_mismatch",
                    "declared_cve_ids": description_cves,
                    "authoritative_products": [],
                    "authority_state": "",
                    "authority_source": "local",
                }
                finding["risk_eligible"] = False
                finding["risk_exclusion_reason"] = "cve_identifier_description_mismatch"
                status_counts["identifier_mismatch"] += 1
    for cve_id in selected:
        authority, source = _load_authority(cve_id, cache_dir, mode=mode, refresh=refresh)
        cache_hits += source == "cache"
        live_requests += source == "live"
        products = authoritative_products(authority)
        authority_state = str((authority.get("cveMetadata") or {}).get("state") or "")
        for association in findings[cve_id]:
            finding = association["finding"]
            if (finding.get("authority_validation") or {}).get("status") == "identifier_mismatch":
                continue
            declared = extract_declared_component(str(finding.get("description") or ""))
            status = compare_component(declared, products)
            finding["authority_validation"] = {
                "status": status,
                "declared_component": declared,
                "authoritative_products": products,
                "authority_state": authority_state,
                "authority_source": source,
            }
            if status == "component_mismatch":
                finding["risk_eligible"] = False
                finding["risk_exclusion_reason"] = "cve_authority_component_mismatch"
            status_counts[status] += 1
    return {
        "mode": mode,
        "min_fanout": min_fanout,
        "selected_cves": len(selected),
        "reviewed_associations": sum(status_counts.values()),
        "status_counts": dict(sorted(status_counts.items())),
        "cache_hits": cache_hits,
        "live_requests": live_requests,
    }


def extract_declared_component(description: str) -> str:
    match = COMPONENT_RE.search(" ".join((description or "").split()))
    if not match:
        return ""
    return URL_RE.sub("", match.group(1)).strip(" ,:：[]()")[:160]


def extract_description_cve_ids(description: str) -> list[str]:
    return sorted({match.upper() for match in CVE_RE.findall(description or "")})


def authoritative_products(payload: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(affected.get("product") or "").strip()
            for affected in ((payload.get("containers") or {}).get("cna") or {}).get("affected") or []
            if str(affected.get("product") or "").strip()
        }
    )


def compare_component(declared: str, products: list[str]) -> str:
    if not declared:
        return "component_missing"
    if not products:
        return "authority_missing"
    declared_tokens = _tokens(declared)
    declared_compact = _compact(declared)
    for product in products:
        if declared_tokens & _tokens(product):
            return "authoritative_match"
        product_compact = _compact(product)
        if declared_compact and product_compact and (
            declared_compact in product_compact or product_compact in declared_compact
        ):
            return "authoritative_match"
    return "component_mismatch"


def _findings_by_cve(scout: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    findings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for org, org_data in (scout.get("orgs") or {}).items():
        for project_name, project in (org_data.get("projects") or {}).items():
            for finding in project.get("cves") or []:
                if finding.get("cve_id"):
                    findings[str(finding["cve_id"])].append(
                        {"project_key": f"{org}/{project_name}", "finding": finding}
                    )
    return findings


def _projects(rows: list[dict[str, Any]]) -> set[str]:
    return {str(row["project_key"]) for row in rows}


def _load_authority(cve_id: str, cache_dir: Path, *, mode: str, refresh: bool) -> tuple[dict[str, Any], str]:
    cache_path = cache_dir / f"{cve_id}.json"
    if cache_path.is_file() and (not refresh or mode == "cache"):
        try:
            return json.loads(cache_path.read_text(encoding="utf-8")), "cache"
        except json.JSONDecodeError:
            if mode == "cache":
                return {}, "invalid_cache"
    if mode == "cache":
        return {}, "missing"
    request = Request(CVE_API.format(cve_id=cve_id), headers={"User-Agent": "ai4sec-platform/1.0"})
    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return {}, "unavailable"
    cache_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload, "live"


def _tokens(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", value.lower()) if len(token) >= 3}


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())
