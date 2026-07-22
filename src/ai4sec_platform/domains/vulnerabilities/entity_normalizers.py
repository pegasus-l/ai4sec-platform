from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.IGNORECASE)
VERSION_RE = re.compile(r"(?:version|versions|版本|affected|影响版本|fixed in|修复版本|before|<=|<)[:：\s]*([A-Za-z0-9_.\-/]+)", re.IGNORECASE)

PRODUCT_HINTS = {
    "apache": "Apache HTTP Server",
    "httpd": "Apache HTTP Server",
    "mali": "Arm Mali GPU",
    "pixel": "Google Pixel",
    "kernel": "Linux/Android Kernel",
    "csp": "Browser CSP",
    "xml": "XML parser",
    "xxe": "XML parser",
    "sql": "Database query builder",
    "desync": "HTTP proxy / frontend-backend",
}


def enrich_material_entities(item: dict[str, Any]) -> dict[str, Any]:
    text = material_text(item)
    cve_ids = extract_cve_ids(text)
    cwe_ids = extract_cwe_ids(text)
    affected_versions = extract_versions(text)
    affected_products = normalize_affected_products(item, text)
    source_host = source_host_from_url(item.get("url") or item.get("source_url") or "")
    return {
        **item,
        "cve_ids": cve_ids,
        "cwe_ids": cwe_ids,
        "affected_versions": affected_versions,
        "affected_products": affected_products,
        "source_host": item.get("source_host") or source_host,
        "entity_mentions": {
            "cve_ids": cve_ids,
            "cwe_ids": cwe_ids,
            "affected_versions": affected_versions,
            "affected_products": affected_products,
        },
    }


def extract_cve_ids(text: str) -> list[str]:
    return sorted({match.upper() for match in CVE_RE.findall(text or "")})


def extract_cwe_ids(text: str) -> list[str]:
    return sorted({match.upper() for match in CWE_RE.findall(text or "")})


def extract_versions(text: str) -> list[str]:
    versions = []
    for match in VERSION_RE.finditer(text or ""):
        value = match.group(1).strip(" ,.;()[]{}\n\t")
        if value and value not in versions:
            versions.append(value)
    return versions[:12]


def normalize_affected_products(item: dict[str, Any], text: str | None = None) -> list[str]:
    products: list[str] = []
    for value in item.get("affected_products") or item.get("products") or []:
        if isinstance(value, str) and value not in products:
            products.append(value)
    lowered = (text if text is not None else material_text(item)).lower()
    for hint, label in PRODUCT_HINTS.items():
        if hint in lowered and label not in products:
            products.append(label)
    return products[:12]


def source_host_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.removeprefix("www.")
    except Exception:
        return ""


def material_text(item: dict[str, Any]) -> str:
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    values: list[Any] = [
        item.get("title"),
        item.get("summary"),
        item.get("cleaned_text_excerpt"),
        item.get("url"),
        item.get("search_keywords"),
        " ".join(str(x) for x in item.get("key_findings") or []),
        raw.get("title"),
        raw.get("summary"),
        raw.get("check_reason"),
        raw.get("cleaned_text"),
        raw.get("markdown"),
    ]
    return "\n".join(str(value or "") for value in values)
