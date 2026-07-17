from __future__ import annotations

import re
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
VERSION_RE = re.compile(r"(?:version|版本|affected|影响版本|<=|<)[:：\s]*([A-Za-z0-9_.\-]+)", re.IGNORECASE)


def extract_material_evidence(item: dict[str, Any]) -> dict[str, Any]:
    text = _text(item)
    cves = sorted({match.upper() for match in CVE_RE.findall(text)})
    versions = sorted({match.group(1) for match in VERSION_RE.finditer(text) if match.group(1)})[:10]
    return {
        "cve_ids": cves,
        "affected_versions": versions,
        "has_poc": any(term in text.lower() for term in ["poc", "exploit", "复现", "利用代码", "payload"]),
        "has_mitigation": any(term in text.lower() for term in ["patch", "fix", "mitigation", "修复", "缓解"]),
        "technical_indicators": [term for term in ["rce", "xss", "sqli", "auth bypass", "命令执行", "越权", "反序列化"] if term in text.lower()],
    }


def _text(item: dict[str, Any]) -> str:
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    values = [item.get("title"), item.get("summary"), " ".join(item.get("key_findings") or []), raw]
    return " ".join(repr(value) for value in values if value is not None)
