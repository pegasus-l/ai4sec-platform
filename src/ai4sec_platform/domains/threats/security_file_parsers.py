from __future__ import annotations

import json
import re
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SA_RE = re.compile(r"(?:OpenHarmony-SA|openEuler-SA|openGauss-SA|opengauss-SA|Huawei-SA|SA)-\d{4}-\d{4,7}", re.I)
CVSS_CONTEXT_RE = re.compile(r"[^\n\r]{0,60}\bcvss\b[^\n\r]{0,120}", re.I)
CVSS_SCORE_RE = re.compile(r"\b(10(?:\.0)?|[0-9](?:\.\d)?)\b")
SEVERITY_TERMS = {
    "critical": ["critical", "紧急", "严重", "致命", "rce", "remote code execution", "远程代码执行"],
    "high": ["high", "高危", "重要", "privilege escalation", "权限提升", "提权"],
    "medium": ["medium", "moderate", "中危", "一般"],
    "low": ["low", "低危"],
}
BROAD_SECURITY_TERMS = [
    "security",
    "vulnerability",
    "vuln",
    "cve",
    "rce",
    "remote code execution",
    "xss",
    "csrf",
    "ssrf",
    "xxe",
    "sqli",
    "sql injection",
    "command injection",
    "code execution",
    "bypass",
    "auth bypass",
    "dos",
    "denial of service",
    "deserialization",
    "overflow",
    "buffer overflow",
    "use-after-free",
    "uaf",
    "out-of-bounds",
    "oob",
    "privilege escalation",
    "information disclosure",
    "hardcoded secret",
    "credential leak",
    "key leak",
    "path traversal",
    "directory traversal",
    "arbitrary file",
    "注入",
    "sql注入",
    "越权",
    "命令执行",
    "代码执行",
    "远程代码执行",
    "拒绝服务",
    "跨站",
    "反序列化",
    "信息泄露",
    "敏感信息",
    "缓冲区溢出",
    "越界",
    "任意文件",
    "文件上传",
    "路径穿越",
    "目录遍历",
    "硬编码",
    "密钥泄露",
    "权限提升",
    "权限绕过",
    "访问控制",
    "认证绕过",
    "未授权",
    "弱口令",
    "漏洞",
    "安全",
]


def parse_security_file(content: str, *, source_path: str = "", source_url: str = "", repo_names: list[str] | None = None) -> list[dict[str, Any]]:
    text = content or ""
    rows = parse_markdown_table_rows(text)
    items: list[dict[str, Any]] = []
    if rows:
        for row in rows:
            row_text = " | ".join(row)
            items.extend(_items_from_text(row_text, source_path=source_path, source_url=source_url, repo_names=repo_names, source_type="security_repo_file", row=row))
    if not items:
        items.extend(_items_from_text(text, source_path=source_path, source_url=source_url, repo_names=repo_names, source_type="security_repo_file"))
    return dedupe_security_items(items)


def parse_security_json(raw: Any, *, source_path: str = "", source_url: str = "", repo_names: list[str] | None = None) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return parse_security_file(raw, source_path=source_path, source_url=source_url, repo_names=repo_names)
    items = _walk_json(raw)
    parsed: list[dict[str, Any]] = []
    for item in items:
        parsed.extend(_items_from_text(repr(item), source_path=source_path, source_url=source_url, repo_names=repo_names, source_type="security_repo_file", row=item if isinstance(item, dict) else None))
    return dedupe_security_items(parsed)


def parse_markdown_table_rows(content: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in (content or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or "|" not in stripped[1:]:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append(cells)
    return rows[1:] if len(rows) > 1 else rows


def dedupe_security_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped = []
    for item in items:
        key = _dedupe_key(item)
        if not key or key in seen:
            continue
        seen.add(str(key))
        deduped.append(item)
    return deduped


def _dedupe_key(item: dict[str, Any]) -> str:
    cve_id = str(item.get("cve_id") or "")
    sa_id = str(item.get("sa_id") or "")
    source = str(item.get("source_url") or item.get("source_path") or "")
    if cve_id or sa_id:
        return f"{cve_id}:{sa_id}:{source}"
    return f"{item.get('source_type')}:{item.get('description')}"


def _items_from_text(text: str, *, source_path: str, source_url: str, repo_names: list[str] | None, source_type: str, row: Any = None) -> list[dict[str, Any]]:
    cves = sorted({match.upper() for match in CVE_RE.findall(text or "")})
    sas = sorted({match.upper() for match in SA_RE.findall(text or "")})
    severity = infer_severity(text)
    projects = _project_hints(text, repo_names or [])
    source_repo = _source_repo_hint(text, repo_names or [], row)
    items = []
    for cve in cves:
        items.append({"cve_id": cve, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "source_path": source_path, "source_repo": source_repo, "project_hints": projects, "raw_row": row})
    for sa in sas:
        items.append({"sa_id": sa, "is_sa": True, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "source_path": source_path, "source_repo": source_repo, "project_hints": projects, "raw_row": row})
    if not cves and not sas and _is_broad_security(text):
        items.append({"is_broad_sec": True, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "source_path": source_path, "source_repo": source_repo, "matched_keywords": _broad_keywords(text), "project_hints": projects, "raw_row": row})
    return items


def infer_severity(text: str) -> str:
    lowered = (text or "").lower()
    for level, terms in SEVERITY_TERMS.items():
        if any(term.lower() in lowered for term in terms):
            return level
    cvss_values = _cvss_scores(text)
    if cvss_values:
        score = max(cvss_values)
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    return "unknown"


def _cvss_scores(text: str) -> list[float]:
    scores: list[float] = []
    for context in CVSS_CONTEXT_RE.findall(text or ""):
        context_scores = []
        for match in CVSS_SCORE_RE.finditer(context):
            prefix = context[max(0, match.start() - 12):match.start()].lower()
            if re.search(r"(?:\bv|version\s*)$", prefix):
                continue
            try:
                value = float(match.group(1))
            except ValueError:
                continue
            if 0 <= value <= 10:
                context_scores.append(value)
        if len(context_scores) == 1 and context_scores[0] <= 4 and re.search(r"\bcvss\s+v?3(?:\.1)?\b", context, re.I):
            continue
        scores.extend(context_scores)
    return scores


def _walk_json(value: Any) -> list[Any]:
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_walk_json(item))
        return out
    if isinstance(value, dict):
        if any(key in value for key in ["cve", "cve_id", "id", "title", "description", "summary"]):
            return [value]
        out = []
        for item in value.values():
            out.extend(_walk_json(item))
        return out
    return []


def _is_broad_security(text: str) -> bool:
    return bool(_broad_keywords(text))


def _broad_keywords(text: str) -> list[str]:
    lowered = (text or "").lower()
    return [term for term in BROAD_SECURITY_TERMS if term in lowered]


def broad_security_keywords(text: str) -> list[str]:
    return _broad_keywords(text)


def _project_hints(text: str, repo_names: list[str]) -> list[str]:
    lowered = (text or "").lower()
    return [name for name in repo_names if name and name.lower() in lowered][:10]


def _source_repo_hint(text: str, repo_names: list[str], row: Any) -> str:
    hints = _project_hints(text, repo_names)
    if hints:
        return hints[0]
    if isinstance(row, list):
        for cell in row:
            value = str(cell or "").strip()
            if value and not CVE_RE.search(value) and not SA_RE.search(value):
                return value[:120]
    return ""


def _compact(text: str, limit: int = 500) -> str:
    return " ".join((text or "").split())[:limit]
