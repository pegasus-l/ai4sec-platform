"""外部漏洞源(NVD / OSV)→ 案例字段的**纯转换**:不碰网络、不碰数据库。

单独拆一层的理由:这些映射规则是 P3 里唯一"数据对不对"的地方(标题取哪句、CVSS 取哪个、
哪条引用才算补丁),而它们全是纯函数 —— 可以拿真实响应的片段直接喂单测,不必起 HTTP、
不必建库、不必等一晚跑批。

三条口径(与 cases.py 的诚实性硬规则配套):

1. **CVSS 以 NVD 自己的为准,退而求其次用 CNA 的。** 实测 2026-10-12~19 的 5496 条新 CVE 里,
   只有 7.0% 有 `cvssMetricV31/Primary`(NVD 分析完的),76.2% 只有 `Secondary`(CNA 自评)。
   不区分这两者,就等于把厂商自己的打分当成 NVD 结论。
2. **无分数不等于 0 分。** `min_cvss` 过滤的是"有分且低于阈值";没分的洞按阈值口径
   **默认不收**(否则阈值形同虚设),但调用方可以传 `min_cvss=0` 全收。
3. **引用里只有 github/gitlab 的 commit、PR 链接才可能是补丁。** NVD 的 references 实测
   **几乎不打 `Patch`/`Fix` 标签**(抽样 tags 全空),只能靠 URL 形态认;真正带 `type=FIX`
   的是 OSV。两条路都走,才能把补丁率从 11% 抬到 15%(2026-10-19 基线实测)。
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

# NVD 的"没有 CWE"占位值,不是真的弱点类型
NOISE_CWE = ("NVD-CWE-noinfo", "NVD-CWE-Other")

# NVD 2.0 的 metrics 键按版本从新到旧;同一版本里 Primary(NVD 自己分析)优先于 Secondary(CNA)。
CVSS_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

# GHSA 的 database_specific.severity 用的是 MODERATE,NVD 用 MEDIUM —— 统一到 NVD 口径
GHSA_SEVERITY = {"low": "LOW", "moderate": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}

_GH_COMMIT_RE = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-fA-F]{7,40})", re.IGNORECASE)
_GH_PR_RE = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s]+)/pull/(\d{1,8})", re.IGNORECASE)
_GL_COMMIT_RE = re.compile(r"^https?://gitlab\.com/(.+?)/-/commit/([0-9a-fA-F]{7,40})", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d+$")
_DIFF_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)


# ── NVD ──────────────────────────────────────────────────────────────────────

def pick_cvss(cve: dict[str, Any]) -> tuple[float | None, str, str]:
    """返回 (baseScore, baseSeverity, vectorString)。拿不到分数时返回 (None, "", "")。

    同一版本有 Primary 就绝不看 Secondary —— 两者可能差一个等级,混用会让"严重度"变成随机值。
    """
    metrics = cve.get("metrics") or {}
    for key in CVSS_METRIC_KEYS:
        entries = [entry for entry in (metrics.get(key) or []) if isinstance(entry, dict)]
        if not entries:
            continue
        primary = [entry for entry in entries if entry.get("type") == "Primary"]
        entry = (primary or entries)[0]
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        severity = str(data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()
        vector = str(data.get("vectorString") or "")
        return (float(score) if score is not None else None), severity, vector
    return None, "", ""


def description(cve: dict[str, Any]) -> str:
    """取英文描述(NVD 实测 5496 条全是 en,西语是附带的重复文案)。"""
    for item in cve.get("descriptions") or []:
        if str(item.get("lang") or "") == "en" and str(item.get("value") or "").strip():
            return str(item["value"]).strip()
    for item in cve.get("descriptions") or []:
        if str(item.get("value") or "").strip():
            return str(item["value"]).strip()
    return ""


def cwe_ids(cve: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = str(desc.get("value") or "").strip()
            if value and value not in NOISE_CWE and _CWE_RE.match(value) and value not in out:
                out.append(value)
    return out


def references(cve: dict[str, Any]) -> list[str]:
    """NVD references 的 URL 列表。frontend 的 references 字段就是 string[],不要塞对象进去。"""
    out: list[str] = []
    for ref in cve.get("references") or []:
        url = str(ref.get("url") or "").strip()
        if url and url not in out:
            out.append(url)
    return out


def short_title(cve_id: str, desc: str, limit: int = 90) -> str:
    """`CVE-xxx · 第一句描述`。卡片上截 2 行,所以标题本身要短。

    取第一句而不是整段:描述动辄 300+ 字,原样当标题会让列表完全没法扫。
    """
    text = str(desc or "").strip()
    # 第一句:遇到 ". " 且后面是大写/NVD 固定句式就断。描述里 "(CVE-xxx)" 这种点不在句末。
    cut = text
    for marker in (". ", ".\n"):
        at = text.find(marker)
        if 20 <= at <= limit * 2:
            cut = text[: at + 1]
            break
    cut = cut.strip()
    if len(cut) > limit:
        cut = cut[:limit].rsplit(" ", 1)[0].rstrip(",;:") + "…"
    return f"{cve_id} · {cut}" if cut else cve_id


def nvd_case_fields(cve: dict[str, Any], *, min_cvss: float = 0.0) -> dict[str, Any] | None:
    """一条 NVD `{"cve": {...}}` → upsert_case 的字段。低于阈值/已拒绝返回 None。

    `modified_at` 原样带上:它是回溯富化的 watermark(upsert_case 取较大值)。
    """
    cve_id = str(cve.get("id") or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    if str(cve.get("vulnStatus") or "") == "Rejected":
        return None
    score, severity, vector = pick_cvss(cve)
    if score is None:
        # 无分数的洞在阈值口径下不收。注意它是**未知**不是 0 分 —— 这些洞将来 NVD/CNA 补了分,
        # 由回溯步(按 lastModified 重拉)补收,不是永远丢掉。
        if min_cvss > 0:
            return None
    elif score < min_cvss:
        return None
    desc = description(cve)
    fields: dict[str, Any] = {
        "canonical_id": cve_id,
        "id_kind": "cve",
        "title": short_title(cve_id, desc),
        "summary": desc,
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "cwe_ids": cwe_ids(cve),
        "references": references(cve),
        "published_at": _stamp(cve.get("published")),
        "modified_at": _stamp(cve.get("lastModified")),
        "source": "nvd",
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }
    return {key: value for key, value in fields.items() if value not in ("", None, [])}


def published_at(cve: dict[str, Any]) -> str:
    """公开发布时间(站内统一 `...Z` 形态)。回溯步用它把"很久以前的老洞"挡在外面。"""
    return _stamp(cve.get("published"))


def _stamp(value: Any) -> str:
    """NVD 的时间是 `2026-10-13T14:15:22.123`(无时区),站内统一 `...Z`。"""
    text = str(value or "").strip()
    if not text:
        return ""
    text = text.split(".")[0]
    return text + "Z" if len(text) == 19 else text


# ── OSV ──────────────────────────────────────────────────────────────────────

def merge_osv_payloads(primary: dict[str, Any], extra: dict[str, Any] | None) -> dict[str, Any]:
    """把 GHSA 记录并进 CVE 记录。

    为什么必须取两次:OSV 里 `CVE-*` 与 `GHSA-*` 是**两条独立记录**,内容不一样 ——
    实测 CVE-2021-44228 的 CVE 记录里 `type=FIX` 的三条全是厂商博客/Oracle 公告页,
    真正的修复链接(`apache/logging-log4j2/pull/608`)只出现在它的 GHSA 记录里。
    只查 CVE 的话,补丁线索会凭空少一半。
    """
    if not extra:
        return primary
    merged = dict(primary)
    merged["aliases"] = list(dict.fromkeys([*(primary.get("aliases") or []), *(extra.get("aliases") or [])]))
    seen: set[str] = set()
    refs: list[dict[str, Any]] = []
    for ref in [*(primary.get("references") or []), *(extra.get("references") or [])]:
        url = str((ref or {}).get("url") or "")
        if url and url not in seen:
            seen.add(url)
            refs.append(ref)
    merged["references"] = refs
    # affected 取并集而不是"主记录没有才用附带的":实测 CVE-2021-44228 的 CVE 记录只有一条
    # 没有包名的 range,真正的受影响包在 GHSA 记录里 —— 只保留主记录会得到空的产品列表。
    affected: list[Any] = []
    seen_affected: set[str] = set()
    for entry in [*(primary.get("affected") or []), *(extra.get("affected") or [])]:
        key = json.dumps(entry, sort_keys=True, ensure_ascii=False)
        if key not in seen_affected:
            seen_affected.add(key)
            affected.append(entry)
    if affected:
        merged["affected"] = affected
    if not primary.get("severity") and extra.get("severity"):
        merged["severity"] = extra["severity"]
    primary_db = (primary.get("database_specific") or {}).get("severity")
    extra_db = (extra.get("database_specific") or {}).get("severity")
    if not primary_db and extra_db:
        merged["database_specific"] = {**(primary.get("database_specific") or {}), "severity": extra_db}
    return merged


def osv_canonical_id(payload: dict[str, Any]) -> tuple[str, str]:
    """OSV 记录 → (案例主键, id_kind)。优先级 CVE > GHSA > OSV > 原始 id。

    同一条洞在 OSV 里可能只有 GHSA 记录(新公开的洞还没分配 CVE),也可能只有 OSV-Fuzz
    的 OSV-* 记录;按此优先级归一,才能和 NVD 那条线按同一个主键对齐、不重复建案例。
    """
    seen: list[str] = []
    for value in [payload.get("id"), *(payload.get("aliases") or [])]:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.append(text)
    for text in seen:
        if text.upper().startswith("CVE-"):
            return text.upper(), "cve"
    for text in seen:
        if text.upper().startswith("GHSA-"):
            # 与 cases.normalize_canonical_id 同一口径:GHSA 后缀统一小写
            return "GHSA-" + text[5:].lower(), "ghsa"
    for text in seen:
        if text.upper().startswith("OSV-"):
            return text.upper(), "osv"
    if seen:
        return seen[0], "osv"
    return "", ""


def osv_case_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """一条 OSV 记录 → 新建案例需要的完整字段(NVD 那套之外的"从 OSV 起家"路径)。

    与 `osv_fields()` 的分工:那个只回"OSV 才知道的东西"(别名/受影响范围/修复链接),
    这个把它扩成能直接 `upsert_case` 的完整字段 —— 用于「盯的包/仓」发现了库里还没有的洞。
    `details` 才是完整描述,`summary` 只适合当标题;两者不能互换(标题会变成一整段)。
    """
    canonical_id, id_kind = osv_canonical_id(payload)
    if not canonical_id:
        return {}
    details = str(payload.get("details") or "").strip()
    summary = str(payload.get("summary") or "").strip()
    fields = osv_fields(payload)
    # fix_urls 只在选补丁链接时有用;osv_id/summary 与这里要写的列同名但含义不同,先摘掉
    for key in ("fix_urls", "osv_id", "summary"):
        fields.pop(key, None)
    fields.update({
        "canonical_id": canonical_id,
        "id_kind": id_kind,
        "title": short_title(canonical_id, summary or details),
        "summary": details or summary,
        "source_url": f"https://osv.dev/vulnerability/{payload.get('id') or canonical_id}",
    })
    return {key: value for key, value in fields.items() if value not in ("", None, [])}


# OSV 的 ecosystem 是大小写敏感的(PyPI / Maven / crates.io),人写 `pkg:pypi/django` 时要归一。
# 认不出的就原样传下去 —— OSV 会返回 400,比我们猜一个错的值更诚实。
ECOSYSTEM_ALIASES = {
    "pypi": "PyPI", "npm": "npm", "maven": "Maven", "go": "Go", "golang": "Go",
    "packagist": "Packagist", "composer": "Packagist", "cargo": "crates.io", "crates.io": "crates.io",
    "nuget": "NuGet", "rubygems": "RubyGems", "gem": "RubyGems", "hex": "Hex", "pub": "Pub",
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine", "oss-fuzz": "OSS-Fuzz",
    "linux": "Linux", "android": "Android", "swifturl": "SwiftURL",
}


def parse_package_identifier(identifier: str) -> tuple[str, str] | None:
    """`pkg:pypi/django` / `PyPI:django` / `pypi/django` → (包名, OSV ecosystem)。

    返回 None 表示缺生态 —— 没有生态就查不了 OSV(同名包在 npm 和 PyPI 是两个东西),
    调用方必须记成"输入不合法",不能猜一个生态去查。
    """
    text = str(identifier or "").strip()
    if text.lower().startswith("pkg:"):
        text = text[4:]
    if "/" not in text and ":" in text:
        text = text.replace(":", "/", 1)
    if "/" not in text:
        return None
    ecosystem, name = text.split("/", 1)
    ecosystem = ecosystem.strip()
    name = name.strip()
    if not ecosystem or not name:
        return None
    # PURL 的版本写法 `pkg:pypi/django@4.0`;npm 的 scope(`@scope/name`)不在此列
    if "@" in name and not name.startswith("@"):
        name = name.split("@", 1)[0]
    return name, ECOSYSTEM_ALIASES.get(ecosystem.lower(), ecosystem)


_GITHUB_REPO_RE = re.compile(
    r"^(?:github:)?(?:https?://github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


def parse_github_repo(identifier: str) -> str:
    """`github:org/repo` / `https://github.com/org/repo` / `org/repo` → `org/repo`;认不出返回空串。"""
    match = _GITHUB_REPO_RE.match(str(identifier or "").strip())
    return f"{match.group(1)}/{match.group(2)}" if match else ""


def osv_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """OSV 记录 → 案例字段(只回"OSV 才知道的东西")。标题/摘要不从这里取。

    OSV 的价值是:NVD 没有的 GHSA 别名、受影响的包与版本区间、以及**唯一可信的补丁线索**
    (`references[].type == "FIX"`)。
    """
    aliases = [str(value).strip() for value in payload.get("aliases") or [] if str(value).strip()]
    ghsa_ids = [value for value in aliases if value.upper().startswith("GHSA-")]
    cve_ids = [value.upper() for value in aliases if value.upper().startswith("CVE-")]
    products: list[str] = []
    ranges: list[str] = []
    fixed: list[str] = []
    for entry in payload.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        name = str(package.get("name") or "").strip()
        ecosystem = str(package.get("ecosystem") or "").strip()
        if name:
            label = f"{ecosystem}:{name}" if ecosystem else name
            if label not in products:
                products.append(label)
        for range_entry in entry.get("ranges") or []:
            if not isinstance(range_entry, dict):
                continue
            events = [event for event in (range_entry.get("events") or []) if isinstance(event, dict)]
            introduced = [str(event.get("introduced")) for event in events if event.get("introduced")]
            fixed_at = [str(event.get("fixed")) for event in events if event.get("fixed")]
            kind = str(range_entry.get("type") or "")
            parts = []
            if introduced:
                parts.append("introduced " + ", ".join(introduced))
            if fixed_at:
                parts.append("fixed " + ", ".join(fixed_at))
            text = (kind + ": " if kind else "") + "; ".join(parts)
            if text.strip() and text not in ranges:
                ranges.append(text)
            for value in fixed_at:
                if value not in fixed:
                    fixed.append(value)
    urls: list[str] = []
    fix_urls: list[str] = []
    for ref in payload.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "").strip()
        if not url:
            continue
        if url not in urls:
            urls.append(url)
        if str(ref.get("type") or "").upper() == "FIX" and url not in fix_urls:
            fix_urls.append(url)
    vector = ""
    for entry in payload.get("severity") or []:
        score = str((entry or {}).get("score") or "")
        if score.upper().startswith("CVSS:"):
            vector = score
            break
    db_severity = str((payload.get("database_specific") or {}).get("severity") or "").lower()
    return {
        "ghsa_ids": ghsa_ids,
        "cve_ids": cve_ids,
        "aliases": [value for value in aliases if value not in ghsa_ids],
        "affected_products": products,
        "affected_ranges": ranges,
        "fixed_versions": fixed,
        "references": urls,
        "cvss_vector": vector,
        "severity": GHSA_SEVERITY.get(db_severity, ""),
        "fix_urls": fix_urls,
        "published_at": _stamp(payload.get("published")),
        "modified_at": _stamp(payload.get("modified")),
        "osv_id": str(payload.get("id") or ""),
        "summary": str(payload.get("summary") or "").strip(),
    }


# ── 补丁 ─────────────────────────────────────────────────────────────────────

def patch_candidates(urls: list[str]) -> list[dict[str, str]]:
    """从一堆引用 URL 里认出**能下载到 diff** 的链接,返回 [{repo, commit_sha, url}]。

    只认 github/gitlab 的 commit 与 PR:它们的 `.patch` 是纯文本 diff,不用登录、不用 API key。
    其它形态(NVD 的厂商公告页、CVE 记录页)一律不试 —— 抓下来是 HTML,存进 patch_diff 就是假数据。
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in urls:
        url = str(raw or "").strip()
        if not url:
            continue
        match = _GH_COMMIT_RE.match(url)
        if match:
            owner, repo, sha = match.group(1), match.group(2), match.group(3)
            patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
            key = patch_url.lower()
            if key not in seen:
                seen.add(key)
                out.append({"repo": f"{owner}/{repo}", "commit_sha": sha, "url": patch_url})
            continue
        match = _GH_PR_RE.match(url)
        if match:
            owner, repo, number = match.group(1), match.group(2), match.group(3)
            patch_url = f"https://github.com/{owner}/{repo}/pull/{number}.patch"
            key = patch_url.lower()
            if key not in seen:
                seen.add(key)
                out.append({"repo": f"{owner}/{repo}", "commit_sha": f"pr-{number}", "url": patch_url})
            continue
        match = _GL_COMMIT_RE.match(url)
        if match:
            project, sha = match.group(1), match.group(2)
            patch_url = f"https://gitlab.com/{project}/-/commit/{sha}.patch"
            key = patch_url.lower()
            if key not in seen:
                seen.add(key)
                out.append({"repo": project, "commit_sha": sha, "url": patch_url})
    return out


def looks_like_diff(text: str) -> bool:
    """是不是一段真 diff。抓回来一页 HTML 或 404 页面时,绝不能当补丁存进库。"""
    head = str(text or "")[:20000]
    if not head.strip():
        return False
    if "diff --git " in head:
        return True
    # git format-patch 的邮件头形态
    if head.lstrip().startswith("From ") and "\n---\n" in head:
        return True
    return "\n@@ " in head or head.startswith("@@ ")


# 这些扩展名的改动几乎从来不是漏洞修复本身。实测 apache/logging-log4j2 的修复 PR,
# 第一个改动文件是 `log4j-core/pom.xml` —— 拿它当"漏洞点所在文件"展示是误导。
_NON_CODE_SUFFIXES = frozenset({
    ".xml", ".pom", ".json", ".lock", ".yml", ".yaml", ".md", ".txt", ".csv", ".ini",
    ".toml", ".gradle", ".properties", ".sum", ".mod", ".cfg", ".conf.example",
})


def first_changed_file(diff: str) -> str:
    """diff 里优先返回第一个**代码**文件;全是配置/文档时退回第一个。"""
    files = [name.strip() for name in _DIFF_FILE_RE.findall(str(diff or "")) if name.strip()]
    if not files:
        return ""
    for path in files:
        if os.path.splitext(path)[1].lower() not in _NON_CODE_SUFFIXES:
            return path
    return files[0]
