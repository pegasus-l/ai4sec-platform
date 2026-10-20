"""项目自有安全源(P5b):把「项目自己发的公告」读进来,补第三方汇总库的漏。

为什么需要这一层:NVD/OSV 是**别人替我们整理的**,两个客观缺口 ——
① 不是所有修复都有 CVE 编号,很多项目只在发布说明里写一句"修了某个越权/崩溃";
② 有编号也可能要等 NVD 人工审核(实测新洞 T+0 的 OSV 命中率只有 16~20%)。
自有源就是厂家自己的渠道:releases(发布说明)、CHANGELOG、SECURITY.md。

**三条诚实性硬规则(写进实现,不由页面自觉):**

1. **只认能验证的编号。** 文本里解析出 CVE/GHSA 后必须能在 NVD/OSV 查到才建案例;
   查不到记成 `unverified`,**不建案例、不显示为漏洞**。纯文本里的 "security fix"、
   "hardening" 一律不推断 —— 没有编号就是没有。
2. **"没配置 / 没新增" ≠ "没有漏洞"。** 项目没配自有源时返回 `configured=False`,
   页面必须显示"未配置",不能显示成"该项目没有漏洞"。这两件事对用户意义相反。
3. **失败不推进游标。** releases 拉取失败、某个 CHANGELOG 网络错误时,对应游标保持原值,
   下一晚从同一位置重来;404 是"没有这个文件"(正常),不当失败。

关于归属口径(必须写清楚):发布说明里提到的 CVE **可能是它依赖的第三方漏洞**
(例如 "bump foo to 2.0, fixes CVE-xxx")。所以关联类型用 `advisory`、confidence 0.6,
页面文案是「项目公告里提到」,不是「这个项目的漏洞」。要更强的归属证据,得等 P5c 的
资产/包级命中。

外部请求只有两个,都免 token、不消耗 `api.github.com` 的 60 次/小时:
`github.com/{repo}/releases.atom` 与 `raw.githubusercontent.com/{repo}/HEAD/{path}`。
不支持 `github_advisories`(需要 token)与 `issues`(噪声大)—— 它们在页面上标「未启用」,
采集步记进 `unsupported_sources`,而不是静默跳过。
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from typing import Any, Iterable

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.vulnerabilities import case_ingest
from ai4sec_platform.domains.vulnerabilities import cases as cases_repo
from ai4sec_platform.domains.vulnerabilities import projects as projects_repo
from ai4sec_platform.domains.vulnerabilities.projects import NATIVE_SOURCE_KINDS

# 已知四种自有源。前两种本期实现;后两种在页面上显式标「未启用」。
UNSUPPORTED_NATIVE_SOURCES = {
    "github_advisories": "需要 GitHub token(未配置)",
    "issues": "噪声大,只当线索,本期不启用",
}
NATIVE_SOURCE_LABELS = {
    "releases": "发布说明",
    "changelog": "CHANGELOG / SECURITY",
    "github_advisories": "GitHub 安全公告",
    "issues": "Issues(security)",
}

# 仓库根目录的候选文件。顺序即优先级:命中第一个就不再往下找 —— 同一个项目同时有
# CHANGELOG.md 和 CHANGES.md 时,两份内容往往重复,读两遍只会把同一批 CVE 解析两次。
CHANGELOG_PATHS = (
    "CHANGELOG.md", "CHANGELOG.rst", "CHANGELOG", "CHANGES.md", "CHANGES",
    "HISTORY.md", "NEWS.md", "SECURITY.md",
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)

# 游标里最多留多少待处理/未核实 id。它们只是"下一晚再试一次"的提示,不是资产;
# 不封顶的话,一个把历年 CVE 全列进 CHANGELOG 的项目会让 sync_cursor_json 无限膨胀。
MAX_PENDING_IDS = 200
MAX_UNVERIFIED_IDS = 50


# ── 输入归一 ─────────────────────────────────────────────────────────────────

def extract_ids(text: str) -> list[str]:
    """从一段文本里抽 CVE/GHSA 编号(去重、保序)。CVE 大写、GHSA 后缀小写,与案例主键同口径。"""
    out: list[str] = []
    seen: set[str] = set()
    for match in CVE_RE.finditer(str(text or "")):
        value = match.group(0).upper()
        if value not in seen:
            seen.add(value)
            out.append(value)
    for match in GHSA_RE.finditer(str(text or "")):
        value = "GHSA-" + match.group(0)[5:].lower()
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def text_digest(text: str) -> str:
    return hashlib.sha1(str(text or "").encode("utf-8", errors="replace")).hexdigest()


# ── 单项目同步 ──────────────────────────────────────────────────────────────

def sync_project(
    conn: sqlite3.Connection,
    project_id: int,
    *,
    github: Any,
    osv: Any,
    nvd: Any,
    release_limit: int = 5,
    max_ids: int = 15,
    interval: float = 0.2,
    nvd_interval: float = 6.0,
    retry_unverified: int = 5,
    now: str | None = None,
) -> dict[str, Any]:
    """同步一个项目的自有源。连接器由调用方注入 —— 单测不需要起 HTTP。

    返回的 stats 里的每个数字都是页面能看见的口径:`created`(新建案例)、
    `existing`(库里已有,只补关联)、`unverified`(解析到但查不到,不建案例)、
    `errors`(网络/接口失败,游标不推进)。
    """
    now = now or utc_now()
    row = conn.execute("SELECT * FROM vulnerability_projects WHERE id = ?", (int(project_id),)).fetchone()
    if row is None:
        raise ValueError("项目不存在")
    project = projects_repo.serialize_project(row)
    stats: dict[str, Any] = {
        "project_id": int(project_id), "slug": project["slug"], "configured": False,
        "sources": list(project.get("native_sources") or []), "sources_checked": 0, "unsupported_sources": [],
        "releases_new": 0, "files_changed": 0,
        "ids_found": 0, "created": 0, "existing": 0, "unverified": 0, "linked": 0,
        "errors": 0, "error_samples": [],
        # "没新增"有四种截然不同的原因(仓没有 Releases / 文件不存在 / 内容没变 / 都失败),
        # 页面上必须能分辨 —— 否则用户会把"仓库地址写错了"读成"这个项目很干净"。
        "notes": [],
    }
    if not project["enabled"]:
        stats["skipped"] = "disabled"
        return stats

    sources = list(project.get("native_sources") or [])
    if not sources:
        # 未配置 ≠ 没有漏洞。不更新 last_synced_at,页面才能显示"从未同步"。
        stats["skipped"] = "unconfigured"
        return stats
    stats["configured"] = True
    unsupported = [name for name in sources if name in UNSUPPORTED_NATIVE_SOURCES]
    supported = [name for name in sources if name not in UNSUPPORTED_NATIVE_SOURCES]
    stats["unsupported_sources"] = unsupported

    def fail(sample: str) -> None:
        stats["errors"] += 1
        if len(stats["error_samples"]) < 5:
            stats["error_samples"].append(sample[:200])

    def note(message: str) -> None:
        if len(stats["notes"]) < 5:
            stats["notes"].append(message[:200])

    cursor = project.get("sync_cursor") or {}
    next_cursor: dict[str, Any] = {key: value for key, value in cursor.items() if key not in {"files", "releases", "last_run", "pending_ids", "unverified_ids"}}
    repo_name = f"{project['org']}/{project['repo']}"
    texts: list[tuple[str, str]] = []

    # ① releases:atom 流,免 token。只处理上次之后的新条目。
    if "releases" in supported:
        if project["platform"] != "github":
            fail(f"releases: 平台 {project['platform']} 暂不支持")
        else:
            release_cursor = dict(cursor.get("releases") or {})
            try:
                entries = github.recent_releases(repo_name, limit=max(1, int(release_limit)))
            except Exception as exc:  # noqa: BLE001 - 网络失败不推进游标,下一晚重来
                fail(f"releases: {exc}")
            else:
                stats["sources_checked"] += 1
                last_updated = str(release_cursor.get("last_entry_updated") or "")
                fresh = [item for item in entries if str(item.get("updated") or "") > last_updated]
                stats["releases_new"] = len(fresh)
                if not entries:
                    # 连接器把 404 与"feed 为空"都折成空列表(两者对同步是同一件事),
                    # 但页面上要让它可分辨:这里只能如实说"没取到任何条目"。
                    note("发布说明：没有取到任何条目（仓库没有 Releases，或仓库不存在）")
                elif not fresh:
                    note(f"发布说明：最近 {len(entries)} 条都在上次同步之前，无新增")
                for item in fresh:
                    texts.append((f"releases:{item.get('title') or item.get('entry_id') or ''}",
                                  f"{item.get('title') or ''}\n{item.get('content') or ''}"))
                newest = max((str(item.get("updated") or "") for item in entries), default="")
                if newest:
                    next_cursor["releases"] = {
                        "last_entry_updated": newest,
                        "last_entry_id": str(next((item.get("entry_id") for item in entries if str(item.get("updated") or "") == newest), "") or ""),
                        "last_checked_at": now,
                    }
                else:
                    next_cursor["releases"] = release_cursor

    # ② CHANGELOG / SECURITY:按内容哈希判变化。404 = 项目没有这个文件(正常,不记错)。
    if "changelog" in supported:
        if project["platform"] != "github":
            fail(f"changelog: 平台 {project['platform']} 暂不支持")
        else:
            files_cursor = dict(cursor.get("files") or {})
            found = changed = 0
            for path in CHANGELOG_PATHS:
                try:
                    text = github.fetch_file(repo_name, "HEAD", path)
                except Exception as exc:  # noqa: BLE001 - 该文件游标不动,下一晚重试
                    fail(f"{path}: {exc}")
                    continue
                if text is None:
                    continue
                found += 1
                stats["sources_checked"] += 1
                digest = text_digest(text)
                if str((files_cursor.get(path) or {}).get("hash") or "") == digest:
                    continue  # 内容没变:不重复解析、不重复请求 NVD
                files_cursor[path] = {"hash": digest, "checked_at": now, "bytes": len(text)}
                changed += 1
                stats["files_changed"] += 1
                texts.append((f"changelog:{path}", text))
            next_cursor["files"] = files_cursor
            if not found:
                note(f"CHANGELOG/SECURITY：{len(CHANGELOG_PATHS)} 个常见路径都没有该文件")
            elif not changed:
                note(f"CHANGELOG/SECURITY：找到 {found} 个文件，内容未变化")

    # ③ 解析编号:上一轮没处理完的 → 本轮新解析出的 → 上一轮未核实的(有限重试)
    fresh_ids: list[str] = []
    for _, text in texts:
        for value in extract_ids(text):
            if value not in fresh_ids:
                fresh_ids.append(value)
    candidates: list[str] = []
    for value in [*(cursor.get("pending_ids") or []), *fresh_ids, *(cursor.get("unverified_ids") or [])]:
        value = str(value or "").strip()
        if value and value not in candidates:
            candidates.append(value)
    stats["ids_found"] = len(fresh_ids)

    limit = max(1, int(max_ids))
    retry_budget = max(0, int(retry_unverified))
    processed: list[str] = []
    leftover: list[str] = []
    unverified: list[str] = []
    unverified_set = {str(value) for value in (cursor.get("unverified_ids") or [])}
    retried = 0
    for value in candidates:
        if len(processed) >= limit:
            leftover.append(value)
            continue
        is_retry = value in unverified_set and value not in fresh_ids
        if is_retry:
            if retried >= retry_budget:
                leftover.append(value)  # 留到下一晚,不丢掉
                continue
            retried += 1
        outcome = _apply_id(conn, project, value, osv=osv, nvd=nvd,
                            nvd_interval=nvd_interval, interval=interval, fail=fail, now=now)
        if outcome == "error":
            leftover.append(value)  # 网络失败:既不算核实也不算未核实
            continue
        processed.append(value)
        if outcome == "unverified":
            unverified.append(value)
            stats["unverified"] += 1
        else:
            stats[outcome] += 1  # created / existing
        if outcome in {"created", "existing"}:
            stats["linked"] += _link_advisory(conn, _case_id(conn, value), int(project_id), now)

    next_cursor["pending_ids"] = leftover[:MAX_PENDING_IDS]
    next_cursor["unverified_ids"] = unverified[:MAX_UNVERIFIED_IDS]
    next_cursor["last_run"] = {
        "at": now, "sources": sources, "ids_found": stats["ids_found"],
        # 公告/文件的增量数要落进 last_run: 页面要能区分"没新公告"与"没配源"。
        "releases_new": stats["releases_new"], "files_changed": stats["files_changed"],
        "created": stats["created"], "existing": stats["existing"],
        "unverified": stats["unverified"], "linked": stats["linked"], "errors": stats["errors"],
        "unsupported_sources": unsupported, "notes": list(stats["notes"]),
    }
    updates: list[tuple[str, Any]] = [("sync_cursor_json", repo.dumps(next_cursor))]
    if stats["sources_checked"]:
        # 全部来源都失败时不刷新 last_synced_at —— 页面上"最近同步"必须是真同步过。
        updates.append(("last_synced_at", now))
    assignments = ", ".join(f"{column} = ?" for column, _ in updates)
    conn.execute(f"UPDATE vulnerability_projects SET {assignments} WHERE id = ?",
                 (*[value for _, value in updates], int(project_id)))
    conn.commit()
    return stats


def _apply_id(conn: sqlite3.Connection, project: dict[str, Any], raw_id: str, *,
              osv: Any, nvd: Any, nvd_interval: float, interval: float, fail, now: str) -> str:
    """核实一个编号并落库。返回 `created` / `existing` / `unverified` / `error`。

    已有案例也走这里:它可能是别的源早就收进来的洞,自有源的价值就是"把它和项目挂上"。
    """
    normalized = cases_repo.normalize_canonical_id(raw_id)
    if not normalized:
        return "unverified"
    canonical_id = normalized["canonical_id"]
    if case_ingest.case_row(conn, canonical_id) is not None:
        return "existing"
    try:
        if normalized["id_kind"] == "cve":
            item = nvd.fetch_by_id(canonical_id)
            if item:
                # min_cvss=0:项目在公告里点名的洞,即使 NVD 还没给分也要进来。
                case_ingest.apply_nvd_items(conn, [item], min_cvss=0.0, actor="project_buglist")
            if nvd_interval:
                time.sleep(float(nvd_interval))
        elif normalized["id_kind"] == "ghsa":
            payload = osv.lookup(canonical_id)
            if payload:
                case_ingest.apply_osv_record(conn, payload, source_identifier=str(project["slug"]), actor="project_buglist")
            if interval:
                time.sleep(float(interval))
        else:
            return "unverified"
    except Exception as exc:  # noqa: BLE001 - 这次查不成,不算"没有",留给下一轮
        fail(f"{canonical_id}: {exc}")
        return "error"
    return "created" if case_ingest.case_row(conn, canonical_id) is not None else "unverified"


def _case_id(conn: sqlite3.Connection, raw_id: str) -> int:
    normalized = cases_repo.normalize_canonical_id(raw_id)
    row = case_ingest.case_row(conn, normalized["canonical_id"]) if normalized else None
    return int(row["id"]) if row is not None else 0


def _link_advisory(conn: sqlite3.Connection, case_id: int, project_id: int, now: str) -> int:
    """把案例挂到项目上。`link_kind='advisory'` 与包匹配/仓匹配分开记 ——
    它的证据是"项目公告里提到了",不等于"这个项目的代码有这个洞"。"""
    if not case_id:
        return 0
    cursor = conn.execute(
        "INSERT OR IGNORE INTO vulnerability_case_projects (case_id, project_id, link_kind, confidence, created_at) "
        "VALUES (?, ?, 'advisory', 0.6, ?)",
        (int(case_id), int(project_id), now),
    )
    return max(cursor.rowcount, 0)


# ── 批量 ─────────────────────────────────────────────────────────────────────

def sync_projects(conn: sqlite3.Connection, *, project_ids: Iterable[int] | None = None, **options: Any) -> dict[str, Any]:
    """每晚跑批(或手动指定项目)。单项目失败不拖垮整批,错误进 error_samples。"""
    ids = [int(value) for value in (project_ids or []) if str(value).strip()]
    if ids:
        placeholders = ", ".join("?" for _ in ids)
        rows = conn.execute(
            f"SELECT id FROM vulnerability_projects WHERE enabled = 1 AND id IN ({placeholders}) ORDER BY id", ids
        ).fetchall()
    else:
        rows = conn.execute("SELECT id FROM vulnerability_projects WHERE enabled = 1 ORDER BY id").fetchall()
    stats: dict[str, Any] = {
        "projects": len(rows), "synced": 0, "unconfigured": 0, "unsupported": 0,
        "created": 0, "existing": 0, "unverified": 0, "linked": 0, "errors": 0,
        "by_source": {name: 0 for name in NATIVE_SOURCE_KINDS}, "error_samples": [], "runs": [],
    }
    for row in rows:
        try:
            result = sync_project(conn, int(row["id"]), **options)
        except Exception as exc:  # noqa: BLE001 - 单项目失败继续
            stats["errors"] += 1
            if len(stats["error_samples"]) < 5:
                stats["error_samples"].append(f"project#{int(row['id'])}: {str(exc)[:200]}")
            continue
        if result.get("skipped") == "unconfigured":
            stats["unconfigured"] += 1
            continue
        if result.get("skipped") == "disabled":
            continue
        stats["synced"] += 1
        for key in ("created", "existing", "unverified", "linked", "errors"):
            stats[key] += int(result.get(key) or 0)
        stats["unsupported"] += len(result.get("unsupported_sources") or [])
        for name in result.get("sources") or []:
            if name in stats["by_source"]:
                stats["by_source"][name] += 1
        stats["runs"].append({key: result.get(key) for key in ("project_id", "slug", "configured", "ids_found", "created", "existing", "unverified", "linked", "errors")})
        for sample in result.get("error_samples") or []:
            if len(stats["error_samples"]) < 5:
                stats["error_samples"].append(f"project#{int(row['id'])}: {sample}")
    return stats
