"""项目清单(P5a):把「一个开源项目」变成案例库里的一个可筛选维度。

为什么要有这一层:案例库现在的主键是**洞**(CVE/GHSA/OSV),而领导的原始需求里还有
「开源项目的 buglist」—— 用户想知道的是「log4j 这个项目有哪些已知洞」,不是「所有洞」。
项目 = 一个有名字、可能有多个发布包、可能有多条自有公告源的实体;它和「盯源」
(`vulnerability_case_sources`)不是一回事:盯源是零散的长期订阅,项目是可展示、可聚合的维度。

本模块的边界:
- **只做项目和关联**,不抓项目公告(P5b 再做);
- 项目 → 案例的关联靠**已有的数据**:OSV 写入的 `affected_products`(`Ecosystem:name`)与
  补丁上下文里的 `repo`(`owner/repo`)。不为了关联去额外请求任何外部服务;
- 自动识别包(`detect_packages`)是**候选**,不直接生效 —— monorepo 的根 manifest 经常
  不是真正的发布包,让人在页面上确认一次。

关联规则(写进实现,不由调用方自觉):
1. 包名匹配必须是 `Ecosystem:name` **完全相等**,不做大小写模糊或前缀匹配 ——
   同名包在 npm 和 PyPI 是两个东西,猜错比漏掉更糟。
2. 仓库匹配只认补丁上下文里的 `repo` 字段和引用 URL 里的 `github.com/org/repo/`,
   不拿标题/描述里的项目名去猜。
3. 关联是**幂等**的:`UNIQUE(case_id, project_id, link_kind)` + `INSERT OR IGNORE`,
   每晚重跑不会长重复行。
"""

from __future__ import annotations

import json
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.vulnerabilities import case_sources

TIERS = ("asset", "benchmark")
LINK_KINDS = ("package_match", "repo_match", "advisory", "manual")

_GITHUB_URL_RE = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([^/?#]+)/([^/?#]+)", re.IGNORECASE)
_GITHUB_SHORT_RE = re.compile(r"^github:([^/]+)/([^/]+)$", re.IGNORECASE)
_GITLAB_URL_RE = re.compile(r"^(?:https?://)?(?:www\.)?gitlab\.com/(.+?)(?:/-/.*)?$", re.IGNORECASE)
_GITLAB_SHORT_RE = re.compile(r"^gitlab:(.+)$", re.IGNORECASE)
_PLAIN_REPO_RE = re.compile(r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)$")

# 自动识别包的候选文件。顺序即优先级:同一个生态只取第一个能解析出名字的文件,
# 避免 setup.py / pyproject.toml 同时给两个不同的名字时把两个都当真。
_MANIFESTS = (
    ("package.json", "npm", 1.0),
    ("pyproject.toml", "PyPI", 0.9),
    ("setup.py", "PyPI", 0.6),
    ("setup.cfg", "PyPI", 0.8),
    ("pom.xml", "Maven", 0.8),
    ("go.mod", "Go", 1.0),
    ("Cargo.toml", "crates.io", 1.0),
    ("composer.json", "Packagist", 1.0),
)


# ── 输入归一 ─────────────────────────────────────────────────────────────────

def parse_project_url(raw: str) -> dict[str, str] | None:
    """把用户粘的仓地址归一成 {platform, org, repo, slug, url};认不出返回 None。

    接受 `github:org/repo` / `https://github.com/org/repo`(可带 .git 或子路径)/
    `org/repo`(默认 GitHub)/ `gitlab:group/repo` / `https://gitlab.com/group/repo`。
    不支持 Gitee / GitCode / AtomGit —— P5a 的包识别只走 GitHub raw,先不假装支持。
    """
    text = str(raw or "").strip()
    if not text:
        return None
    text = text.rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    match = _GITHUB_SHORT_RE.match(text)
    if match:
        return _project("github", match.group(1), match.group(2))
    match = _GITHUB_URL_RE.match(text)
    if match:
        return _project("github", match.group(1), match.group(2))
    match = _GITLAB_SHORT_RE.match(text)
    if match:
        return _gitlab_project(match.group(1).strip("/"))
    match = _GITLAB_URL_RE.match(text)
    if match:
        return _gitlab_project(match.group(1).strip("/"))
    match = _PLAIN_REPO_RE.match(text)
    if match:
        return _project("github", match.group(1), match.group(2))
    return None


def _project(platform: str, org: str, name: str) -> dict[str, str] | None:
    org = str(org or "").strip()
    name = str(name or "").strip()
    if not org or not name:
        return None
    return {
        "platform": platform,
        "org": org,
        "repo": name,
        "slug": f"{platform}:{org}/{name}".lower(),
        "url": f"https://{'github.com' if platform == 'github' else 'gitlab.com'}/{org}/{name}",
    }


def _gitlab_project(path: str) -> dict[str, str] | None:
    """GitLab 支持嵌套 group(subgroup/repo);最后一个 / 之前都算 org。"""
    if "/" not in path:
        return None
    org, name = path.rsplit("/", 1)
    return _project("gitlab", org, name)


def _known_ecosystems() -> set[str]:
    return set(case_sources.ECOSYSTEM_ALIASES.values())


def normalize_package_spec(raw: str) -> dict[str, str] | None:
    """`pkg:pypi/django` / `PyPI:django` / `npm:@scope/name` / `pypi/django` → {ecosystem, name}。

    与 `case_sources.parse_package_identifier` 的区别只有两点:
    ① 先认 `<生态>:<包名>` 这种冒号写法(npm 的 scope 自带 `@scope/`,不能按第一个 `/` 切);
    ② Maven 的 PURL 是 `group/artifact`,OSV 要 `group:artifact`,这里统一成后者。
    """
    text = str(raw or "").strip()
    if not text:
        return None
    if not text.lower().startswith("pkg:") and ":" in text:
        head, rest = text.split(":", 1)
        canonical = case_sources.ECOSYSTEM_ALIASES.get(head.strip().lower())
        if canonical and rest.strip():
            return _package(canonical, rest.strip())
    parsed = case_sources.parse_package_identifier(text)
    if not parsed:
        return None
    name, ecosystem = parsed
    return _package(ecosystem, name)


def _package(ecosystem: str, name: str) -> dict[str, str] | None:
    ecosystem = str(ecosystem or "").strip()
    name = str(name or "").strip()
    if not ecosystem or not name:
        return None
    if ecosystem == "Maven" and "/" in name:
        # PURL: pkg:maven/org.apache.logging.log4j/log4j-core → group:artifact
        name = name.replace("/", ":", 1)
    if ecosystem not in _known_ecosystems():
        return None
    return {"ecosystem": ecosystem, "name": name}


def normalize_packages(values: Iterable[Any]) -> list[dict[str, str]]:
    """字符串数组或 {ecosystem,name} 数组 → 去重后的规范列表。认不出的直接丢弃。"""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for value in values or []:
        if isinstance(value, dict):
            item = _package(str(value.get("ecosystem") or ""), str(value.get("name") or ""))
        else:
            item = normalize_package_spec(str(value))
        if not item:
            continue
        key = f"{item['ecosystem']}:{item['name']}"
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def package_label(item: dict[str, Any]) -> str:
    return f"{item.get('ecosystem') or ''}:{item.get('name') or ''}"


# ── 自动识别发布包(候选)─────────────────────────────────────────────────────

def detect_packages(repo_name: str, *, timeout: int = 10) -> dict[str, Any]:
    """读仓库根目录的 manifest,猜它发布了哪些包。**只回候选**,是否采用由人确认。

    只用 raw.githubusercontent.com(免 key、不消耗 api.github.com 的 60 次/小时),
    每个文件 256 KB 上限、10s 超时;404 跳过,网络错误记进 notes 而不是抛出去 ——
    识别失败不该让用户连项目都加不了。
    """
    parsed = parse_project_url(repo_name)
    if not parsed:
        raise ValueError("认不出这个仓地址")
    if parsed["platform"] != "github":
        return {"packages": [], "fetched": [], "notes": ["自动识别目前只支持 GitHub 仓库"]}
    owner_repo = f"{parsed['org']}/{parsed['repo']}"
    packages: list[dict[str, Any]] = []
    fetched: list[str] = []
    notes: list[str] = []
    seen_ecosystems: set[str] = set()
    for path, ecosystem, confidence in _MANIFESTS:
        if ecosystem in seen_ecosystems:
            continue
        try:
            text = _fetch_raw(owner_repo, path, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 - 单个文件失败不该终止识别
            notes.append(f"{path}: {str(exc)[:120]}")
            continue
        if not text:
            continue
        fetched.append(path)
        items = _packages_from_manifest(path, text)
        if not items:
            continue
        for name in items:
            packages.append({"ecosystem": ecosystem, "name": name, "manifest": path, "confidence": confidence})
        seen_ecosystems.add(ecosystem)
    if not packages:
        notes.append("没有从根目录 manifest 识别出发布包;可以手动填 `生态:包名`,或先按仓库关联")
    return {"packages": packages, "fetched": fetched, "notes": notes}


def _fetch_raw(owner_repo: str, path: str, *, timeout: int = 10, max_bytes: int = 256 * 1024) -> str:
    url = f"https://raw.githubusercontent.com/{urllib.parse.quote(owner_repo, safe='/')}/HEAD/{path}"
    request = urllib.request.Request(url, headers={"User-Agent": "ai4sec-case-projects/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - 固定 raw.githubusercontent.com
            data = response.read(max_bytes + 1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return ""
        raise
    if len(data) > max_bytes:
        return ""
    return data.decode("utf-8", errors="replace")


def _packages_from_manifest(path: str, text: str) -> list[str]:
    """纯解析,不联网 —— 单测直接喂字符串。"""
    if path == "package.json":
        try:
            payload = json.loads(text)
        except ValueError:
            return []
        name = str(payload.get("name") or "").strip() if isinstance(payload, dict) else ""
        return [name] if name else []
    if path == "composer.json":
        try:
            payload = json.loads(text)
        except ValueError:
            return []
        name = str(payload.get("name") or "").strip() if isinstance(payload, dict) else ""
        return [name] if name else []
    if path == "go.mod":
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("module "):
                return [line[len("module "):].strip()]
        return []
    if path in {"pyproject.toml", "Cargo.toml"}:
        section = "project" if path == "pyproject.toml" else "package"
        name = _toml_section_name(text, section)
        if not name and path == "pyproject.toml":
            name = _toml_section_name(text, "tool.poetry")
        return [name] if name else []
    if path == "setup.cfg":
        name = _ini_section_name(text, "metadata")
        return [name] if name else []
    if path == "setup.py":
        match = re.search(r"\bname\s*=\s*['\"]([^'\"]+)['\"]", text)
        return [match.group(1).strip()] if match else []
    if path == "pom.xml":
        body = re.sub(r"<parent>.*?</parent>", "", text, flags=re.DOTALL)
        body = re.sub(r"<dependencies>.*?</dependencies>", "", body, flags=re.DOTALL)
        body = re.sub(r"<build>.*?</build>", "", body, flags=re.DOTALL)
        group = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", body)
        artifact = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", body)
        if not artifact:
            return []
        return [f"{group.group(1)}:{artifact.group(1)}" if group else artifact.group(1)]
    return []


def _toml_section_name(text: str, section: str) -> str:
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped.strip("[]").strip()
            continue
        if current != section:
            continue
        match = re.match(r"name\s*=\s*['\"]([^'\"]+)['\"]", stripped)
        if match:
            return match.group(1).strip()
    return ""


def _ini_section_name(text: str, section: str) -> str:
    current = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped.strip("[]").strip().lower()
            continue
        if current != section.lower():
            continue
        match = re.match(r"name\s*=\s*(.+)", stripped)
        if match:
            return match.group(1).strip()
    return ""


# ── 写:项目 ─────────────────────────────────────────────────────────────────

def add_project(
    conn: sqlite3.Connection,
    *,
    url: str,
    display_name: str = "",
    packages: Iterable[Any] | None = None,
    tier: str = "benchmark",
    native_sources: Iterable[str] | None = None,
    created_by: str = "",
) -> dict[str, Any]:
    """新增项目。重复添加 = 合并包并重新启用(与盯源/威胁域 add_target 语义一致)。"""
    parsed = parse_project_url(url)
    if not parsed:
        raise ValueError("认不出这个仓地址:支持 github:org/repo、https://github.com/org/repo、org/repo")
    tier = str(tier or "benchmark").strip()
    if tier not in TIERS:
        raise ValueError(f"不支持的 tier: {tier}")
    normalized = normalize_packages(packages or [])
    now = utc_now()
    existing = conn.execute("SELECT * FROM vulnerability_projects WHERE slug = ?", (parsed["slug"],)).fetchone()
    if existing is not None:
        merged = normalize_packages([*(repo.loads(existing["packages_json"], []) or []), *normalized])
        conn.execute(
            "UPDATE vulnerability_projects SET display_name = ?, packages_json = ?, tier = ?, enabled = 1, updated_by = ?, updated_at = ? WHERE id = ?",
            (
                str(display_name or existing["display_name"] or "").strip()[:200],
                repo.dumps(merged),
                tier,
                str(created_by or ""),
                now,
                int(existing["id"]),
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM vulnerability_projects WHERE id = ?", (int(existing["id"]),)).fetchone()
        return {"project": serialize_project(row), "created": False}
    conn.execute(
        "INSERT INTO vulnerability_projects "
        "(slug, platform, org, repo, url, display_name, packages_json, native_sources_json, tier, enabled, created_by, created_at, updated_by, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
        (
            parsed["slug"], parsed["platform"], parsed["org"], parsed["repo"], parsed["url"],
            str(display_name or parsed["repo"]).strip()[:200], repo.dumps(normalized),
            repo.dumps([str(item) for item in (native_sources or [])]), tier,
            str(created_by or ""), now, str(created_by or ""), now,
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM vulnerability_projects WHERE id = last_insert_rowid()").fetchone()
    return {"project": serialize_project(row), "created": True}


def update_project(conn: sqlite3.Connection, project_id: int, *, actor: str = "", **fields: Any) -> dict[str, Any]:
    """页面编辑。只允许改白名单,URL/slug 是身份,不可改。"""
    row = conn.execute("SELECT * FROM vulnerability_projects WHERE id = ?", (int(project_id),)).fetchone()
    if row is None:
        raise ValueError("项目不存在")
    updates: dict[str, Any] = {}
    for field, value in fields.items():
        if value is None:
            continue
        if field == "display_name":
            updates[field] = str(value).strip()[:200]
        elif field == "packages":
            updates["packages_json"] = repo.dumps(normalize_packages(value))
        elif field == "native_sources":
            updates["native_sources_json"] = repo.dumps([str(item) for item in value])
        elif field == "tier":
            if str(value) not in TIERS:
                raise ValueError(f"不支持的 tier: {value}")
            updates[field] = str(value)
    if not updates:
        return {"project": serialize_project(row), "changed": 0}
    updates["updated_by"] = str(actor or "")
    updates["updated_at"] = utc_now()
    assignments = ", ".join(f"{column} = ?" for column in updates)
    conn.execute(f"UPDATE vulnerability_projects SET {assignments} WHERE id = ?", (*updates.values(), int(project_id)))
    conn.commit()
    row = conn.execute("SELECT * FROM vulnerability_projects WHERE id = ?", (int(project_id),)).fetchone()
    return {"project": serialize_project(row), "changed": len(updates) - 2}


def set_project_enabled(conn: sqlite3.Connection, project_id: int, enabled: bool) -> dict[str, Any]:
    conn.execute("UPDATE vulnerability_projects SET enabled = ?, updated_at = ? WHERE id = ?", (1 if enabled else 0, utc_now(), int(project_id)))
    conn.commit()
    row = conn.execute("SELECT * FROM vulnerability_projects WHERE id = ?", (int(project_id),)).fetchone()
    if row is None:
        raise ValueError("项目不存在")
    return serialize_project(row)


def delete_project(conn: sqlite3.Connection, project_id: int) -> int:
    """删项目。显式删关联行 —— 生产开了 foreign_keys,但单测/脚本里的内存库不一定开。"""
    conn.execute("DELETE FROM vulnerability_case_projects WHERE project_id = ?", (int(project_id),))
    cursor = conn.execute("DELETE FROM vulnerability_projects WHERE id = ?", (int(project_id),))
    conn.commit()
    return max(cursor.rowcount, 0)


# ── 读 ───────────────────────────────────────────────────────────────────────

def serialize_project(row: sqlite3.Row | dict[str, Any], stats: dict[str, Any] | None = None) -> dict[str, Any]:
    item = dict(row)
    item["packages"] = repo.loads(item.pop("packages_json", None), []) or []
    item["native_sources"] = repo.loads(item.pop("native_sources_json", None), []) or []
    item["sync_cursor"] = repo.loads(item.pop("sync_cursor_json", None), {}) or {}
    item["package_count"] = len(item["packages"])
    if stats:
        item.update(stats)
    item.setdefault("case_total", 0)
    item.setdefault("by_severity", {})
    return item


def list_projects(conn: sqlite3.Connection, *, include_disabled: bool = True) -> dict[str, Any]:
    clause = "" if include_disabled else "WHERE enabled = 1"
    rows = conn.execute(f"SELECT * FROM vulnerability_projects {clause} ORDER BY enabled DESC, tier, display_name, id").fetchall()
    ids = [int(row["id"]) for row in rows]
    if not ids:
        return {"count": 0, "items": []}
    placeholders = ", ".join("?" for _ in ids)
    # 同一条案例可能同时因包和仓命中(两行 link_kind),计数必须 DISTINCT 到案例,
    # 否则项目卡片上的"案例数"会比实际多。
    totals = {int(row["project_id"]): int(row["total"]) for row in conn.execute(
        f"SELECT project_id, COUNT(DISTINCT case_id) AS total FROM vulnerability_case_projects WHERE project_id IN ({placeholders}) GROUP BY project_id",
        ids,
    ).fetchall()}
    severities: dict[int, dict[str, int]] = {value: {} for value in ids}
    for row in conn.execute(
        f"SELECT l.project_id, c.severity, COUNT(DISTINCT l.case_id) AS total FROM vulnerability_case_projects l "
        f"JOIN vulnerability_cases c ON c.id = l.case_id WHERE l.project_id IN ({placeholders}) "
        f"GROUP BY l.project_id, c.severity",
        ids,
    ).fetchall():
        severities[int(row["project_id"])][str(row["severity"] or "")] = int(row["total"])
    items = [serialize_project(row, {"case_total": totals.get(int(row["id"]), 0), "by_severity": severities.get(int(row["id"]), {})}) for row in rows]
    return {"count": len(items), "items": items}


def get_project(conn: sqlite3.Connection, project_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM vulnerability_projects WHERE id = ?", (int(project_id),)).fetchone()
    return serialize_project(row) if row else None


# ── 项目 ↔ 案例关联 ─────────────────────────────────────────────────────────

def link_project_cases(conn: sqlite3.Connection, project_id: int, *, since: str = "") -> dict[str, Any]:
    """把一个项目的包/仓与案例关联。`since` 为空 = 全量重扫(新增/编辑项目时用)。

    命中规则:
      - `package_match`:案例的 `affected_products` 里有完全相等的 `Ecosystem:name`;
      - `repo_match`:补丁上下文的 `repo` 等于项目的 `org/repo`,或案例引用 URL 里出现
        `github.com/org/repo/`(GitLab 同理)。
    两类可以同时存在(一行一个 link_kind),因为它们的证据不同,页面上可以分开解释。
    """
    row = conn.execute("SELECT * FROM vulnerability_projects WHERE id = ?", (int(project_id),)).fetchone()
    if row is None:
        raise ValueError("项目不存在")
    project = serialize_project(row)
    matched: dict[int, set[str]] = {}
    package_labels = [package_label(item) for item in project["packages"]]
    since_clause = " AND c.updated_at >= ?" if since else ""
    since_params: tuple[Any, ...] = (since,) if since else ()

    for label in package_labels:
        sql = (
            "SELECT DISTINCT c.id FROM vulnerability_cases c, json_each(c.affected_products_json) j "
            "WHERE j.value = ?" + since_clause
        )
        for item in conn.execute(sql, (label, *since_params)).fetchall():
            matched.setdefault(int(item["id"]), set()).add("package_match")

    owner_repo = f"{project['org']}/{project['repo']}"
    if owner_repo and project["platform"] in {"github", "gitlab"}:
        sql = (
            "SELECT DISTINCT c.id FROM vulnerability_case_context x JOIN vulnerability_cases c ON c.id = x.case_id "
            "WHERE lower(x.repo) = lower(?)" + since_clause
        )
        for item in conn.execute(sql, (owner_repo, *since_params)).fetchall():
            matched.setdefault(int(item["id"]), set()).add("repo_match")
        host = "github.com" if project["platform"] == "github" else "gitlab.com"
        needle = f"{host}/{owner_repo}/".lower()
        sql = (
            "SELECT DISTINCT c.id FROM vulnerability_cases c, json_each(c.references_json) j "
            "WHERE instr(lower(j.value), ?) > 0" + since_clause
        )
        for item in conn.execute(sql, (needle, *since_params)).fetchall():
            matched.setdefault(int(item["id"]), set()).add("repo_match")

    now = utc_now()
    created = 0
    for case_id, kinds in matched.items():
        for kind in sorted(kinds):
            confidence = 1.0 if kind == "package_match" else 0.9
            cursor = conn.execute(
                "INSERT OR IGNORE INTO vulnerability_case_projects (case_id, project_id, link_kind, confidence, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (case_id, int(project_id), kind, confidence, now),
            )
            created += max(cursor.rowcount, 0)
    conn.commit()
    return {
        "project_id": int(project_id),
        "package_labels": package_labels,
        "cases_matched": len(matched),
        "links_created": created,
    }


def link_all_projects(conn: sqlite3.Connection, *, since: str = "") -> dict[str, Any]:
    """每晚跑批:只处理启用的项目。单项目失败不拖垮整批,错误进 error_samples。"""
    rows = conn.execute("SELECT id FROM vulnerability_projects WHERE enabled = 1 ORDER BY id").fetchall()
    stats: dict[str, Any] = {"projects": len(rows), "projects_linked": 0, "cases_matched": 0, "links_created": 0, "errors": 0}
    error_samples: list[str] = []
    for row in rows:
        try:
            result = link_project_cases(conn, int(row["id"]), since=since)
        except Exception as exc:  # noqa: BLE001 - 单项目失败继续
            stats["errors"] += 1
            if len(error_samples) < 5:
                error_samples.append(f"project#{int(row['id'])}: {str(exc)[:200]}")
            continue
        stats["projects_linked"] += 1
        stats["cases_matched"] += int(result["cases_matched"])
        stats["links_created"] += int(result["links_created"])
    stats["error_samples"] = error_samples
    return stats


def case_ids_for_project(conn: sqlite3.Connection, project_id: int) -> list[int]:
    return [int(row["case_id"]) for row in conn.execute(
        "SELECT case_id FROM vulnerability_case_projects WHERE project_id = ? ORDER BY case_id",
        (int(project_id),),
    ).fetchall()]
