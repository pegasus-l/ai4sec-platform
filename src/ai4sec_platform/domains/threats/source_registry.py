"""威胁洞察数据源登记表(2026-10-08 领导反馈 #5)。

**为什么要这张表**:旧版 `/api/ops/sources` 直接对 `raw_artifacts.source` 做 GROUP BY,
把内部标识(repos / firmware / ascendhub …)当成"数据源"列出来。领导看不到"从哪个网站取的",
也无法添加。这里把每个数据源的**站点、采集器、类型、可添加的采集目标形态**显式登记下来,
页面只渲染这张表,采集参数由 `load_collect_params()` 反向下发。

约定:
- `key` 是页面上的行标识。它与 `raw_artifacts.source` **不是一一对应**:
  `repos` 实际由 gitcode 与 atomgit 两个站点的采集器共同产出,页面上拆成两行
  (用户加组织时必须知道加到哪个站),但两行共用 `stats_source=repos` 的采集量,
  因此记录数在"总记录数"里只算一次(见 `sources_payload` 的去重逻辑)。
- `builtin` 目标是**代码里写死的默认值**(`DEFAULT_LIVE_ORGS` / `DEFAULT_ASCENDHUB_TARGETS`),
  页面上只读;人工添加的才可停用/删除。
- 人工添加的采集目标真的会影响下一轮采集:`pipelines/steps/threat_sources.py` 在
  params 未显式给出 orgs/ascendhub_targets 时,调用 `load_collect_params()` 合并入库的人工目标。
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from ai4sec_platform.domains.threats.adapters.huawei_sources import (
    DEFAULT_ASCENDHUB_TARGETS,
    DEFAULT_LIVE_ORGS,
    parse_repo_url,
)

# 人工登记的两种形态
KIND_TARGET = "target"  # 挂到既有数据源上的采集目标(组织名 / hub id),立刻生效
KIND_SITE = "site"      # 登记一个还没接入的**新数据源**(站点),只落库待开发采集器

# 采集目标里的 source_key → 采集器的 platform(stock 的 orgs 参数按 platform 区分站点)
PLATFORM_BY_KEY = {"repos_gitcode": "gitcode", "repos_atomgit": "atomgit"}

# 数据源清单。顺序 = 页面显示顺序:先代码仓(主力),再素材/漏洞,再各资产站。
SOURCE_GROUPS: list[dict[str, Any]] = [
    {
        "key": "repos_gitcode",
        "name": "代码仓 · GitCode",
        "site": "gitcode.com",
        "entry_url": "https://gitcode.com",
        "collector": "GitCodeConnector(api.gitcode.com/api/v5)",
        "kind": "repo",
        "stats_source": "repos",
        "note": "华为系开源组织的代码仓库主站,按组织逐个分页抓取",
        "target_label": "组织",
    },
    {
        "key": "repos_atomgit",
        "name": "代码仓 · AtomGit",
        "site": "atomgit.com",
        "entry_url": "https://atomgit.com",
        "collector": "AtomGitConnector(api.atomgit.com/api/v5)",
        "kind": "repo",
        "stats_source": "repos",
        "note": "openEuler / MindSpore 等组织的托管平台",
        "target_label": "组织",
    },
    {
        "key": "org_security_materials",
        "name": "组织安全素材",
        "site": "gitcode.com / atomgit.com",
        "entry_url": "",
        "collector": "组织仓二次筛选(安全公告、漏洞库、CVE 仓库)",
        "kind": "material",
        "stats_source": "org_security_materials",
        "note": "从上一步抓到的仓库里二次筛出的安全类素材,不是独立站点",
        "target_label": "",
    },
    {
        "key": "cve_findings",
        "name": "仓库 CVE 线索",
        "site": "派生(仓库自身的安全线索)",
        "entry_url": "",
        "collector": "threat_cve_scout(逐仓汇总 CVE/SA/广谱安全条目)",
        "kind": "vuln",
        "stats_source": "cve_findings",
        "note": "由仓库数据派生,没有可添加的站点参数",
        "target_label": "",
    },
    {
        "key": "firmware",
        "name": "昇腾固件与驱动",
        "site": "hiascend.com 软件中心",
        "entry_url": "https://www.hiascend.com/software",
        "collector": "HiAscendConnector(softwareCenter/queryResourceProductList)",
        "kind": "asset",
        "stats_source": "firmware",
        "note": "按产品→型号→CANN 版本→固件包逐层展开(社区版+商用版)",
        "target_label": "",
    },
    {
        "key": "ascendhub",
        "name": "Ascend Hub 镜像仓库",
        "site": "hiascend.com/developer/ascendhub",
        "entry_url": "https://www.hiascend.com/developer/ascendhub",
        "collector": "HiAscendConnector(ascendHub/repositories/detail)",
        "kind": "asset",
        "stats_source": "ascendhub",
        "note": "逐个 hub 拉取仓库详情与镜像 tag 列表",
        "target_label": "hub",
    },
    {
        "key": "mirrors",
        "name": "华为云镜像站",
        "site": "mirrors.huaweicloud.com",
        "entry_url": "https://mirrors.huaweicloud.com",
        "collector": "HuaweiMirrorConnector(api/v1/repositories)",
        "kind": "asset",
        "stats_source": "mirrors",
        "note": "镜像仓库目录整体拉取,无可添加参数",
        "target_label": "",
    },
    {
        "key": "openx_huawei",
        "name": "OpenX 华为文件区",
        "site": "arquivos.openx.com.br/Huawei",
        "entry_url": "https://arquivos.openx.com.br/Huawei/",
        "collector": "OpenXHuaweiConnector(递归目录树)",
        "kind": "asset",
        "stats_source": "openx_huawei",
        "note": "第三方巴西镜像站的华为固件归档,递归爬完整棵目录树",
        "target_label": "",
    },
    {
        "key": "repos_manual",
        "name": "代码仓 · 单个仓",
        "site": "gitcode.com / atomgit.com",
        "entry_url": "https://gitcode.com",
        "collector": "GitCode/AtomGitConnector(单个仓库)",
        "kind": "repo",
        "stats_source": "repos",
        "note": "人工指定单个仓库,只抓这一个仓;组织不在默认清单(25 个)里的仓用这里加",
        "target_label": "仓库",
    },
]

# 可人工添加采集目标的数据源(表单里的下拉)。hint 直接当输入框 placeholder。
ADDABLE_KEYS: list[dict[str, str]] = [
    {"key": "repos_gitcode", "name": "代码仓 · GitCode", "hint": "gitcode 组织名,如 openGauss"},
    {"key": "repos_atomgit", "name": "代码仓 · AtomGit", "hint": "atomgit 组织名,如 mindspore"},
    {"key": "ascendhub", "name": "Ascend Hub 镜像仓库", "hint": "hub id(32 位十六进制)"},
    {"key": "repos_manual", "name": "代码仓 · 单个仓", "hint": "仓地址,如 https://gitcode.com/openkylin/kylin-system-security-checker"},
]

_ASCENDHUB_DETAIL = "https://www.hiascend.com/developer/ascendhub/detail/"

# 目标输入的口径限制:GitHub/GitCode 组织名与 32 位十六进制 hub id。
# 不做严格正则拒绝 —— 只要不含空白与斜杠就收,避免把合法组织名挡在门外(err on 收下侧)。
_MAX_IDENTIFIER = 120


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def source_groups() -> list[dict[str, Any]]:
    """数据源登记表的副本(含内建采集目标),调用方可安全修改。"""
    groups: list[dict[str, Any]] = []
    for spec in SOURCE_GROUPS:
        group = {k: v for k, v in spec.items() if k not in ("stats_source", "target_label")}
        group["target_label"] = spec.get("target_label", "")
        group["targets"] = _builtin_targets(spec["key"])
        groups.append(group)
    return groups


def _builtin_targets(key: str) -> list[dict[str, Any]]:
    if key not in PLATFORM_BY_KEY:
        if key == "ascendhub":
            return [
                {
                    "id": None,
                    "source_key": key,
                    "identifier": str(t.get("hub_id") or ""),
                    "label": str(t.get("name") or t.get("label") or ""),
                    "builtin": True,
                    "enabled": True,
                    "created_by": "",
                    "created_at": "",
                }
                for t in DEFAULT_ASCENDHUB_TARGETS
                if t.get("hub_id")
            ]
        return []
    platform = PLATFORM_BY_KEY[key]
    return [
        {
            "id": None,
            "source_key": key,
            "identifier": str(t.get("org") or ""),
            "label": "",
            "builtin": True,
            "enabled": True,
            "created_by": "",
            "created_at": "",
        }
        for t in DEFAULT_LIVE_ORGS
        if str(t.get("platform") or "") == platform
    ]


def addable_keys() -> list[dict[str, str]]:
    return [dict(item) for item in ADDABLE_KEYS]


def group_by_key(key: str) -> dict[str, Any] | None:
    for spec in SOURCE_GROUPS:
        if spec["key"] == key:
            return spec
    return None


def ensure_table(conn: sqlite3.Connection) -> None:
    """建 threat_source_targets(与 db/models 的 SCHEMA_SQL 同源,重复执行安全)。"""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS threat_source_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL DEFAULT 'target',
            source_key TEXT NOT NULL,
            identifier TEXT NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(kind, source_key, identifier)
        );
        CREATE INDEX IF NOT EXISTS idx_threat_source_targets_kind
            ON threat_source_targets(kind, source_key, enabled);
        """
    )
    conn.commit()


def table_ready(conn: sqlite3.Connection) -> bool:
    try:
        return bool(
            conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='threat_source_targets'"
            ).fetchone()
        )
    except sqlite3.Error:
        return False


def _row_to_target(row: sqlite3.Row | tuple) -> dict[str, Any]:
    def get(key: str, index: int) -> Any:
        try:
            return row[key]
        except (TypeError, IndexError, KeyError):
            return row[index]

    return {
        "id": int(get("id", 0)),
        "source_key": str(get("source_key", 2) or ""),
        "identifier": str(get("identifier", 3) or ""),
        "label": str(get("label", 4) or ""),
        "note": str(get("note", 5) or ""),
        "enabled": bool(get("enabled", 6)),
        "created_by": str(get("created_by", 7) or ""),
        "created_at": str(get("created_at", 8) or ""),
        "builtin": False,
    }


def load_manual_targets(conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    """按 source_key 归类的**人工添加**采集目标(kind='target',停用的也返回,页面要显示为删除线)。"""
    if not table_ready(conn):
        return {}
    rows = conn.execute(
        "SELECT id, kind, source_key, identifier, label, note, enabled, created_by, created_at "
        "FROM threat_source_targets WHERE kind = ? ORDER BY id",
        (KIND_TARGET,),
    ).fetchall()
    out: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        target = _row_to_target(row)
        out.setdefault(target["source_key"], []).append(target)
    return out


def load_pending_sources(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """人工登记、还没有采集器的新数据源(kind='site')。"""
    if not table_ready(conn):
        return []
    rows = conn.execute(
        "SELECT id, kind, source_key, identifier, label, note, enabled, created_by, created_at "
        "FROM threat_source_targets WHERE kind = ? ORDER BY id DESC",
        (KIND_SITE,),
    ).fetchall()
    return [_row_to_target(row) for row in rows]


# ---------------------------------------------------------------- 写操作


def _clean_identifier(value: str) -> str:
    return str(value or "").strip().strip("/")


def add_target(conn: sqlite3.Connection, *, source_key: str, identifier: str, label: str, created_by: str) -> dict[str, Any]:
    """人工添加采集目标。返回 {target, created};重复添加视为幂等(把停用的重新启用)。"""
    spec = group_by_key(source_key)
    if not spec or not spec.get("target_label"):
        raise ValueError("不支持为该数据源添加采集目标")
    clean = _clean_identifier(identifier)
    if not clean:
        raise ValueError("标识不能为空")
    if len(clean) > _MAX_IDENTIFIER or any(ch.isspace() for ch in clean):
        raise ValueError("标识不合法:不能含空白,且长度不超过 120")
    if source_key == "repos_manual":
        # 单个仓收的是**仓地址**,不是组织名 —— 落库前归一成 platform:org/name。
        # 归一化的意义:带不带 https、带不带 .git、带不带尾斜杠都塌成同一行,
        # 于是"重复添加同一条地址"天然幂等(下面的 exists 查询用的是 identifier)。
        platform, org, name = parse_repo_url(clean)
        clean = f"{platform}:{org}/{name}"
    elif "/" in clean:
        raise ValueError("只填名称本身,不要带平台域名或路径")
    if source_key == "ascendhub" and (len(clean) != 32 or any(c not in "0123456789abcdefABCDEF" for c in clean)):
        raise ValueError("Ascend Hub 的标识必须是 32 位十六进制 hub id")
    ensure_table(conn)
    existing = conn.execute(
        "SELECT id, enabled FROM threat_source_targets WHERE kind=? AND source_key=? AND identifier=?",
        (KIND_TARGET, source_key, clean),
    ).fetchone()
    if existing:
        target_id, enabled = int(existing[0]), bool(existing[1])
        if not enabled:
            # 之前停用过,再添一次就当启用(而不是插一条重复的)
            conn.execute("UPDATE threat_source_targets SET enabled=1 WHERE id=?", (target_id,))
            conn.commit()
        return {"target": _fetch_target(conn, target_id), "created": False}
    label = str(label or "").strip()[:120]
    conn.execute(
        "INSERT INTO threat_source_targets (kind, source_key, identifier, label, note, enabled, created_by, created_at) "
        "VALUES (?, ?, ?, ?, '', 1, ?, ?)",
        (KIND_TARGET, source_key, clean, label, str(created_by or ""), _now()),
    )
    conn.commit()
    target_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    return {"target": _fetch_target(conn, target_id), "created": True}


def add_site(conn: sqlite3.Connection, *, site_url: str, label: str, note: str, created_by: str) -> dict[str, Any]:
    """登记一个待接入的新数据源。只落库,不会产生数据(页面已写明)。"""
    url = str(site_url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("请填完整站点 URL(含 http/https)")
    name = str(label or "").strip()[:120] or parsed.netloc
    ensure_table(conn)
    existing = conn.execute(
        "SELECT id FROM threat_source_targets WHERE kind=? AND identifier=?",
        (KIND_SITE, url),
    ).fetchone()
    if existing:
        return {"source": _fetch_target(conn, int(existing[0])), "created": False}
    conn.execute(
        "INSERT INTO threat_source_targets (kind, source_key, identifier, label, note, enabled, created_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
        (KIND_SITE, "site:manual", url, name, str(note or "")[:400], str(created_by or ""), _now()),
    )
    conn.commit()
    source_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    return {"source": _fetch_target(conn, source_id), "created": True}


def _fetch_target(conn: sqlite3.Connection, target_id: int) -> dict[str, Any]:
    row = conn.execute(
        "SELECT id, kind, source_key, identifier, label, note, enabled, created_by, created_at "
        "FROM threat_source_targets WHERE id=?",
        (target_id,),
    ).fetchone()
    if row is None:
        raise ValueError("记录不存在")
    return _row_to_target(row)


def set_target_enabled(conn: sqlite3.Connection, target_id: int, enabled: bool) -> dict[str, Any]:
    if not table_ready(conn):
        raise ValueError("记录不存在")
    row = conn.execute("SELECT id FROM threat_source_targets WHERE id=?", (target_id,)).fetchone()
    if row is None:
        raise ValueError("记录不存在")
    conn.execute("UPDATE threat_source_targets SET enabled=? WHERE id=?", (1 if enabled else 0, target_id))
    conn.commit()
    return {"id": target_id, "enabled": bool(enabled), "target": _fetch_target(conn, target_id)}


def delete_target(conn: sqlite3.Connection, target_id: int) -> bool:
    if not table_ready(conn):
        return False
    cursor = conn.execute("DELETE FROM threat_source_targets WHERE id=?", (target_id,))
    conn.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------- 采集参数下发


def load_collect_params(conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    """把人工添加的启用目标变成采集器认得的 params(orgs / ascendhub_targets / manual_repos)。

    内建默认值不在这里重复下发 —— 采集器自己会兜底 DEFAULT_*,这里只补"人工新增"的部分。
    """
    out: dict[str, list[dict[str, Any]]] = {"orgs": [], "ascendhub_targets": [], "manual_repos": []}
    if not table_ready(conn):
        return out
    rows = conn.execute(
        "SELECT source_key, identifier, label FROM threat_source_targets "
        "WHERE kind=? AND enabled=1 ORDER BY id",
        (KIND_TARGET,),
    ).fetchall()
    for row in rows:
        source_key = str(row[0] or "")
        identifier = str(row[1] or "").strip()
        label = str(row[2] or "").strip()
        if not identifier:
            continue
        platform = PLATFORM_BY_KEY.get(source_key)
        if platform:
            out["orgs"].append({"platform": platform, "org": identifier})
        elif source_key == "ascendhub":
            out["ascendhub_targets"].append(
                {
                    "hub_id": identifier,
                    "name": label or identifier,
                    "label": label or identifier,
                    "url": f"{_ASCENDHUB_DETAIL}{identifier}",
                }
            )
        elif source_key == "repos_manual":
            # 落库时已归一成 platform:org/name(见 add_target)。老行或手工改过的行可能不合规,
            # 解析失败就跳过 —— 一行脏数据不该让整条采集挂掉。
            try:
                platform, repo_slug = identifier.split(":", 1)
                org, name = repo_slug.split("/", 1)
            except ValueError:
                continue
            if platform and org and name:
                out["manual_repos"].append({"platform": platform, "org": org, "name": name, "label": label})
    return out


# ---------------------------------------------------------------- 页面数据


def _days_ago(iso_str: str) -> int | None:
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(str(iso_str).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def _collect_stats(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """按 raw_artifacts.source 汇总采集量。

    注意 `records` 用的是 SUM(item_count)(原始条目数,去重前),
    不是 COUNT(*) —— 每轮采集会写多条 artifact,COUNT(*) 只是"写了几个文件"。
    """
    stats: dict[str, dict[str, Any]] = {}
    try:
        rows = conn.execute(
            "SELECT source, SUM(item_count) AS items, MAX(created_at) AS last_sync "
            "FROM raw_artifacts WHERE domain='threats' GROUP BY source"
        ).fetchall()
    except sqlite3.Error:
        return stats
    for row in rows:
        source = str(row[0] or "")
        stats[source] = {"records": int(row[1] or 0), "last_sync": str(row[2] or "")}
    return stats


def _status(last_sync: str, days_ago: int | None) -> str:
    """采集状态。阈值与页面文案一致:**只有当天**才算 ok(页面写"今日已采集",
    且 KPI「今日已采集」数的是 days_ago==0)。采集是每天一轮,隔天就该报黄,
    否则会出现"状态=今日已采集、最近采集=2 天前"这种自相矛盾的行。
    """
    if not last_sync:
        return "never"
    if days_ago is None or days_ago <= 0:
        return "ok"
    return "stale"


def sources_payload(conn: sqlite3.Connection) -> dict[str, Any]:
    """组装 /api/ops/sources 的响应(页面数据一次性给全)。"""
    manual = load_manual_targets(conn)
    stats = _collect_stats(conn)
    groups: list[dict[str, Any]] = []
    for spec in SOURCE_GROUPS:
        stat = stats.get(str(spec["stats_source"]), {})
        last_sync = stat.get("last_sync", "")
        days = _days_ago(last_sync)
        group = {k: v for k, v in spec.items() if k != "stats_source"}
        group.update(
            {
                "targets": _builtin_targets(spec["key"]) + manual.get(spec["key"], []),
                "records": stat.get("records", 0),
                "last_sync": last_sync,
                "days_ago": days,
                "status": _status(last_sync, days),
            }
        )
        groups.append(group)
    # 总记录数按 stats_source 去重(repos 拆成两行,采集量是同一条 artifact)
    total_records = sum(stats.get(str(s["stats_source"]), {}).get("records", 0) for s in SOURCE_GROUPS if s["stats_source"] != "repos")
    total_records += stats.get("repos", {}).get("records", 0)
    return {
        "groups": groups,
        "pending_sources": load_pending_sources(conn),
        "addable_keys": addable_keys(),
        "total_records": total_records,
    }
