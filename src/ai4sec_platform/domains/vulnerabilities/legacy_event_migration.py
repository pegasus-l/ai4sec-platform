"""存量 event → 案例库的一次性迁移(可重复跑,幂等)。

顺序:1 seed → 2 supersede(1 必须早于 2)。3/4 是事后修正,与 1/2 解耦,什么时候跑都行。

背景:「漏洞事件库」原来是**从素材聚合出来的主题**(`item_type='event'`),存量 524 条里
单 CVE 139 / 多 CVE 152 / **无 CVE 的知识主题 233**。2026-10-16 领导要求它变成"一个个单独的洞",
所以旧 event 直接替掉,**但继承它们的素材关联** —— 否则新库上线当天是个空壳。

四步:

1. `seed_cases_from_events()` —— 遍历非 superseded 的 event,把 `payload.cve_ids` 里每个 CVE
   建成一条案例(`status='pending_fetch'`、`source='legacy_event'`),并把该 event 的
   `payload.material_ids` 写成 `context_type='reference'`、`provenance='from_legacy_event'` 的
   上下文行(指向站内素材,抽屉里可直接跳)。**无 CVE 的 233 条不进**(领导要的是洞,不是主题)。
   ⚠️ 这一步**必须早于** `supersede_legacy_events()`:supersede 之后这里就再也看不到那些 event 了。
2. `supersede_legacy_events()` —— `status='superseded'`,**不删行**。`_active_events()`
   (domains/vulnerabilities/service.py)本来就过滤这个状态,所以事件列表自然清空;
   回滚只需要把 status 改回 active。
3. `restamp_legacy_case_dates()` —— 把继承来的案例的 `created_at` 拉回源 event 的时间。
   不这么做的话,今日情报页会把这一整批历史一次性算成"本批新登记 896 个洞"(含 CVE-2019-0708),
   见该函数的 docstring。它**刻意与 step 1/2 解耦**(读全部 event,不看 status),所以可以
   supersede 之后再补跑 —— 第一次上线时漏了这一步,第二次也得能修回来。
4. `retitle_legacy_cases()` —— 重拼案例标题。多 CVE 事件的标题是机器拼的 id 列表,拿它当单个洞
   的标题等于挂着别人的编号(实测 773/896 条),见 `_case_titles`。同样与 1/2 解耦。
5. (人工)从 `pipelines/registry.py` 摘掉 event 聚合流水线的注册 —— 见该文件的注释。

每步都幂等,重复跑只有 0 效果。**种子是一次性的**(库里已有继承来的案例时它会拒绝再跑,
除非 `--force`):它按 event 的旧值 upsert,连人工在页面上改过的字段都会盖回去。
后补的修正一律走 `--restamp` / `--retitle` 这类"只碰一列、不碰 updated_at"的动作。

跑法(容器内,PYTHONPATH 必须指到 src):

    docker exec -e PYTHONPATH=/app/src fusion-v2-ai4sec-1 python3 -m ai4sec_platform.domains.vulnerabilities.legacy_event_migration --seed --supersede --restamp --retitle

不带任何动作开关时默认只跑 `--seed`。先看数就加 `--dry-run`(只统计不写)。
注意这个模块**自己开库**(走 db.session.connect,带 WAL + foreign_keys ON),
不要在 API 进程里 import 它的入口函数。
"""

from __future__ import annotations

import sys
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.vulnerabilities import cases as cases_repo

DOMAIN = "vulnerabilities"
# 这些 event 没有 CVE,是"知识主题",不是洞 —— 按拍板不进案例库
TOPIC_KINDS = {"knowledge_topic"}

# 多 CVE 事件的标题是机器拼的:"多 CVE 事件 · CVE-a, CVE-b, CVE-c"(取前 3 个 id)。
# 拿它当**单个洞**的案例标题是错的 —— 那串 id 是同一个 event 里**别的洞**的编号,
# 实测 773/896 条案例的头条都挂着一串不属于自己的 id(案例 CVE-2026-10702 的标题里写着
# CVE-2026-31431, CVE-2026-43499),点开抽屉才是本人。所以这类标题一律重拼。
GENERIC_TITLE_PREFIX = "多 CVE 事件"


def _mentions(text: str, cve_id: str) -> bool:
    """text 里是否出现了这个 CVE 编号(要求后面不是数字, 免得 `CVE-2021-3797` 命中 `CVE-2021-37975`)。"""
    start = 0
    while True:
        at = text.find(cve_id, start)
        if at < 0:
            return False
        after = text[at + len(cve_id):at + len(cve_id) + 1]
        if not after.isdigit():
            return True
        start = at + 1


def _case_titles(cve_ids: list[str], event_title: Any, research_title: str) -> dict[str, str]:
    """给同一个 event 里的每个洞各取一个标题。返回 `{cve_id: title}`。

    1. event 标题**指名了这个洞**时用它 —— 单 CVE 事件天然如此(`CVE-2019-0708 · Exploitation of
       Windows RDP ...`),多 CVE 事件里也有标题只讲某一个洞的(34/152)。
    2. 否则退回 `<id> · <研究文章标题>`:文章标题是这批上下文真正的来处(素材就是它),是事实不是
       编出来的话。**但研究标题点名了同 event 里别的洞时对它只字不提** —— 那种情况下挂上去,
       刚修完"挂着别人的编号"就变成"挂着别人的标题",同一个错换件衣服。
    3. 连这也不行就只剩 id 本身(卡片上徽章与标题会重复一次, 但至少不说错话)。
    """
    title = str(event_title or "").strip()
    generic = (not title) or title.startswith(GENERIC_TITLE_PREFIX)
    titles: dict[str, str] = {}
    for cve_id in cve_ids:
        if not generic and (len(cve_ids) == 1 or _mentions(title, cve_id)):
            titles[cve_id] = title
            continue
        if research_title and not any(other != cve_id and _mentions(research_title, other) for other in cve_ids):
            titles[cve_id] = f"{cve_id} · {research_title}"
        else:
            titles[cve_id] = cve_id
    return titles


def seed_cases_from_events(conn, *, dry_run: bool = False, actor: str = "legacy_event_migration") -> dict[str, Any]:
    """把旧 event 里的 CVE 与素材关联搬进案例库。返回统计。"""
    rows = conn.execute(
        "SELECT id, title, summary, payload_json, created_at FROM domain_items WHERE domain = ? AND item_type = 'event' AND status != 'superseded' ORDER BY id",
        (DOMAIN,),
    ).fetchall()
    stats: dict[str, Any] = {
        "events_scanned": len(rows),
        "events_with_cve": 0,
        "events_skipped_no_cve": 0,
        "cases_created": 0,
        "cases_updated": 0,
        "context_inserted": 0,
        "distinct_cves": 0,
        "skipped_kinds": {},
    }
    cves: set[str] = set()
    for row in rows:
        payload = repo.loads(row["payload_json"], {}) or {}
        kind = str(payload.get("kind") or "")
        cve_ids = [str(value).strip().upper() for value in payload.get("cve_ids") or [] if str(value).strip()]
        material_ids = [int(value) for value in payload.get("material_ids") or []]
        if not cve_ids:
            stats["events_skipped_no_cve"] += 1
            stats["skipped_kinds"][kind or "unknown"] = stats["skipped_kinds"].get(kind or "unknown", 0) + 1
            continue
        stats["events_with_cve"] += 1
        titles = _case_titles(cve_ids, row["title"], str(payload.get("canonical_research_title") or "").strip())
        materials = _material_meta(conn, material_ids)
        context_rows = [
            {
                "context_type": "reference",
                "provenance": "from_legacy_event",
                # 不给 content:素材正文不进上下文表(会重演威胁域 800MB 的坑),
                # 抽屉按 ref_item_id 去读原素材。空 content + ref_item_id 时指纹取自素材 id,
                # 所以同一条素材重复挂到同一个洞上只会落一行。
                "content": "",
                "ref_item_id": material_id,
                "label": materials.get(material_id, {}).get("title") or f"素材 #{material_id}",
                "source_url": materials.get(material_id, {}).get("source_url") or "",
            }
            for material_id in material_ids
        ]
        for cve_id in dict.fromkeys(cve_ids):
            cves.add(cve_id)
            if dry_run:
                stats["cases_created"] += 1
                stats["context_inserted"] += len(context_rows)
                continue
            result = cases_repo.upsert_case(
                conn,
                canonical_id=cve_id,
                id_kind="cve",
                title=titles.get(cve_id) or cve_id,
                summary=str(payload.get("root_cause_summary") or row["summary"] or ""),
                cwe_ids=[str(value) for value in payload.get("cwe_ids") or []],
                source="legacy_event",
                status="pending_fetch",
                actor=actor,
                context_rows=context_rows,
                legacy_material_ids=material_ids,
                payload={"seeded_from_event": int(row["id"]), "seeded_at": utc_now(), "legacy_kind": kind},
            )
            stats["cases_created" if result["created"] else "cases_updated"] += 1
            stats["context_inserted"] += int(result.get("context_inserted") or 0)
    stats["distinct_cves"] = len(cves)
    return stats


def restamp_legacy_case_dates(conn, *, dry_run: bool = False) -> int:
    """把继承来的案例的 `created_at` 拉回**它最初来自的那个 event 的时间**。返回被改的行数。

    为什么必须做:今日情报页的"本批新登记了哪些洞"是靠 `created_at >= 本批开始时间` 圈的
    (cases.list_cases 的 created_since)。迁移在**一次事务里**给 896 条案例盖上同一个"现在",
    于是上线当天这一页会显示"本批新登记 896 个洞",里面躺着 CVE-2019-0708 这种几年前的老洞 ——
    一个说不通的数字, 正是这个页面之前"跑得快就变空"那类口径 bug 的反面。

    继承源 event 的时间之后, 这条案例的"登记时间"就等于它的知识进平台的时间, 只有真在
    **本批**里产出过素材的洞才会算新。用 `created_at > 目标值` 做条件, 所以:
    幂等(重复跑不再改)、自愈(已经盖错的会被拉回来)、**只碰 `source='legacy_event'` 的行**
    (人工添加的、以及采集步自己写的, 一个字都不动)。

    刻意**不按 status 过滤 event**:这一步与 seed 解耦 —— seed 必须先于 supersede 跑(之后就看不到
    那些 event 了), 而回填时间戳恰恰要在 supersede **之后**也能重跑(第一次迁移时忘了做, 第二次
    就得能补上)。因为只改 `source='legacy_event'` 的行, 把已取代的 event 算进来是安全的。
    """
    rows = conn.execute(
        "SELECT payload_json, created_at FROM domain_items WHERE domain = ? AND item_type = 'event'",
        (DOMAIN,),
    ).fetchall()
    earliest: dict[str, str] = {}
    for row in rows:
        stamp = str(row["created_at"] or "")
        if not stamp:
            continue
        payload = repo.loads(row["payload_json"], {}) or {}
        for value in payload.get("cve_ids") or []:
            cve_id = str(value).strip().upper()
            if cve_id:
                earliest[cve_id] = min(earliest.get(cve_id, stamp), stamp)
    if dry_run:
        return sum(
            1
            for cve_id, stamp in earliest.items()
            if conn.execute(
                "SELECT 1 FROM vulnerability_cases WHERE canonical_id = ? AND source = 'legacy_event' AND created_at > ?",
                (cve_id, stamp),
            ).fetchone()
        )
    changed = 0
    for cve_id, stamp in earliest.items():
        cursor = conn.execute(
            "UPDATE vulnerability_cases SET created_at = ? WHERE canonical_id = ? AND source = 'legacy_event' AND created_at > ?",
            (stamp, cve_id, stamp),
        )
        changed += max(cursor.rowcount, 0)
    conn.commit()
    return changed


def retitle_legacy_cases(conn, *, dry_run: bool = False) -> int:
    """把继承来的案例的标题重拼成"这个洞"的标题(见 `_case_titles`)。返回被改的行数。

    为什么单独一步:2026-10-16 上线时 896 条案例里有 773 条的头条是机器拼的
    "多 CVE 事件 · CVE-a, CVE-b, CVE-c" —— 串的是同一个 event 里**别的洞**的编号,
    案例库的头版等于在报别人的名字。种子已经改对了,但库里那批是在改之前落的,
    所以要有个能在**不改种子、不动 created_at/updated_at** 的前提下就地修标题的动作。

    与 `restamp_legacy_case_dates` 一样:读全部 event(不看 status)、只碰
    `source='legacy_event'` 的行、幂等(标题已对的行 rowcount=0)。
    同一个洞出现在多个 event 里时**按 id 升序后写胜出** —— 与种子的 upsert 顺序一致,
    所以这一步的结果与"从零重跑一遍种子"逐字相同。
    只更新 title 一列:连 updated_at 都不碰,否则 896 行会一起显示"刚刚更新",又是同一个谎。
    """
    rows = conn.execute(
        "SELECT payload_json, title FROM domain_items WHERE domain = ? AND item_type = 'event' ORDER BY id",
        (DOMAIN,),
    ).fetchall()
    titles: dict[str, str] = {}
    for row in rows:
        payload = repo.loads(row["payload_json"], {}) or {}
        cve_ids = [str(value).strip().upper() for value in payload.get("cve_ids") or [] if str(value).strip()]
        if cve_ids:
            titles.update(_case_titles(cve_ids, row["title"], str(payload.get("canonical_research_title") or "").strip()))
    if dry_run:
        return sum(
            1
            for cve_id, title in titles.items()
            if conn.execute(
                "SELECT 1 FROM vulnerability_cases WHERE canonical_id = ? AND source = 'legacy_event' AND title != ?",
                (cve_id, title),
            ).fetchone()
        )
    changed = 0
    for cve_id, title in titles.items():
        cursor = conn.execute(
            "UPDATE vulnerability_cases SET title = ? WHERE canonical_id = ? AND source = 'legacy_event' AND title != ?",
            (title, cve_id, title),
        )
        changed += max(cursor.rowcount, 0)
    conn.commit()
    return changed


def supersede_legacy_events(conn, *, dry_run: bool = False) -> int:
    """旧 event 全部置 superseded(**不删行**)。回滚 = 把这批改回 active。"""
    count = int(conn.execute("SELECT COUNT(*) FROM domain_items WHERE domain = ? AND item_type = 'event' AND status != 'superseded'", (DOMAIN,)).fetchone()[0])
    if not count or dry_run:
        return count
    conn.execute(
        "UPDATE domain_items SET status = 'superseded' WHERE domain = ? AND item_type = 'event' AND status != 'superseded'",
        (DOMAIN,),
    )
    conn.commit()
    return count


def recompute_all(conn) -> int:
    """批量重算所有案例的 4 位上下文完整度(改了口径/补了历史数据后用)。"""
    case_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM vulnerability_cases ORDER BY id").fetchall()]
    for case_id in case_ids:
        cases_repo.refresh_completeness(conn, case_id, commit=False)
    conn.commit()
    return len(case_ids)


def _material_meta(conn, material_ids: list[int]) -> dict[int, dict[str, str]]:
    """只取 id/标题/链接三件套 —— 不要用 repo.detail,那会把整页原文拉回内存。"""
    if not material_ids:
        return {}
    placeholders = ", ".join("?" for _ in material_ids)
    rows = conn.execute(
        f"SELECT id, title, source_url FROM domain_items WHERE domain = ? AND item_type = 'material' AND id IN ({placeholders})",
        (DOMAIN, *material_ids),
    ).fetchall()
    return {int(row["id"]): {"title": str(row["title"] or ""), "source_url": str(row["source_url"] or "")} for row in rows}


def main(argv: list[str] | None = None) -> int:
    from ai4sec_platform.db.session import connect

    args = list(argv if argv is not None else sys.argv[1:])
    dry_run = "--dry-run" in args
    # 动作开关: 一个都不给时退回"只 seed"(见模块 docstring)
    actions = [flag for flag in ("--seed", "--supersede", "--restamp", "--retitle", "--recompute", "--stats") if flag in args]
    do_seed = "--seed" in args or not actions
    conn = connect()
    try:
        # 表是 SCHEMA_SQL 里的 CREATE TABLE IF NOT EXISTS:这里显式 init 一次,
        # 免得在 API 从没起过的空库上跑迁移时报"no such table"
        init_db(conn)
        # 只看数的用法: --stats 且没有别的动作
        if actions == ["--stats"]:
            print(cases_repo.case_stats(conn))
            return 0
        if do_seed:
            # 种子是**一次性**的: 库里的行已经在了,再跑一遍会把人工在页面上改过的
            # title/summary/severity 用 event 里的旧值盖回去(source 仍是 legacy_event,
            # 所以 upsert 的"人工案例只填空缺"保护对它无效)。真要重来必须显式 --force。
            seeded = int(conn.execute("SELECT COUNT(*) FROM vulnerability_cases WHERE source = 'legacy_event'").fetchone()[0])
            if seeded and "--force" not in args:
                print(f"seed: 跳过 —— 库里已有 {seeded} 条从旧事件继承的案例。重跑会覆盖人工改过的字段,要强制重跑加 --force;"
                      f"只想修时间戳/标题用 --restamp / --retitle。")
            else:
                print("seed:", seed_cases_from_events(conn, dry_run=dry_run))
        if "--supersede" in args:
            print("superseded_events:", supersede_legacy_events(conn, dry_run=dry_run))
        if "--restamp" in args:
            # 单独一行输出: 这个数必须能一眼看出来(dry_run 时是"待改行数")
            print(("restamped_cases(dry-run): " if dry_run else "restamped_cases: ") + str(restamp_legacy_case_dates(conn, dry_run=dry_run)))
        if "--retitle" in args:
            print(("retitled_cases(dry-run): " if dry_run else "retitled_cases: ") + str(retitle_legacy_cases(conn, dry_run=dry_run)))
        if "--recompute" in args:
            print("recomputed_cases:", recompute_all(conn))
        print("stats:", cases_repo.case_stats(conn))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
