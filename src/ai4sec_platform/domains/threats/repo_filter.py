"""威胁洞察:代码仓过滤规则(唯一真源)。

背景(2026-10-08 领导反馈 #4):8118 个代码仓里 72% 是空壳仓/上游镜像/赛事仓/样例仓这类
"一看就没用"的仓,混在列表里把真正要看的 2270 个淹了。本模块给出判据、离线干跑与落库回填。

设计取舍(与实施计划 3.5 "绝不做物理删除"一致):
* 只打标,不删行、不改 payload。结论落在一张独立小表 ``threat_repo_filters`` 里
  (8118 行 × 几十字节),而不是回写每个仓 100KB 的 payload_json —— 回写要重写约 800MB 的
  生产库,收益只有"少一次 join"。
* 查询侧过滤 = ``/api/threats/targets`` 里 join 这张表。之所以不把规则写进 SQL:规则是
  Python 正则,同一套判据写两份(LIKE/json_extract)必然走偏。
* 回滚 = ``DROP TABLE threat_repo_filters`` + 去掉 API 里那个 join,零数据损失。
* 名称匹配一律按**词段**(``(^|[_-.])词([_\-.]|$)``)而不是裸子串,否则 lib/*test* 之类会误伤。
  实测误伤 0:被硬过滤且 score≥70 的仓一个都没有(见 3.4)。

历史坑:v1 规则曾误伤 ``openFuyao/sig-container-platform``(75 分,被 ``^sig-`` 命中)→ 把 SIG
从硬过滤降级成软过滤 S1;``openharmony/accesscontrol_sandbox_manager``(75 分,被 ``sandbox``
命中)→ 从 F8 判据里删掉 ``sandbox`` 这个词。改判据前请先跑 ``--dry-run`` 看误伤清单。

用法(容器内):
    python -m ai4sec_platform.domains.threats.repo_filter --dry-run      # 只读,打印规则覆盖率
    python -m ai4sec_platform.domains.threats.repo_filter --backfill     # 整表重算(改规则后用这个)
    python -m ai4sec_platform.domains.threats.repo_filter --backfill --only-missing   # 只补新仓

采集流水线(``threats.huawei_full_migration_pipeline``)收尾会自动跑一次 ``--only-missing`` 等价逻辑
(``pipelines/steps/threat_repo_filter.py``),所以每晚新采到的仓当场就有结论,页面不会慢慢失真。
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DOMAIN = "threats"

# 规则代号 → 人类可读原因(前端 filterLabels.ts 有同一份映射;这里也落库,便于直接查库看懂)
CODE_LABELS: dict[str, str] = {
    "F1": "空壳仓:无描述、无 Star、无安全线索",
    "F2": "第三方/上游镜像仓(只做同步,非自有代码)",
    "F3": "赛事/活动临时仓",
    "F4": "测试/Mock/基准仓",
    "F5": "文档/网站仓",
    "F6": "sample/demo/example 样例仓",
    "F7": "CI/打包胶水仓",
    "F8": "教程/lab/练习仓",
    "F9": "模板/脚手架仓",
    "F10": "琐碎名仓(readme/license/homepage 等)",
    "S1": "SIG/治理类仓(仅降权)",
    "S2": "发行版重打包仓(仅降权)",
}

# 硬过滤:默认在列表里隐藏(勾选「显示已过滤」可见)
HARD_CODES = ("F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10")
# 软过滤:只降权,不隐藏
SOFT_CODES = ("S1", "S2")


def _words(*words: str) -> re.Pattern[str]:
    """词段匹配:两侧必须是名字的边界(下划线/连字符/点)或串首尾。"""
    body = "|".join(re.escape(w) for w in words)
    return re.compile(rf"(^|[_\-.])({body})([_\-.]|$)")


_SEG_TEST = _words("test", "tests", "testing", "unittest", "mock", "fixture", "benchmark")
_SEG_SAMPLE = _words("sample", "demo", "example")
_SEG_LEARN = _words("tutorial", "playground", "lab", "course", "homework", "practice", "exercise")
_SEG_TEMPLATE = _words("template", "boilerplate", "scaffold", "starter", "quickstart")
_SEG_EVENT = _words("hackathon", "competition")
_SEG_JENKINS = _words("jenkins")
_SEG_SIG = _words("sig", "tc", "pmc", "community", "governance", "charter")

_RE_F3 = re.compile(r"^ghf\d{4}[-_]")
_RE_F2_SUB = re.compile(r"third_party|chromium_third|android-platform-external|external_")
_RE_F2_PREFIX = re.compile(r"^(vendor|prebuilts|device_board)_")
_RE_F5_END = re.compile(r"-(website|site|docs|documentation|handbook|guide|blog)$")
_RE_F5_START = re.compile(r"^(website|docs)-|^hands-on")
_RE_F7_PREFIX = re.compile(r"^(gradle|maven|pypi|npm|nuget)-")
_RE_F7_SUB = re.compile(r"workflow-sample|-action|obs-helper")
_RE_F10 = re.compile(r"^(readme|license|changelog|contributing|\.github)")
_RE_S1 = re.compile(r"^sig-|-sig")


def hard_matches(*, name: str = "", description: str = "", stars: int = 0, cve_count: int = 0, manual: bool = False) -> list[str]:
    """该仓命中的所有硬过滤规则(按判定优先级排序)。干跑时用它统计"单规则命中数"。

    ``manual`` = 页面人工添加的仓(2026-10-10),豁免 F1 一条:单仓元数据端点恒 401,
    描述和 star 根本取不到,不豁免就会被当空壳从列表里隐藏,变成"加了却查无此仓"。
    其余 F 码判的是仓的**内容形态**(第三方/测试/示例/文档…),照旧生效。
    """
    lowered = (name or "").lower()
    codes: list[str] = []
    if _RE_F2_SUB.search(lowered) or _RE_F2_PREFIX.match(lowered):
        codes.append("F2")
    if _RE_F3.match(lowered) or _SEG_EVENT.search(lowered):
        codes.append("F3")
    if _RE_F10.match(lowered):
        codes.append("F10")
    if _SEG_TEST.search(lowered):
        codes.append("F4")
    if _RE_F5_END.search(lowered) or _RE_F5_START.search(lowered):
        codes.append("F5")
    if _SEG_SAMPLE.search(lowered):
        codes.append("F6")
    if _RE_F7_PREFIX.match(lowered) or _RE_F7_SUB.search(lowered) or _SEG_JENKINS.search(lowered):
        codes.append("F7")
    if _SEG_LEARN.search(lowered):
        codes.append("F8")
    if _SEG_TEMPLATE.search(lowered):
        codes.append("F9")
    # F1 空壳:上游没写描述 + 无 Star + 无 CVE。放最后 —— 集合不变,但理由更具体。
    if not manual and not (description or "").strip() and int(stars or 0) <= 0 and int(cve_count or 0) <= 0:
        codes.append("F1")
    return codes


def is_soft(*, name: str = "") -> str:
    """软过滤(SIG/治理):只降权。返回代号或空串。"""
    lowered = (name or "").lower()
    if _RE_S1.search(lowered) or _SEG_SIG.search(lowered):
        return "S1"
    return ""


def classify(
    *,
    name: str = "",
    org: str = "",
    description: str = "",
    stars: int = 0,
    cve_count: int = 0,
    manual: bool = False,
) -> dict[str, Any]:
    """判一个仓是否该被过滤。

    返回 ``{filtered, code, reason, soft, soft_code}``。命中的多条硬规则里取优先级最高的那条作为
    ``code``(理由更具体的那条通常排前面),``filtered_reason`` 就是给人看的理由。
    ``manual`` 见 ``hard_matches``。
    """
    codes = hard_matches(name=name, description=description, stars=stars, cve_count=cve_count, manual=manual)
    filter_code = codes[0] if codes else ""
    soft_code = "" if filter_code else is_soft(name=name)
    return {
        "filtered": bool(filter_code),
        "code": filter_code,
        "reason": CODE_LABELS.get(filter_code, "") if filter_code else "",
        "soft": bool(soft_code),
        "soft_code": soft_code,
    }


def extract_fields(payload: dict[str, Any], *, item_summary: str = "", item_url: str = "") -> dict[str, Any]:
    """从 domain_item 的 payload 里取判据需要的字段(干跑与回填共用一份口径)。

    字段来源经线上样本核对(2026-10-09):``payload.raw.name`` / ``payload.raw.org`` /
    ``payload.raw.description`` / ``payload.stars``(回退 ``raw.star_count``) /
    ``payload.cve_count``(回退 ``vulnerability_signals.cve_count``)。

    注意 description **只认上游仓库自己的描述**(``description_original`` / ``raw.description``),
    绝不回退到 ``summary`` 系列:那是流水线生成的中文摘要,8118 个仓几乎人人都有,
    一旦回退过去 F1 空壳规则就会恒为 0(2026-10-09 实测踩过)。``item_summary`` 只作兜底参数保留。
    """
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    signals = payload.get("vulnerability_signals")
    if not isinstance(signals, dict):
        signals = payload.get("signals") if isinstance(payload.get("signals"), dict) else {}
    title = str(payload.get("title") or "")
    name = str(raw.get("name") or payload.get("name") or (title.split("/")[-1] if "/" in title else title) or "")
    org = str(raw.get("org") or payload.get("org") or (title.split("/")[0] if "/" in title else "") or "")
    description = payload.get("description_original") or raw.get("description") or ""
    stars = payload.get("stars")
    if stars is None:
        stars = raw.get("star_count", raw.get("stargazers_count", 0))
    cve_count = payload.get("cve_count")
    if cve_count is None:
        cve_count = signals.get("cve_count", 0)
    return {
        "name": name,
        "org": org,
        "description": str(description or ""),
        "stars": _as_int(stars),
        "cve_count": _as_int(cve_count),
        "url": str(item_url or payload.get("url") or raw.get("url") or ""),
        "manual": bool(raw.get("manual")),
    }


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


DDL = """
CREATE TABLE IF NOT EXISTS threat_repo_filters (
    item_id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT 'threats',
    filtered INTEGER NOT NULL DEFAULT 0,
    code TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    soft INTEGER NOT NULL DEFAULT 0,
    soft_code TEXT NOT NULL DEFAULT '',
    computed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_repo_filters_filtered ON threat_repo_filters(domain, filtered);
"""


def ensure_table(conn: sqlite3.Connection) -> None:
    conn.executescript(DDL)
    conn.commit()


def table_ready(conn: sqlite3.Connection) -> bool:
    """表存在**且有数据**才算可用——空表会让列表页误以为"什么都没被过滤"。"""
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='threat_repo_filters'"
        ).fetchone()
        if not row:
            return False
        return bool(conn.execute("SELECT 1 FROM threat_repo_filters LIMIT 1").fetchone())
    except sqlite3.Error:
        return False


def load_verdicts(conn: sqlite3.Connection, item_ids: list[int]) -> dict[int, dict[str, Any]]:
    """取一批 item 的过滤结论(供列表/详情接口附加 filtered / filtered_reason)。"""
    if not item_ids:
        return {}
    placeholders = ",".join("?" for _ in item_ids)
    rows = conn.execute(
        f"SELECT item_id, filtered, code, reason, soft, soft_code FROM threat_repo_filters "
        f"WHERE item_id IN ({placeholders})",
        item_ids,
    ).fetchall()
    out: dict[int, dict[str, Any]] = {}
    for row in rows:
        out[int(row[0] if not hasattr(row, "keys") else row["item_id"])] = {
            "filtered": bool(_row_get(row, "filtered", 1)),
            "code": str(_row_get(row, "code", 2) or ""),
            "reason": str(_row_get(row, "reason", 3) or ""),
            "soft": bool(_row_get(row, "soft", 4)),
            "soft_code": str(_row_get(row, "soft_code", 5) or ""),
        }
    return out


def _row_get(row: Any, key: str, index: int) -> Any:
    """sqlite3.Row 与 tuple 都能取值(row_factory 不保证)。"""
    try:
        return row[key]
    except (TypeError, IndexError, KeyError):
        return row[index]


def iter_targets(conn: sqlite3.Connection) -> list[tuple[int, str, str, dict[str, Any]]]:
    """列出全部待判定的代码仓:(item_id, title, summary, payload)。"""
    rows = conn.execute(
        "SELECT id, title, summary, payload_json FROM domain_items WHERE domain = ? AND item_type = 'target'",
        (DOMAIN,),
    ).fetchall()
    out: list[tuple[int, str, str, dict[str, Any]]] = []
    for row in rows:
        item_id = int(_row_get(row, "id", 0))
        title = str(_row_get(row, "title", 1) or "")
        summary = str(_row_get(row, "summary", 2) or "")
        raw_json = _row_get(row, "payload_json", 3)
        try:
            payload = json.loads(raw_json) if isinstance(raw_json, str) else (raw_json or {})
        except (TypeError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        out.append((item_id, title, summary, payload))
    return out


def render_verdict(fields: dict[str, Any]) -> dict[str, Any]:
    return classify(
        name=fields["name"],
        org=fields["org"],
        description=fields["description"],
        stars=fields["stars"],
        cve_count=fields["cve_count"],
        manual=bool(fields.get("manual")),
    )


def dry_run(conn: sqlite3.Connection, *, limit_mis_hits: int = 40) -> dict[str, Any]:
    """只读干跑:单规则命中数、并集、保留数、误伤清单(被硬过滤且 score≥70)。

    ``per_rule_independent`` 是每条规则**单独**跑出来的命中数(可与实施计划 3.2 的表格逐格对照);
    ``per_rule_first_match`` 是最终落库会取的那条理由(一个仓可能命中多条,只记优先级最高的)。
    """
    per_rule_independent: dict[str, int] = {}
    per_rule_first_match: dict[str, int] = {}
    filtered_ids: set[int] = set()
    soft_only = 0
    kept_ids: set[int] = set()
    kept_with_star = 0
    mis_hits: list[dict[str, Any]] = []
    total = 0
    scores: dict[int, float] = {}

    for item_id, _title, summary, payload in iter_targets(conn):
        total += 1
        fields = extract_fields(payload, item_summary=summary)
        matches = hard_matches(name=fields["name"], description=fields["description"], stars=fields["stars"], cve_count=fields["cve_count"], manual=bool(fields.get("manual")))
        for code in matches:
            per_rule_independent[code] = per_rule_independent.get(code, 0) + 1
        verdict = render_verdict(fields)
        score = payload.get("risk_score")
        if score is None:
            attack_surface = payload.get("attack_surface")
            score = attack_surface.get("score") if isinstance(attack_surface, dict) else None
        try:
            scores[item_id] = float(score or 0)
        except (TypeError, ValueError):
            scores[item_id] = 0.0
        if verdict["filtered"]:
            per_rule_first_match[verdict["code"]] = per_rule_first_match.get(verdict["code"], 0) + 1
            filtered_ids.add(item_id)
            if scores[item_id] >= 70:
                mis_hits.append({"item_id": item_id, "org": fields["org"], "name": fields["name"], "code": verdict["code"], "score": scores[item_id], "stars": fields["stars"], "cve": fields["cve_count"]})
        else:
            kept_ids.add(item_id)
            if (fields["stars"] or 0) > 0:
                kept_with_star += 1
            if verdict["soft"]:
                soft_only += 1

    mis_hits.sort(key=lambda r: -r["score"])
    return {
        "total": total,
        "filtered": len(filtered_ids),
        "kept": len(kept_ids),
        "filtered_pct": round(len(filtered_ids) / total * 100, 1) if total else 0.0,
        "per_rule_independent": {code: per_rule_independent.get(code, 0) for code in HARD_CODES},
        "per_rule_first_match": {code: per_rule_first_match.get(code, 0) for code in HARD_CODES},
        "soft_only": soft_only,
        # 保留集里的高分仓(score≥70):这批是"绝不能误伤"的清单,与误伤数一起看
        "kept_high_score": sum(1 for i in kept_ids if (scores.get(i) or 0) >= 70),
        "kept_with_star": kept_with_star,
        "mis_hits": mis_hits[:limit_mis_hits],
        "mis_hit_count": len(mis_hits),
    }


def missing_target_ids(conn: sqlite3.Connection) -> set[int]:
    """还没有过滤结论的仓 id(采集每晚都会新进一批,靠这个做增量补齐)。"""
    rows = conn.execute(
        "SELECT d.id FROM domain_items d LEFT JOIN threat_repo_filters f ON f.item_id = d.id "
        "WHERE d.domain = ? AND d.item_type = 'target' AND f.item_id IS NULL",
        (DOMAIN,),
    ).fetchall()
    return {int(_row_get(row, "id", 0)) for row in rows}


def is_manual_target(payload: dict[str, Any]) -> bool:
    """这条仓是不是页面「代码仓 · 单个仓」人工添加的(打标在 ``payload.raw.manual``)。"""
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    return bool(raw.get("manual") or payload.get("manual"))


def backfill(conn: sqlite3.Connection, *, only_missing: bool = False) -> dict[str, Any]:
    """把判定结果写入 threat_repo_filters(幂等,写一次事务)。

    ``only_missing=True`` 只算**还没有结论**的仓 —— 采集流水线每天都在加新仓,收尾时用它把
    新仓补上(通常每晚几十个,毫秒级),否则新进的空壳/样例仓不会被过滤,页面上的"已隐藏"
    会一天天失真。**改规则之后必须跑默认的整表重算**,增量模式不会刷新已有行。

    例外:**人工添加的仓每次都重算**(2026-10-10)。它们的典型形态恰恰是"组织扫描早就抓回来
    过、上一轮已判过 F1 空壳"的仓,增量模式会把那条旧结论一直留着 —— 用户在页面上加了仓,
    手动豁免永远落不了地,他要的那个仓还是被隐藏。所以增量模式下也把这类仓捞出来重判。
    """
    ensure_table(conn)
    targets = iter_targets(conn)
    if only_missing:
        missing = missing_target_ids(conn)
        targets = [t for t in targets if t[0] in missing or is_manual_target(t[3])]
    now = _now()
    rows: list[tuple[int, str, int, str, str, int, str, str]] = []
    for item_id, _title, summary, payload in targets:
        fields = extract_fields(payload, item_summary=summary)
        verdict = render_verdict(fields)
        rows.append((
            item_id,
            DOMAIN,
            1 if verdict["filtered"] else 0,
            verdict["code"],
            verdict["reason"],
            1 if verdict["soft"] else 0,
            verdict["soft_code"],
            now,
        ))
    try:
        with conn:
            if not only_missing:
                conn.execute("DELETE FROM threat_repo_filters")
            conn.executemany(
                "INSERT INTO threat_repo_filters "
                "(item_id, domain, filtered, code, reason, soft, soft_code, computed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(item_id) DO UPDATE SET "
                "domain=excluded.domain, filtered=excluded.filtered, code=excluded.code, "
                "reason=excluded.reason, soft=excluded.soft, soft_code=excluded.soft_code, "
                "computed_at=excluded.computed_at",
                rows,
            )
    except sqlite3.Error as exc:
        # 不用 SystemExit:本函数也会被 pipeline 步骤调用(SystemExit 不是 Exception,
        # 会直接穿透步骤里的 except 把整轮跑批带走)。
        raise RuntimeError(f"backfill failed: {exc}") from exc
    filtered = sum(1 for r in rows if r[2] == 1)
    return {
        "written": len(rows),
        "filtered": filtered,
        "kept": len(rows) - filtered,
        "computed_at": now,
        "only_missing": only_missing,
    }


def _open_ro(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="威胁洞察代码仓过滤:干跑 / 回填")
    parser.add_argument("--db", default="/app/output/ai4sec_platform.db", help="SQLite 路径")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="只读跑规则,打印覆盖率与误伤清单")
    mode.add_argument("--backfill", action="store_true", help="把判定写进 threat_repo_filters")
    parser.add_argument("--only-missing", action="store_true", help="配合 --backfill:只补还没有结论的仓(采集后增量用)")
    parser.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = parser.parse_args(argv)

    path = Path(args.db)
    if args.dry_run:
        report = dry_run(_open_ro(path))
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            print(f"总数 {report['total']} | 过滤 {report['filtered']} ({report['filtered_pct']}%) | 保留 {report['kept']}")
            print(f"  {'规则':<4} {'单规则命中':>8} {'最终理由':>8}  说明")
            for code in HARD_CODES:
                print(f"  {code:<4} {report['per_rule_independent'][code]:>8} {report['per_rule_first_match'][code]:>8}  {CODE_LABELS[code]}")
            print(f"  软过滤(仅降权) S1 {report['soft_only']}")
            print(f"误伤(被过滤且 score≥70): {report['mis_hit_count']}")
            for row in report["mis_hits"]:
                print(f"    {row['score']:>5} {row['code']} {row['org']}/{row['name']} (star {row['stars']}, cve {row['cve']})")
        return 0

    conn = sqlite3.connect(str(path), timeout=60)
    conn.row_factory = sqlite3.Row
    try:
        stats = backfill(conn, only_missing=args.only_missing)
    except (sqlite3.Error, RuntimeError) as exc:
        print(f"backfill failed: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    print(json.dumps(stats, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
