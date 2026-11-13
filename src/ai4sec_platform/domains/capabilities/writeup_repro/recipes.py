"""T5.1: 从复现报告抽出两件能复用的东西 —— recipe(怎么跑) 与 pattern(怎么找)。

分工
====

=====================================  ==================  ==========================================
产物                                   回答                入库门槛
=====================================  ==================  ==========================================
recipe(`writeup_repro_recipes`)        这一类怎么**跑**    来源是 ``success``(或 ``partial`` 但标 degraded)
pattern(`writeup_repro_patterns`)      这一类怎么**找**    第 6 节**通过校验**, 与结论无关
=====================================  ==================  ==========================================

pattern 的门槛为什么不是"复现成功": 复现失败否定的是我们的环境或原文的完整性,
**不否定根因分析** —— 原文把根因写清楚了, 而我们是环境装不起来, 这条规律照样能用(§13.7)。
所以 ``cannot_repro`` 的报告也能产 pattern, 只要 ``pattern_json["verified"]`` 为真。

三条纪律(与 T4.3 同一个路数: 能由规则保证的, 不写成注释里的承诺)
================================================================

1. **每条命令都能回指证据**。recipe 的每一段都是
   ``{"index": <报告第 3 节的 commands[].index>, "cmd": ...}`` —— 拿 ``index`` 去报告里查,
   一定查得到。凭空生成一条"应该这么跑"的命令是最容易混进来的假货。
2. **没有的那一段就是空数组**, 不猜。没有包管理器命令就没有 ``setup``,
   没有 clone 就没有 ``acquire``; 硬补一段会让复用者照着一条从没跑过的流程走。
3. **重抽是覆盖, 不是追加**。同一份证据被数成两条规律, 等于把"这个写法危险"说重了一倍;
   报告重新生成后第 6 节**没通过**校验时, 上一版的 pattern 会被**删掉**(结论降级了,
   下游不该还留着旧结论)。
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from ai4sec_platform.domains.capabilities.writeup_repro import report as report_module
from ai4sec_platform.domains.capabilities.writeup_repro import store, tasks

RECIPE_VERSION = 1
#: 一条 recipe 里保留的命令上限。长任务跑几百条命令, 全塞进 recipe 就没人读了;
#: 截断时 `recipe_json["truncated"]` 会写明少了几条, 不静默丢。
MAX_RECIPE_COMMANDS = 60

GENERALIZATIONS = ("framework", "language", "generic")


def now() -> str:
    return f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


# ---------------------------------------------------------------- 命令分段(规则)

#: 拉取目标源码/制品。**先判这一档**: `git clone x && pip install -e .` 属于"拿到目标",
#: 不是"准备环境"。
_ACQUIRE = re.compile(
    r"(?:^|[\s;&|])(?:git\s+clone|git\s+checkout|codeload\.github\.com|"
    r"curl\s+[^;&|]*\.(?:tar\.gz|tgz|zip)|wget\s+[^;&|]*\.(?:tar\.gz|tgz|zip))",
    re.I,
)

#: 环境准备: 装依赖、建虚拟环境、编译。
_SETUP = re.compile(
    r"(?:^|[\s;&|])(?:"
    r"(?:sudo\s+)?(?:apt-get|apt|apk|yum|dnf|zypper|pacman|brew)\s+(?:install|add|update)|"
    r"(?:sudo\s+)?(?:pip3?|pipx)\s+install|"
    r"uv\s+(?:venv|sync|pip\s+install)|"
    r"(?:python3?|py)\s+-m\s+venv|"
    r"(?:npm|yarn|pnpm)\s+(?:install|ci|add)|"
    r"composer\s+install|cargo\s+(?:build|install|fetch)|go\s+(?:mod\s+download|get|build|install)|"
    r"make(?:\s|$)|cmake\b|meson\b|ninja\b|\./configure\b|"
    r"(?:gcc|g\+\+|clang|cc)\s|"
    r"source\s+[^;&|]*activate"
    r")",
    re.I,
)

#: **纯导航**命令: 对"怎么跑"没有任何信息量的那些。
#: 只收这几个 —— ``echo``/``cat`` 常常是把 PoC 写进文件的关键步骤(**绝不能**当噪声丢掉),
#: ``cd`` 只有单独一条时才算噪声(``cd x && ./run`` 里的 cd 属于那条命令的一部分)。
_NOISE = re.compile(
    r"^\s*(?:ls(?:\s|$)|pwd\s*$|true\s*$|false\s*$|sleep\s+\d|which\s|command\s+-v\s|cd\s+[^\s;&|]+\s*$)",
    re.I,
)

#: 拆子命令用的分隔符。判类看的是**每个子命令**, 而不是整行 ——
#: ``cd /w && source .venv/bin/activate && pip install -e .`` 是 setup, 不是 trigger。
_SUBCMD_SPLIT = re.compile(r"\s*(?:&&|\|\||[;|]|\n)\s*")

#: 攻击面关键词 → 指纹 token。**只做确定性映射, 不做语义推断**:
#: 匹配不到就不加这个 token, 不写 "unknown" 之类看着像结论的东西。
_SURFACES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("memory_corruption", re.compile(
        r"内存破坏|memory corruption|use[- ]after[- ]free|\buaf\b|buffer overflow|"
        r"堆溢出|栈溢出|double free|out[- ]of[- ]bounds|越界读|越界写", re.I)),
    ("rce", re.compile(r"\brce\b|remote code execution|远程代码执行|命令执行|任意代码执行", re.I)),
    ("xss", re.compile(r"\bxss\b|cross[- ]site scripting|跨站脚本", re.I)),
    ("sqli", re.compile(r"\bsql injection|sql 注入|\bsqli\b", re.I)),
    ("ssrf", re.compile(r"\bssrf\b|server[- ]side request forgery|服务端请求伪造", re.I)),
    ("path_traversal", re.compile(r"path traversal|directory traversal|路径穿越|目录穿越", re.I)),
    ("auth_bypass", re.compile(r"auth(?:entication|orization)? bypass|鉴权绕过|认证绕过|越权", re.I)),
    ("deserialization", re.compile(r"deserializ|反序列化", re.I)),
    ("info_leak", re.compile(r"information (?:leak|disclosure)|信息泄露|敏感信息", re.I)),
    ("dos", re.compile(r"denial of service|\bdos\b|拒绝服务", re.I)),
)

_LANG_ALIASES = {
    "py": "python", "python2": "python", "python3": "python", "python": "python",
    "c": "c", "cpp": "cpp", "c++": "cpp", "cxx": "cpp",
    "php": "php", "js": "javascript", "javascript": "javascript", "node": "javascript",
    "ts": "typescript", "typescript": "typescript",
    "java": "java", "go": "go", "golang": "go", "rust": "rust", "rb": "ruby", "ruby": "ruby",
    "sh": "shell", "bash": "shell", "shell": "shell", "zsh": "shell",
}


def normalize_lang(value: Any) -> str:
    text = str(value or "").strip().lower()
    return _LANG_ALIASES.get(text, text if re.fullmatch(r"[a-z0-9+#]{1,16}", text) else "")


def _subcommands(cmd: str) -> list[str]:
    return [part.strip() for part in _SUBCMD_SPLIT.split(str(cmd or "")) if part.strip()]


def classify_command(cmd: str) -> str:
    """把一条命令分到 ``acquire`` / ``setup`` / ``trigger`` / ``noise``。

    **按子命令判**, 优先级 acquire > setup: 一条命令里既 clone 又 install, 归到 acquire
    —— 它解决的是"目标从哪来", 复用时这一段换掉就够, 后面的安装往往可以照抄。
    """
    text = str(cmd or "").strip()
    if not text:
        return "noise"
    if _NOISE.match(text):
        return "noise"
    kinds = set()
    for part in _subcommands(text):
        if _ACQUIRE.search(part):
            kinds.add("acquire")
        elif _SETUP.search(part):
            kinds.add("setup")
    if "acquire" in kinds:
        return "acquire"
    if "setup" in kinds:
        return "setup"
    return "trigger"


def segment_commands(
    commands: list[dict[str, Any]],
    probe_cmd: str,
) -> dict[str, Any]:
    """按语义切四段。返回的每条命令都带 ``index``(报告第 3 节的编号)。

    ``probe`` 取**最后一次**出现的同名命令(与判定层 ``find_probe_command`` 同一个口径:
    前面那几次往往是环境没对齐时试的, 真正算数的是最后那次)。同一个命令的前几次**不丢**,
    照常按语义归到 ``trigger`` —— 它们确实是"怎么触发"的证据, 只是不算判定依据。
    """
    probe_norm = " ".join(str(probe_cmd or "").split())
    segments: dict[str, list[dict[str, Any]]] = {"setup": [], "acquire": [], "trigger": []}
    omitted: list[dict[str, Any]] = []
    probe_occurrences = 0
    probe_row: dict[str, Any] | None = None
    probe_index: int | None = None

    if probe_norm:
        # 先定"最后一次"是哪一条, 再看它后面还有没有同类 —— 一遍扫完没法事后改判。
        for row in commands or []:
            if not isinstance(row, dict):
                continue
            if " ".join(str(row.get("cmd") or "").split()) == probe_norm:
                probe_occurrences += 1
                probe_index = int(row.get("index") or 0)

    for row in commands or []:
        if not isinstance(row, dict):
            continue
        index = int(row.get("index") or 0)
        cmd = str(row.get("cmd") or "")
        if probe_index is not None and index == probe_index:
            probe_row = {"index": index, "cmd": cmd, "exit_code": row.get("exit_code")}
            continue
        kind = classify_command(cmd)
        if kind == "noise":
            omitted.append({"index": index, "cmd": cmd, "reason": "导航命令"})
            continue
        segments[kind].append({"index": index, "cmd": cmd, "exit_code": row.get("exit_code")})

    kept = sum(len(items) for items in segments.values()) + (1 if probe_row else 0)
    truncated = 0
    if kept > MAX_RECIPE_COMMANDS:
        # 截断顺序: **trigger 最先保**, 其次 setup, 最后 acquire —— 复用时最常被整段替换掉的
        # 就是"目标从哪来"那几条, 而 trigger 是这个洞的独有部分。
        # 同类里从**尾部**截: 命令越靠后越接近真正跑通的那一版(前面是试错)。
        budget = MAX_RECIPE_COMMANDS - (1 if probe_row else 0)
        total = sum(len(items) for items in segments.values())
        keep: dict[str, list[dict[str, Any]]] = {"setup": [], "acquire": [], "trigger": []}
        remaining = max(0, budget)
        for kind in ("trigger", "setup", "acquire"):
            items = segments[kind]
            take = items[-remaining:] if remaining > 0 else []
            keep[kind] = take
            remaining -= len(take)
        truncated = total - sum(len(items) for items in keep.values())
        segments = keep

    return {
        "setup": segments["setup"],
        "acquire": segments["acquire"],
        "trigger": segments["trigger"],
        "probe": probe_row or {},
        "probe_occurrences": probe_occurrences,
        "omitted": omitted,
        "truncated": truncated,
        "command_count": kept,
    }


# ---------------------------------------------------------------- 指纹

def build_fingerprint(
    task: dict[str, Any],
    candidate: dict[str, Any] | None,
    pattern: dict[str, Any] | None = None,
) -> list[str]:
    """``["lang:python", "target:package", "surface:memory_corruption", "gen:generic"]``。

    只放**能确定的事实**: 语言来自预筛、目标形态来自任务、泛化边界来自第 7 节、
    攻击面来自关键词映射。**不放仓库名与版本** —— 那会让指纹退化成"只对这一个目标有效",
    而复用的前提正好相反(§8.1)。
    """
    candidate = candidate or {}
    pattern = pattern or {}
    tokens: list[str] = []

    lang = normalize_lang(candidate.get("poc_lang") or task.get("poc_lang"))
    if lang:
        tokens.append(f"lang:{lang}")

    kind = str(task.get("target_kind") or candidate.get("target_kind") or "").strip().lower()
    if kind and kind != "unknown":
        tokens.append(f"target:{kind}")

    blob = " ".join(str(x or "") for x in (
        task.get("claim"), candidate.get("claimed_effect"), pattern.get("discriminator"),
    ))
    hits = [name for name, rx in _SURFACES if rx.search(blob)]
    for name in hits[:2]:
        tokens.append(f"surface:{name}")

    generalization = str(pattern.get("generalization") or "").strip().lower()
    if generalization in GENERALIZATIONS:
        tokens.append(f"gen:{generalization}")

    return tokens


# ---------------------------------------------------------------- recipe

def recipe_key(task: dict[str, Any]) -> str:
    """一条任务一条 recipe。**不带随机后缀** —— 键不稳定, 重抽就会插出第二行。"""
    return f"wr-{int(task['material_id'])}-{int(task['id'])}"


def build_recipe(
    task: dict[str, Any],
    report: dict[str, Any],
    candidate: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """返回 ``(recipe, 不产出的原因)``。只有 ``success`` / ``partial`` 产 recipe。"""
    verdict = str(task.get("verdict") or "")
    if verdict not in ("success", "partial"):
        return None, [f"结论是 {verdict}, 不产 recipe(只有 success/partial 有可复用的执行路径)"]

    evidence = report.get("evidence_json") or {}
    commands = (evidence.get("section") or {}).get("commands") or []
    if not commands:
        return None, ["证据包里没有任何已执行命令, 没有可固化的东西"]

    observed = report.get("observed_json") or {}
    probe_cmd = str(observed.get("cmd") or observed.get("spec_cmd") or "")
    seg = segment_commands(commands, probe_cmd)
    if not (seg["setup"] or seg["acquire"] or seg["trigger"] or seg["probe"]):
        return None, ["所有命令都被判成导航命令, 抽不出一条可复用的步骤"]

    spec = task.get("spec_json") or {}
    target = dict(spec.get("target") or {})
    fingerprint = build_fingerprint(task, candidate, report.get("pattern_json") or {})
    matched = observed.get("matched")

    recipe = {
        "version": RECIPE_VERSION,
        "applies_to": {
            "fingerprint": fingerprint,
            "target_kind": str(task.get("target_kind") or ""),
        },
        "acquire": seg["acquire"],
        "setup": seg["setup"],
        "trigger": seg["trigger"],
        "probe": {
            **(seg["probe"] or {"index": None, "cmd": probe_cmd, "exit_code": None}),
            "success_signal": str(observed.get("success_signal") or ""),
            "matched": matched,
            "occurrences": seg["probe_occurrences"],
            "index_found": bool(seg["probe"].get("index")),
        },
        "target": target,
        "known_pitfalls": _pitfalls(report),
        "degraded": verdict != "success",
        "omitted": seg["omitted"],
        "truncated": seg["truncated"],
        "verified_on": [f"task:{int(task['id'])}"],
        "source": {
            "task_id": int(task["id"]),
            "material_id": int(task["material_id"]),
            "attempt": task.get("attempt"),
            "verdict": verdict,
            "duration_seconds": task.get("duration_seconds"),
            "tool_calls": task.get("tool_calls"),
        },
    }
    return recipe, []


def _pitfalls(report: dict[str, Any]) -> list[str]:
    """把报告第 8 节里**讲执行的那几条**搬过来当"已知坑"。

    只挑提到环境/版本/安装/命令的 caveat —— 归因、推断类的不属于"怎么跑"。
    搬运而不是让模型另写一段: 这些句子已经在证据里被核对过一遍了。
    """
    keywords = ("环境", "版本", "装", "依赖", "命令", "wheel", "python", "编译", "镜像", "yank")
    out: list[str] = []
    for item in report.get("caveats") or []:
        text = str(item or "").strip()
        if not text or len(text) > 300:
            continue
        if any(word in text.lower() or word in text for word in keywords):
            out.append(text)
    return out[:8]


def _save_recipe(conn: sqlite3.Connection, task: dict[str, Any], recipe: dict[str, Any]) -> dict[str, Any]:
    key = recipe_key(task)
    success = 1 if str(task.get("verdict")) == "success" else 0
    conn.execute(
        "INSERT INTO writeup_repro_recipes (recipe_key, task_id, material_id, fingerprint_json,"
        " recipe_json, degraded, success_count, fail_count, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)"
        " ON CONFLICT(recipe_key) DO UPDATE SET"
        "   fingerprint_json = excluded.fingerprint_json,"
        "   recipe_json = excluded.recipe_json,"
        "   degraded = excluded.degraded,"
        "   success_count = excluded.success_count,"
        "   updated_at = excluded.updated_at",
        (
            key, int(task["id"]), int(task["material_id"]),
            json.dumps(recipe["applies_to"]["fingerprint"], ensure_ascii=False),
            json.dumps(recipe, ensure_ascii=False), 0 if success else 1, success,
            now(), now(),
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM writeup_repro_recipes WHERE recipe_key = ?", (key,)).fetchone()
    return _parse_recipe_row(row)


def _parse_recipe_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    out = dict(row)
    for key, default in (("fingerprint_json", []), ("recipe_json", {})):
        try:
            out[key] = json.loads(out.get(key) or json.dumps(default))
        except (TypeError, ValueError):
            out[key] = default
    out["degraded"] = bool(out.get("degraded"))
    return out


# ---------------------------------------------------------------- pattern

def build_pattern(
    task: dict[str, Any],
    report: dict[str, Any],
    candidate: dict[str, Any] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """第 7 节**通过校验**才入库。结论本身不设门槛(§13.7)。"""
    pattern = report.get("pattern_json") or {}
    if not pattern:
        return None, ["报告里没有第 7 节(没有不变量, 规律无从溯源)"]

    blockers = pattern.get("blockers") or []
    if not pattern.get("verified"):
        reason = "; ".join(str(item) for item in blockers) or "第 7 节未通过入库闸门"
        return None, [f"第 7 节未通过入库闸门: {reason}"]

    invariant = str(pattern.get("invariant") or "").strip()
    if not invariant:
        return None, ["第 7 节没有不变量"]

    generalization = str(pattern.get("generalization") or "").strip().lower()
    provenance = str(pattern.get("provenance") or "").strip().lower()
    confidence = pattern.get("confidence")
    row = {
        "report_id": int(task["id"]),
        "material_id": int(task["material_id"]),
        "invariant": invariant,
        "code_feature": str(pattern.get("code_feature") or "").strip(),
        "audit_entry": str(pattern.get("audit_entry") or "").strip(),
        "discriminator": str(pattern.get("discriminator") or "").strip(),
        "generalization": generalization if generalization in GENERALIZATIONS else "framework",
        "fingerprint": json.dumps(build_fingerprint(task, candidate, pattern), ensure_ascii=False),
        "provenance": provenance,
        "confidence": float(confidence) if isinstance(confidence, (int, float)) else None,
        "created_at": now(),
    }
    return row, []


def _save_pattern(conn: sqlite3.Connection, row: dict[str, Any]) -> dict[str, Any]:
    conn.execute(
        "INSERT INTO writeup_repro_patterns (report_id, material_id, invariant, code_feature,"
        " audit_entry, discriminator, generalization, fingerprint, provenance, confidence, created_at)"
        " VALUES (:report_id, :material_id, :invariant, :code_feature, :audit_entry,"
        " :discriminator, :generalization, :fingerprint, :provenance, :confidence, :created_at)"
        " ON CONFLICT(report_id) DO UPDATE SET"
        "   invariant = excluded.invariant, code_feature = excluded.code_feature,"
        "   audit_entry = excluded.audit_entry, discriminator = excluded.discriminator,"
        "   generalization = excluded.generalization, fingerprint = excluded.fingerprint,"
        "   provenance = excluded.provenance, confidence = excluded.confidence,"
        "   created_at = excluded.created_at",
        row,
    )
    conn.commit()
    saved = conn.execute(
        "SELECT * FROM writeup_repro_patterns WHERE report_id = ?", (row["report_id"],)
    ).fetchone()
    return dict(saved) if saved is not None else {}


# ---------------------------------------------------------------- 入口

def extract_for_task(
    task_id: int,
    *,
    regenerate: bool = True,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """给一条有报告的任务抽 recipe + pattern。**幂等**: 重抽覆盖同一行。

    ``regenerate=False`` 时已有产物就原样返回(执行器正常收尾走这条, 手动重抽走
    ``POST /tasks/{id}/extract``)。
    """
    own = conn is None
    conn = conn or _connect()
    try:
        task = tasks.get_task(conn, int(task_id))
        if task is None:
            return {"status": "missing_task", "reason": f"任务 {task_id} 不存在"}
        report = report_module.get_report(conn, int(task_id))
        if report is None:
            return {"status": "no_report", "reason": "还没有复现报告, 先 POST /tasks/{id}/report"}

        if not regenerate:
            existing_recipe = _get_recipe(conn, task)
            existing_pattern = _get_pattern(conn, int(task["id"]))
            if existing_recipe or existing_pattern:
                return {"status": "exists", "recipe": existing_recipe, "pattern": existing_pattern}

        candidate = store.get_candidate(conn, int(task["material_id"])) or {}
        reasons: list[str] = []

        recipe, recipe_reasons = build_recipe(task, report, candidate)
        reasons.extend(recipe_reasons)
        saved_recipe = None
        if recipe is not None:
            saved_recipe = _save_recipe(conn, task, recipe)
            tasks.link_recipe(conn, int(task["id"]), int(saved_recipe["id"]))
        else:
            # 结论不再支持 recipe(例如重生成后变了口径)⇒ 旧行必须清掉, 否则复用它的人
            # 拿到的是"这条已经不被支持"的路径。
            _delete_recipe(conn, task)

        pattern, pattern_reasons = build_pattern(task, report, candidate)
        reasons.extend(pattern_reasons)
        saved_pattern = None
        if pattern is not None:
            saved_pattern = _save_pattern(conn, pattern)
        else:
            _delete_pattern(conn, int(task["id"]))

        status = "ok" if (saved_recipe or saved_pattern) else "no_products"
        return {
            "status": status,
            "recipe": saved_recipe,
            "pattern": saved_pattern,
            "reasons": reasons,
        }
    finally:
        if own:
            conn.close()


def _get_recipe(conn: sqlite3.Connection, task: dict[str, Any]) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM writeup_repro_recipes WHERE recipe_key = ?", (recipe_key(task),)
    ).fetchone()
    return _parse_recipe_row(row)


def _get_pattern(conn: sqlite3.Connection, task_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM writeup_repro_patterns WHERE report_id = ?", (int(task_id),)
    ).fetchone()
    return dict(row) if row is not None else None


def _delete_recipe(conn: sqlite3.Connection, task: dict[str, Any]) -> None:
    conn.execute("DELETE FROM writeup_repro_recipes WHERE recipe_key = ?", (recipe_key(task),))
    tasks.link_recipe(conn, int(task["id"]), None)
    conn.commit()


def _delete_pattern(conn: sqlite3.Connection, task_id: int) -> None:
    conn.execute("DELETE FROM writeup_repro_patterns WHERE report_id = ?", (int(task_id),))
    conn.commit()


# ---------------------------------------------------------------- 查询

def list_recipes(
    conn: sqlite3.Connection,
    *,
    fingerprint: str | None = None,
    degraded: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    where: list[str] = []
    params: list[Any] = []
    if fingerprint:
        where.append("fingerprint_json LIKE ?")
        params.append(f'%"{str(fingerprint).strip()}"%')
    if degraded is not None:
        where.append("degraded = ?")
        params.append(1 if degraded else 0)
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM writeup_repro_recipes{clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM writeup_repro_recipes{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        [*params, int(limit), int(offset)],
    ).fetchall()
    return [item for item in (_parse_recipe_row(row) for row in rows) if item], int(total)


def list_patterns(
    conn: sqlite3.Connection,
    *,
    fingerprint: str | None = None,
    generalization: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    where: list[str] = []
    params: list[Any] = []
    if fingerprint:
        where.append("fingerprint LIKE ?")
        params.append(f'%"{str(fingerprint).strip()}"%')
    if generalization:
        where.append("generalization = ?")
        params.append(str(generalization).strip().lower())
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM writeup_repro_patterns{clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM writeup_repro_patterns{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        [*params, int(limit), int(offset)],
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        try:
            item["fingerprint"] = json.loads(item.get("fingerprint") or "[]")
        except (TypeError, ValueError):
            item["fingerprint"] = []
        items.append(item)
    return items, int(total)


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    recipe = conn.execute("SELECT COUNT(*) FROM writeup_repro_recipes").fetchone()[0]
    degraded = conn.execute("SELECT COUNT(*) FROM writeup_repro_recipes WHERE degraded = 1").fetchone()[0]
    pattern = conn.execute("SELECT COUNT(*) FROM writeup_repro_patterns").fetchone()[0]
    sources = conn.execute(
        "SELECT COUNT(DISTINCT material_id) FROM writeup_repro_patterns"
    ).fetchone()[0]
    return {
        "recipes": int(recipe),
        "degraded_recipes": int(degraded),
        "patterns": int(pattern),
        "pattern_materials": int(sources),
    }


def _connect() -> sqlite3.Connection:
    from ai4sec_platform.db.session import connect

    return connect()
