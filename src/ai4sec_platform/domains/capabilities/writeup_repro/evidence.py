"""T3.3:证据包 —— 从会话 transcript 里抽, 不听 agent 自己复述。

为什么不信 agent 的报告
=======================

``===REPORT===`` 里那块 JSON 是 **agent 自己写的**, 而 agent 刚刚花半小时试图让攻击成功。
让它同时当运动员和裁判, 结果一定是"看起来都跑通了"。所以报告只当**线索**(它说了什么、
它认为哪条命令是 probe), 真正的证据从 **transcript 里 tool part 的实际命令与输出** 里抽:

- ``cmd``: 实际执行的命令文本;
- ``exit_code``: shell 真实退出码(transcript 的 ``state.metadata.exit``);
- ``stdout_sha1`` / ``stdout_tail``: 完整输出的指纹与尾部。

**"证据能独立复算"的定义**: 拿 ``cmd`` 在同一个环境重跑一遍, 输出的 sha1 应当相同
(或至少 ``stdout_tail`` 能对上)。不成立的证据就是不能用的证据 —— 所以这里宁可留
``matched=None``(证据不足), 也不把"agent 说它命中了"翻译成命中。

判定信号由**平台**算, 不由 agent 填
==================================

``probe.success_signal`` 是 T2 校验过"机器可判"的那条判据(如 ``exit_code == 0`` /
``stdout 包含 uid=0``)。这里把它**解析成可执行的条件**, 再拿真实 exit_code 与 stdout
去跑一遍 —— agent 报告里的 ``probe_result.signal_matched`` 直接丢弃(保留在
``agent_claim`` 里, 只作对照)。

解析不出来(判据写得含糊)时返回 ``matched=None``: 那是 spec 的问题, 结果是
"证据不完整 → 最高 partial", 不是"成功"。
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Iterable

#: 每条命令保留的输出尾部长度。完整输出留在任务日志里; 证据包只留足够核对的一小段。
STDOUT_TAIL_CHARS = 2000
#: 证据包里的命令条数上限。长任务可能跑几百条, 只留尾部(最后的 probe 一定在里面)。
MAX_COMMANDS = 200

_EXIT_CLAUSE = re.compile(
    r"(?:exit[_\s]?code|returncode|return\s+code|退出码|返回码)\s*(==|!=|>=|<=|>|<)\s*(-?\d+)",
    re.I,
)
_CONTAINS_CLAUSE = re.compile(
    r"(?:stdout|stderr|标准输出|标准错误|输出|output)?\s*"
    r"(?:中包含|中包括|包含|含有|出现|includes?|contains?|匹配|matches?)\s*(?P<needle>.+)$",
    re.I,
)
#: 判据里连接多个子条件的词。
_CLAUSE_SPLIT = re.compile(r"\s*(?:且|并且|而且|\band\b|[;；])\s*", re.I)
#: 逗号**只有**后面紧跟判据关键词时才当分隔符 —— 否则 ``uid=0(root),gid=0(root)`` 这种
#: 待匹配串会被从中间切开, 判成"有子条件无法解析"。
_COMMA_SPLIT = re.compile(
    r"\s*[,，]\s*(?=(?:exit[_\s]?code|returncode|return\s+code|stdout|stderr|输出|标准输出|"
    r"标准错误|包含|含有|匹配|contains?|includes?|matches?))",
    re.I,
)


def _now() -> str:
    return f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


def text_sha1(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", "replace")).hexdigest()


def _tail(text: str, limit: int = STDOUT_TAIL_CHARS) -> str:
    out = str(text or "")
    return out if len(out) <= limit else "…\n" + out[-limit:]


# ---------------------------------------------------------------- transcript

def extract_commands(messages: Iterable[Any]) -> list[dict[str, Any]]:
    """从 opencode 会话消息里抽**真正执行过**的命令。

    只认 ``type=tool`` 且 ``tool=bash`` 的 part: 其余工具(read/write/edit)不产生可复算的
    执行证据。``state.output`` 在命令还在跑时是增量的, 这里取那一刻的快照 —— 调用方应在
    会话结束后再调一次。
    """
    rows: list[dict[str, Any]] = []
    for message in messages or []:
        if not isinstance(message, dict):
            continue
        for part in message.get("parts") or []:
            if not isinstance(part, dict) or part.get("type") != "tool":
                continue
            if str(part.get("tool") or "") != "bash":
                continue
            state = part.get("state") if isinstance(part.get("state"), dict) else {}
            command = str((state.get("input") or {}).get("command") or "").strip()
            if not command:
                continue
            output = str(state.get("output") or "")
            exit_code = (state.get("metadata") or {}).get("exit")
            rows.append({
                "cmd": command,
                "exit_code": int(exit_code) if isinstance(exit_code, (int, float)) else None,
                "stdout_sha1": text_sha1(output),
                "stdout_tail": _tail(output),
                "stdout_chars": len(output),
                "completed": exit_code is not None,
                # 完整输出只在本模块内部用来跑判据; build_evidence 落库前会把它剥掉。
                "stdout": output,
            })
    if len(rows) > MAX_COMMANDS:
        rows = rows[-MAX_COMMANDS:]
    return rows


# ---------------------------------------------------------------- probe

def _clean_needle(raw: str) -> tuple[str, bool]:
    """返回 (待匹配串, 是否正则)。去掉引号/反引号; ``/.../`` 视为正则。"""
    needle = str(raw or "").strip().strip("`\"'“”‘’ ")
    if len(needle) >= 2 and needle.startswith("/") and needle.endswith("/"):
        return needle[1:-1], True
    return needle, False


def _clauses(signal: str) -> list[str]:
    out: list[str] = []
    for chunk in _CLAUSE_SPLIT.split(str(signal or "").strip()):
        out.extend(_COMMA_SPLIT.split(chunk))
    return [c for c in out if c.strip()]


def evaluate_signal(signal: str, exit_code: int | None, stdout: str) -> dict[str, Any]:
    """把 ``probe.success_signal`` 解析成条件, 用真实 exit_code / stdout 跑一遍。

    ``matched``: ``True`` 全中 / ``False`` 有未满足 / ``None`` 判据解析不出来(证据不足)。
    """
    text = str(signal or "").strip()
    clauses = _clauses(text)
    checks: list[dict[str, Any]] = []
    unparsed: list[str] = []
    for clause in clauses:
        exit_match = _EXIT_CLAUSE.search(clause)
        if exit_match:
            op, raw = exit_match.group(1), int(exit_match.group(2))
            ok = _compare(exit_code, op, raw)
            checks.append({"clause": clause.strip(), "kind": "exit_code", "op": op,
                           "expected": raw, "actual": exit_code, "ok": ok})
            continue
        contains_match = _CONTAINS_CLAUSE.search(clause)
        if contains_match:
            needle, is_regex = _clean_needle(contains_match.group("needle"))
            if not needle:
                unparsed.append(clause.strip())
                continue
            haystack = str(stdout or "")
            if is_regex:
                try:
                    ok = re.search(needle, haystack, re.S) is not None
                except re.error:
                    unparsed.append(clause.strip())
                    continue
            else:
                ok = needle in haystack
            checks.append({"clause": clause.strip(), "kind": "output_contains",
                           "needle": needle, "regex": is_regex, "ok": bool(ok)})
            continue
        unparsed.append(clause.strip())

    if not checks:
        return {"matched": None, "checks": [], "unparsed": unparsed,
                "why": "判据解析不出来, 无法机器判定"}
    matched = all(c["ok"] for c in checks) and not unparsed
    return {
        "matched": bool(matched),
        "checks": checks,
        "unparsed": unparsed,
        "why": "" if matched else ("有子条件未满足" if not all(c["ok"] for c in checks) else "有子条件无法解析"),
    }


def _compare(actual: Any, op: str, expected: int) -> bool:
    if actual is None:
        return False
    try:
        value = int(actual)
    except (TypeError, ValueError):
        return False
    return {
        "==": value == expected, "!=": value != expected,
        ">": value > expected, "<": value < expected,
        ">=": value >= expected, "<=": value <= expected,
    }.get(op, False)


def _norm_cmd(text: str) -> str:
    return " ".join(str(text or "").split()).lower()


def find_probe_command(commands: list[dict[str, Any]], probe_cmd: str) -> dict[str, Any] | None:
    """在真实执行记录里找到 probe 那一条。

    先找"执行记录包含 spec 的 probe.cmd"(模型通常会把命令原样跑一遍), 再反向找
    "probe.cmd 包含执行记录里的那条命令"(spec 可能写得更完整, 比如加了管道)。都没有
    就返回 ``None`` —— **不要拿最后一条命令顶替**: 那会把"跑了个 ls"当成 probe。

    **同一条命令跑了多次时取最后一次**(2026-11-12 真跑暴露)。agent 为了对齐环境常常会
    先试一次(换 Python 版本、加不加 timeout), 再按 spec 跑一次正式的; 取第一次等于拿
    "环境还没对齐时的结果"下结论 —— 实测第一次在 3.11.2 上是 SIGSEGV、没有
    ``free(): invalid pointer``, 最后一次在 3.11.8 上才是原文那个 SIGABRT。最后一次是
    最终环境里的最终事实, 也是唯一能被"重跑同一条命令"复核的那一次。
    ``occurrences`` 一并落库, 让复核的人知道这条命令跑过几次。
    """
    wanted = _norm_cmd(probe_cmd)
    if not wanted:
        return None
    forward = [row for row in commands if wanted in _norm_cmd(row["cmd"])]
    if forward:
        found = dict(forward[-1])
        found["occurrences"] = len(forward)
        return found
    backward = [
        row for row in commands
        if len(_norm_cmd(row["cmd"])) >= 8 and _norm_cmd(row["cmd"]) in wanted
    ]
    if backward:
        found = dict(backward[-1])
        found["occurrences"] = len(backward)
        return found
    return None


# ---------------------------------------------------------------- 组装

def build_evidence(
    *,
    spec: dict[str, Any],
    report: dict[str, Any] | None,
    commands: list[dict[str, Any]],
    egress: dict[str, Any] | None = None,
    guard: dict[str, Any] | None = None,
    duration_seconds: int | None = None,
    tool_calls: int | None = None,
    extra_notes: Iterable[str] = (),
) -> dict[str, Any]:
    """把 transcript 里的执行记录 + 平台自己的判定, 拼成一份能被独立复核的证据包。

    ``report`` 原样放进 ``agent_claim``: 它是**当事方的陈述**, 不是证据。
    """
    spec = spec or {}
    probe_spec = spec.get("probe") if isinstance(spec.get("probe"), dict) else {}
    probe_cmd = str(probe_spec.get("cmd") or "")
    signal = str(probe_spec.get("success_signal") or "")

    reasons: list[str] = [str(n) for n in extra_notes if str(n).strip()]
    if not commands:
        reasons.append("会话里没有采集到任何已执行命令(agent 没动手, 或 transcript 已不可读)")

    found = find_probe_command(commands, probe_cmd)
    if found is None:
        probe_block: dict[str, Any] = {
            "spec_cmd": probe_cmd, "success_signal": signal, "found": False,
            "cmd": "", "exit_code": None, "stdout_sha1": "", "stdout_tail": "",
            "matched": None, "why": "执行记录里找不到 probe 命令, 无法核对",
        }
        reasons.append("找不到 probe 命令的实际执行记录")
    else:
        # 判据在**完整输出**上跑(只用尾部会把"输出包含"判漏), 落库只留指纹与尾部。
        judged = evaluate_signal(signal, found.get("exit_code"), str(found.get("stdout") or ""))
        probe_block = {
            "spec_cmd": probe_cmd, "success_signal": signal, "found": True,
            "cmd": found.get("cmd", ""), "exit_code": found.get("exit_code"),
            "stdout_sha1": found.get("stdout_sha1", ""),
            "stdout_tail": found.get("stdout_tail", ""),
            "matched": judged["matched"],
            "checks": judged["checks"],
            "why": judged.get("why", ""),
            # 同一条命令跑了几次; >1 时上面记的是**最后一次**。
            "occurrences": int(found.get("occurrences") or 1),
        }
        if judged["matched"] is None:
            reasons.append(f"probe 判据无法机器判定: {signal[:120]!r}")
        elif judged["matched"] is False:
            reasons.append("probe 判据未满足")

    if not report:
        reasons.append("agent 没有输出结构化报告")

    # 完整输出不落证据包(一条命令的 stdout 可以有几十 MB); 指纹 + 尾部足够复核。
    public_commands = [
        {key: value for key, value in row.items() if key != "stdout"} for row in commands
    ]
    return {
        "version": 1,
        "collected_at": _now(),
        "commands": public_commands,
        "probe": probe_block,
        "egress": egress or {},
        "guard": guard or {},
        "agent_claim": report or {},
        "duration_seconds": duration_seconds,
        "tool_calls": tool_calls if tool_calls is not None else len(commands),
        "incomplete": bool(reasons),
        "incomplete_reasons": list(dict.fromkeys(reasons)),
    }


def evidence_gaps(evidence: dict[str, Any]) -> list[str]:
    """判定层要的"证据缺了什么"。空列表 = 证据齐全, 才允许判 success。"""
    reasons: list[str] = list((evidence or {}).get("incomplete_reasons") or [])
    probe = (evidence or {}).get("probe") or {}
    if not probe.get("found"):
        reasons.append("没有 probe 的执行记录")
    elif probe.get("matched") is not True:
        reasons.append("probe 未命中或无法判定")
    return list(dict.fromkeys(reasons))
