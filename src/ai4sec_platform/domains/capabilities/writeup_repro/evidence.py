"""T3.3:证据包 —— 从会话 transcript 里抽, 不听 agent 自己复述。

为什么不信 agent 的报告
=======================

``===REPORT===`` 里那块 JSON 是 **agent 自己写的**, 而 agent 刚刚花半小时试图让攻击成功。
让它同时当运动员和裁判, 结果一定是"看起来都跑通了"。所以报告只当**线索**(它说了什么、
它认为哪条命令是 probe), 真正的证据从 **transcript 里 tool part 的实际命令与输出** 里抽:

- ``cmd``: 实际执行的命令文本;
- ``exit_code``: 那条 shell 命令的退出码(transcript 的 ``state.metadata.exit``)。**注意它不等于
  probe 的退出码** —— agent 在尾巴加一句 ``echo`` 就把 0 顶上去了, 所以判定前要走
  :func:`probe_exit_status` 还原(见下);
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
#: 「有没有输出」这类判据判的是**长度**, 不是匹配某个串 —— 它同样是机器可判的, 所以必须认。
#: 2026-11-16 task #4 的实况: 判据写成 ``stdout 非空且包含 backdoor.php``, 前半句解析不出来,
#: 整组按"有子条件无法解析"判成不成立 —— 可 ``find /`` 明明找到了 ``/backdoor.php``,
#: 于是一次真的复现被记成 partial/probe_not_matched。
_EMPTY_CLAUSE = re.compile(
    r"(?:stdout|stderr|标准输出|标准错误|输出|output)\s*"
    r"(?P<neg>非空|不为空|不空|有内容|有输出|not\s+empty|non-?empty"
    r"|为空|是空的|没有输出|无输出|empty)",
    re.I,
)
#: 判"输出为空"的那几种写法。其余一律按"非空"。
_EMPTY_WORDS = frozenset({"为空", "是空的", "没有输出", "无输出", "empty"})
#: 「输出整段等于某个值」—— ``curl -s -o /dev/null -w '%{http_code}'`` 只有一行 ``200``,
#: 判据自然写成 ``stdout 等于 200``。这是**精确**比较(去掉首尾空白后整段相比),
#: 不做子串包含: 那正是 ``包含`` 与 ``等于`` 的区别, 混起来会把 ``2001`` 认成 ``200``。
_EQUALS_CLAUSE = re.compile(
    r"(?:stdout|stderr|标准输出|标准错误|输出|output)\s*(?:==|=|等于|equals?|为|是)\s*(?P<needle>.+)$",
    re.I,
)
#: 判据里连接多个子条件的词(且)。
_CLAUSE_SPLIT = re.compile(r"\s*(?:且|并且|而且|\band\b|[;；])\s*", re.I)
#: 判据里表示"任一满足即可"的词(或)。**AND 结合更紧**, 先按它切组, 再在组内按 AND 切。
#: 只认词, 不认 ``|`` —— 竖线是正则里的"或", 切了就把 ``/a|b/`` 拆坏。
#: 后面必须紧跟一个新的子条件(与逗号那条同一道理): ``stdout 包含 成功或失败`` 里的"或"
#: 是待匹配串的一部分, 不是分隔符。
_ALT_SPLIT = re.compile(
    r"\s*(?:或者|或|\bor\b)\s*(?=(?:exit[_\s]?code|returncode|return\s+code|stdout|stderr|"
    r"输出|标准输出|标准错误|包含|含有|匹配|contains?|includes?|matches?))",
    re.I,
)
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


def _clause_groups(signal: str) -> list[list[str]]:
    """判据 → ``[[子条件, ...], ...]``, **组内是"且", 组间是"或"**。

    ``且`` 结合更紧, 所以先按 ``或`` 切组, 再在组内按 ``且`` 切。
    同一件事可以有多种等价观测(同一个洞在 glibc 2.35 报 ``free(): invalid pointer``、
    在 2.36 只报 ``Segmentation fault``), 写成 ``A 或 B`` 时任一成立即算成立 ——
    否则结论会被绑死在某台机器的措辞上(2026-11-12 task #2 的实况)。
    """
    groups: list[list[str]] = []
    for alternative in _ALT_SPLIT.split(str(signal or "").strip()):
        out: list[str] = []
        for chunk in _CLAUSE_SPLIT.split(alternative):
            out.extend(_COMMA_SPLIT.split(chunk))
        group = [c for c in out if c.strip()]
        if group:
            groups.append(group)
    return groups


def _judge_clause(clause: str, exit_code: int | None, stdout: str, *,
                  exit_code_known: bool) -> dict[str, Any] | None:
    """一条子条件 → check; 解析不出来返回 ``None``。"""
    exit_match = _EXIT_CLAUSE.search(clause)
    if exit_match:
        op, raw = exit_match.group(1), int(exit_match.group(2))
        check: dict[str, Any] = {"clause": clause.strip(), "kind": "exit_code", "op": op,
                                 "expected": raw, "actual": exit_code, "ok": _compare(exit_code, op, raw)}
        if not exit_code_known:
            check["actual"] = None
            check["ok"] = None
        return check
    empty_match = _EMPTY_CLAUSE.search(clause)
    if empty_match:
        word = " ".join(empty_match.group("neg").split()).lower()
        text = str(stdout or "").strip()
        want_empty = word in _EMPTY_WORDS
        return {"clause": clause.strip(),
                "kind": "output_empty" if want_empty else "output_nonempty",
                "chars": len(text),
                "ok": (not text) if want_empty else bool(text)}
    equals_match = _EQUALS_CLAUSE.search(clause)
    if equals_match:
        needle, is_regex = _clean_needle(equals_match.group("needle"))
        if not needle:
            return None
        haystack = str(stdout or "").strip()
        if is_regex:
            try:
                ok = re.fullmatch(needle, haystack, re.S) is not None
            except re.error:
                return None
        else:
            ok = haystack == needle.strip()
        return {"clause": clause.strip(), "kind": "output_equals",
                "needle": needle, "regex": is_regex, "ok": bool(ok)}
    contains_match = _CONTAINS_CLAUSE.search(clause)
    if contains_match:
        needle, is_regex = _clean_needle(contains_match.group("needle"))
        if not needle:
            return None
        haystack = str(stdout or "")
        check: dict[str, Any] = {"clause": clause.strip(), "kind": "output_contains",
                                 "needle": needle, "regex": is_regex}
        if is_regex:
            try:
                ok = re.search(needle, haystack, re.S) is not None
            except re.error:
                return None
            if not ok and _is_line_anchored(needle):
                # 锚定判据(``^0$`` 这类)按行再试一次。agent 常把 probe 嵌进复合命令,
                # 整段 stdout 里混着回显, 锚在串首尾的正则必然不中 —— 而那一行事实是
                # 真的(实测: filelock 把 victim 文件截成 0 字节, 判据 ``^0$`` 却判不过)。
                # **这是放宽, 必须留痕**: 命中时记 ``anchored_line_fallback``, 复核的人
                # 能看出这次不是整段匹配出来的。
                try:
                    hit = next(
                        (line for line in haystack.splitlines()
                         if re.search(needle, line, re.S) is not None),
                        None,
                    )
                except re.error:
                    hit = None
                if hit is not None:
                    ok = True
                    check["anchored_line_fallback"] = True
                    check["matched_line"] = hit.strip()[:200]
        else:
            ok = needle in haystack
        check["ok"] = bool(ok)
        return check
    return None


def evaluate_signal(signal: str, exit_code: int | None, stdout: str, *,
                    exit_code_known: bool = True) -> dict[str, Any]:
    """把 ``probe.success_signal`` 解析成条件, 用真实 exit_code / stdout 跑一遍。

    ``matched``: ``True`` 有一个"或"组全中 / ``False`` 所有组都不成立 / ``None`` 判据解析不出来,
    或**退出码本身判不了**(``exit_code_known=False``, 见 :func:`probe_exit_status`) —— 证据不足,
    不是失败。

    ``或`` 组之间的判定顺序: 只要有一组成立就是 ``True``(哪怕另一组因为退出码不可知而无法判定);
    没有成立但有一组判不了才是 ``None``。
    """
    groups = _clause_groups(signal)
    checks: list[dict[str, Any]] = []
    unparsed: list[str] = []
    results: list[bool | None] = []
    for index, clauses in enumerate(groups):
        group_checks: list[dict[str, Any]] = []
        group_unparsed: list[str] = []
        for clause in clauses:
            check = _judge_clause(clause, exit_code, stdout, exit_code_known=exit_code_known)
            if check is None:
                group_unparsed.append(clause.strip())
                continue
            check["group"] = index
            group_checks.append(check)
        checks.extend(group_checks)
        unparsed.extend(group_unparsed)
        if not group_checks:
            results.append(None)                       # 整组都解析不出来
        elif any(c["ok"] is None for c in group_checks):
            results.append(None)                       # 退出码判不了
        elif group_unparsed:
            results.append(False)                      # 有子条件无法解析 → 这组不成立(与旧口径一致)
        else:
            results.append(all(c["ok"] for c in group_checks))

    if not checks and not unparsed:
        return {"matched": None, "checks": [], "unparsed": [],
                "why": "判据解析不出来, 无法机器判定"}
    if any(r is True for r in results):
        matched: bool | None = True
    elif any(r is None for r in results):
        matched = None
    else:
        matched = False

    if matched is True:
        why = ""
    elif matched is None:
        unknown_exit = any(c["ok"] is None for c in checks)
        why = ("退出码无法确定(probe 后面还有别的语句), 不能拿外层 shell 的退出码代替"
               if unknown_exit else "判据解析不出来, 无法机器判定")
    elif unparsed and all(c["ok"] for c in checks):
        why = "有子条件无法解析"
    else:
        why = "有子条件未满足"
    return {"matched": matched, "checks": checks, "unparsed": unparsed, "why": why}


def unparsed_clauses(signal: str) -> list[str]:
    """判据里**解析器看不懂**的子条件(空列表 = 每个子条件都能机器判定)。

    给 spec 校验用。``spec._is_machine_checkable`` 只查有没有关键词, 比解析器宽; 判据里只要
    有一个子条件解析不了, 那一组"或"就永远不成立 —— 等到跑完才判成 partial, 一次复现已经烧掉
    (2026-11-16 task #4)。所以校验时就把它挑出来, 写进 notes 让人在跑之前看见。
    """
    return list(evaluate_signal(signal, 0, "")["unparsed"])


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


def _is_line_anchored(pattern: str) -> bool:
    """判据正则是否"整段锚定"—— 以 ``^``/``\\A`` 开头或以 ``$``/``\\Z`` 结尾。

    只有这类才有"按行再试一次"的意义: 非锚定的正则本来就该在整个输出里找, 逐行重试只会
    把同一件事做两遍; 而锚定的正则碰到复合命令的回显就必然失效。
    """
    body = pattern.strip()
    return body.startswith(("^", r"\A")) or body.endswith(("$", r"\Z"))


def _norm_cmd(text: str) -> str:
    return " ".join(str(text or "").split()).lower()


def _tokens(text: str) -> list[str]:
    """按空白切成 token, 小写。只用于"同一条命令被加了参数"这一种比对。"""
    return [tok for tok in _norm_cmd(text).split() if tok]


def _is_subsequence(wanted: list[str], have: list[str]) -> bool:
    """``wanted`` 的每个 token 是否按原顺序出现在 ``have`` 里(允许多出来的 token)。

    agent 几乎不会一字不差地照抄 probe: 实测会给 curl 补 ``--max-time 15``、给 pip 补
    ``-q``。这种改动不改变"它确实执行了这条 probe"这个事实, 字面包含却会判成没跑过。
    """
    cursor = iter(have)
    return all(any(tok == item for item in cursor) for tok in wanted)


def _subsequence_candidates(commands: list[dict[str, Any]], wanted: list[str]) -> list[dict[str, Any]]:
    """字面匹配失败后的第二档: token 顺序子序列。

    **门槛刻意设得很硬**, 因为放宽匹配等于放宽证据:

    - probe 至少 4 个 token, 且至少一个 token 长于 8 字符(URL / 路径这种锚点)——
      ``ls -la`` 这种短命令永远不会靠这一档命中;
    - 反过来不要求"执行记录被 probe 包含": 那会退化成"跑了个前缀就认"。
    """
    if len(wanted) < 4 or not any(len(tok) >= 8 for tok in wanted):
        return []
    return [row for row in commands if _is_subsequence(wanted, _tokens(row["cmd"]))]


#: probe 里常见的占位符主机。agent 执行时必然把它们换成本地地址, 于是字面/子序列都断掉
#: (2026-11-19 实测: probe 写 ``http://TARGET:8080/deserialize``, agent 跑的是
#: ``http://127.0.0.1:8080/deserialize``, 判成"没跑过 probe")。
_PLACEHOLDER_WORDS = (
    "target", "victim", "host", "server", "rhost", "lhost", "yourtarget", "your-host",
    "remote_host", "remote-host",
)
_URL_PREFIX = re.compile(r"\b(?:https?|wss?)://", re.I)
#: URL(含 scheme 与主机), 遮主机时用; 判断"有没有占位符"时不看它。
_URL_TOKEN = re.compile(r"\b(?:https?|wss?)://[^\s'\"]+", re.I)
#: 真正的占位符写法: ``TARGET`` / ``target.local`` / ``TARGET:8080`` / ``<target_ip>``。
_PLACEHOLDER_TOKEN = re.compile(
    r"(?:<)?" + r"\b(?:" + "|".join(_PLACEHOLDER_WORDS) + r")\b[\w.\-]*(?::\d+)?(?:>)?",
    re.I,
)
_MASK_TOKEN = re.compile(_URL_TOKEN.pattern + "|" + _PLACEHOLDER_TOKEN.pattern, re.I)


def has_placeholder(text: str) -> bool:
    """这段文本里有没有占位符主机/URL —— 有才值得走"遮掉主机再比"这一档。"""
    return bool(_PLACEHOLDER_TOKEN.search(str(text or "")))


def mask_hosts(text: str) -> str:
    """把命令里的 **URL 与占位符主机** 统一换成 ``<HOST>``, 保留路径与参数。

    只遮主机, 不遮路径: "打的是哪个地址"在复现里不重要(都应该是本地实例), "打了哪个端点、
    带什么参数"才是这条 probe 的身份。
    """
    def _repl(match: re.Match[str]) -> str:
        whole = match.group(0)
        prefix = _URL_PREFIX.match(whole)
        if prefix:
            # 保留 scheme 与端口之后的部分
            rest = whole[prefix.end():]
            tail = ""
            slash = rest.find("/")
            if slash >= 0:
                tail = rest[slash:]
            return "%s__HOST__%s" % (prefix.group(0), tail)
        return "__HOST__"

    masked = _MASK_TOKEN.sub(_repl, str(text or ""))
    # 端口也遮: agent 按提示用 8101~8199 的空闲端口, 与 spec 里写的 8080 对不上是常态。
    # 主机在同一台机器上, 端口不同不改变"打的是哪个端点"。
    masked = re.sub(r"(__HOST__):\d+", r"\1", masked)
    # 载荷参数的写法在 curl 里可以互换(-d / --data / --data-urlencode / --data-binary …),
    # 对"这条 probe 打的是什么"没有影响。
    masked = re.sub(r"(?:^|(?<=\s))(?:-d|--data|--data-raw|--data-binary|--data-urlencode|-F|--form)(?=\s|$)",
                    "--data", masked)
    return masked


def _is_placeholder_token(token: str) -> bool:
    """``data=<BASE64_PAYLOAD>`` 这种: 尖括号里的内容在执行时必然被替换, 只能当通配符。"""
    return "<" in token and ">" in token


def _is_wild_subsequence(wanted: list[str], have: list[str]) -> bool:
    """占位符 token 匹配任意一个 token, 其余按顺序精确比对。

    ``http://__HOST__:8080/deserialize`` 里的 ``__HOST__`` 是**字面哨兵**, 不是占位符 —— 主机
    被遮掉, 端点与端口仍要一致; 只有 ``<...>`` 才是"随便填"。
    """
    cursor = iter(have)
    for token in wanted:
        if _is_placeholder_token(token):
            if next(cursor, None) is None:
                return False
            continue
        if not any(item == token for item in cursor):
            return False
    return True


def _placeholder_candidates(commands: list[dict[str, Any]], probe_cmd: str) -> list[dict[str, Any]]:
    """第三档: 遮掉主机之后再做 token 子序列。

    门槛比上一档更硬 —— 必须**同时**满足: probe 本身带占位符(否则没有遮的理由)、遮完
    仍有 ≥4 个 token 且至少一个 ≥8 字符锚点(路径/参数)。
    """
    if not has_placeholder(probe_cmd):
        return []
    wanted = _tokens(mask_hosts(probe_cmd))
    if len(wanted) < 4 or not any(len(tok) >= 8 for tok in wanted):
        return []
    return [row for row in commands if _is_wild_subsequence(wanted, _tokens(mask_hosts(row["cmd"])))]


def find_probe_command(commands: list[dict[str, Any]], probe_cmd: str) -> dict[str, Any] | None:
    """在真实执行记录里找到 probe 那一条。

    先找"执行记录包含 spec 的 probe.cmd"(模型通常会把命令原样跑一遍), 再反向找
    "probe.cmd 包含执行记录里的那条命令"(spec 可能写得更完整, 比如加了管道), 最后放宽到
    **token 顺序子序列**(agent 给命令补了 ``--max-time`` 之类参数)。都没有就返回 ``None``
    —— **不要拿最后一条命令顶替**: 那会把"跑了个 ls"当成 probe。

    **同一条命令跑了多次时取最后一次**(2026-11-12 真跑暴露)。agent 为了对齐环境常常会
    先试一次(换 Python 版本、加不加 timeout), 再按 spec 跑一次正式的; 取第一次等于拿
    "环境还没对齐时的结果"下结论 —— 实测第一次在 3.11.2 上是 SIGSEGV、没有
    ``free(): invalid pointer``, 最后一次在 3.11.8 上才是原文那个 SIGABRT。最后一次是
    最终环境里的最终事实, 也是唯一能被"重跑同一条命令"复核的那一次。
    ``occurrences`` 一并落库, 让复核的人知道这条命令跑过几次;
    ``match`` 记命中的是哪一档(``substring`` / ``reverse`` / ``tokens`` / ``placeholder``),
    复核时能看出这次结论建立在多宽松的匹配上。``placeholder`` = spec 写的是 ``TARGET`` 这类
    占位符、agent 换成本地地址执行 —— 遮掉主机后按路径与参数比对。
    """
    wanted = _norm_cmd(probe_cmd)
    if not wanted:
        return None
    forward = [row for row in commands if wanted in _norm_cmd(row["cmd"])]
    if forward:
        found = dict(forward[-1])
        found["occurrences"] = len(forward)
        found["match"] = "substring"
        return found
    backward = [
        row for row in commands
        if len(_norm_cmd(row["cmd"])) >= 8 and _norm_cmd(row["cmd"]) in wanted
    ]
    if backward:
        found = dict(backward[-1])
        found["occurrences"] = len(backward)
        found["match"] = "reverse"
        return found
    tokens = _subsequence_candidates(commands, _tokens(probe_cmd))
    if tokens:
        found = dict(tokens[-1])
        found["occurrences"] = len(tokens)
        found["match"] = "tokens"
        return found
    masked = _placeholder_candidates(commands, probe_cmd)
    if masked:
        found = dict(masked[-1])
        found["occurrences"] = len(masked)
        found["match"] = "placeholder"
        return found
    return None


# ---------------------------------------------------------------- 退出码

#: agent 在命令尾巴上把退出码打印出来的常见写法。只认这些标签 —— 它们约定俗成指"这条命令的
#: 退出码"; ``status=`` / ``ELAPSED_MS=`` 之类不收, 那更像被测程序自己的输出, 拿去当退出码
#: 会把 2225 毫秒读成"退出了 2225"。
_PRINTED_EXIT_LABELS = {"EXIT", "EXIT_CODE", "EXITCODE", "PROBE_EXIT", "POC_EXIT", "RETURNCODE", "RC"}
#: 「<谁>_EXIT」是同一件事的另一种写法(2026-11-13 task #3 实测打的是 ``POC_EXIT=134``)。
#: 只认**后缀**: 前缀随便(poc/target/build), 但整词必须落在退出码语义上 —— ``_RET`` 这种
#: 过于泛化的缩写不收, ``EXIT_CODE_ELAPSED`` 这种"以退出码开头"的也不收。
_PRINTED_EXIT_SUFFIXES = ("_EXIT", "_EXIT_CODE", "_EXITCODE", "_RETURNCODE")
_ECHO_LABEL_RE = re.compile(
    r"echo\s+(?:-e\s+)?[\"']?\s*(?P<label>[A-Za-z_][A-Za-z0-9_]*)\s*=", re.I
)


def _is_printed_exit_label(label: str) -> bool:
    """这个 ``echo LABEL=…`` 打印的是不是"刚跑的那条命令的退出码"。"""
    return label in _PRINTED_EXIT_LABELS or label.endswith(_PRINTED_EXIT_SUFFIXES)
#: 切语句的口径与 ``guard._segments`` 一致(``;`` ``&&`` ``||`` ``|`` 与换行)。
_SEGMENT_SPLIT = re.compile(r"(\n|;|&&|\|\||\|)")
#: 循环/分支的收尾词: 它们不是"又跑了一条命令", 后面的东西不覆盖退出码。
_STRUCTURAL_SEGMENTS = {"done", "fi", "esac", "}", "})", ")", "end"}


def _split_segments(cmd: str) -> list[tuple[str, str]]:
    """切成 ``[(前置分隔符, 语句), ...]`` —— 分隔符本身有用(见 :func:`probe_exit_status`)。"""
    out: list[tuple[str, str]] = []
    separator = ""
    for piece in _SEGMENT_SPLIT.split(str(cmd or "")):
        if piece in ("\n", ";", "&&", "||", "|"):
            separator = piece
            continue
        if piece.strip():
            out.append((separator, piece))
        separator = ""
    return out


def _echoed_exit_labels(segments: Iterable[str]) -> list[str]:
    labels: list[str] = []
    for segment in segments or []:
        for match in _ECHO_LABEL_RE.finditer(str(segment or "")):
            label = match.group("label").upper()
            if _is_printed_exit_label(label) and label not in labels:
                labels.append(label)
    return labels


def _printed_value(stdout: str, label: str) -> int | None:
    """输出里 ``LABEL=<整数>`` 的**最后一次**出现(同一条命令跑多遍时以最后一遍为准)。

    ``\\b`` 边界很重要: 找 ``EXIT`` 时不能命中 ``PROBE_EXIT=134``。
    """
    hit = None
    for match in re.finditer(rf"(?i)\b{label}\b\s*=\s*(-?\d+)", str(stdout or "")):
        hit = match
    return int(hit.group(1)) if hit else None


def probe_exit_status(cmd: str, shell_exit: int | None, stdout: str,
                      probe_cmd: str = "") -> dict[str, Any]:
    """probe 那条命令**自己的**退出码, 而不是 agent 那整条 shell 命令的。

    为什么要这一步(2026-11-12 重跑真跑暴露): ``shell_exit`` 是整条 shell 的退出码。agent 习惯
    写成 ``poc.py 2>&1 | tee log; echo "EXIT=${PIPESTATUS[0]}"`` —— 这时 shell 的退出码是末尾
    那条 ``echo`` 的(**恒为 0**), 被测进程其实是 139。拿 0 去跑 ``exit_code == 0`` 等于把
    "崩溃了"判成"成功"; 反过来, 只知道后面还有语句却读不到真值, 也不能当失败 —— 那是证据不足。

    返回 ``exit_code`` / ``known`` / ``source``:

    - ``shell``: probe 就是最后一段(或在循环体里, 后面只剩 ``done``), shell 退出码可信;
    - ``printed``: 从输出里读回 agent 自己打印的退出码(``EXIT=139`` / ``PROBE_EXIT=$?`` /
      ``POC_EXIT=134``);
    - ``unknown``: 后面还有别的语句, 输出里也没有打印 —— **判不了**, 不是 0。

    ``A && B`` 是唯一能"白拿"的例外: shell 退出码是 0 就说明 A 一定成功过(否则 B 跑不起来),
    非 0 则归不到 A 头上。
    """
    segments = _split_segments(cmd)
    wanted = _norm_cmd(probe_cmd)
    hits = [i for i, (_, segment) in enumerate(segments)
            if wanted and wanted in _norm_cmd(segment)]
    if not hits:
        # 定位不到是哪一段: 沿用 shell 退出码(旧行为), 至少不比原来更差。
        return {"exit_code": shell_exit, "known": shell_exit is not None, "source": "shell"}
    index = hits[-1]
    tail = [i for i in range(index + 1, len(segments))
            if _norm_cmd(segments[i][1]) not in _STRUCTURAL_SEGMENTS]
    if not tail:
        return {"exit_code": shell_exit, "known": shell_exit is not None, "source": "shell"}
    if shell_exit == 0 and all(segments[i][0] == "&&" for i in tail):
        return {"exit_code": 0, "known": True, "source": "shell"}
    for label in reversed(_echoed_exit_labels(segment for _, segment in segments[index:])):
        value = _printed_value(stdout, label)
        if value is not None:
            return {"exit_code": value, "known": True, "source": "printed"}
    return {"exit_code": None, "known": False, "source": "unknown"}


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
            "cmd": "", "exit_code": None, "shell_exit_code": None, "exit_code_source": "",
            "stdout_sha1": "", "stdout_tail": "",
            "matched": None, "why": "执行记录里找不到 probe 命令, 无法核对",
        }
        reasons.append("找不到 probe 命令的实际执行记录")
    else:
        stdout_full = str(found.get("stdout") or "")
        # 先弄清"probe 这条命令自己的退出码"。agent 常在尾巴加 `; echo ...`, 那时 shell 退出码
        # 是 echo 的(恒 0), 直接拿来跑 `exit_code == 0` 会把崩溃判成成功。
        stage_exit = probe_exit_status(
            str(found.get("cmd") or ""), found.get("exit_code"), stdout_full, probe_cmd,
        )
        # 判据在**完整输出**上跑(只用尾部会把"输出包含"判漏), 落库只留指纹与尾部。
        judged = evaluate_signal(signal, stage_exit["exit_code"], stdout_full,
                                 exit_code_known=bool(stage_exit["known"]))
        probe_block = {
            "spec_cmd": probe_cmd, "success_signal": signal, "found": True,
            "cmd": found.get("cmd", ""),
            # probe 自己的退出码; 与 agent 那条 shell 命令的退出码不同时, 后者单独记。
            "exit_code": stage_exit["exit_code"],
            "shell_exit_code": found.get("exit_code"),
            "exit_code_source": stage_exit["source"],
            "stdout_sha1": found.get("stdout_sha1", ""),
            "stdout_tail": found.get("stdout_tail", ""),
            "matched": judged["matched"],
            "checks": judged["checks"],
            "why": judged.get("why", ""),
            # 同一条命令跑了几次; >1 时上面记的是**最后一次**。
            "occurrences": int(found.get("occurrences") or 1),
            # 命中档次: substring / reverse / tokens。tokens = 执行记录里那条命令
            # 只是"按序含全部 token", agent 补过参数; 复核时据此知道匹配有多宽。
            "match": str(found.get("match") or "substring"),
        }
        if judged["matched"] is None:
            why = str(judged.get("why") or "")
            reasons.append(f"probe 判据无法机器判定: {why or signal[:120]!r}")
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
