"""T3:执行、证据包、安全边界。

这三块各有各的"看起来对、实际撒谎"的失败方式:

- **安全边界**松一格 ⇒ 平台替用户去打了一个别人的生产系统;
- **证据包**信 agent 的自述 ⇒ agent 说成功就成功, 报告写着 probe 命中, 实际命令退出码 1;
- **判定**把"没跑成"记成"原文不可复现" ⇒ 作者的稿子被平台的环境问题判死。

所以下面每条测试都对着一个具体的撒谎路径, 而不是对着函数签名。
"""
from __future__ import annotations

import sqlite3

import pytest

from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.writeup_repro import evidence, executor, guard, tasks


# ---------------------------------------------------------------- guard: 开跑前

def test_local_target_is_allowed() -> None:
    spec = {"steps": [{"run": "curl -s http://127.0.0.1:8000/admin"}], "probe": {"cmd": "curl -s http://localhost:8000/admin"}}
    result = guard.preflight({"target_kind": "oss_repo"}, spec)
    assert result.allowed is True
    assert result.reason == ""


def test_online_service_task_is_refused_even_before_spec() -> None:
    """T1 已经拦过一次; 人工建的任务 / 人改的 spec 也要过同一道闸。"""
    result = guard.preflight({"target_kind": "online_service"}, {"steps": []})
    assert result.allowed is False
    assert result.reason == "online_target"


def test_spec_pointing_at_a_real_public_site_is_refused() -> None:
    """spec 里的步骤要打一个公网站点 —— 不管它长得多像靶场, 都不开跑。"""
    spec = {"steps": [{"run": "curl -s -X POST https://shop.acme-prod.com/api/checkout -d qty=1"}]}
    result = guard.preflight({"target_kind": "oss_repo"}, spec)
    assert result.allowed is False
    assert "shop.acme-prod.com" in result.detail


def test_dependency_install_may_reach_the_internet() -> None:
    """装依赖本来就是出网, 拦掉它等于让所有复现都跑不起来。"""
    spec = {"steps": [{"run": "python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"}]}
    assert guard.preflight({"target_kind": "oss_repo"}, spec).allowed is True

    clone = {"steps": [{"run": "git clone https://github.com/acme/foo.git && cd foo"}]}
    assert guard.preflight({"target_kind": "oss_repo"}, clone).allowed is True


def test_install_and_attack_in_one_command_is_still_refused() -> None:
    """``pip install; curl victim`` 不能被前半段的 install 标签带走。"""
    spec = {"steps": [{"run": "pip install requests && curl -s https://shop.acme-prod.com/x"}]}
    assert guard.preflight({"target_kind": "oss_repo"}, spec).allowed is False


def test_private_network_is_treated_as_local_lab() -> None:
    """CTF/靶场常常是 10.x。整类判死会让这类素材全部误杀, 代价由作者承担。"""
    spec = {"steps": [{"run": "curl -s http://10.10.14.7:8080/index.php"}]}
    result = guard.preflight({"target_kind": "ctf"}, spec)
    assert result.allowed is True
    assert any("10.10.14.7" in note for note in result.notes)


def test_scanning_a_private_host_is_refused() -> None:
    """私有网段放行的是"照原文打一个确定的目标", 不是"扫一片内网"。"""
    spec = {"steps": [{"run": "nmap -p- 10.10.14.0/24"}]}
    assert guard.preflight({"target_kind": "ctf"}, spec).allowed is False


def test_placeholder_host_is_allowed_but_noted() -> None:
    spec = {"steps": [{"run": "curl http://TARGET:8080/admin"}]}
    result = guard.preflight({"target_kind": "oss_repo"}, spec)
    assert result.allowed is True


@pytest.mark.parametrize(
    "cmd, expected",
    [
        ("git clone https://github.com/acme/foo.git", "install"),
        ("git status", "other"),
        ("curl -s http://127.0.0.1:8000", "request"),
        ("curl -sO https://pypi.org/simple/", "download"),
        ("python3 exploit.py --target http://127.0.0.1:9000", "other"),
        ("go test ./...", "other"),
        ("nmap -sV 10.0.0.1", "request"),
        ("uv pip install -e .", "install"),
    ],
)
def test_command_classification(cmd: str, expected: str) -> None:
    assert guard.classify_command(cmd) == expected


def test_egress_audit_flags_real_requests_only() -> None:
    rows = [
        {"cmd": "pip install -r requirements.txt -i https://pypi.org/simple"},
        {"cmd": "git clone https://github.com/acme/foo.git"},
        {"cmd": "curl -s https://shop.acme-prod.com/api/checkout"},
        {"cmd": "curl -s http://127.0.0.1:8000/admin"},
    ]
    audit = guard.audit_egress(rows, {})
    assert audit["review_required"] is True
    assert audit["external_requests"] == ["shop.acme-prod.com"]
    assert "pypi.org" in audit["dependency_hosts"]
    assert "127.0.0.1" in audit["domains_accessed"]


def test_egress_audit_is_quiet_when_only_dependencies_were_used() -> None:
    audit = guard.audit_egress([{"cmd": "pip install -r requirements.txt"}], {})
    assert audit["review_required"] is False
    assert audit["external_requests"] == []


def test_filenames_are_not_hosts() -> None:
    """``main.py`` / ``v1.2.3`` 被当成域名的话, 每一次正常复现都会被判死。"""
    assert guard.extract_hosts("python3 main.py --config config.yaml") == []
    assert guard.extract_hosts("echo v1.2.3") == []


def test_shell_array_indexes_are_not_hosts() -> None:
    """``${PIPESTATUS[0]}`` 被抽成主机 "[0]" 的话, 证据包里会多一条无中生有的出网记录。

    2026-11-12 真跑里实际出现过: ``echo "EXIT_CODE=${PIPESTATUS[0]}"`` → 出网主机 ``[0]``。
    """
    assert guard.extract_hosts('echo "EXIT_CODE=${PIPESTATUS[0]}"') == []
    assert guard.extract_hosts("echo ${arr[0]}") == []
    audit = guard.audit_egress([{"cmd": 'echo "EXIT_CODE=${PIPESTATUS[0]}"'}], {})
    assert audit["domains_accessed"] == []
    assert audit["external_requests"] == []


def test_ipv6_literal_is_still_a_host() -> None:
    assert "::1" in [h.strip("[]") for h in guard.extract_hosts("curl -g http://[::1]:8080/x")]


# ---------------------------------------------------------------- evidence

def _messages(*parts: dict) -> list[dict]:
    return [{"info": {"role": "assistant"}, "parts": list(parts)}]


def _bash(cmd: str, output: str, exit_code: int | None = 0) -> dict:
    return {
        "type": "tool", "tool": "bash",
        "state": {"input": {"command": cmd}, "output": output, "metadata": {"exit": exit_code}},
    }


def test_extract_commands_reads_the_transcript_not_the_report() -> None:
    rows = evidence.extract_commands(_messages(
        _bash("id", "uid=0(root) gid=0(root)", 0),
        {"type": "text", "text": "我成功了"},
    ))
    assert len(rows) == 1
    assert rows[0]["cmd"] == "id"
    assert rows[0]["exit_code"] == 0
    assert rows[0]["stdout_sha1"] == evidence.text_sha1("uid=0(root) gid=0(root)")


def test_unfinished_commands_are_marked_not_completed() -> None:
    rows = evidence.extract_commands(_messages(_bash("./poc", "", None)))
    assert rows[0]["completed"] is False
    assert rows[0]["exit_code"] is None


@pytest.mark.parametrize(
    "signal, exit_code, stdout, expected",
    [
        ("exit_code == 0", 0, "", True),
        ("exit_code == 0", 1, "", False),
        ("stdout 包含 uid=0", 0, "uid=0(root) gid=0(root)", True),
        ("stdout 包含 uid=0", 0, "permission denied", False),
        ('exit_code == 0 且 stdout 包含 "root_shell"', 0, "root_shell acquired", True),
        ('exit_code == 0 且 stdout 包含 "root_shell"', 0, "nothing", False),
        ("stdout 包含 uid=0(root),gid=0(root)", 0, "uid=0(root),gid=0(root)", True),
        ("匹配 /uid=0\\(root\\)/", 0, "uid=0(root)", True),
        ("看起来成功了", 0, "", None),
    ],
)
def test_probe_signal_is_evaluated_by_the_platform(signal, exit_code, stdout, expected) -> None:
    assert evidence.evaluate_signal(signal, exit_code, stdout)["matched"] is expected


def test_find_probe_command_does_not_fall_back_to_the_last_command() -> None:
    """拿最后一条命令顶替 probe, 会把"跑了个 ls"当成命中判定。"""
    rows = evidence.extract_commands(_messages(
        _bash("./poc 127.0.0.1", "boom", 0),
        _bash("ls -la", "total 0", 0),
    ))
    assert evidence.find_probe_command(rows, "./poc 127.0.0.1 2>&1 | tee /tmp/out") is not None
    assert evidence.find_probe_command(rows, "curl -s http://127.0.0.1:8000/verify") is None


def test_repeated_probe_uses_the_last_execution() -> None:
    """同一条命令跑了多次取最后一次(2026-11-12 真跑 CVE-2024-21502 暴露)。

    第一次在系统 python3.11.2 上只是 SIGSEGV、没有原文那句 ``free(): invalid pointer``;
    换了 3.11.8 之后才复现出原文的 SIGABRT。取第一次 = 拿"环境还没对齐时"的结果下结论。
    """
    rows = evidence.extract_commands(_messages(
        _bash(".venv/bin/python3 -u poc.py 2>&1", "Segmentation fault", 139),
        _bash("ls", "out", 0),
        _bash(".venv/bin/python3 -u poc.py 2>&1", "free(): invalid pointer\nAborted", 134),
    ))
    found = evidence.find_probe_command(rows, "python3 -u poc.py 2>&1")
    assert found is not None
    assert found["exit_code"] == 134
    assert found["occurrences"] == 2
    assert evidence.evaluate_signal("stdout 包含 free(): invalid pointer",
                                    found["exit_code"], found["stdout"])["matched"] is True


def test_a_later_failing_run_wins_over_an_earlier_success() -> None:
    """反过来也一样: 最后一次没命中就是没命中, 不挑"历史上命中过的那一次"。"""
    rows = evidence.extract_commands(_messages(
        _bash("python3 poc.py", "free(): invalid pointer", 134),
        _bash("python3 poc.py", "permission denied", 1),
    ))
    found = evidence.find_probe_command(rows, "python3 poc.py")
    assert found["exit_code"] == 1
    assert evidence.evaluate_signal("stdout 包含 free(): invalid pointer",
                                    found["exit_code"], found["stdout"])["matched"] is False


# ---------------------------------------------------------------- 退出码还原
#
# agent 写命令几乎总带尾巴: `poc.py 2>&1 | tee log; echo "EXIT=${PIPESTATUS[0]}"`。
# 这时 transcript 记的 shell 退出码是**末尾 echo 的**(恒 0), 被测进程其实是 139。

def test_probe_at_the_end_uses_the_shell_exit_code() -> None:
    status = evidence.probe_exit_status(".venv/bin/python3 -u poc.py", 134, "boom", "python3 -u poc.py")
    assert status == {"exit_code": 134, "known": True, "source": "shell"}


def test_exit_code_swallowed_by_a_trailing_echo_is_recovered_from_the_output() -> None:
    """真跑 2026-11-13 的形态: 崩溃的进程 139, shell 报 0。"""
    cmd = ('cd /workspace/writeup-2 && .venv/bin/python3 -u poc.py 2>&1 | tee step3.log; '
           'echo "EXIT=${PIPESTATUS[0]}"')
    stdout = "X: 0x0\nY: 0x0\n(On curve <MyCurve>)\nEXIT=139\n"
    status = evidence.probe_exit_status(cmd, 0, stdout, "python3 -u poc.py 2>&1")
    assert status == {"exit_code": 139, "known": True, "source": "printed"}


def test_exit_code_printed_through_a_variable_is_recovered() -> None:
    """agent 常见的两跳写法: ``ec=$?`` 再 ``echo "EXIT_CODE=$ec"``。"""
    cmd = ("cd /w && timeout 60 .venv/bin/python3 -u poc.py 2>&1; ec=$?; "
           'echo "EXIT_CODE=$ec"; echo "ELAPSED_MS=2125"')
    status = evidence.probe_exit_status(cmd, 0, "free(): invalid pointer\nEXIT_CODE=134\n",
                                        "python3 -u poc.py 2>&1")
    assert status["exit_code"] == 134 and status["source"] == "printed"


def test_a_loop_tail_does_not_make_the_exit_code_unknown() -> None:
    """``for ...; do poc.py; done`` 的 shell 退出码就是最后一轮的, 后面没有别的命令。"""
    status = evidence.probe_exit_status(
        "for i in 1 2 3; do .venv/bin/python3 -u poc.py; done", 139, "Segmentation fault",
        "python3 -u poc.py",
    )
    assert status == {"exit_code": 139, "known": True, "source": "shell"}


def test_an_and_chain_with_zero_exit_still_proves_the_probe_succeeded() -> None:
    """``A && B`` 的 shell 退出码为 0 ⇒ A 一定成功过(否则 B 跑不起来); 非 0 则归不到 A 头上。"""
    ok = evidence.probe_exit_status("cd /w && ./poc && echo ok", 0, "boom\nok", "./poc")
    assert ok == {"exit_code": 0, "known": True, "source": "shell"}
    bad = evidence.probe_exit_status("cd /w && ./poc && echo ok", 5, "boom", "./poc")
    assert bad == {"exit_code": None, "known": False, "source": "unknown"}


def test_an_unprinted_exit_code_is_unknown_not_zero() -> None:
    """尾部有别的语句又没打印退出码 ⇒ 判不了。拿 wrapper 的 0 当成功是最坏的结果。"""
    status = evidence.probe_exit_status("python3 -u poc.py; echo done", 0, "boom\ndone",
                                        "python3 -u poc.py")
    assert status == {"exit_code": None, "known": False, "source": "unknown"}

    judged = evidence.evaluate_signal("exit_code == 0", status["exit_code"],
                                     "boom", exit_code_known=status["known"])
    assert judged["matched"] is None, "判不了 ≠ 命中, 也 ≠ 没命中"


def test_exit_signal_judged_unknown_caps_the_evidence_at_partial() -> None:
    spec = {"steps": [{"run": "python3 -u poc.py"}],
            "probe": {"cmd": "python3 -u poc.py", "success_signal": "exit_code == 0"}}
    commands = evidence.extract_commands(_messages(
        _bash("python3 -u poc.py; echo done", "boom\ndone", 0),
    ))
    collected = evidence.build_evidence(spec=spec, report={"self_verdict": "success"},
                                        commands=commands)
    assert collected["probe"]["exit_code"] is None
    assert collected["probe"]["shell_exit_code"] == 0
    assert collected["probe"]["exit_code_source"] == "unknown"
    assert collected["probe"]["matched"] is None
    assert collected["incomplete"] is True
    assert any("退出码" in reason for reason in collected["incomplete_reasons"])


# ---------------------------------------------------------------- 判据里的"或"
#
# 同一个洞在不同发行版/glibc 上崩溃形态不同: glibc 2.35 报 `free(): invalid pointer`(SIGABRT),
# 2.36 只报 `Segmentation fault`(SIGSEGV)。判据只写一种, 成功就会被判成 partial。

def test_any_alternative_is_enough() -> None:
    signal = "stdout 包含 free(): invalid pointer 或 stdout 包含 Segmentation fault"
    assert evidence.evaluate_signal(signal, 134, "free(): invalid pointer")["matched"] is True
    assert evidence.evaluate_signal(signal, 139, "Segmentation fault (core dumped)")["matched"] is True
    assert evidence.evaluate_signal(signal, 0, "all good")["matched"] is False


def test_and_binds_tighter_than_or() -> None:
    """``A 且 B 或 C`` = ``(A 且 B) 或 C``。"""
    signal = "exit_code == 0 且 stdout 包含 root_shell 或 stdout 包含 bypassed"
    assert evidence.evaluate_signal(signal, 0, "root_shell")["matched"] is True
    assert evidence.evaluate_signal(signal, 1, "bypassed")["matched"] is True
    assert evidence.evaluate_signal(signal, 1, "nothing")["matched"] is False


def test_a_satisfied_alternative_wins_even_if_another_cannot_be_judged() -> None:
    """退出码判不了, 但另一条路已经成立 —— 结论就是成立, 不必等退出码。"""
    signal = "exit_code == 0 或 stdout 包含 boom"
    assert evidence.evaluate_signal(signal, None, "boom", exit_code_known=False)["matched"] is True
    assert evidence.evaluate_signal(signal, None, "quiet", exit_code_known=False)["matched"] is None


def test_an_or_inside_a_needle_is_not_a_separator() -> None:
    """``stdout 包含 成功或失败`` 里的"或"是待匹配串的一部分, 切开就永远匹配不上。"""
    judged = evidence.evaluate_signal("stdout 包含 成功或失败", 0, "结果：成功或失败")
    assert judged["matched"] is True
    assert len(judged["checks"]) == 1


def test_a_vertical_bar_inside_a_regex_is_not_an_or() -> None:
    """``/a|b/`` 里的竖线是正则的"或", 不能被当成组间分隔符拆开。"""
    signal = "输出匹配 /Segmentation fault|core dumped/"
    judged = evidence.evaluate_signal(signal, 139, "Segmentation fault (core dumped)")
    assert judged["matched"] is True
    assert len(judged["checks"]) == 1


def test_two_crash_forms_of_the_same_claim_are_not_a_partial() -> None:
    """task #2 的实况: 判据只写 glibc 那句时判 partial; 写成"或"之后同一份证据判成功。"""
    cmd = ('cd /w && .venv/bin/python3 -u poc.py 2>&1 | tee log; echo "EXIT=${PIPESTATUS[0]}"')
    stdout = "X: 0x0\nY: 0x0\nSegmentation fault (core dumped)\nEXIT=139\n"
    commands = evidence.extract_commands(_messages(_bash(cmd, stdout, 0)))
    spec = {
        "steps": [{"run": "python3 -u poc.py"}],
        "probe": {"cmd": "python3 -u poc.py 2>&1",
                  "success_signal": "stdout 包含 free(): invalid pointer 或 "
                                    "stdout 匹配 /Segmentation fault|core dumped/"},
    }
    collected = evidence.build_evidence(spec=spec, report={"self_verdict": "success"},
                                        commands=commands)
    assert collected["probe"]["exit_code"] == 139
    assert collected["probe"]["matched"] is True
    assert collected["incomplete"] is False


def test_recovered_exit_code_turns_a_swallowed_crash_into_a_real_failure() -> None:
    """同一个 probe, 若判据是 ``exit_code == 0``: 旧口径(wrapper 0) 会判成功, 新口径判失败。"""
    cmd = ('cd /w && .venv/bin/python3 -u poc.py 2>&1 | tee log; echo "EXIT=${PIPESTATUS[0]}"')
    spec = {"steps": [{"run": "python3 -u poc.py"}],
            "probe": {"cmd": "python3 -u poc.py 2>&1", "success_signal": "exit_code == 0"}}
    commands = evidence.extract_commands(_messages(_bash(cmd, "Segmentation fault\nEXIT=139\n", 0)))
    collected = evidence.build_evidence(spec=spec, report={"self_verdict": "success"},
                                        commands=commands)
    assert collected["probe"]["exit_code"] == 139
    assert collected["probe"]["matched"] is False, "崩溃不能因为 agent 加了 echo 就算成功"
    assert any("probe 判据未满足" in reason for reason in collected["incomplete_reasons"])


def test_output_contains_signal_still_works_when_the_exit_code_is_unknown() -> None:
    """退出码判不了, 但判据只看输出 —— 该判照判, 不连坐。"""
    spec = {"steps": [{"run": "python3 -u poc.py"}],
            "probe": {"cmd": "python3 -u poc.py", "success_signal": "stdout 包含 boom"}}
    commands = evidence.extract_commands(_messages(_bash("python3 -u poc.py; echo done", "boom\ndone", 0)))
    collected = evidence.build_evidence(spec=spec, report={"self_verdict": "success"},
                                        commands=commands)
    assert collected["probe"]["exit_code"] is None
    assert collected["probe"]["matched"] is True


def _success_evidence(**kwargs):
    spec = {
        "steps": [{"run": "./poc 127.0.0.1", "expect": "shell"}],
        "probe": {"cmd": "./poc 127.0.0.1", "success_signal": "stdout 包含 uid=0"},
    }
    commands = evidence.extract_commands(_messages(_bash("./poc 127.0.0.1", "uid=0(root)", 0)))
    return evidence.build_evidence(spec=spec, report={"self_verdict": "success"}, commands=commands, **kwargs)


def test_evidence_is_complete_only_when_the_probe_actually_matched() -> None:
    collected = _success_evidence()
    assert collected["incomplete"] is False
    assert collected["probe"]["matched"] is True
    assert evidence.evidence_gaps(collected) == []


def test_evidence_without_a_probe_record_is_incomplete() -> None:
    spec = {"steps": [{"run": "id"}], "probe": {"cmd": "cat /flag", "success_signal": "exit_code == 0"}}
    commands = evidence.extract_commands(_messages(_bash("id", "uid=0", 0)))
    collected = evidence.build_evidence(spec=spec, report={"self_verdict": "success"}, commands=commands)
    assert collected["incomplete"] is True
    assert any("probe" in reason for reason in collected["incomplete_reasons"])
    assert evidence.evidence_gaps(collected)


def test_evidence_drops_full_stdout_but_keeps_the_fingerprint() -> None:
    """完整输出可能几十 MB; 证据包只留可复算的指纹与尾部。"""
    collected = _success_evidence()
    row = collected["commands"][0]
    assert "stdout" not in row
    assert row["stdout_sha1"] and row["stdout_tail"]


# ---------------------------------------------------------------- executor

def test_parse_report_extracts_the_block() -> None:
    text = (
        "先说两句废话 {不是 JSON}\n"
        "===REPORT===\n"
        '{"executed_steps": [{"step_index": 1, "cmd": "id", "exit_code": 0}],'
        ' "probe_result": {"cmd": "id", "exit_code": 0, "signal_matched": true},'
        ' "self_verdict": "success", "self_reason": "拿到 root", "failure_bucket": "",'
        ' "gotchas": ["需要 gcc"]}\n'
        "===REPORT===\n"
        "结束语"
    )
    report, error = executor.parse_report(text)
    assert error == ""
    assert report["self_verdict"] == "success"
    assert report["gotchas"] == ["需要 gcc"]


def test_parse_report_handles_braces_inside_strings() -> None:
    text = '===REPORT===\n{"self_verdict": "partial", "self_reason": "输出里有 {a: 1} 这种串"}\n===REPORT==='
    report, error = executor.parse_report(text)
    assert error == "" and report["self_verdict"] == "partial"


def test_parse_report_rejects_a_missing_or_bogus_verdict() -> None:
    assert executor.parse_report("什么都没有")[0] is None
    report, error = executor.parse_report('===REPORT===\n{"self_verdict": "maybe"}\n===REPORT===')
    assert report is None and "self_verdict" in error


def test_prompt_carries_the_spec_and_the_red_lines() -> None:
    task = {"id": 12, "claim": "拿到 root"}
    material = {"title": "foo", "url": "https://x", "cleaned_text": "正文"}
    spec = {"steps": [{"run": "./poc 127.0.0.1", "expect": "root"}], "probe": {"cmd": "id", "success_signal": "exit_code == 0"}}
    prompt = executor.build_exec_prompt(task=task, material=material, spec=spec, budget_seconds=1800)
    assert "./poc 127.0.0.1" in prompt
    assert "writeup-12" in prompt
    assert "严禁访问互联网上的任何真实站点" in prompt
    assert "30 分钟" in prompt


# ---------------------------------------------------------------- decide

def _decide(**kwargs):
    return executor.decide(**kwargs)


def test_decide_blocks_before_anything_else() -> None:
    verdict, reason, _ = _decide(
        report={"self_verdict": "success"},
        evidence=_success_evidence(),
        preflight={"allowed": False, "reason": "online_target", "detail": "目标是线上服务"},
    )
    assert (verdict, reason) == ("blocked", "online_target")


def test_decide_blocks_when_the_agent_reached_a_real_site() -> None:
    collected = _success_evidence(
        egress={"review_required": True, "external_requests": ["shop.acme-prod.com"]},
    )
    verdict, reason, notes = _decide(report={"self_verdict": "success"}, evidence=collected)
    assert (verdict, reason) == ("blocked", "online_target")
    assert any("shop.acme-prod.com" in note for note in notes)


def test_decide_treats_a_missing_report_as_our_failure() -> None:
    """没跑完是我们的问题, 不能记成"原文不可复现"贴到作者身上。"""
    collected = _success_evidence()  # 证据齐全但报告缺失
    verdict, reason, _ = _decide(report=None, evidence=collected)
    assert (verdict, reason) == ("failed", "env_error")


def test_decide_does_not_trust_the_agents_success_claim() -> None:
    spec = {"steps": [{"run": "id"}], "probe": {"cmd": "cat /flag", "success_signal": "exit_code == 0"}}
    commands = evidence.extract_commands(_messages(_bash("id", "uid=0", 0)))
    collected = evidence.build_evidence(spec=spec, report={"self_verdict": "success"}, commands=commands)
    verdict, reason, _ = _decide(report={"self_verdict": "success"}, evidence=collected)
    assert (verdict, reason) == ("partial", "probe_not_matched")


def test_decide_maps_every_self_verdict_to_an_allowed_pair() -> None:
    for self_verdict, bucket in [
        ("success", ""), ("partial", "degraded"), ("cannot_repro", "article_incomplete"),
        ("cannot_repro", "version_mismatch"), ("failed", "env_error"), ("blocked", "online_target"),
    ]:
        collected = _success_evidence()
        report = {"self_verdict": self_verdict, "failure_bucket": bucket, "self_reason": "r"}
        verdict, reason, _ = _decide(report=report, evidence=collected)
        assert reason in tasks.VERDICT_FAILURES[verdict], f"{verdict}/{reason} 不是允许的配对"


def test_decide_never_invents_a_reason_outside_the_table() -> None:
    """模型可以给任意 failure_bucket; 落到库里必须是词表内的值。"""
    report = {"self_verdict": "cannot_repro", "failure_bucket": "model_got_confused"}
    verdict, reason, _ = _decide(report=report, evidence=_success_evidence())
    assert (verdict, reason) == ("cannot_repro", "article_incomplete")


# ---------------------------------------------------------------- 库侧

def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    conn.execute(
        "INSERT INTO writeup_repro_tasks (id, material_id, status, created_at, updated_at)"
        " VALUES (1, 100, 'running', 'x', 'x')"
    )
    conn.commit()
    return conn


def test_append_log_keeps_the_tail() -> None:
    conn = _conn()
    tasks.append_log(conn, 1, "第一行")
    tasks.append_log(conn, 1, "第二行")
    log = conn.execute("SELECT log FROM writeup_repro_tasks WHERE id = 1").fetchone()[0]
    assert "第一行" in log and "第二行" in log

    tasks.append_log(conn, 1, "x" * (tasks.LOG_LIMIT + 100))
    log = conn.execute("SELECT log FROM writeup_repro_tasks WHERE id = 1").fetchone()[0]
    assert len(log) <= tasks.LOG_LIMIT
    assert "第一行" not in log, "超限后保留尾部 —— 开头是早就没用的提示词"


def test_set_runtime_ignores_unknown_fields() -> None:
    conn = _conn()
    tasks.set_runtime(conn, 1, session_id="s1", status="success")
    row = conn.execute("SELECT session_id, status FROM writeup_repro_tasks WHERE id = 1").fetchone()
    assert row["session_id"] == "s1"
    assert row["status"] == "running", "运行时字段更新不能顺手改状态"


def test_running_task_can_be_cancelled_and_queued_task_can_be_blocked() -> None:
    """状态机原来缺这两条边: 点"停止"报 400, 开跑前拦截得先假装 running。"""
    conn = _conn()
    tasks.cancel(conn, 1)
    assert tasks.get_task(conn, 1)["status"] == "cancelled"

    conn.execute("INSERT INTO writeup_repro_tasks (id, material_id, status, created_at, updated_at)"
                 " VALUES (2, 101, 'spec_ready', 'x', 'x')")
    conn.commit()
    tasks.transition(conn, 2, "blocked", verdict="blocked", failure_reason="online_target")
    assert tasks.get_task(conn, 2)["status"] == "blocked"
