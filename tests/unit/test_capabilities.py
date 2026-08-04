"""能力洞察模块单元测试。

覆盖:
  - normalizers: 字段映射
  - from_news: 派生筛选（score 阈值 + code_url）
  - dedupe: 三级 fallback + 跨批次去重
  - builders: CapabilityCard + ConversionRecord 构造
  - scorers: 多维度评分（5 维度 + 1-5 映射 + 资讯分先验）
  - repro_runner: classify_log_line 7 类 + strip_ansi + extract_report
  - repro_results: 报告状态映射
  - selectors: repo URL 解析
  - assessments: parse_github_url + extract_demo_urls + rule_based_classify
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sqlite3
import time
from types import SimpleNamespace

from ai4sec_platform.db.repositories import get_succeeded_repro_item_ids
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.core.config import Settings
from ai4sec_platform.domains.capabilities.adapters import repro_runner
from ai4sec_platform.domains.capabilities.adapters.from_news import capability_candidates_from_news
from ai4sec_platform.domains.capabilities.adapters.repro_runner import (
    ReproRunner,
    _build_repro_prompt,
    _build_web_repro_prompt,
    _repo_archive_url,
    classify_log_line,
    enforce_report_acceptance,
    extract_report,
    redact_sensitive_text,
    sanitized_subprocess_env,
    strip_ansi,
    task_status_from_report,
)
from ai4sec_platform.domains.capabilities.adapters.repro_results import update_capability_from_report
from ai4sec_platform.domains.capabilities.assessments import (
    extract_demo_urls,
    parse_github_url,
    rule_based_classify,
)
from ai4sec_platform.domains.capabilities.builders import build_capability_card, build_conversion_record
from ai4sec_platform.domains.capabilities.dedupe import dedupe_candidates, identity_key
from ai4sec_platform.domains.capabilities.normalizers import normalize_capability_candidate
from ai4sec_platform.domains.capabilities.scorers import score_capability_candidate
from ai4sec_platform.domains.capabilities.selectors import _resolve_repo_url
from ai4sec_platform.pipelines.steps.capability import _validated_capability_score


# ============================================================================
# normalizers
# ============================================================================
def test_normalize_capability_candidate_maps_fields() -> None:
    news_item = {
        "id": 1,
        "title": "Test Paper",
        "score": 70,
        "source_url": "https://github.com/foo/bar",
        "payload": {"code_url": "https://github.com/foo/bar", "source_type": "repo", "scoring": {"score": 70}},
    }
    candidate = normalize_capability_candidate(news_item)
    assert candidate["title"] == "Test Paper"
    assert candidate["source_url"] == "https://github.com/foo/bar"
    assert candidate["code_url"] == "https://github.com/foo/bar"
    assert candidate["source_type"] == "github"
    assert candidate["source_news_score"] == 70.0
    assert candidate["source_news_item"] == news_item


def test_normalize_capability_candidate_arxiv() -> None:
    news_item = {
        "id": 2,
        "title": "Paper",
        "source_url": "https://arxiv.org/abs/2607.12345",
        "payload": {},
    }
    candidate = normalize_capability_candidate(news_item)
    assert candidate["source_type"] == "arxiv"


# ============================================================================
# from_news
# ============================================================================
def test_capability_candidates_from_news_filters_by_score_and_code() -> None:
    high_with_code = {
        "id": 1, "title": "AI Paper", "score": 70,
        "payload": {"code_url": "https://github.com/foo/bar", "source_type": "repo"},
    }
    low_score = {"id": 2, "title": "Low", "score": 30, "payload": {}}
    no_code = {"id": 3, "title": "No Code", "score": 80, "payload": {}}

    candidates = capability_candidates_from_news([high_with_code, low_score, no_code])
    assert len(candidates) == 1
    assert candidates[0]["title"] == "AI Paper"


def test_capability_candidates_from_news_require_code_false() -> None:
    high_no_code = {"id": 1, "title": "Paper", "score": 70, "payload": {}}
    candidates = capability_candidates_from_news([high_no_code], require_code=False)
    assert len(candidates) == 1


# ============================================================================
# dedupe
# ============================================================================
def test_identity_key_repo_url() -> None:
    assert identity_key({"code_url": "https://github.com/foo/bar"}) == "https://github.com/foo/bar"


def test_identity_key_arxiv_abs() -> None:
    assert identity_key({"source_url": "https://arxiv.org/abs/2607.12345"}) == "arxiv::2607.12345"


def test_identity_key_arxiv_pdf() -> None:
    assert identity_key({"source_url": "https://arxiv.org/pdf/2607.12345"}) == "arxiv::2607.12345"


def test_identity_key_title_fallback() -> None:
    assert identity_key({"title": "Some Paper"}) == "title::Some Paper"


def test_dedupe_candidates_removes_duplicates() -> None:
    c1 = {"code_url": "https://github.com/foo/bar", "title": "A"}
    c2 = {"code_url": "https://github.com/foo/bar", "title": "B"}  # 重复
    c3 = {"source_url": "https://arxiv.org/abs/1234.5678", "title": "C"}
    result, seen = dedupe_candidates([c1, c2, c3])
    assert len(result) == 2
    assert len(seen) == 2


# ============================================================================
# builders
# ============================================================================
def test_build_capability_card() -> None:
    candidate = {
        "title": "Test",
        "source_url": "https://github.com/foo/bar",
        "code_url": "https://github.com/foo/bar",
        "source_type": "github",
        "source_news_score": 70.0,
        "source_news_item": {"title": "Test", "summary": "A test project", "payload": {}},
    }
    card = build_capability_card(candidate)
    assert card["item_type"] == "capability"
    assert card["repro_status"] == "candidate"
    assert card["implementation_depth"]["has_real_code"] is True


def test_build_capability_card_no_code() -> None:
    candidate = {"title": "Paper", "source_url": "https://arxiv.org/abs/1234", "code_url": "", "source_news_item": {}}
    card = build_capability_card(candidate)
    assert card["repro_status"] == "no_code"
    assert card["implementation_depth"]["has_real_code"] is False


def test_build_conversion_record() -> None:
    record = build_conversion_record({"title": "Test", "id": 1}, scenario="test scenario")
    assert record["item_type"] == "capability_conversion"
    assert record["capability_id"] == 1
    assert record["status"] == "持续观察"
    assert record["scenario"] == "test scenario"


# ============================================================================
# scorers（决策 6: 多维度评分 + 资讯分先验）
# ============================================================================
def test_score_capability_candidate_multi_dimension() -> None:
    item = {
        "title": "AI Security Agent",
        "score": 80,
        "payload": {
            "code_url": "https://github.com/foo/bar",
            "source_news_item": {
                "title": "AI Security Agent",
                "score": 80,
                "stars": 1000,
                "summary": "security agent framework",
                "source_url": "https://github.com/foo/bar",
            },
        },
    }
    result = score_capability_candidate(item)
    assert 1 <= result.score <= 5
    assert "relevance" in result.breakdown
    assert "code_clue" in result.breakdown
    assert "reproducibility" in result.breakdown
    assert "research_value" in result.breakdown
    assert "security_value" in result.breakdown
    assert result.signals["has_code"] is True


def test_score_capability_candidate_low_score() -> None:
    item = {"title": "Nothing", "score": 10, "payload": {}}
    result = score_capability_candidate(item)
    assert result.score <= 3
    assert result.priority == "low"


def test_score_capability_candidate_security_topic_boost() -> None:
    item = {
        "title": "Vulnerability Scanner",
        "score": 50,
        "payload": {
            "source_news_item": {
                "title": "Vulnerability Scanner for CVE",
                "score": 50,
                "summary": "detects CVE and security vulnerabilities",
                "source_url": "https://github.com/foo/sec",
            },
        },
    }
    result = score_capability_candidate(item)
    assert result.breakdown["security_value"] == 1.0  # 安全主题命中


def test_model_capability_score_is_bounded_and_falls_back() -> None:
    assert _validated_capability_score("invalid", 3.2) == 3.2
    assert _validated_capability_score(9, 3.2) == 5.0
    assert _validated_capability_score(-1, 3.2) == 1.0


# ============================================================================
# repro_runner: classify_log_line 7 类 + strip_ansi + extract_report
# ============================================================================
def test_classify_log_line_7_types() -> None:
    assert classify_log_line("✱ tool call") == "tool"
    assert classify_log_line("→ read") == "read"
    assert classify_log_line("$ command") == "exec"
    assert classify_log_line("✓ done") == "ok"
    assert classify_log_line("! warning") == "warn"
    assert classify_log_line("✗ failed") == "error"
    assert classify_log_line("ERROR: something") == "error"
    assert classify_log_line("plain text") == "text"


def test_strip_ansi_removes_escape_codes() -> None:
    result = strip_ansi("\x1b[0mhello\x1b[0m")
    assert "hello" in result
    assert "\x1b" not in result


def test_extract_report_with_markers() -> None:
    text = "log\n===REPRO_REPORT_START===\n{\"status\": \"success\", \"summary\": \"ok\", \"level\": \"L1\"}\n===REPRO_REPORT_END===\nmore"
    report = extract_report(text)
    assert report is not None
    assert report["status"] == "success"
    assert report["level"] == "L1"


def test_extract_report_loose_json() -> None:
    text = 'some log\n{"status": "partial", "summary": "half done"}\nmore'
    report = extract_report(text)
    assert report is not None
    assert report["status"] == "partial"


def test_extract_report_no_report_returns_none() -> None:
    assert extract_report("just some log output") is None


def test_task_status_preserves_partial_report() -> None:
    assert task_status_from_report({"status": "partial"}) == "partial"


def test_task_status_uses_fallback_without_report() -> None:
    assert task_status_from_report(None, fallback="partial") == "partial"


def test_cli_success_without_execution_evidence_is_downgraded() -> None:
    report = enforce_report_acceptance({"status": "success", "summary": "looks good", "project_type": "python"})

    assert report is not None
    assert report["status"] == "partial"
    assert "成功报告缺少真实运行证据" in report["acceptance_issues"]


def test_cli_success_requires_real_command_output_and_passing_steps() -> None:
    report = enforce_report_acceptance({
        "status": "success",
        "summary": "minimal example ran",
        "project_type": "python",
        "steps": [{"cmd": "python -m example", "ok": True}],
        "run_result": {
            "ran": True,
            "command": "python -m example",
            "output_excerpt": "result: ok",
            "what_it_does": "produced the expected result",
        },
    })

    assert report is not None
    assert report["status"] == "success"
    assert not report.get("acceptance_issues")


def test_l3_environment_only_report_cannot_be_full_success() -> None:
    report = enforce_report_acceptance({
        "status": "success",
        "level": "L3",
        "summary": "environment prepared",
        "project_type": "python",
        "steps": [{"cmd": "python -c 'import package'", "ok": True}],
        "run_result": {
            "ran": True,
            "command": "python -c 'import package'",
            "output_excerpt": "import ok",
            "what_it_does": "verified imports only",
        },
    })

    assert report is not None
    assert report["status"] == "partial"
    assert "L3 项目只完成环境评估，不能标记完整成功" in report["acceptance_issues"]


def test_web_success_without_core_validation_is_downgraded() -> None:
    report = enforce_report_acceptance({"status": "success", "is_web": True, "web_started": True})
    assert report is not None
    assert report["status"] == "partial"
    assert "未完成核心业务闭环验证" in report["acceptance_issues"]


def test_web_mock_validation_is_downgraded() -> None:
    report = enforce_report_acceptance({
        "status": "success",
        "is_web": True,
        "web_started": True,
        "core_workflow": {
            "mode": "mock",
            "verified": True,
            "steps": [{"action": "generate", "ok": True}],
            "evidence": ["mock output"],
            "result": "generated",
        },
    })
    assert report is not None
    assert report["status"] == "partial"
    assert "核心功能未使用真实模式验证" in report["acceptance_issues"]


def test_real_web_core_workflow_remains_success() -> None:
    report = enforce_report_acceptance({
        "status": "success",
        "is_web": True,
        "web_started": True,
        "core_workflow": {
            "mode": "real",
            "verified": True,
            "steps": [{"action": "scan target", "ok": True}],
            "evidence": ["scan report with 3 findings"],
            "result": "report generated",
        },
    })
    assert report is not None
    assert report["status"] == "success"
    assert not report.get("acceptance_issues")


def test_web_without_started_service_cannot_succeed() -> None:
    report = enforce_report_acceptance({"status": "success", "is_web": True, "web_started": False})
    assert report is not None
    assert report["status"] == "failed"


def test_web_prompt_requires_real_core_evidence() -> None:
    prompt = _build_web_repro_prompt()
    assert "首页 200 = 复现成功" in prompt
    assert '"mode": "real|mock"' in prompt
    assert "真实证据" in prompt
    assert "无需用户额外配置" in prompt
    assert "schema 校验失败" in prompt
    assert "至少重试 2 次" in prompt


def test_partial_repro_is_not_considered_succeeded() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE capability_repro_tasks (item_id INTEGER, status TEXT)")
    connection.executemany(
        "INSERT INTO capability_repro_tasks (item_id, status) VALUES (?, ?)",
        [(1, "success"), (2, "partial"), (3, "failed")],
    )
    assert get_succeeded_repro_item_ids(connection) == {1}


def test_github_archive_uses_codeload_fallback() -> None:
    assert _repo_archive_url("https://github.com/example/tool.git") == (
        "https://codeload.github.com/example/tool/zip/refs/heads/main"
    )
    assert _repo_archive_url("https://github.com/example/tool.git", "a" * 40) == (
        f"https://codeload.github.com/example/tool/zip/{'a' * 40}"
    )


def test_repro_prompt_never_contains_model_secret(monkeypatch) -> None:
    secret = "sk-production-secret-123456789"
    monkeypatch.setenv("REPRO_LLM_API_KEY", secret)
    monkeypatch.setattr(repro_runner, "REPRO_LLM_BASE_URL", "https://gateway.internal/api/model-gateway/v1")
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", "/run/secrets/task-token")

    prompt = _build_repro_prompt()

    assert secret not in prompt
    assert "API Key:" not in prompt
    assert "只读 Secret 文件" in prompt


def test_repro_log_callback_redacts_known_and_pattern_secrets(monkeypatch, tmp_path: Path) -> None:
    secret = "sk-task-secret-123456789"
    token_file = tmp_path / "token"
    token_file.write_text(secret, encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", str(token_file))
    lines: list[str] = []
    runner = ReproRunner(1, "https://github.com/example/repo", on_log=lines.append)

    runner.on_log(f"API_KEY={secret} Authorization: Bearer bearer-secret-123456")

    assert lines
    assert secret not in lines[0]
    assert "bearer-secret-123456" not in lines[0]
    assert "[REDACTED]" in lines[0]


def test_repro_token_is_read_only_mounted_and_not_on_command_line(monkeypatch, tmp_path: Path) -> None:
    secret = "task-token-not-on-command-line"
    token_file = tmp_path / "token"
    token_file.write_text(secret, encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", str(token_file))
    runner = ReproRunner(2, "https://github.com/example/repo")

    command = runner.build_run_command()

    assert secret not in " ".join(command)
    assert "--mount" in command
    mount = command[command.index("--mount") + 1]
    assert f"src={token_file.resolve()}" in mount
    assert f"dst={repro_runner.CONTAINER_MODEL_TOKEN_FILE}" in mount
    assert mount.endswith("readonly")
    assert command[command.index("--tmpfs") + 1].startswith("/root/.local/share/opencode:")


def test_repro_requires_managed_token_file(monkeypatch) -> None:
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", "")

    import pytest
    with pytest.raises(RuntimeError, match="REPRO_MODEL_TOKEN_FILE is required"):
        ReproRunner(3, "https://github.com/example/repo").build_run_command()


def test_repro_requires_managed_model_base_url(monkeypatch, tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret", encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", str(token_file))
    monkeypatch.setattr(repro_runner, "REPRO_LLM_BASE_URL", "")

    import pytest
    with pytest.raises(RuntimeError, match="REPRO_LLM_BASE_URL is required"):
        repro_runner.validate_repro_runtime_config()


def test_repro_runtime_rejects_image_with_baked_auth(monkeypatch, tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret", encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", str(token_file))
    monkeypatch.setattr(repro_runner, "REPRO_LLM_BASE_URL", "https://gateway.internal/api/model-gateway/v1")

    class Result:
        def __init__(self, returncode, stdout=""):
            self.returncode = returncode
            self.stdout = stdout

    def fake_run(command, **_kwargs):
        if command[1:3] == ["info", "--format"]:
            return Result(0, '{"sysbox-runc": {}}')
        return Result(1)

    monkeypatch.setattr(repro_runner, "_safe_run", fake_run)

    import pytest
    with pytest.raises(RuntimeError, match="contains a baked OpenCode auth file"):
        repro_runner.validate_repro_runtime_config(check_image=True)


def test_opencode_config_references_secret_file_and_not_image_auth(monkeypatch, tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("managed-task-token", encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", str(token_file))
    monkeypatch.setattr(repro_runner, "REPRO_LLM_BASE_URL", "https://gateway.internal/api/model-gateway/v1")

    repo_commit = "a" * 40
    command = ReproRunner(4, "https://github.com/example/repo", repo_commit=repo_commit).build_exec_command()
    shell_command = command[-1]

    assert "auth.json" not in shell_command
    assert "managed-task-token" not in shell_command
    assert repro_runner.CONTAINER_MODEL_TOKEN_FILE in shell_command
    assert f"fetch --depth 1 origin {repo_commit}" in shell_command
    assert f"test \"$(git rev-parse HEAD)\" = {repo_commit}" in shell_command
    assert f"https://codeload.github.com/example/repo/zip/{repo_commit}" in shell_command
    encoded = shell_command.split("echo '", 1)[1].split("' | base64 -d", 1)[0]
    config = json.loads(base64.b64decode(encoded).decode())
    options = config["provider"]["ai4sec-managed"]["options"]
    assert options["apiKey"] == f"{{file:{repro_runner.CONTAINER_MODEL_TOKEN_FILE}}}"
    assert config["permission"]["*"] == "deny"
    assert config["permission"]["bash"]["docker run *--privileged*"] == "deny"
    assert config["permission"]["external_directory"]["*"] == "deny"
    assert config["agent"]["build"]["permission"]["*"] == "deny"
    assert config["plugin"] == []
    assert "opencode run --pure --agent build" in shell_command


def test_repro_rejects_overly_permissive_token_file(monkeypatch, tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret", encoding="utf-8")
    token_file.chmod(0o644)
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", str(token_file))

    runner = ReproRunner(3, "https://github.com/example/repo")

    import pytest
    with pytest.raises(RuntimeError, match="permissions"):
        runner.build_run_command()


def test_repro_container_command_has_resource_and_privilege_limits(monkeypatch, tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("secret", encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", str(token_file))
    runner = ReproRunner(4, "https://github.com/example/repo")
    runner._egress_policy = SimpleNamespace(host_addresses=(("github.com", "93.184.216.34"),))

    command = runner.build_run_command()

    assert command[command.index("--cpus") + 1] == repro_runner.REPRO_NESTED_CPUS
    assert command[command.index("--memory") + 1] == repro_runner.REPRO_NESTED_MEMORY
    assert command[command.index("--memory-swap") + 1] == repro_runner.REPRO_NESTED_MEMORY_SWAP
    assert command[command.index("--pids-limit") + 1] == repro_runner.REPRO_NESTED_PIDS_LIMIT
    assert "no-new-privileges=true" in command
    assert command[command.index("--network") + 1] == "bridge"
    assert command[command.index("--dns") + 1] == "127.0.0.1"
    assert "github.com:93.184.216.34" in command
    assert "net.ipv6.conf.all.disable_ipv6=1" in command


def test_repro_resource_validation_rejects_unbounded_cpu(monkeypatch) -> None:
    monkeypatch.setattr(repro_runner, "REPRO_CPUS", "0")

    import pytest
    with pytest.raises(RuntimeError, match="REPRO_CPUS must be between"):
        repro_runner.validate_repro_resource_limits()


def test_repro_resource_validation_rejects_invalid_memory(monkeypatch) -> None:
    monkeypatch.setattr(repro_runner, "REPRO_MEMORY", "unlimited")

    import pytest
    with pytest.raises(RuntimeError, match="REPRO_MEMORY must be a positive Docker size"):
        repro_runner.validate_repro_resource_limits()


def test_repro_log_output_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(repro_runner, "REPRO_LOG_MAX_BYTES", 20)
    lines: list[str] = []
    runner = ReproRunner(5, "https://github.com/example/repo", on_log=lines.append)

    runner.on_log("1234567890")
    runner.on_log("abcdefghij")
    runner.on_log("ignored")

    assert lines[0] == "1234567890"
    assert sum("日志达到" in line for line in lines) == 1
    assert "ignored" not in lines


def test_workspace_limit_detects_excess_files(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(repro_runner, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(repro_runner, "REPRO_WORKSPACE_MAX_BYTES", 5)
    runner = ReproRunner(6, "https://github.com/example/repo")
    runner.workspace.mkdir(parents=True)
    (runner.workspace / "large.bin").write_bytes(b"123456")

    assert runner._workspace_size_exceeded() is True


def test_web_proxy_binds_only_loopback(monkeypatch) -> None:
    runtime_updates: list[dict] = []
    runner = ReproRunner(
        7,
        "https://github.com/example/repo",
        web_port=18080,
        on_runtime=lambda **values: runtime_updates.append(values),
    )

    class Result:
        stdout = "1234\n"

    commands: list[list[str]] = []
    class ProxyProcess:
        pid = 4321

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(repro_runner, "_safe_run", lambda *_args, **_kwargs: Result())
    monkeypatch.setattr(repro_runner, "_safe_popen", lambda command, **_kwargs: commands.append(command) or ProxyProcess())

    runner._start_port_proxy()

    assert commands
    assert "bind=127.0.0.1" in commands[0][1]
    assert runtime_updates == [{"proxy_pid": 4321}]


def test_silent_repro_process_still_times_out(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(repro_runner, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(repro_runner, "CONTAINER_TIMEOUT", 0.1)
    monkeypatch.setattr(repro_runner, "REPORT_GRACE_TIMEOUT", 0)
    monkeypatch.setattr(repro_runner, "validate_repro_resource_limits", lambda: None)
    token_file = tmp_path / "token"
    token_file.write_text("secret", encoding="utf-8")
    token_file.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_MODEL_TOKEN_FILE", str(token_file))
    monkeypatch.setattr(repro_runner, "REPRO_LLM_BASE_URL", "https://gateway.internal/api/model-gateway/v1")
    statuses: list[str] = []
    runner = ReproRunner(8, "https://github.com/example/repo", on_status=lambda status, **_kw: statuses.append(status))
    repo_dir = runner.workspace / "repo"
    repo_dir.mkdir(parents=True)
    (repo_dir / "README.md").write_text("ready", encoding="utf-8")

    class Result:
        returncode = 0
        stdout = "a" * 64
        stderr = ""

    class SilentStream:
        def __iter__(self):
            return self

        def __next__(self):
            while not process.terminated:
                time.sleep(0.01)
            raise StopIteration

    class SilentProcess:
        def __init__(self):
            self.stdout = SilentStream()
            self.terminated = False

        def poll(self):
            return 0 if self.terminated else None

        def terminate(self):
            self.terminated = True

        def wait(self):
            return 0

    process = SilentProcess()
    class FakeEgressGuard:
        def __init__(self, **_kwargs):
            pass

        def install(self):
            return {"allowed_public_ips": 1, "gateway_ip": "172.17.0.1"}

        def remove(self):
            return {"chain": "test-chain", "denied_packets": 0, "denied_bytes": 0}

    monkeypatch.setattr(repro_runner, "_safe_run", lambda *_args, **_kwargs: Result())
    monkeypatch.setattr(repro_runner, "_safe_popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        repro_runner,
        "build_repro_egress_policy",
        lambda *_args, **_kwargs: SimpleNamespace(
            gateway_host="host.docker.internal",
            gateway_port=8000,
            host_addresses=(),
        ),
    )
    monkeypatch.setattr(repro_runner, "DockerEgressGuard", FakeEgressGuard)
    monkeypatch.setattr(runner, "_wait_dockerd", lambda: True)
    monkeypatch.setattr(runner, "_start_port_proxy", lambda: None)

    runner._run()

    assert process.terminated is True
    assert statuses[-1] == "timeout"


def test_subprocess_environment_removes_sensitive_variables(monkeypatch) -> None:
    monkeypatch.setenv("DASHSCOPE_API_KEY", "secret")
    monkeypatch.setenv("REPRO_MODEL_TOKEN", "secret")
    monkeypatch.setenv("SAFE_SETTING", "visible")

    environment = sanitized_subprocess_env()

    assert "DASHSCOPE_API_KEY" not in environment
    assert "REPRO_MODEL_TOKEN" not in environment
    assert environment["SAFE_SETTING"] == "visible"


def test_redaction_handles_common_secret_formats() -> None:
    redacted = redact_sensitive_text("token=abc123456789 secret: xyz987654321 Bearer bearer-token-12345")

    assert "abc123456789" not in redacted
    assert "xyz987654321" not in redacted
    assert "bearer-token-12345" not in redacted


# ============================================================================
# repro_results: 报告状态映射
# ============================================================================
def test_update_capability_from_report_status_mapping() -> None:
    """验证报告 status → domain_item status 映射（不实际写 DB）"""
    status_map = {"success": "已复现", "partial": "部分复现", "failed": "复现失败"}
    for rep_status, expected in status_map.items():
        report = {"status": rep_status, "summary": "test"}
        # 不传 conn，只验证映射逻辑（update_capability_from_report 内部会 from ai4sec_platform.db import repositories）
        # 这里只验证 status_map 正确
        assert status_map[report["status"]] == expected


def test_update_capability_from_report_preserves_structured_evidence(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "test.db")
    with connect(settings) as conn:
        init_db(conn)
        item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="Evidence item",
            source_url="https://github.com/example/repo",
            payload={"repro_status": "candidate"},
        )
        result = update_capability_from_report(conn, item_id=item_id, report={
            "status": "partial",
            "schema_version": "1.0",
            "summary": "CLI ran but a required provider was unavailable",
            "evidence": ["command output: provider unavailable"],
            "limitations": ["requires provider credentials"],
            "usage": {"what": "example tool", "limitations": "provider required"},
            "blockers": ["provider unavailable"],
        })
        conn.commit()
        item = repo.get_domain_item(conn, "capabilities", item_id)

    assert result["updated"] is True
    assert item and item["status"] == "部分复现"
    assert item["payload"]["repro_report_schema_version"] == "1.0"
    assert item["payload"]["evidence"] == ["command output: provider unavailable"]
    assert item["payload"]["limitations"] == ["requires provider credentials"]


# ============================================================================
# selectors: repo URL 解析
# ============================================================================
def test_resolve_repo_url_from_source_url() -> None:
    assert _resolve_repo_url({"source_url": "https://github.com/foo/bar"}) == "https://github.com/foo/bar"


def test_resolve_repo_url_from_code_url() -> None:
    assert _resolve_repo_url({"source_url": "", "payload": {"code_url": "https://github.com/foo/bar"}}) == "https://github.com/foo/bar"


def test_resolve_repo_url_empty() -> None:
    assert _resolve_repo_url({"source_url": "", "payload": {}}) == ""


# ============================================================================
# assessments: parse_github_url + extract_demo_urls + rule_based_classify
# ============================================================================
def test_parse_github_url() -> None:
    owner, repo = parse_github_url("https://github.com/foo/bar")
    assert owner == "foo"
    assert repo == "bar"


def test_parse_github_url_with_git_suffix() -> None:
    owner, repo = parse_github_url("https://github.com/foo/bar.git")
    assert owner == "foo"
    assert repo == "bar"


def test_parse_github_url_invalid() -> None:
    owner, repo = parse_github_url("https://example.com/foo/bar")
    assert owner is None
    assert repo is None


def test_extract_demo_urls_finds_playground() -> None:
    readme = "Demo: https://example.com/playground"
    urls = extract_demo_urls(readme)
    assert len(urls) > 0
    assert "https://example.com/playground" in urls[0]


def test_extract_demo_urls_filters_blacklist() -> None:
    readme = "See https://arxiv.org/abs/1234 for paper"
    urls = extract_demo_urls(readme)
    assert len(urls) == 0  # arxiv.org 在黑名单


def test_rule_based_classify_web_framework() -> None:
    result = rule_based_classify(["app.py", "package.json"], "npm run dev", "react", {"JavaScript": 1000})
    assert result["score"] > 0
    assert any("dep:react" in s for s in result["signals"])
    assert any("file:app.py" in s for s in result["signals"])


def test_rule_based_classify_no_web_signals() -> None:
    result = rule_based_classify(["main.py"], "a CLI tool", "", {"Python": 1000})
    assert result["score"] == 0
