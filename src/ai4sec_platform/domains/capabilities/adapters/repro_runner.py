"""复现编排器 - 迁移自旧 v1 repro.py（829 行）。

适配点（决策 1/5/8）：
  1. Prompt 和日志不包含模型凭据，任务 token 通过只读文件挂载
  2. 去掉 ReproRunner 内部的 import db 调用（db.get_repro_task/db.update_item_web_class），
     改为通过 on_status 回调通知外部，由外部处理 DB 回写
  3. sysbox + 端口代理（socat+nsenter）+ classify_log_line 7 类 + extract_report 全保留

运行环境（决策 2）: WSL2 + 生产服务器都支持，环境差异通过 .env 注入。
"""
from __future__ import annotations

import base64
import copy
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import threading
import time
import queue
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
import urllib.parse

from ai4sec_platform.core.env import load_env_file
from ai4sec_platform.domains.capabilities.egress import DockerEgressGuard, build_repro_egress_policy, validate_repro_egress_runtime
from ai4sec_platform.domains.capabilities.repro_policy import validate_repro_queue_limits

load_env_file()

# ============================================================================
# 配置（集中在这里，方便调整。从 .env 读，去硬编码）
# ============================================================================
REPRO_IMAGE = os.environ.get("REPRO_IMAGE", "repro-runner:v6")
REPRO_RUNTIME = os.environ.get("REPRO_RUNTIME", "sysbox-runc")
REPRO_STANDARD_IMAGE = os.environ.get("REPRO_STANDARD_IMAGE", "repro-runner-standard:v3")
WORKSPACE_ROOT = Path(os.environ.get("REPRO_WORKSPACE_ROOT", str(Path.home() / "repro_workspaces")))
CONTAINER_TIMEOUT = int(os.environ.get("REPRO_CONTAINER_TIMEOUT", str(30 * 60)))  # 30 分钟
WEB_CONTAINER_TIMEOUT = int(os.environ.get("REPRO_WEB_CONTAINER_TIMEOUT", str(50 * 60)))  # 50 分钟
REPORT_GRACE_TIMEOUT = int(os.environ.get("REPRO_REPORT_GRACE_TIMEOUT", str(10 * 60)))
DOCKERD_WAIT = int(os.environ.get("REPRO_DOCKERD_WAIT", "30"))
INTERNAL_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
REPRO_CPUS = os.environ.get("REPRO_CPUS", "2.0")
REPRO_MEMORY = os.environ.get("REPRO_MEMORY", "4g")
REPRO_MEMORY_SWAP = os.environ.get("REPRO_MEMORY_SWAP", REPRO_MEMORY)
REPRO_PIDS_LIMIT = os.environ.get("REPRO_PIDS_LIMIT", "1024")
REPRO_NESTED_CPUS = os.environ.get("REPRO_NESTED_CPUS", "1.5")
REPRO_NESTED_MEMORY = os.environ.get("REPRO_NESTED_MEMORY", "3g")
REPRO_NESTED_MEMORY_SWAP = os.environ.get("REPRO_NESTED_MEMORY_SWAP", REPRO_NESTED_MEMORY)
REPRO_NESTED_PIDS_LIMIT = os.environ.get("REPRO_NESTED_PIDS_LIMIT", "768")
REPRO_WORKSPACE_MAX_BYTES = int(os.environ.get("REPRO_WORKSPACE_MAX_BYTES", str(10 * 1024 * 1024 * 1024)))
REPRO_LOG_MAX_BYTES = int(os.environ.get("REPRO_LOG_MAX_BYTES", str(5 * 1024 * 1024)))
_DOCKER_SIZE_RE = re.compile(r"^[1-9][0-9]*(?:[bkmg])?$", re.IGNORECASE)

# DashScope API 代理（sysbox 容器内直连会卡死，通过宿主机 nginx 反代转发）
DASHSCOPE_PROXY_URL = os.environ.get("DASHSCOPE_PROXY_URL", "")

# 复现任务内 LLM 配置。真实凭据不得进入 Prompt。
REPRO_LLM_BASE_URL = os.environ.get("REPRO_LLM_BASE_URL", DASHSCOPE_PROXY_URL or "")
REPRO_LLM_MODEL = os.environ.get("REPRO_LLM_MODEL", "glm-5.2")
REPRO_GO_PROXY = os.environ.get("REPRO_GO_PROXY", "https://proxy.golang.org,direct")
REPRO_CARGO_REGISTRY_PROTOCOL = os.environ.get("REPRO_CARGO_REGISTRY_PROTOCOL", "sparse")
REPRO_CARGO_HTTP_MULTIPLEXING = os.environ.get("REPRO_CARGO_HTTP_MULTIPLEXING", "false")
REPRO_MODEL_TOKEN_FILE = os.environ.get("REPRO_MODEL_TOKEN_FILE", "")
CONTAINER_MODEL_TOKEN_FILE = "/run/secrets/repro_model_token"
CONTAINER_MANAGED_OPENCODE_CONFIG = "/etc/opencode/opencode.json"
REPRO_DOCKER_LABEL_RESOURCE = "com.ai4sec.resource"
REPRO_DOCKER_LABEL_OWNER = "com.ai4sec.runtime-owner"
REPRO_DOCKER_LABEL_TASK = "com.ai4sec.task-id"
REPRO_DOCKER_LABEL_PROFILE = "com.ai4sec.execution-profile"
REPRO_DOCKER_RESOURCE = "capability-repro"


def _repo_archive_url(repo_url: str, repo_commit: str = "") -> str:
    match = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", repo_url)
    if match:
        owner, name = match.groups()
        archive_ref = repo_commit or "refs/heads/main"
        return f"https://codeload.github.com/{owner}/{name.removesuffix('.git')}/zip/{archive_ref}"
    archive_ref = repo_commit or "refs/heads/main"
    return repo_url.removesuffix(".git").rstrip("/") + f"/archive/{archive_ref}.zip"


# ============================================================================
# 复现任务凭据与日志安全
# ============================================================================
_SENSITIVE_NAME_RE = re.compile(r"(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.IGNORECASE)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)((?:api[_ -]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+"),
)


def _managed_llm_prompt_section() -> str:
    if not REPRO_LLM_BASE_URL:
        return ""
    return f"""
# 受管模型服务（项目确实需要 LLM 时使用）
- Base URL: {REPRO_LLM_BASE_URL}
- 模型: {REPRO_LLM_MODEL}
- 任务凭据由执行器通过只读 Secret 文件管理；不要读取、输出、记录或复制任何凭据。
- 使用上面的 Base URL；禁止把凭据写入源码、报告或日志。
"""


def _profile_permission_prompt_section(execution_profile: str) -> str:
    docker_rule = (
        "- 本任务禁止 Docker/Podman；如果项目必须依赖容器编排，在报告中说明需要 nested_docker Profile。"
        if execution_profile == "standard"
        else "- 允许使用 Docker/Compose，但禁止 privileged 容器以及 host network/PID/IPC/UTS namespace。"
    )
    return f"""
# 执行权限边界
- 只能修改 `/workspace` 或 `/tmp`，禁止访问其他外部目录和 `/run/secrets`。
- 禁止 sudo、su、mount、nsenter、unshare、iptables、nft、systemctl 和递归启动 OpenCode。
- 禁止子代理、Skill、WebFetch、WebSearch 和交互式提问；网络访问只能通过 shell，并受任务出口白名单约束。
{docker_rule}
"""


def redact_sensitive_text(text: str, secret_values: tuple[str, ...] = ()) -> str:
    redacted = text
    for secret in secret_values:
        if len(secret) >= 4:
            redacted = redacted.replace(secret, "[REDACTED]")
    for pattern in _SECRET_VALUE_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]", redacted)
    return redacted


def sanitized_subprocess_env() -> dict[str, str]:
    return {name: value for name, value in os.environ.items() if not _SENSITIVE_NAME_RE.search(name)}


def _safe_run(command: list[str], **kwargs):
    kwargs.setdefault("env", sanitized_subprocess_env())
    return subprocess.run(command, **kwargs)


def _safe_popen(command: list[str], **kwargs):
    kwargs.setdefault("env", sanitized_subprocess_env())
    return subprocess.Popen(command, **kwargs)


def _task_secret_values() -> tuple[str, ...]:
    values = [value for name, value in os.environ.items() if _SENSITIVE_NAME_RE.search(name) and value]
    token_path = Path(REPRO_MODEL_TOKEN_FILE).expanduser() if REPRO_MODEL_TOKEN_FILE else None
    if token_path and token_path.is_file():
        try:
            token = token_path.read_text(encoding="utf-8").strip()
            if token:
                values.append(token)
        except OSError:
            pass
    return tuple(dict.fromkeys(values))


def _validated_token_path(token_path: Path | None = None) -> Path:
    configured_path = str(token_path or REPRO_MODEL_TOKEN_FILE)
    if not configured_path:
        raise RuntimeError("REPRO_MODEL_TOKEN_FILE is required for capability reproduction")
    token_path = Path(configured_path).expanduser()
    try:
        file_stat = token_path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Repro model token file does not exist: {token_path}") from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise RuntimeError("Repro model token path must be a regular non-symlink file")
    if file_stat.st_mode & 0o077:
        raise RuntimeError("Repro model token file permissions must not allow group or other access")
    return token_path.resolve()


def _validated_managed_config_path(config_path: Path) -> Path:
    config_path = config_path.expanduser()
    try:
        file_stat = config_path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Managed OpenCode config file does not exist: {config_path}") from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise RuntimeError("Managed OpenCode config path must be a regular non-symlink file")
    if file_stat.st_mode & 0o077:
        raise RuntimeError("Managed OpenCode config permissions must not allow group or other access")
    return config_path.resolve()


def validate_repro_runtime_config(
    *,
    check_image: bool = False,
    token_path: Path | None = None,
    require_token: bool = True,
    execution_profile: str = "nested_docker",
) -> Path | None:
    if execution_profile not in {"standard", "nested_docker"}:
        raise RuntimeError(f"unknown reproduction execution profile: {execution_profile}")
    validate_repro_resource_limits()
    validate_repro_queue_limits()
    validated_token_path = _validated_token_path(token_path) if require_token else None
    if not REPRO_LLM_BASE_URL:
        raise RuntimeError("REPRO_LLM_BASE_URL is required for capability reproduction")
    parsed_gateway = urllib.parse.urlparse(REPRO_LLM_BASE_URL)
    if parsed_gateway.scheme not in {"http", "https"} or parsed_gateway.username or parsed_gateway.password or not parsed_gateway.path.rstrip("/").endswith("/api/model-gateway/v1"):
        raise RuntimeError("REPRO_LLM_BASE_URL must point to the AI4SEC /api/model-gateway/v1 endpoint")
    if check_image:
        if execution_profile == "standard":
            security = _safe_run(
                ["docker", "info", "--format", "{{json .SecurityOptions}}"],
                capture_output=True,
                text=True,
            )
            if security.returncode != 0 or "rootless" not in str(security.stdout).casefold():
                raise RuntimeError("standard reproduction profile requires a rootless Docker daemon")
            raise RuntimeError(
                "standard reproduction profile remains disabled until a rootless egress enforcement adapter is implemented"
            )
        else:
            runtimes = _safe_run(
                ["docker", "info", "--format", "{{json .Runtimes}}"],
                capture_output=True,
                text=True,
            )
            if runtimes.returncode != 0 or REPRO_RUNTIME not in str(runtimes.stdout):
                raise RuntimeError(f"nested_docker reproduction profile requires Docker runtime: {REPRO_RUNTIME}")
        image = REPRO_STANDARD_IMAGE if execution_profile == "standard" else REPRO_IMAGE
        image_check = _safe_run(
            [
                "docker", "run", "--rm", "--entrypoint", "/bin/sh", image, "-c",
                "test ! -e /root/.local/share/opencode/auth.json "
                "-a ! -e /home/repro/.local/share/opencode/auth.json",
            ],
            capture_output=True,
            text=True,
        )
        if image_check.returncode != 0:
            raise RuntimeError(
                f"Repro image is unavailable or contains a baked OpenCode auth file: {image}"
            )
        validate_repro_egress_runtime(_safe_run, gateway_url=REPRO_LLM_BASE_URL)
    return validated_token_path


def validate_repro_resource_limits() -> None:
    try:
        cpus = float(REPRO_CPUS)
        nested_cpus = float(REPRO_NESTED_CPUS)
    except ValueError as exc:
        raise RuntimeError("REPRO_CPUS and REPRO_NESTED_CPUS must be numbers") from exc
    if not 0.1 <= cpus <= 64:
        raise RuntimeError("REPRO_CPUS must be between 0.1 and 64")
    if not 0.1 <= nested_cpus <= cpus:
        raise RuntimeError("REPRO_NESTED_CPUS must be between 0.1 and REPRO_CPUS")
    for name, value in (
        ("REPRO_MEMORY", REPRO_MEMORY),
        ("REPRO_MEMORY_SWAP", REPRO_MEMORY_SWAP),
        ("REPRO_NESTED_MEMORY", REPRO_NESTED_MEMORY),
        ("REPRO_NESTED_MEMORY_SWAP", REPRO_NESTED_MEMORY_SWAP),
    ):
        if not _DOCKER_SIZE_RE.fullmatch(value):
            raise RuntimeError(f"{name} must be a positive Docker size such as 512m or 4g")
    try:
        pids_limit = int(REPRO_PIDS_LIMIT)
        nested_pids_limit = int(REPRO_NESTED_PIDS_LIMIT)
    except ValueError as exc:
        raise RuntimeError("REPRO_PIDS_LIMIT must be an integer") from exc
    numeric_limits = (
        ("REPRO_PIDS_LIMIT", pids_limit, 16, 65536),
        ("REPRO_NESTED_PIDS_LIMIT", nested_pids_limit, 16, 65536),
        ("REPRO_CONTAINER_TIMEOUT", CONTAINER_TIMEOUT, 60, 86400),
        ("REPRO_WEB_CONTAINER_TIMEOUT", WEB_CONTAINER_TIMEOUT, 60, 86400),
        ("REPRO_REPORT_GRACE_TIMEOUT", REPORT_GRACE_TIMEOUT, 0, 7200),
        ("REPRO_WORKSPACE_MAX_BYTES", REPRO_WORKSPACE_MAX_BYTES, 100 * 1024 * 1024, 100 * 1024 * 1024 * 1024),
        ("REPRO_LOG_MAX_BYTES", REPRO_LOG_MAX_BYTES, 64 * 1024, 50 * 1024 * 1024),
    )
    for name, value, minimum, maximum in numeric_limits:
        if not minimum <= value <= maximum:
            raise RuntimeError(f"{name} must be between {minimum} and {maximum}")


def repro_resource_limits_payload() -> dict[str, Any]:
    validate_repro_resource_limits()
    return {
        "cpus": float(REPRO_CPUS),
        "memory": REPRO_MEMORY,
        "memory_swap": REPRO_MEMORY_SWAP,
        "pids": int(REPRO_PIDS_LIMIT),
        "container_timeout_seconds": CONTAINER_TIMEOUT,
        "web_container_timeout_seconds": WEB_CONTAINER_TIMEOUT,
        "report_grace_timeout_seconds": REPORT_GRACE_TIMEOUT,
        "workspace_max_bytes": REPRO_WORKSPACE_MAX_BYTES,
        "log_max_bytes": REPRO_LOG_MAX_BYTES,
        "profiles": {
            "standard": {
                "cpus": float(REPRO_CPUS),
                "memory": REPRO_MEMORY,
                "memory_swap": REPRO_MEMORY_SWAP,
                "pids": int(REPRO_PIDS_LIMIT),
            },
            "nested_docker": {
                "cpus": float(REPRO_NESTED_CPUS),
                "memory": REPRO_NESTED_MEMORY,
                "memory_swap": REPRO_NESTED_MEMORY_SWAP,
                "pids": int(REPRO_NESTED_PIDS_LIMIT),
                "max_concurrent_tasks": 1,
                "approval_required": True,
            },
        },
    }


def opencode_permission_policy(execution_profile: str) -> dict[str, Any]:
    if execution_profile not in {"standard", "nested_docker"}:
        raise ValueError(f"unknown reproduction execution profile: {execution_profile}")
    bash_rules = {
        "*": "allow",
        "sudo": "deny",
        "sudo *": "deny",
        "su": "deny",
        "su *": "deny",
        "mount": "deny",
        "mount *": "deny",
        "umount": "deny",
        "umount *": "deny",
        "nsenter *": "deny",
        "unshare *": "deny",
        "iptables *": "deny",
        "ip6tables *": "deny",
        "nft *": "deny",
        "systemctl *": "deny",
        "service *": "deny",
        "opencode *": "deny",
    }
    if execution_profile == "standard":
        bash_rules.update({
            "docker": "deny",
            "docker *": "deny",
            "dockerd *": "deny",
            "podman": "deny",
            "podman *": "deny",
        })
    else:
        bash_rules.update({
            "docker run *--privileged*": "deny",
            "docker run *--network host*": "deny",
            "docker run *--network=host*": "deny",
            "docker run *--pid host*": "deny",
            "docker run *--pid=host*": "deny",
            "docker run *--ipc host*": "deny",
            "docker run *--ipc=host*": "deny",
            "docker run *--uts host*": "deny",
            "docker run *--uts=host*": "deny",
        })
    policy = {
        "*": "deny",
        "read": {
            "*": "allow",
            "*.env": "deny",
            "*.env.*": "deny",
            "*.env.example": "allow",
            "/run/secrets/**": "deny",
        },
        "edit": "allow",
        "glob": "allow",
        "grep": "allow",
        "list": "allow",
        "bash": bash_rules,
        "task": "deny",
        "skill": "deny",
        "lsp": "allow",
        "todowrite": "allow",
        "question": "deny",
        "webfetch": "deny",
        "websearch": "deny",
        "external_directory": {
            "*": "deny",
            "/workspace/**": "allow",
            "/tmp/**": "allow",
        },
        "doom_loop": "deny",
    }
    validate_opencode_permission_policy(policy, execution_profile=execution_profile)
    return policy


def validate_opencode_permission_policy(policy: dict[str, Any], *, execution_profile: str) -> None:
    actions = {"allow", "deny", "ask"}
    for rule in policy.values():
        if isinstance(rule, str):
            if rule not in actions:
                raise RuntimeError(f"invalid OpenCode permission action: {rule}")
        elif isinstance(rule, dict):
            if not rule or any(action not in actions for action in rule.values()):
                raise RuntimeError("invalid granular OpenCode permission policy")
        else:
            raise RuntimeError("invalid OpenCode permission rule")
    if policy.get("*") != "deny":
        raise RuntimeError("OpenCode permissions must deny unknown tools by default")
    if policy.get("external_directory", {}).get("*") != "deny":
        raise RuntimeError("OpenCode external directories must be denied by default")
    bash = policy.get("bash")
    if not isinstance(bash, dict) or bash.get("*") != "allow":
        raise RuntimeError("OpenCode reproduction requires an explicit bash fallback")
    required_denials = ("sudo *", "mount *", "nsenter *", "unshare *", "iptables *", "nft *")
    if any(bash.get(pattern) != "deny" for pattern in required_denials):
        raise RuntimeError("OpenCode bash policy is missing a required dangerous-command denial")
    if execution_profile == "standard" and bash.get("docker *") != "deny":
        raise RuntimeError("standard OpenCode profile must deny Docker commands")
    if execution_profile == "nested_docker" and bash.get("docker run *--privileged*") != "deny":
        raise RuntimeError("nested_docker OpenCode profile must deny privileged child containers")


def managed_opencode_config(execution_profile: str) -> dict[str, Any]:
    managed_provider = "ai4sec-managed"
    permissions = opencode_permission_policy(execution_profile)
    return {
        "$schema": "https://opencode.ai/config.json",
        "provider": {
            managed_provider: {
                "npm": "@ai-sdk/openai-compatible",
                "name": "AI4SEC Managed Model",
                "options": {
                    "baseURL": REPRO_LLM_BASE_URL,
                    "apiKey": f"{{file:{CONTAINER_MODEL_TOKEN_FILE}}}",
                },
                "models": {REPRO_LLM_MODEL: {"name": REPRO_LLM_MODEL}},
            }
        },
        "model": f"{managed_provider}/{REPRO_LLM_MODEL}",
        "permission": permissions,
        "agent": {"build": {"permission": permissions}},
        "plugin": [],
    }


# ============================================================================
# 复现任务 prompt
# ============================================================================
def _build_repro_prompt(execution_profile: str = "nested_docker") -> str:
    """构建普通项目复现 prompt，不包含任何模型凭据。"""
    llm_section = _managed_llm_prompt_section()
    permission_section = _profile_permission_prompt_section(execution_profile)
    identity = (
        "你是 root，可安装系统包并使用嵌套 Docker"
        if execution_profile == "nested_docker"
        else "你是 rootless 容器内的 root，但不能使用系统包管理器、sudo 或 Docker"
    )
    return f"""你在一个隔离容器里（{identity}），目标是【把一个开源项目跑起来、确认环境可用、并尽量跑出真实运行效果】。
仓库已 clone 到 /workspace/repo。全程用中文说明你在做什么。
{llm_section}
{permission_section}
# 第一步:判断复现难度(决定你要跑多深)
读 README、依赖清单、项目结构后,判断这个项目属于哪一级:
- L1 轻量:纯库/命令行工具,依赖小。→ 装好 + 跑出最小示例/demo,看到真实输出。
- L2 中等:有较重依赖但能装。→ 装好 + 能 import + 能跑 --help 或最小示例。
- L3 重型:需要 GPU / 大数据集 / 大模型权重 / 必须的外部 API key 才能真正运行。
  → 只做"环境就绪":装好依赖、确认入口存在,然后明确报告"需要什么才能实际运行",不要硬跑(会超时白费)。

# 探索预算（必须遵守）
- 最多使用 6 次定位命令了解仓库；优先只读根目录 README、主依赖清单和明确的 examples/ 入口。
- 禁止递归 `ls`/`find`/`rg` 扫描 `docs`、`.git`、`node_modules`、`target`、测试夹具或生成目录；不要为了“了解项目”列举整棵目录树。
- 框架或库项目应在 `/tmp` 写最小调用程序，引用 `/workspace/repo` 的固定源码；Web 项目优先启动最小路由并用 loopback HTTP 请求验证，不要先阅读完整文档站。
- 任一网络下载或命令连续两次失败时停止重试，记录 blocker 并进入报告；不得耗尽任务时限。

# 第二步:按难度复现
1. 装依赖(venv 或直接装都行,你是 root)。
   ⚠️ 重要:不要试图装全部依赖。先看哪些是"导入主模块/跑最小示例"必需的核心依赖,只装核心。
   - 大包(torch/scipy/tensorflow 等)非核心就跳过,别装。
   - 单个 pip 命令最多等几分钟,装不上就跳过那个包,继续下一步,绝不在依赖上反复重试耗死。
   - 如果一个项目要装十几个重包才能跑,基本说明它是 L3 重型,直接判 L3、报告"环境就绪需要这些依赖"即可,不要硬装。
2. 确认能跑:优先 `python -c "import 主模块"`、`xxx --help`、README 里的最小示例。
   ❌ 不要跑 pytest/完整测试套件,不要为测试通过反复调参数。
3. L1/L2 尽量真的跑一下最小示例,记录真实输出(这是复现报告最有价值的部分)。
   L3 确认环境就绪即可,如实报告缺什么。
4. 单步卡住就跳过并记录,不要反复重试。

# 第三步(最重要):输出结构化复现报告
完成后,你必须在最后输出一段 JSON 报告,用下面的标记包裹(便于程序提取):
===REPRO_REPORT_START===
{{
  "schema_version": "1.0",
  "level": "L1|L2|L3",
  "status": "success|partial|failed",
  "summary": "一句话结论,如:成功装好依赖并跑通最小示例,输出符合预期",
  "project_type": "python|node|rust|go|其他",
  "environment": {{
    "language": "如 Python 3.10",
    "key_deps": ["列出关键依赖"],
    "needs_gpu": true/false,
    "needs_api_key": true/false,
    "needs_dataset": true/false
  }},
  "steps": [
    {{"cmd": "实际执行的关键命令", "ok": true/false, "note": "可选,如耗时/报错简述"}}
  ],
  "run_result": {{
    "ran": true/false,
    "command": "实际用于运行的命令(没跑成填空)",
    "output_excerpt": "真实输出的关键片段(没有填空)",
    "what_it_does": "用中文说明跑出了什么、是否符合项目宣称的功能"
  }},
  "evidence": ["真实命令输出、生成文件或服务响应摘要"],
  "limitations": ["当前限制"],
  "blockers": ["卡点/缺失项,如:需 OpenAI key 才能调用核心功能"],
  "gotchas": ["踩坑记录,如:README 命令有误,真实入口是 src/run.py"],
  "usage": {{
    "what": "这个项目是干什么的(一两句话,让没接触过的人看懂)",
    "how_to_use": "用户拿到这个项目后具体怎么用(操作流程/命令/页面交互,写清楚步骤)",
    "prerequisites": "使用前必须配置的东西(API key、数据库、环境变量等,没有就留空)",
    "limitations": "当前状态下的限制或注意事项(哪些功能不可用、需要额外条件等,没有就留空)"
  }}
}}
===REPRO_REPORT_END===

usage 字段是给用户看的"使用说明",注意:不要写安装部署步骤(已经装好了),重点写:
- what: 这个项目是干什么的,解决什么问题
- how_to_use: 具体怎么用(如:运行什么命令/打开什么页面/怎么输入/输出是什么)
- prerequisites: 使用前必须先配好的东西(如 API key、数据库连接),没有就留空
- limitations: 当前有什么限制(如某功能需要 GPU、某模块未启动等)
- 用中文,简洁直接,站在"用户已经拿到这个工具了,告诉他怎么用"的角度写
- 如果复现失败(status=failed),usage 里只填 what 和 limitations

报告要诚实:跑不起来就 status=failed 并在 blockers 说清缺什么;部分成功用 partial。
非 Web 项目只有在真实执行了最小示例、所有关键 steps 的 ok 都为 true、run_result.ran=true 且同时填写 command、output_excerpt、what_it_does 后才能使用 status=success；只完成 import、--help 或环境准备的 L3 项目最多使用 partial。
status=failed/partial 的报告同样有价值(让使用者知道这个项目要什么、卡在哪)。
JSON 必须合法(可被解析),字符串里不要有未转义的引号或换行。
"""


def _build_web_repro_prompt(execution_profile: str = "nested_docker") -> str:
    """构建 Web 项目复现 prompt，不包含任何模型凭据。"""
    llm_section = _managed_llm_prompt_section()
    permission_section = _profile_permission_prompt_section(execution_profile)
    identity = (
        "你是 root，可安装系统包并使用嵌套 Docker"
        if execution_profile == "nested_docker"
        else "你是 rootless 容器内的 root，但不能使用系统包管理器、sudo 或 Docker"
    )
    return f"""你在一个隔离容器里（{identity}），需要复现一个项目。仓库已 clone 到 /workspace/repo。全程用中文说明。
{llm_section}
{permission_section}
# 时间纪律
- Web 复现总预算约 50 分钟。必须在第 45 分钟前停止继续探索，把已经验证的事实立即整理成结构化报告。
- 核心闭环已经验证后，不要继续枚举非必要 API 或追求覆盖所有功能；优先输出报告，未覆盖部分写入 limitations。

# 第零步(最重要):先判断这个项目【本身】到底有没有 Web 界面
读 README、看项目结构,判断它是否【自带】一个真正的 Web 应用/界面:
- 有真 Web 界面的标志:项目里有前端代码(React/Vue/HTML 应用)、或用 streamlit/gradio/flask/fastapi 写的、
  README 明确说"启动后访问 localhost:xxxx 看界面/dashboard"。
- ❌ 如果项目【本身没有】Web 界面(它是 CLI 工具、Python 库、研究代码、prompt/数据集合集等),
  你【绝对不要】自己造一个网页(比如写个 Flask 把一堆 .md 文件列出来)。那样毫无价值。
  这种情况直接如实报告:is_web=false、web_started=false,在 summary 说清"该项目本身没有 Web 界面,它是 XX 类型"。
- 例外仅适用于本轮明确标为 Web 框架库的 FastAPI、Express、Gin、Axum：仓库没有独立应用入口时，
  必须在 `/tmp` 用 `/workspace/repo` 的固定源码写一个最小真实路由应用，启动到 0.0.0.0:8080，
  再以 HTTP 请求验证框架路由/参数/响应。该最小应用是框架能力证据，不是伪造网页；报告要明确它位于 `/tmp`。

# 如果确认项目自带 Web 界面,才执行下面的启动流程
- 服务必须监听 0.0.0.0:8080(容器已把主机端口映射到容器内 8080)。
- 常见启动方式:
  · Streamlit: `streamlit run xxx.py --server.address 0.0.0.0 --server.port 8080`
  · Gradio: 设 server_name="0.0.0.0", server_port=8080
  · Flask/FastAPI: `uvicorn main:app --host 0.0.0.0 --port 8080`
  · Node/Vite/React: `--host 0.0.0.0 --port 8080` 或 PORT=8080;前端项目先 npm install
- 在【后台】启动(nohup/setsid &)。启动后【sleep 10 秒等服务起来】,再 `curl -s http://localhost:8080`。
  如果 curl 暂时没响应,最多等 30 秒重试 2-3 次,仍不行就如实报告 web_started=false 并结束。
- 用项目【原有】的前端,不要自己另写页面。服务起成功后保持运行,不要停。

# 启动命令纪律（避免“项目能跑但命令写错”导致假失败）
- 启动前先定位真正的应用根目录；容器复现一律不要使用 `--reload` 或 hot reload。
- 后台启动后记录 PID，需要停止重试时精确 kill 该 PID，禁止使用可能误杀当前 shell 的 `pkill -f`。
- 首次启动失败不能直接结束：读取服务日志，检查工作目录、模块路径、端口和依赖，至少修正重试一次。
- 前后端分离项目必须确认前端 `/api` 代理指向已启动的后端，并验证配置由实际运行进程读取。
- `curl http://localhost:8080` 只证明页面服务启动，不能单独作为项目复现成功的依据。

# 核心可用性验收（必须执行，禁止“首页 200 = 复现成功”）
- 先定义项目最核心的用户价值与最短操作闭环，至少完成一条超越登录和普通 CRUD 的真实业务链。
- 核心链依赖 LLM、API 或数据库时，必须检查真实 provider/model、响应内容和错误信息，不能只检查 HTTP 状态码。
- 若核心 LLM 阶段出现超时、JSON 解析失败或 schema 校验失败，先读取错误详情，降低 temperature、启用结构化输出，并至少重试 2 次。
- `status=success` 只用于核心业务链完整跑通；使用 mock、超时或关键阶段失败只能标记 partial/failed。
- 报告必须写出 `core_workflow`、实测步骤、真实证据、最终产物或失败阶段；未执行核心业务链不得报告 success。

# 步骤
1. 读 README/项目结构,先做第零步判断。
2. 若有 Web 界面:装依赖(你是 root)、按项目原有方式把服务起到 0.0.0.0:8080、curl 验证。
   装包注意:容器已配好 pip/npm 国内镜像(清华源/npmmirror),直接 pip install / npm install 即可,
   【不要】自己加 -i 指定别的源(尤其别用国外源),否则会很慢甚至超时。
3. 若无 Web 界面:不要启动任何东西,直接如实报告。

# 最后必须输出结构化报告(用标记包裹)
===REPRO_REPORT_START===
{{
  "schema_version": "1.0",
  "is_web": true/false,
  "status": "success|partial|failed",
  "summary": "一句话结论。若项目无 Web 界面,明确说明它是什么类型、为什么没界面",
  "web_started": true/false,
  "web_framework": "如 Streamlit / Gradio / React+Vite;无则填空",
  "start_command": "你启动服务的命令;没启动填空",
  "verify": "curl 验证结果;没验证填空",
  "core_workflow": {{"goal": "核心用户价值", "mode": "real|mock", "steps": [{{"action": "实际操作", "ok": true/false}}], "evidence": ["真实响应/产物摘要"], "result": "产物或失败阶段", "verified": true/false}},
  "environment": {{"language": "如 Python 3.10", "key_deps": ["关键依赖"]}},
  "steps": [{{"cmd": "关键命令", "ok": true/false, "note": "可选"}}],
  "evidence": ["真实响应/产物摘要"],
  "limitations": ["当前限制"],
  "blockers": ["卡点;若项目本身无Web界面,在此说明"],
  "gotchas": ["踩坑"],
  "usage": {{
    "what": "这个项目是干什么的(一两句话,让没接触过的人看懂)",
    "how_to_use": "用户打开页面后怎么用(页面上有什么功能/怎么操作/API怎么调用)",
    "prerequisites": "使用前必须配置的东西(API key、后端服务、数据库等,没有就留空)",
    "limitations": "当前状态下的限制(哪些功能不可用、需要额外条件等,没有就留空)"
  }}
}}
===REPRO_REPORT_END===

usage 字段是给用户看的"使用说明",不要写安装部署步骤,重点写怎么用:
- what: 项目是干什么的; how_to_use: 打开页面后怎么操作; prerequisites: 必须先配好什么; limitations: 有什么限制
- 用中文,站在"用户已经能访问这个服务了,告诉他怎么用"的角度写
- 若本次复现已经配置并验证 LLM/API/数据库，必须明确写“当前复现环境已配置并验证，无需用户额外配置”；只有缺失或未验证的配置才列为前置条件。
- 复现失败的话 usage 只填 what 和 limitations。

诚实第一:项目没有 Web 界面就如实说,绝不自己编造页面充数。JSON 必须合法。
"""


# ============================================================================
# 任务运行（迁自旧 repro.py ReproRunner）
# ============================================================================
class ReproRunner:
    """运行单个复现任务。把日志流通过回调推出去（供 SSE/WebSocket 用）。

    由 CapabilityReproWorker 在当前 Worker 线程中调用 run()。
    """

    def __init__(
        self,
        task_id: int,
        repo_url: str,
        repo_commit: str = "",
        on_log: Callable[[str], None] | None = None,
        on_status: Callable[..., None] | None = None,
        web_port: int | None = None,
        should_stop: Callable[[], bool] | None = None,
        on_heartbeat: Callable[[], None] | None = None,
        model_token_path: Path | None = None,
        approved_egress_domains: tuple[str, ...] = (),
        execution_profile: str = "nested_docker",
        managed_config_path: Path | None = None,
        runtime_owner_id: str = "",
        on_runtime: Callable[..., None] | None = None,
    ):
        self.task_id = task_id
        self.repo_url = repo_url
        if repo_commit and not re.fullmatch(r"[0-9a-fA-F]{40}", repo_commit):
            raise ValueError("repo_commit must be an empty value or a 40-character Git commit SHA")
        self.repo_commit = repo_commit.casefold()
        raw_on_log = on_log or (lambda line: None)
        self._raw_on_log = raw_on_log
        self._secret_values = _task_secret_values()
        self.on_log = self._emit_log
        self.on_status = on_status or (lambda status, **kw: None)
        self.should_stop = should_stop or (lambda: False)
        self.on_heartbeat = on_heartbeat or (lambda: None)
        self.model_token_path = model_token_path
        self.approved_egress_domains = approved_egress_domains
        if execution_profile not in {"standard", "nested_docker"}:
            raise ValueError(f"unknown reproduction execution profile: {execution_profile}")
        self.execution_profile = execution_profile
        self.managed_config_path = managed_config_path
        self.runtime_owner_id = runtime_owner_id
        self.on_runtime = on_runtime or (lambda **_values: None)
        _stamp = int(time.time())
        self.container_name = f"repro-{task_id}-{_stamp}"
        self.container_id = ""
        self.workspace = WORKSPACE_ROOT / f"task-{task_id}-{_stamp}"
        self.proc: subprocess.Popen | None = None
        self.status = "queued"
        self.web_port = web_port  # 主机端口（有则映射到容器内 8080，用于 Web 项目复现）
        self._logged_bytes = 0
        self._log_truncated = False
        self._egress_guard: DockerEgressGuard | None = None
        self._egress_policy = None
        self._proxy_proc: subprocess.Popen | None = None

    # ---- docker 命令构建 ----
    def build_run_command(self):
        """按任务 Profile 创建隔离容器。"""
        cpus, memory, memory_swap, pids_limit = (
            (REPRO_NESTED_CPUS, REPRO_NESTED_MEMORY, REPRO_NESTED_MEMORY_SWAP, REPRO_NESTED_PIDS_LIMIT)
            if self.execution_profile == "nested_docker"
            else (REPRO_CPUS, REPRO_MEMORY, REPRO_MEMORY_SWAP, REPRO_PIDS_LIMIT)
        )
        cmd = [
            "docker", "run",
            "-d",
            "--name", self.container_name,
            "--label", f"{REPRO_DOCKER_LABEL_RESOURCE}={REPRO_DOCKER_RESOURCE}",
            "--label", f"{REPRO_DOCKER_LABEL_OWNER}={self.runtime_owner_id}",
            "--label", f"{REPRO_DOCKER_LABEL_TASK}={self.task_id}",
            "--label", f"{REPRO_DOCKER_LABEL_PROFILE}={self.execution_profile}",
            "--cpus", cpus,
            "--memory", memory,
            "--memory-swap", memory_swap,
            "--pids-limit", pids_limit,
            "--security-opt", "no-new-privileges=true",
            "--network", "bridge",
            "--dns", "127.0.0.1",
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
            "--add-host", "host.docker.internal:host-gateway",
            "--env", f"GOPROXY={REPRO_GO_PROXY}",
            "--env", f"CARGO_REGISTRIES_CRATES_IO_PROTOCOL={REPRO_CARGO_REGISTRY_PROTOCOL}",
            "--env", f"CARGO_HTTP_MULTIPLEXING={REPRO_CARGO_HTTP_MULTIPLEXING}",
            "-v", f"{self.workspace}:/workspace",
        ]
        if self.execution_profile == "nested_docker":
            cmd.extend([
                "--runtime", REPRO_RUNTIME,
                "--tmpfs", "/root/.local/share/opencode:rw,nosuid,nodev,noexec,mode=700",
            ])
            image = REPRO_IMAGE
        else:
            cmd.extend([
                "--read-only",
                "--cap-drop", "ALL",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,mode=1777",
                "--tmpfs", "/root/.config:rw,nosuid,nodev,noexec,mode=700",
                "--tmpfs", "/root/.local:rw,nosuid,nodev,noexec,mode=700",
            ])
            image = REPRO_STANDARD_IMAGE
        if self._egress_policy:
            for domain, address in self._egress_policy.host_addresses:
                if ":" not in address:
                    cmd.extend(["--add-host", f"{domain}:{address}"])
        token_path = _validated_token_path(self.model_token_path)
        cmd.extend(["--mount", f"type=bind,src={token_path},dst={CONTAINER_MODEL_TOKEN_FILE},readonly"])
        if self.managed_config_path:
            config_path = _validated_managed_config_path(self.managed_config_path)
            cmd.extend([
                "--mount",
                f"type=bind,src={config_path},dst={CONTAINER_MANAGED_OPENCODE_CONFIG},readonly",
            ])
        cmd.append(image)
        return cmd

    def build_exec_command(self):
        """docker exec 进容器，以 root 跑 clone + opencode。"""
        validate_repro_runtime_config(token_path=self.model_token_path, execution_profile=self.execution_profile)
        opencode_config = json.dumps(managed_opencode_config(self.execution_profile))
        encoded_config = base64.b64encode(opencode_config.encode()).decode()
        home = "/root"
        inject_managed_config = (
            f"mkdir -p {home}/.config/opencode; "
            f"echo '{encoded_config}' | base64 -d > {home}/.config/opencode/opencode.json; "
            f"echo '✓ opencode 已配置受管模型服务: {REPRO_LLM_BASE_URL}'; "
        )

        prompt = (
            _build_web_repro_prompt(self.execution_profile)
            if self.web_port
            else _build_repro_prompt(self.execution_profile)
        )
        if self.repo_commit:
            clone_command = (
                "rm -rf /workspace/repo; mkdir -p /workspace/repo; "
                "git -C /workspace/repo init -q; "
                f"git -C /workspace/repo remote add origin {shlex.quote(self.repo_url)}; "
                f"timeout 120 git -C /workspace/repo fetch --depth 1 origin {self.repo_commit} 2>&1 && "
                "git -C /workspace/repo checkout --detach -q FETCH_HEAD 2>&1"
            )
        else:
            clone_command = f"timeout 120 git clone --depth 1 {shlex.quote(self.repo_url)} /workspace/repo 2>&1"
        zip_url = _repo_archive_url(self.repo_url, self.repo_commit)

        inner = (
            "export LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONIOENCODING=utf-8; "
            f"if [ -f {CONTAINER_MODEL_TOKEN_FILE} ]; then "
            f"export OPENAI_API_KEY=\"$(cat {CONTAINER_MODEL_TOKEN_FILE})\" LLM_API_KEY=\"$(cat {CONTAINER_MODEL_TOKEN_FILE})\"; fi; "
            "export GIT_HTTP_LOW_SPEED_LIMIT=1000 GIT_HTTP_LOW_SPEED_TIME=30; "
            "set -e; "
            + inject_managed_config +
            f"mkdir -p {home}/.pip {home}/.config/pip; "
            "printf '[global]\\nindex-url = https://pypi.tuna.tsinghua.edu.cn/simple\\n"
            "trusted-host = pypi.tuna.tsinghua.edu.cn\\ntimeout = 120\\nretries = 5\\n' "
            f"| tee {home}/.pip/pip.conf {home}/.config/pip/pip.conf > /dev/null; "
            "npm config set registry https://registry.npmmirror.com 2>/dev/null || true; "
            "if [ -n \"$(ls -A /workspace/repo 2>/dev/null)\" ]; then "
            "  echo '✓ 宿主机已预下载 repo,跳过 clone'; "
            "else "
            "n=0; until [ $n -ge 3 ]; do "
            f"  {clone_command} && break; "
            "  n=$((n+1)); echo \"⚠ clone 失败(第 $n 次),5 秒后重试…\"; "
            "  rm -rf /workspace/repo; mkdir -p /workspace/repo; sleep 5; "
            "done; "
            "if [ -z \"$(ls -A /workspace/repo 2>/dev/null)\" ]; then "
            "  echo '⚠ git clone 三次均失败,尝试 zip 下载…'; "
            f"  ZIP_URL={shlex.quote(zip_url)}; "
            "  curl -fsSL --http1.1 --connect-timeout 30 --max-time 300 -o /tmp/repo.zip \"$ZIP_URL\" 2>&1 && "
            "  unzip -q /tmp/repo.zip -d /tmp/repo_unzip && "
            "  mv /tmp/repo_unzip/*/* /workspace/repo/ 2>/dev/null; mv /tmp/repo_unzip/*/.* /workspace/repo/ 2>/dev/null; "
            "  rm -rf /tmp/repo.zip /tmp/repo_unzip; "
            "  if [ -z \"$(ls -A /workspace/repo 2>/dev/null)\" ]; then echo '✗ zip 下载也失败,放弃'; exit 1; fi; "
            "  echo '✓ 已通过 zip 下载成功'; "
            "fi; "
            "fi; "
            "cd /workspace/repo; "
            "git config --global --add safe.directory /workspace/repo; "
            + (
                f"if [ -d .git ]; then test \"$(git rev-parse HEAD)\" = {self.repo_commit}; "
                f"else echo '✓ 已使用固定 commit archive: {self.repo_commit}'; fi; "
                if self.repo_commit else ""
            ) +
            "echo \"✓ 已 clone: $(git -C /workspace/repo remote get-url origin 2>/dev/null)\"; "
            "echo \"✓ pip 源: $(pip config get global.index-url 2>/dev/null || echo 默认)\"; "
            f"stdbuf -oL -eL opencode run --pure --agent build {shlex.quote(prompt)} 2>&1"
        )
        return [
            "docker", "exec", "-u", "root",
            "-e", "LANG=C.UTF-8", "-e", "LC_ALL=C.UTF-8", "-e", "PYTHONIOENCODING=utf-8",
            "-e", "HOME=/root",
            self.container_name,
            "bash", "-lc", inner,
        ]

    def run(self) -> None:
        """在当前线程执行，供持久 Worker 管理生命周期。"""
        if not self.managed_config_path:
            raise RuntimeError("managed OpenCode config is required for reproduction execution")
        _validated_managed_config_path(self.managed_config_path)
        if not re.fullmatch(r"[a-f0-9]{24}", self.runtime_owner_id):
            raise RuntimeError("valid repro runtime owner id is required")
        self._prepare_workspace()
        self._run()

    def _prepare_workspace(self) -> None:
        self.workspace.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(self.workspace, 1000, 1000)
        except (PermissionError, OSError):
            pass

    def _set_status(self, status, **kw):
        self.status = status
        self.on_status(status, **kw)

    def _emit_log(self, line: str) -> None:
        line = redact_sensitive_text(str(line), self._secret_values)
        if self._log_truncated:
            return
        encoded_bytes = len(line.encode("utf-8", errors="replace")) + 1
        if self._logged_bytes + encoded_bytes <= REPRO_LOG_MAX_BYTES:
            self._logged_bytes += encoded_bytes
            self._raw_on_log(line)
            return
        if not self._log_truncated:
            self._log_truncated = True
            self._raw_on_log(f"⚠ 日志达到 {REPRO_LOG_MAX_BYTES} 字节上限，后续输出已截断")

    def _remember_output(self, line: str) -> None:
        self._full_output.append(line)
        self._full_output_bytes += len(line.encode("utf-8", errors="replace")) + 1
        while self._full_output and self._full_output_bytes > REPRO_LOG_MAX_BYTES:
            removed = self._full_output.pop(0)
            self._full_output_bytes -= len(removed.encode("utf-8", errors="replace")) + 1

    def _workspace_size_exceeded(self) -> bool:
        total = 0
        try:
            for path in self.workspace.rglob("*"):
                if path.is_file() and not path.is_symlink():
                    total += path.stat().st_size
                    if total > REPRO_WORKSPACE_MAX_BYTES:
                        return True
        except OSError:
            return False
        return False

    def _run(self):
        self._set_status("running")
        self._tail: list[str] = []
        self._full_output: list[str] = []
        self._full_output_bytes = 0
        try:
            # 1. 起 systemd 容器（后台）
            _safe_run(["docker", "rm", "-f", self.container_name], capture_output=True, text=True)
            self._egress_policy = build_repro_egress_policy(
                self.repo_url,
                REPRO_LLM_BASE_URL,
                approved_domains=self.approved_egress_domains,
            )
            run_cmd = self.build_run_command()
            self._emit_log(f"$ {' '.join(shlex.quote(c) for c in run_cmd)}")
            r = _safe_run(run_cmd, capture_output=True, text=True)
            if r.returncode != 0:
                self._emit_log(f"✗ 起容器失败: {r.stderr.strip()}")
                self._set_status("failed", error=r.stderr.strip())
                return
            self.container_id = str(r.stdout or "").strip().splitlines()[0]
            if not re.fullmatch(r"[a-f0-9]{12,64}", self.container_id):
                inspected = _safe_run(
                    ["docker", "inspect", "--format", "{{.Id}}", self.container_name],
                    capture_output=True,
                    text=True,
                )
                self.container_id = str(inspected.stdout or "").strip()
            if not re.fullmatch(r"[a-f0-9]{12,64}", self.container_id):
                self._set_status("failed", error="container started without a persistent container id")
                return
            self.on_runtime(container_id=self.container_id)

            policy = self._egress_policy
            self._egress_guard = DockerEgressGuard(task_id=self.task_id, container_name=self.container_name, policy=policy, run_command=_safe_run)
            egress_summary = self._egress_guard.install()
            self.on_log(
                f"✓ 已启用强制出口策略: {egress_summary['allowed_public_ips']} 个公网 IP, "
                f"Gateway {egress_summary['gateway_ip'] or policy.gateway_host}:{policy.gateway_port}"
            )
            for domain in self.approved_egress_domains:
                addresses = sorted(address for mapped_domain, address in policy.host_addresses if mapped_domain == domain)
                self.on_log(f"• 任务出口批准: {domain} -> {', '.join(addresses) or '未解析'}")

            if self.execution_profile == "nested_docker":
                self._emit_log("• 等待容器内 Docker 服务就绪…")
                if not self._wait_dockerd():
                    self._emit_log("✗ nested_docker 容器内 Docker 未就绪")
                    self._set_status("failed", error="nested Docker daemon did not become ready")
                    return

            # 2.1 启动端口代理（sysbox 容器用 nsenter 替代 docker -p）
            self._start_port_proxy()

            # 2.5 宿主机侧预 clone
            host_repo = self.workspace / "repo"
            if not host_repo.exists() or not any(host_repo.iterdir()):
                host_repo.mkdir(parents=True, exist_ok=True)
                self.on_log("• 宿主机侧 clone 仓库…")
                clone_ok = False
                for attempt in range(2):
                    if self.repo_commit:
                        init_result = _safe_run(["git", "-C", str(host_repo), "init", "-q"], capture_output=True, text=True)
                        remote_result = _safe_run(
                            ["git", "-C", str(host_repo), "remote", "add", "origin", self.repo_url],
                            capture_output=True,
                            text=True,
                        )
                        fetch_result = _safe_run(
                            ["timeout", "90", "git", "-C", str(host_repo), "fetch", "--depth", "1", "origin", self.repo_commit],
                            capture_output=True,
                            text=True,
                        )
                        cr = _safe_run(
                            ["git", "-C", str(host_repo), "checkout", "--detach", "-q", "FETCH_HEAD"],
                            capture_output=True,
                            text=True,
                        ) if init_result.returncode == remote_result.returncode == fetch_result.returncode == 0 else fetch_result
                    else:
                        cr = _safe_run(
                            ["timeout", "90", "git", "clone", "--depth", "1", self.repo_url, str(host_repo)],
                            capture_output=True, text=True,
                        )
                    if cr.returncode == 0:
                        clone_ok = True
                        self.on_log("✓ 宿主机 clone 成功")
                        break
                    else:
                        self.on_log(f"⚠ 宿主机 clone 失败(第{attempt + 1}次): {cr.stderr.strip()[:100]}")
                        shutil.rmtree(host_repo, ignore_errors=True)
                        host_repo.mkdir(parents=True, exist_ok=True)
                if not clone_ok:
                    self.on_log("• 尝试宿主机 zip 下载…")
                    zip_url = _repo_archive_url(self.repo_url, self.repo_commit)
                    zr = _safe_run(
                        ["curl", "-fsSL", "--http1.1", "--connect-timeout", "30", "--max-time", "600",
                         "-o", "/tmp/_repro_repo.zip", zip_url],
                        capture_output=True, text=True,
                    )
                    if zr.returncode == 0:
                        _safe_run(["unzip", "-q", "/tmp/_repro_repo.zip", "-d", "/tmp/_repro_unzip"], capture_output=True)
                        import glob
                        subdirs = glob.glob("/tmp/_repro_unzip/*/")
                        if subdirs:
                            for item in os.listdir(subdirs[0]):
                                src = os.path.join(subdirs[0], item)
                                dst = str(host_repo / item)
                                if os.path.isdir(src):
                                    shutil.copytree(src, dst, dirs_exist_ok=True)
                                else:
                                    shutil.copy2(src, dst)
                        shutil.rmtree("/tmp/_repro_unzip", ignore_errors=True)
                        if os.path.exists("/tmp/_repro_repo.zip"):
                            os.remove("/tmp/_repro_repo.zip")
                        if any(host_repo.iterdir()):
                            self.on_log("✓ 宿主机 zip 下载成功")
                        else:
                            self.on_log("⚠ zip 解压后为空")
                    else:
                        self.on_log(f"⚠ 宿主机 zip 下载失败: {zr.stderr.strip()[:100]}")

            # 3. exec 进去跑复现，流式读输出
            prompt = (
                _build_web_repro_prompt(self.execution_profile)
                if self.web_port
                else _build_repro_prompt(self.execution_profile)
            )
            self._emit_log("┌─ 发给 AI agent 的复现指令(prompt)─────────────")
            for pl in prompt.strip().split("\n"):
                self._emit_log("│ " + pl)
            self._emit_log("└──────────────────────────────────────────────")
            self._emit_log("")
            exec_cmd = self.build_exec_command()
            _env = sanitized_subprocess_env()
            _env.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8"})
            self.proc = _safe_popen(
                exec_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=_env,
            )
            start_ts = time.time()
            grace_started = False
            output_queue: queue.Queue[str | None] = queue.Queue()

            def read_output() -> None:
                try:
                    for output_line in self.proc.stdout:
                        output_queue.put(output_line)
                finally:
                    output_queue.put(None)

            threading.Thread(target=read_output, name=f"repro-output-{self.task_id}", daemon=True).start()
            next_workspace_check = start_ts
            while True:
                try:
                    line = output_queue.get(timeout=0.5)
                except queue.Empty:
                    line = ""
                if line is None:
                    break
                if line:
                    clean = line.rstrip("\n")
                    self.on_log(clean)
                    self._tail.append(clean)
                    self._remember_output(clean)
                    if len(self._tail) > 40:
                        self._tail.pop(0)
                self.on_heartbeat()
                if self.should_stop():
                    self.on_log("■ 收到停止请求，正在终止复现任务")
                    self._stop_port_proxy()
                    _safe_run(["docker", "stop", self.container_name], capture_output=True)
                    if self.proc.poll() is None:
                        self.proc.terminate()
                    self._set_status("stopped")
                    return
                timeout_limit = WEB_CONTAINER_TIMEOUT if self.web_port else CONTAINER_TIMEOUT
                elapsed = time.time() - start_ts
                if elapsed > timeout_limit:
                    report = enforce_report_acceptance(extract_report("\n".join(self._full_output)))
                    if report:
                        final_status = task_status_from_report(report)
                        self.on_log("✓ 已在报告宽限阶段取得结构化报告")
                        if self.proc.poll() is None:
                            self.proc.terminate()
                        self._set_status(final_status, report=report, result="复现报告已完成")
                        return
                    if elapsed <= timeout_limit + REPORT_GRACE_TIMEOUT:
                        if not grace_started:
                            grace_started = True
                            self.on_log(
                                f"⏱ 已达到基础执行时限，额外保留 {REPORT_GRACE_TIMEOUT // 60} 分钟用于输出结构化报告"
                            )
                        continue
                    if self.web_port:
                        self.on_log("⏱ Agent 流程超时,容器保活;未完成核心验收时只能标记部分复现")
                        if self.proc.poll() is None:
                            self.proc.terminate()
                        self._set_status(
                            "partial",
                            report=report,
                            result="agent 流程超时,容器保活;核心可用性需要继续验证",
                        )
                    else:
                        self.on_log("⏱ 超时,停止容器")
                        _safe_run(["docker", "stop", self.container_name], capture_output=True)
                        if self.proc.poll() is None:
                            self.proc.terminate()
                        self._set_status("timeout", report=report)
                    return
                if time.time() >= next_workspace_check:
                    next_workspace_check = time.time() + 5
                    if self._workspace_size_exceeded():
                        self.on_log(f"✗ workspace 超过 {REPRO_WORKSPACE_MAX_BYTES} 字节上限，停止任务")
                        _safe_run(["docker", "stop", self.container_name], capture_output=True)
                        if self.proc.poll() is None:
                            self.proc.terminate()
                        self._set_status("failed", error="workspace size limit exceeded")
                        return
            rc = self.proc.wait()
            full = "\n".join(self._full_output)
            result_summary = "\n".join(self._tail[-20:])
            report = enforce_report_acceptance(extract_report(full))
            # ★ 适配点:去掉旧 v1 的 import db + db.update_item_web_class 调用
            #   原 v1 在这里通过 on_status 回调通知外部，由外部处理 DB 回写
            #   （is_web 修正逻辑移到 on_status 回调处理）
            if not self.web_port:
                _safe_run(["docker", "stop", self.container_name], capture_output=True)
            if report and isinstance(report, dict) and report.get("status"):
                final = task_status_from_report(report)
                self._set_status(final, result=result_summary, report=report)
            elif rc == 0:
                self._set_status("failed", result="Agent 未输出结构化复现报告\n" + result_summary, report=report)
            else:
                self._set_status("failed", returncode=rc, result=result_summary, report=report)
        except Exception as e:
            self.on_log(f"✗ 编排器错误: {e}")
            self._set_status("failed", error=str(e))
        finally:
            if not (self.web_port and self.status in {"success", "partial"}):
                try:
                    self._stop_port_proxy()
                finally:
                    _safe_run(["docker", "stop", self.container_name], capture_output=True)
            if self._egress_guard:
                audit = self._egress_guard.remove()
                self.on_log(
                    f"• 已撤销出口策略 {audit['chain']}; "
                    f"拒绝 {audit['denied_packets']} 个包/{audit['denied_bytes']} 字节"
                )

    def _wait_dockerd(self):
        """等容器内 docker 守护进程就绪（最多 DOCKERD_WAIT 秒）。"""
        deadline = time.time() + DOCKERD_WAIT
        while time.time() < deadline:
            chk = _safe_run(
                ["docker", "exec", self.container_name, "docker", "info"],
                capture_output=True, text=True,
            )
            if chk.returncode == 0:
                return True
            time.sleep(2)
        return False

    # ---- sysbox 端口代理（替代 docker -p）----
    def _start_port_proxy(self):
        """在宿主机启动 socat 代理，通过 nsenter 进入容器网络命名空间转发流量。
        原因:sysbox 容器使用 user namespace 隔离，docker -p 端口映射的 docker-proxy
        无法通过 ARP 到达容器 IP，导致连接被 reset。nsenter -n 绕过此限制。"""
        self._proxy_proc = None
        if not self.web_port:
            return
        try:
            r = _safe_run(
                ["docker", "inspect", "--format", "{{.State.Pid}}", self.container_name],
                capture_output=True, text=True,
            )
            cpid = r.stdout.strip()
            if not cpid or cpid == "0":
                self.on_log("⚠ 无法获取容器 PID,端口代理未启动")
                return
            proxy_cmd = [
                "socat",
                f"TCP-LISTEN:{self.web_port},bind=127.0.0.1,fork,reuseaddr",
                f"EXEC:nsenter -t {cpid} -n socat - TCP\\:127.0.0.1\\:8080",
            ]
            self._proxy_proc = _safe_popen(
                proxy_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            proxy_pid = int(getattr(self._proxy_proc, "pid", 0) or 0)
            if proxy_pid <= 1:
                raise RuntimeError("端口代理未返回有效 PID")
            self.on_runtime(proxy_pid=proxy_pid)
            self.on_log(f"✓ 端口代理已启动: 127.0.0.1:{self.web_port} → 容器:8080 (nsenter PID={cpid})")
        except Exception as e:
            if self._proxy_proc:
                try:
                    self._proxy_proc.terminate()
                    self._proxy_proc.wait(timeout=5)
                except Exception:
                    pass
                self._proxy_proc = None
            self.on_log(f"⚠ 启动端口代理失败: {e}")

    def _stop_port_proxy(self):
        """停止 socat 端口代理进程。"""
        if hasattr(self, '_proxy_proc') and self._proxy_proc:
            try:
                self._proxy_proc.terminate()
                self._proxy_proc.wait(timeout=5)
            except Exception:
                try:
                    self._proxy_proc.kill()
                except Exception:
                    pass
            self._proxy_proc = None
            try:
                self.on_runtime(proxy_pid=0)
            except Exception as error:
                self.on_log(f"⚠ 端口代理已停止，但 PID 状态持久化失败: {error}")

# ============================================================================
# 输出行分类（给大屏/SSE 上色用）- 迁自旧 repro.py 第 623-726 行
# ============================================================================
_ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]')
_BARE_ANSI_RE = re.compile(r'\[[0-9]{1,3}(?:;[0-9]{1,3})*m')


def strip_ansi(line: str) -> str:
    """去掉终端 ANSI 转义码（网页面板自己上色，不需要这些码）。"""
    line = _ANSI_RE.sub('', line)
    line = _BARE_ANSI_RE.sub('', line)
    return line


def enforce_report_acceptance(report: dict | None) -> dict | None:
    if not isinstance(report, dict):
        return report

    normalized = copy.deepcopy(report)
    normalized.setdefault("schema_version", "1.0")
    status = normalized.get("status")
    if status not in {"success", "partial", "failed"}:
        normalized["status"] = "failed"
        status = "failed"
    issues: list[str] = []
    if normalized.get("is_web"):
        if not normalized.get("web_started"):
            issues.append("Web 服务未成功启动或未验证")
        workflow = normalized.get("core_workflow")
        if not isinstance(workflow, dict):
            workflow = {}
        if workflow.get("verified") is not True:
            issues.append("未完成核心业务闭环验证")
        if str(workflow.get("mode") or "").strip().lower() != "real":
            issues.append("核心功能未使用真实模式验证")
        if not workflow.get("steps"):
            issues.append("核心业务闭环缺少实测步骤")
        if not workflow.get("evidence"):
            issues.append("核心业务闭环缺少真实结果证据")
        if not str(workflow.get("result") or "").strip():
            issues.append("核心业务闭环缺少结果说明")
    elif status == "success":
        if not str(normalized.get("summary") or "").strip():
            issues.append("成功报告缺少摘要")
        if not str(normalized.get("project_type") or "").strip():
            issues.append("成功报告缺少项目类型")
        steps = normalized.get("steps")
        if not isinstance(steps, list) or not steps:
            issues.append("成功报告缺少实测步骤")
        elif any(not isinstance(step, dict) or step.get("ok") is not True for step in steps):
            issues.append("成功报告包含未通过的实测步骤")
        run_result = normalized.get("run_result")
        if not isinstance(run_result, dict) or run_result.get("ran") is not True:
            issues.append("成功报告缺少真实运行证据")
        else:
            for field, label in (("command", "实际运行命令"), ("output_excerpt", "真实输出"), ("what_it_does", "结果说明")):
                if not str(run_result.get(field) or "").strip():
                    issues.append(f"成功报告缺少{label}")
        if str(normalized.get("level") or "").strip().upper() == "L3":
            issues.append("L3 项目只完成环境评估，不能标记完整成功")

    if issues and status == "success":
        normalized["status"] = "failed" if normalized.get("is_web") and not normalized.get("web_started") else "partial"
    if issues:
        existing_issues = normalized.get("acceptance_issues")
        if not isinstance(existing_issues, list):
            existing_issues = []
        normalized["acceptance_issues"] = list(dict.fromkeys([*existing_issues, *issues]))
        blockers = normalized.get("blockers")
        if not isinstance(blockers, list):
            blockers = []
        normalized["blockers"] = list(dict.fromkeys([*blockers, *[f"自动验收: {issue}" for issue in issues]]))
    return normalized


def task_status_from_report(report: dict | None, fallback: str = "failed") -> str:
    normalized = enforce_report_acceptance(report)
    if isinstance(normalized, dict) and normalized.get("status") in {"success", "partial", "failed"}:
        return str(normalized["status"])
    return fallback


def extract_report(full_output: str) -> dict | None:
    """从 agent 完整输出里提取结构化复现报告（JSON）。
    容错:标记找不到/JSON 解析失败都返回 None（降级用日志）。"""
    if not full_output:
        return None
    start_mark = "===REPRO_REPORT_START==="
    end_mark = "===REPRO_REPORT_END==="
    try:
        si = full_output.rfind(start_mark)
        ei = full_output.rfind(end_mark)
        if si == -1 or ei == -1 or ei <= si:
            return _try_loose_json(full_output)
        chunk = full_output[si + len(start_mark):ei].strip()
        return _parse_report_json(chunk)
    except Exception:
        return None


def _parse_report_json(chunk: str) -> dict | None:
    """解析报告 JSON，带几种容错。"""
    chunk = chunk.strip()
    if chunk.startswith("```"):
        chunk = chunk.split("\n", 1)[-1] if "\n" in chunk else chunk
        if chunk.endswith("```"):
            chunk = chunk[:-3]
        chunk = chunk.strip()
        if chunk.startswith("json"):
            chunk = chunk[4:].strip()
    try:
        data = json.loads(chunk)
        return data if isinstance(data, dict) else None
    except Exception:
        try:
            a = chunk.find("{")
            b = chunk.rfind("}")
            if a != -1 and b > a:
                return json.loads(chunk[a:b + 1])
        except Exception:
            pass
    return None


def _try_loose_json(text: str) -> dict | None:
    """没标记时，尝试从尾部找一段像报告的 JSON（含 status/summary 字段）。"""
    idx = len(text)
    while True:
        b = text.rfind("}", 0, idx)
        if b == -1:
            return None
        a = text.rfind("{", 0, b)
        while a != -1:
            try:
                cand = json.loads(text[a:b + 1])
                if isinstance(cand, dict) and ("status" in cand or "summary" in cand):
                    return cand
            except Exception:
                pass
            a = text.rfind("{", 0, a)
        idx = b
    return None


def classify_log_line(line: str) -> str:
    """根据 OpenCode 输出格式给行分类，大屏据此上色（7 类）。

    返回: tool|read|exec|ok|warn|error|text
    """
    s = line.lstrip()
    if s.startswith("✱") or s.startswith("•"):
        return "tool"
    if s.startswith("→") or s.startswith("[•]"):
        return "read"
    if s.startswith("$"):
        return "exec"
    if s.startswith(">"):
        return "tool"
    if s.startswith("✓") or s.startswith("[✓]"):
        return "ok"
    if s.startswith("!"):
        return "warn"
    low = s.lower()
    if s.startswith(("✗", "X ", "Error", "ERROR", "EACCES", "Internal Error", "Traceback")) \
       or low.startswith("npm error") or low.startswith("error") \
       or "failed" in s or "SchemaError" in s or "permission denied" in s:
        return "error"
    if s.startswith("#") or s.startswith("["):
        return "tool"
    return "text"
