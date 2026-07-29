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

from ai4sec_platform.core.env import load_env_file

load_env_file()

# ============================================================================
# 配置（集中在这里，方便调整。从 .env 读，去硬编码）
# ============================================================================
REPRO_IMAGE = os.environ.get("REPRO_IMAGE", "repro-runner:v3")
REPRO_RUNTIME = os.environ.get("REPRO_RUNTIME", "sysbox-runc")
WORKSPACE_ROOT = Path(os.environ.get("REPRO_WORKSPACE_ROOT", str(Path.home() / "repro_workspaces")))
CONTAINER_TIMEOUT = int(os.environ.get("REPRO_CONTAINER_TIMEOUT", str(30 * 60)))  # 30 分钟
WEB_CONTAINER_TIMEOUT = int(os.environ.get("REPRO_WEB_CONTAINER_TIMEOUT", str(50 * 60)))  # 50 分钟
DOCKERD_WAIT = int(os.environ.get("REPRO_DOCKERD_WAIT", "30"))
INTERNAL_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
REPRO_CPUS = os.environ.get("REPRO_CPUS", "2.0")
REPRO_MEMORY = os.environ.get("REPRO_MEMORY", "4g")
REPRO_MEMORY_SWAP = os.environ.get("REPRO_MEMORY_SWAP", REPRO_MEMORY)
REPRO_PIDS_LIMIT = os.environ.get("REPRO_PIDS_LIMIT", "1024")
REPRO_WORKSPACE_MAX_BYTES = int(os.environ.get("REPRO_WORKSPACE_MAX_BYTES", str(10 * 1024 * 1024 * 1024)))
REPRO_LOG_MAX_BYTES = int(os.environ.get("REPRO_LOG_MAX_BYTES", str(5 * 1024 * 1024)))

# DashScope API 代理（sysbox 容器内直连会卡死，通过宿主机 nginx 反代转发）
DASHSCOPE_PROXY_URL = os.environ.get("DASHSCOPE_PROXY_URL", "")

# 复现任务内 LLM 配置。真实凭据不得进入 Prompt。
REPRO_LLM_BASE_URL = os.environ.get("REPRO_LLM_BASE_URL", DASHSCOPE_PROXY_URL or "")
REPRO_LLM_MODEL = os.environ.get("REPRO_LLM_MODEL", "glm-5.1")
REPRO_MODEL_TOKEN_FILE = os.environ.get("REPRO_MODEL_TOKEN_FILE", "")
CONTAINER_MODEL_TOKEN_FILE = "/run/secrets/repro_model_token"


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
    credential_guidance = (
        "- 任务凭据已由执行器注入 OPENAI_API_KEY / LLM_API_KEY；不要读取、输出、记录或复制任何凭据。\n"
        if REPRO_MODEL_TOKEN_FILE
        else "- OpenCode 自身模型认证由执行环境管理；项目若需要独立 API Key，禁止读取 OpenCode auth 文件，应在报告中列为前置条件。\n"
    )
    return f"""
# 受管模型服务（项目确实需要 LLM 时使用）
- Base URL: {REPRO_LLM_BASE_URL}
- 模型: {REPRO_LLM_MODEL}
{credential_guidance}- 使用上面的 Base URL；禁止把凭据写入源码、报告或日志。
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


def _validated_token_path() -> Path | None:
    if not REPRO_MODEL_TOKEN_FILE:
        return None
    token_path = Path(REPRO_MODEL_TOKEN_FILE).expanduser()
    try:
        file_stat = token_path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"Repro model token file does not exist: {token_path}") from exc
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise RuntimeError("Repro model token path must be a regular non-symlink file")
    if file_stat.st_mode & 0o077:
        raise RuntimeError("Repro model token file permissions must not allow group or other access")
    return token_path.resolve()


# ============================================================================
# 复现任务 prompt
# ============================================================================
def _build_repro_prompt() -> str:
    """构建普通项目复现 prompt，不包含任何模型凭据。"""
    llm_section = _managed_llm_prompt_section()
    return f"""你在一个隔离容器里(你是 root,可自由装包),目标是【把一个开源项目跑起来、确认环境可用、并尽量跑出真实运行效果】。
仓库已 clone 到 /workspace/repo。全程用中文说明你在做什么。
{llm_section}
# 第一步:判断复现难度(决定你要跑多深)
读 README、依赖清单、项目结构后,判断这个项目属于哪一级:
- L1 轻量:纯库/命令行工具,依赖小。→ 装好 + 跑出最小示例/demo,看到真实输出。
- L2 中等:有较重依赖但能装。→ 装好 + 能 import + 能跑 --help 或最小示例。
- L3 重型:需要 GPU / 大数据集 / 大模型权重 / 必须的外部 API key 才能真正运行。
  → 只做"环境就绪":装好依赖、确认入口存在,然后明确报告"需要什么才能实际运行",不要硬跑(会超时白费)。

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
status=failed/partial 的报告同样有价值(让使用者知道这个项目要什么、卡在哪)。
JSON 必须合法(可被解析),字符串里不要有未转义的引号或换行。
"""


def _build_web_repro_prompt() -> str:
    """构建 Web 项目复现 prompt，不包含任何模型凭据。"""
    llm_section = _managed_llm_prompt_section()
    return f"""你在一个隔离容器里(你是 root,可自由装包),需要复现一个项目。仓库已 clone 到 /workspace/repo。全程用中文说明。
{llm_section}
# 第零步(最重要):先判断这个项目【本身】到底有没有 Web 界面
读 README、看项目结构,判断它是否【自带】一个真正的 Web 应用/界面:
- 有真 Web 界面的标志:项目里有前端代码(React/Vue/HTML 应用)、或用 streamlit/gradio/flask/fastapi 写的、
  README 明确说"启动后访问 localhost:xxxx 看界面/dashboard"。
- ❌ 如果项目【本身没有】Web 界面(它是 CLI 工具、Python 库、研究代码、prompt/数据集合集等),
  你【绝对不要】自己造一个网页(比如写个 Flask 把一堆 .md 文件列出来)。那样毫无价值。
  这种情况直接如实报告:is_web=false、web_started=false,在 summary 说清"该项目本身没有 Web 界面,它是 XX 类型"。

# 如果确认项目自带 Web 界面,才执行下面的启动流程
- 服务必须监听 0.0.0.0:8080(容器已把主机端口映射到容器内 8080)。
- 常见启动方式:
  · Streamlit: `streamlit run xxx.py --server.address 0.0.0.0 --server.port 8080`
  · Gradio: 设 server_name="0.0.0.0", server_port=8080
  · Flask/FastAPI: `uvicorn main:app --host 0.0.0.0 --port 8080`
  · Node/Vite/React: `--host 0.0.0.0 --port 8080` 或 PORT=8080;前端项目先 npm install
- 在【后台】启动(nohup/setsid &)。启动后【sleep 10 秒等服务起来】,再 `curl -s http://localhost:8080`。
  ⚠️ 时间宝贵:服务一旦 curl 能返回 HTML/响应,就【立刻输出报告结束】,不要反复测试、不要再做多余的事。
  如果 curl 暂时没响应,最多等 30 秒重试 2-3 次,仍不行就如实报告 web_started=false 并结束。
- 用项目【原有】的前端,不要自己另写页面。服务起成功后保持运行,不要停。

# 步骤
1. 读 README/项目结构,先做第零步判断。
2. 若有 Web 界面:装依赖(你是 root)、按项目原有方式把服务起到 0.0.0.0:8080、curl 验证。
   装包注意:容器已配好 pip/npm 国内镜像(清华源/npmmirror),直接 pip install / npm install 即可,
   【不要】自己加 -i 指定别的源(尤其别用国外源),否则会很慢甚至超时。
3. 若无 Web 界面:不要启动任何东西,直接如实报告。

# 最后必须输出结构化报告(用标记包裹)
===REPRO_REPORT_START===
{{
  "is_web": true/false,
  "status": "success|partial|failed",
  "summary": "一句话结论。若项目无 Web 界面,明确说明它是什么类型、为什么没界面",
  "web_started": true/false,
  "web_framework": "如 Streamlit / Gradio / React+Vite;无则填空",
  "start_command": "你启动服务的命令;没启动填空",
  "verify": "curl 验证结果;没验证填空",
  "environment": {{"language": "如 Python 3.10", "key_deps": ["关键依赖"]}},
  "steps": [{{"cmd": "关键命令", "ok": true/false, "note": "可选"}}],
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
- 复现失败的话 usage 只填 what 和 limitations。

诚实第一:项目没有 Web 界面就如实说,绝不自己编造页面充数。JSON 必须合法。
"""


# ============================================================================
# 任务运行（迁自旧 repro.py ReproRunner）
# ============================================================================
class ReproRunner:
    """运行单个复现任务。把日志流通过回调推出去（供 SSE/WebSocket 用）。

    用法:
        runner = ReproRunner(task_id=1, repo_url="https://github.com/...",
                             on_log=lambda line: print(line),
                             on_status=lambda s: print("STATUS", s))
        runner.start()   # 异步,在后台线程跑
    """

    def __init__(
        self,
        task_id: int,
        repo_url: str,
        on_log: Callable[[str], None] | None = None,
        on_status: Callable[..., None] | None = None,
        web_port: int | None = None,
    ):
        self.task_id = task_id
        self.repo_url = repo_url
        raw_on_log = on_log or (lambda line: None)
        self._raw_on_log = raw_on_log
        self._secret_values = _task_secret_values()
        self.on_log = self._emit_log
        self.on_status = on_status or (lambda status, **kw: None)
        _stamp = int(time.time())
        self.container_name = f"repro-{task_id}-{_stamp}"
        self.workspace = WORKSPACE_ROOT / f"task-{task_id}-{_stamp}"
        self.proc: subprocess.Popen | None = None
        self.status = "queued"
        self._thread: threading.Thread | None = None
        self.web_port = web_port  # 主机端口（有则映射到容器内 8080，用于 Web 项目复现）
        self._logged_bytes = 0
        self._log_truncated = False

    # ---- docker 命令构建 ----
    def build_run_command(self):
        """起一个 systemd 常驻容器（用 sysbox 运行时，让容器内能跑 docker）。"""
        cmd = [
            "docker", "run",
            "--runtime", REPRO_RUNTIME,
            "-d",
            "--name", self.container_name,
            "--cpus", REPRO_CPUS,
            "--memory", REPRO_MEMORY,
            "--memory-swap", REPRO_MEMORY_SWAP,
            "--pids-limit", REPRO_PIDS_LIMIT,
            "--security-opt", "no-new-privileges=true",
            "-v", f"{self.workspace}:/workspace",
        ]
        token_path = _validated_token_path()
        if token_path:
            cmd.extend(["--mount", f"type=bind,src={token_path},dst={CONTAINER_MODEL_TOKEN_FILE},readonly"])
        cmd.append(REPRO_IMAGE)
        return cmd

    def build_exec_command(self):
        """docker exec 进容器，以 root 跑 clone + opencode。"""
        inject_proxy = ""
        if DASHSCOPE_PROXY_URL:
            _oc_cfg = json.dumps({
                "$schema": "https://opencode.ai/config.json",
                "provider": {
                    "dashscope-proxy": {
                        "npm": "@ai-sdk/openai-compatible",
                        "name": "DashScope-Proxy",
                        "options": {"baseURL": DASHSCOPE_PROXY_URL},
                        "models": {REPRO_LLM_MODEL: {"name": REPRO_LLM_MODEL}},
                    }
                },
                "model": f"dashscope-proxy/{REPRO_LLM_MODEL}",
                "permission": {
                    "*": "allow", "bash": "allow", "edit": "allow",
                    "write": "allow", "read": "allow", "webfetch": "allow",
                    "external_directory": "allow", "doom_loop": "allow",
                },
            })
            _b64_cfg = base64.b64encode(_oc_cfg.encode()).decode()
            inject_proxy = (
                f"echo '{_b64_cfg}' | base64 -d > /tmp/_oc_tpl.json; "
                "python3 -c \""
                "import json,os; "
                "cfg=json.load(open('/tmp/_oc_tpl.json')); "
                f"tp='{CONTAINER_MODEL_TOKEN_FILE}'; "
                "ap='/root/.local/share/opencode/auth.json'; "
                "auth=json.load(open(ap)) if os.path.exists(ap) else {}; "
                "key=open(tp).read().strip() if os.path.exists(tp) else (auth.get('alibaba-cn') or {}).get('key',''); "
                "cfg['provider']['dashscope-proxy']['options']['apiKey']=key; "
                "json.dump(cfg,open('/root/.config/opencode/opencode.json','w'),indent=2); "
                f"print('✓ opencode 已配置 DashScope 代理: {DASHSCOPE_PROXY_URL}')"
                "\"; "
            )

        prompt = _build_web_repro_prompt() if self.web_port else _build_repro_prompt()

        inner = (
            "export LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONIOENCODING=utf-8; "
            f"if [ -f {CONTAINER_MODEL_TOKEN_FILE} ]; then "
            f"export OPENAI_API_KEY=\"$(cat {CONTAINER_MODEL_TOKEN_FILE})\" LLM_API_KEY=\"$(cat {CONTAINER_MODEL_TOKEN_FILE})\"; fi; "
            "export GIT_HTTP_LOW_SPEED_LIMIT=1000 GIT_HTTP_LOW_SPEED_TIME=30; "
            "set -e; "
            + inject_proxy +
            "mkdir -p /root/.pip /root/.config/pip; "
            "printf '[global]\\nindex-url = https://pypi.tuna.tsinghua.edu.cn/simple\\n"
            "trusted-host = pypi.tuna.tsinghua.edu.cn\\ntimeout = 120\\nretries = 5\\n' "
            "| tee /root/.pip/pip.conf /root/.config/pip/pip.conf > /dev/null; "
            "npm config set registry https://registry.npmmirror.com 2>/dev/null || true; "
            "if [ -n \"$(ls -A /workspace/repo 2>/dev/null)\" ]; then "
            "  echo '✓ 宿主机已预下载 repo,跳过 clone'; "
            "else "
            "rm -rf /workspace/repo; mkdir -p /workspace/repo; "
            "n=0; until [ $n -ge 3 ]; do "
            f"  timeout 120 git clone --depth 1 {shlex.quote(self.repo_url)} /workspace/repo 2>&1 && break; "
            "  n=$((n+1)); echo \"⚠ clone 失败(第 $n 次),5 秒后重试…\"; "
            "  rm -rf /workspace/repo; mkdir -p /workspace/repo; sleep 5; "
            "done; "
            "if [ -z \"$(ls -A /workspace/repo 2>/dev/null)\" ]; then "
            "  echo '⚠ git clone 三次均失败,尝试 zip 下载…'; "
            f"  ZIP_URL={shlex.quote(self.repo_url.rstrip('.git').rstrip('/') + '/archive/refs/heads/main.zip')}; "
            "  curl -fsSL --http1.1 --connect-timeout 30 --max-time 300 -o /tmp/repo.zip \"$ZIP_URL\" 2>&1 && "
            "  unzip -q /tmp/repo.zip -d /tmp/repo_unzip && "
            "  mv /tmp/repo_unzip/*/* /workspace/repo/ 2>/dev/null; mv /tmp/repo_unzip/*/.* /workspace/repo/ 2>/dev/null; "
            "  rm -rf /tmp/repo.zip /tmp/repo_unzip; "
            "  if [ -z \"$(ls -A /workspace/repo 2>/dev/null)\" ]; then echo '✗ zip 下载也失败,放弃'; exit 1; fi; "
            "  echo '✓ 已通过 zip 下载成功'; "
            "fi; "
            "fi; "
            "cd /workspace/repo; "
            "echo \"✓ 已 clone: $(git -C /workspace/repo remote get-url origin 2>/dev/null)\"; "
            "echo \"✓ pip 源: $(pip config get global.index-url 2>/dev/null || echo 默认)\"; "
            f"stdbuf -oL -eL opencode run {shlex.quote(prompt)} 2>&1"
        )
        return [
            "docker", "exec", "-u", "root",
            "-e", "LANG=C.UTF-8", "-e", "LC_ALL=C.UTF-8", "-e", "PYTHONIOENCODING=utf-8",
            "-e", "HOME=/root",
            self.container_name,
            "bash", "-lc", inner,
        ]

    # ---- 启动（后台线程）----
    def start(self):
        self.workspace.mkdir(parents=True, exist_ok=True)
        try:
            os.chown(self.workspace, 1000, 1000)
        except (PermissionError, OSError):
            pass
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

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
            run_cmd = self.build_run_command()
            self._emit_log(f"$ {' '.join(shlex.quote(c) for c in run_cmd)}")
            r = _safe_run(run_cmd, capture_output=True, text=True)
            if r.returncode != 0:
                self._emit_log(f"✗ 起容器失败: {r.stderr.strip()}")
                self._set_status("failed", error=r.stderr.strip())
                return

            # 2. 等容器内 docker 守护进程就绪
            self._emit_log("• 等待容器内服务就绪…")
            if not self._wait_dockerd():
                self._emit_log("⚠ 容器内 docker 未在预期时间就绪,仍继续(纯 Python 项目不受影响)")

            # 2.1 启动端口代理（sysbox 容器用 nsenter 替代 docker -p）
            self._start_port_proxy()

            # 2.5 宿主机侧预 clone
            host_repo = self.workspace / "repo"
            if not host_repo.exists() or not any(host_repo.iterdir()):
                host_repo.mkdir(parents=True, exist_ok=True)
                self.on_log("• 宿主机侧 clone 仓库…")
                clone_ok = False
                for attempt in range(2):
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
                    zip_url = self.repo_url.rstrip('.git').rstrip('/') + '/archive/refs/heads/main.zip'
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
            prompt = _build_web_repro_prompt() if self.web_port else _build_repro_prompt()
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
                timeout_limit = WEB_CONTAINER_TIMEOUT if self.web_port else CONTAINER_TIMEOUT
                if time.time() - start_ts > timeout_limit:
                    report = extract_report("\n".join(self._full_output))
                    if self.web_port:
                        self.on_log("⏱ Agent 流程超时,但容器保活(Web 服务可能已就绪,可尝试访问)")
                        if self.proc.poll() is None:
                            self.proc.terminate()
                        self._set_status("success", report=report,
                                         result="agent 流程超时,容器保活,请尝试在线访问验证")
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
            report = extract_report(full)
            # ★ 适配点:去掉旧 v1 的 import db + db.update_item_web_class 调用
            #   原 v1 在这里通过 on_status 回调通知外部，由外部处理 DB 回写
            #   （is_web 修正逻辑移到 on_status 回调处理）
            if not self.web_port:
                _safe_run(["docker", "stop", self.container_name], capture_output=True)
            if report and isinstance(report, dict) and report.get("status"):
                rep_status = report["status"]
                final = "success" if rep_status in ("success", "partial") else "failed"
                self._set_status(final, result=result_summary, report=report)
            elif rc == 0:
                self._set_status("success", result=result_summary, report=report)
            else:
                self._set_status("failed", returncode=rc, result=result_summary, report=report)
        except Exception as e:
            self.on_log(f"✗ 编排器错误: {e}")
            self._set_status("failed", error=str(e))

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
            self.on_log(f"✓ 端口代理已启动: 127.0.0.1:{self.web_port} → 容器:8080 (nsenter PID={cpid})")
        except Exception as e:
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

    def stop(self):
        self._stop_port_proxy()
        _safe_run(["docker", "stop", self.container_name], capture_output=True)
        self._set_status("stopped")

    def cleanup(self):
        self._stop_port_proxy()
        _safe_run(["docker", "rm", "-f", self.container_name], capture_output=True)
        if self.workspace.exists():
            shutil.rmtree(self.workspace, ignore_errors=True)
        self._set_status("cleaned")


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


# ============================================================================
# 任务管理器（迁自旧 repro.py ReproManager）
# ============================================================================
class ReproManager:
    """持有所有运行中的 ReproRunner，供 API/SSE 层启动/停止/清理。

    通过 on_log / on_status 回调拿到日志和状态变化，
    调用方负责写库 + 推 SSE（线程安全问题由调用方处理）。
    """

    def __init__(self):
        self.runners: dict[int, ReproRunner] = {}

    def start_task(
        self,
        task_id: int,
        repo_url: str,
        on_log: Callable[[str], None],
        on_status: Callable[..., None],
        web_port: int | None = None,
    ) -> ReproRunner:
        runner = ReproRunner(task_id, repo_url, on_log=on_log, on_status=on_status, web_port=web_port)
        self.runners[task_id] = runner
        runner.start()
        return runner

    def stop_task(self, task_id: int) -> bool:
        r = self.runners.get(task_id)
        if r:
            r.stop()
            return True
        return False

    def cleanup_task(self, task_id: int, container_name: str | None = None, workspace_path: str | None = None) -> bool:
        """清理:删容器 + 删产物。runner 可能不在内存（server 重启），
        所以支持传入 container_name/workspace_path 直接清理。"""
        r = self.runners.get(task_id)
        if r:
            r.cleanup()
            self.runners.pop(task_id, None)
            return True
        if container_name:
            _safe_run(["docker", "rm", "-f", container_name], capture_output=True)
        if workspace_path:
            p = Path(workspace_path)
            if p.exists():
                shutil.rmtree(p, ignore_errors=True)
        return True


# 全局单例（API 层 import 它）
manager = ReproManager()
