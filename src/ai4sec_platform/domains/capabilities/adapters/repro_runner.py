"""复现编排器 - 迁移自旧 v1 repro.py（829 行）。

适配点（决策 1/5/8）：
  1. 去硬编码 key: REPRO_PROMPT 里的 sk-c4199... → 从 .env 的 REPRO_LLM_API_KEY 读
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
import subprocess
import threading
import time
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
WEB_CONTAINER_TIMEOUT = int(os.environ.get("REPRO_WEB_CONTAINER_TIMEOUT", str(60 * 60)))  # 60 分钟
REPORT_GRACE_TIMEOUT = int(os.environ.get("REPRO_REPORT_GRACE_TIMEOUT", str(10 * 60)))  # 报告收尾宽限
DOCKERD_WAIT = int(os.environ.get("REPRO_DOCKERD_WAIT", "30"))
INTERNAL_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# DashScope API 代理（sysbox 容器内直连会卡死，通过宿主机 nginx 反代转发）
DASHSCOPE_PROXY_URL = os.environ.get("DASHSCOPE_PROXY_URL", "")

# 复现任务内 LLM 配置（决策 8：从 .env 读，去硬编码）
# 这些值会注入到 REPRO_PROMPT 里，供容器内 opencode 使用
REPRO_LLM_API_KEY = os.environ.get("REPRO_LLM_API_KEY", "")
REPRO_LLM_BASE_URL = os.environ.get("REPRO_LLM_BASE_URL", DASHSCOPE_PROXY_URL or "")
REPRO_LLM_MODEL = os.environ.get("REPRO_LLM_MODEL", "glm-5.1")


def _repo_archive_url(repo_url: str) -> str:
    match = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", repo_url)
    if match:
        owner, name = match.groups()
        return f"https://codeload.github.com/{owner}/{name.removesuffix('.git')}/zip/refs/heads/main"
    return repo_url.removesuffix(".git").rstrip("/") + "/archive/refs/heads/main.zip"


# ============================================================================
# 复现任务 prompt（迁自旧 repro.py，去硬编码 key → 从 .env 读）
# ============================================================================
def _build_repro_prompt() -> str:
    """构建普通项目复现 prompt，注入 .env 里的 LLM 配置"""
    llm_section = ""
    if REPRO_LLM_API_KEY and REPRO_LLM_BASE_URL:
        llm_section = f"""
# 可用的 LLM API（如果项目需要 LLM/AI 能力）
如果项目需要配置 LLM API key 才能运行（比如调用 OpenAI、通义千问等），请使用以下配置：
- API Key: {REPRO_LLM_API_KEY}
- Base URL: {REPRO_LLM_BASE_URL}
- 模型: {REPRO_LLM_MODEL}
- 兼容 OpenAI 接口格式，项目里配 OPENAI_API_KEY / LLM_API_KEY 等都可以用这个 key
- 对应的 base url 填上面的 Base URL（不是 OpenAI 官方地址）
"""
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
    """构建 Web 项目复现 prompt，注入 .env 里的 LLM 配置"""
    llm_section = ""
    if REPRO_LLM_API_KEY and REPRO_LLM_BASE_URL:
        llm_section = f"""
# 可用的 LLM API（如果项目需要 LLM/AI 能力）
如果项目需要配置 LLM API key 才能运行（比如调用 OpenAI、通义千问等），请使用以下配置：
- API Key: {REPRO_LLM_API_KEY}
- Base URL: {REPRO_LLM_BASE_URL}
- 模型: {REPRO_LLM_MODEL}
- 兼容 OpenAI 接口格式，项目里配 OPENAI_API_KEY / LLM_API_KEY 等都可以用这个 key
- 对应的 base url 填上面的 Base URL（不是 OpenAI 官方地址）
"""
    return f"""你在一个隔离容器里(你是 root,可自由装包),需要复现一个项目。仓库已 clone 到 /workspace/repo。全程用中文说明。
{llm_section}
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
- 启动前先定位真正的应用根目录。比如仓库是 `backend/app/main.py`,必须先 `cd backend` 再运行
  `uvicorn app.main:app`;不能在仓库根目录直接运行同一命令。
- 容器复现一律不要使用 `--reload` / hot reload。后台 reloader 会改变进程关系和导入上下文,容易假失败。
- 后台启动后立刻记录 PID:`nohup ... >/tmp/service.log 2>&1 & echo $! >/tmp/service.pid`。
  需要停止重试时用 `kill $(cat /tmp/service.pid)`,绝对不要用 `pkill -f`,它可能匹配并杀掉当前 shell 自己。
- 首次启动失败不能直接结束:读取服务日志,检查工作目录、模块路径、端口和依赖,至少修正重试一次。
- 前后端分离项目:后端按其真实目录启动到内部端口(如 8000),前端必须最终监听 0.0.0.0:8080,
  并确认前端的 `/api` 代理指向已启动的后端。
- 写配置前检查项目实际配置加载逻辑（如 Pydantic `env_file`、dotenv 调用和进程 cwd）。配置文件必须放在运行进程真正读取的位置；
  启动后还要通过配置对象、进程环境或实际响应确认 provider/model 等关键配置已生效，不能只确认文件存在。
- `curl http://localhost:8080` 只证明页面服务启动,不能单独作为项目复现成功的依据。
- 如果页面需要登录/注册,不能只验证首页 HTML:必须实际调用注册或登录 API,确认能进入受保护页面。
  如果项目没有预置账号但支持注册,创建专用 Demo 账号（不要复用真实个人账号）,并把账号和密码写入报告
  `usage.prerequisites`；如果注册不可用,必须找到或创建安全的演示入口,不能把用户留在登录页。

# 核心可用性验收（必须执行，禁止“首页 200 = 复现成功”）
- 读 README 和页面功能,先用一句话定义该项目最核心的用户价值与最短操作闭环。
- 至少实际完成一条超越登录和普通 CRUD 的核心业务链。例如 AI 平台要真实调用一次 AI 生成功能；扫描器要提交目标并拿到扫描结果；
  分析工具要导入样例并产出分析报告。只创建账号、创建 Project、打开空 Dashboard 都不算核心功能验证。
- 前后端分离或多目录项目必须确认配置文件放在【实际进程读取的位置】,并从运行中进程或生成结果验证配置已生效；
  不能因为写过 `.env` 就声称已启用。若项目支持 mock,必须区分 mock 输出与真实能力输出。
- 核心链依赖 LLM/API/数据库时,必须检查真实 provider/model、响应内容和错误信息；不能只检查 HTTP 状态码。
- 若核心 LLM 阶段出现超时、JSON 解析失败或 schema 校验失败，不要立刻判定失败：先读取错误详情，
  优先将可配置的 temperature 降低、启用 JSON/structured-output 模式（若项目支持），并对同一阶段至少重试 2 次。
  后续重试成功时，以成功产物为最终结论，并把早先失败记录为 gotcha；全部重试仍失败才报告 partial/failed。
- `status=success`:核心业务链完整跑通且结果可用；`status=partial`:页面和部分功能可用,但核心链仅部分跑通、使用 mock、
  超时或关键阶段失败；`status=failed`:页面不可用或核心入口完全无法执行。
- 报告必须写出 `core_workflow`、每一步实测结果、真实证据、最终产物以及失败阶段。未执行核心业务链时不得报告 success。
- `core_workflow.mode` 必须区分 `real` 和 `mock`；使用 mock/fixture/静态占位输出时只能报告 partial。
- 检查关键页面的入口是否真实可点击。若核心路由/API 可用但页面没有可发现入口,允许做最小导航修复（如增加“进入项目”按钮），
  但不得重写业务功能，并必须在 gotchas 和 steps 中记录修改。

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
  "core_workflow": {{"goal": "核心用户价值", "mode": "real|mock", "steps": [{{"action": "实际操作", "ok": true/false}}], "evidence": ["真实响应/产物摘要"], "result": "产物或失败阶段", "verified": true/false}},
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
- `prerequisites` 只写当前使用者仍需自行完成的前置条件。若本次复现已经配置并验证了 LLM/API/数据库，
  必须明确写“当前复现环境已配置并验证 …，无需用户额外配置”，不能泛泛写“需要配置 LLM API”；
  只有缺失、未验证或用户确实必须自备的配置才写为前置条件。
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
        self.on_log = on_log or (lambda line: None)
        self.on_status = on_status or (lambda status, **kw: None)
        _stamp = int(time.time())
        self.container_name = f"repro-{task_id}-{_stamp}"
        self.workspace = WORKSPACE_ROOT / f"task-{task_id}-{_stamp}"
        self.proc: subprocess.Popen | None = None
        self.status = "queued"
        self._thread: threading.Thread | None = None
        self.web_port = web_port  # 主机端口（有则映射到容器内 8080，用于 Web 项目复现）

    # ---- docker 命令构建 ----
    def build_run_command(self):
        """起一个 systemd 常驻容器（用 sysbox 运行时，让容器内能跑 docker）。"""
        cmd = [
            "docker", "run",
            "--runtime", REPRO_RUNTIME,
            "-d",
            "--name", self.container_name,
            "--pids-limit", os.environ.get("REPRO_PIDS_LIMIT", "4096"),
            "-v", f"{self.workspace}:/workspace",
            REPRO_IMAGE,
        ]
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
                "ap='/root/.local/share/opencode/auth.json'; "
                "auth=json.load(open(ap)) if os.path.exists(ap) else {}; "
                "key=(auth.get('alibaba-cn') or {}).get('key',''); "
                "cfg['provider']['dashscope-proxy']['options']['apiKey']=key; "
                "json.dump(cfg,open('/root/.config/opencode/opencode.json','w'),indent=2); "
                f"print('✓ opencode 已配置 DashScope 代理: {DASHSCOPE_PROXY_URL}')"
                "\"; "
            )

        prompt = _build_web_repro_prompt() if self.web_port else _build_repro_prompt()

        inner = (
            "export LANG=C.UTF-8 LC_ALL=C.UTF-8 PYTHONIOENCODING=utf-8; "
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
            f"  ZIP_URL={shlex.quote(_repo_archive_url(self.repo_url))}; "
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
            if hasattr(os, 'chown'):
                os.chown(self.workspace, 1000, 1000)
        except (PermissionError, OSError):
            pass
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _set_status(self, status, **kw):
        self.status = status
        self.on_status(status, **kw)

    def _run(self):
        self._set_status("running")
        self._tail: list[str] = []
        self._full_output: list[str] = []
        try:
            # 1. 起 systemd 容器（后台）
            subprocess.run(["docker", "rm", "-f", self.container_name],
                           capture_output=True, text=True)
            run_cmd = self.build_run_command()
            self.on_log(f"$ {' '.join(shlex.quote(c) for c in run_cmd)}")
            r = subprocess.run(run_cmd, capture_output=True, text=True)
            if r.returncode != 0:
                self.on_log(f"✗ 起容器失败: {r.stderr.strip()}")
                self._set_status("failed", error=r.stderr.strip())
                return

            # 2. 等容器内 docker 守护进程就绪
            self.on_log("• 等待容器内服务就绪…")
            if not self._wait_dockerd():
                self.on_log("⚠ 容器内 docker 未在预期时间就绪,仍继续(纯 Python 项目不受影响)")

            # 2.1 启动端口代理（sysbox 容器用 nsenter 替代 docker -p）
            self._start_port_proxy()

            # 2.5 宿主机侧预 clone
            host_repo = self.workspace / "repo"
            if not host_repo.exists() or not any(host_repo.iterdir()):
                host_repo.mkdir(parents=True, exist_ok=True)
                self.on_log("• 宿主机侧 clone 仓库…")
                clone_ok = False
                for attempt in range(2):
                    cr = subprocess.run(
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
                    zip_url = _repo_archive_url(self.repo_url)
                    zr = subprocess.run(
                        ["curl", "-fsSL", "--http1.1", "--connect-timeout", "30", "--max-time", "600",
                         "-o", "/tmp/_repro_repo.zip", zip_url],
                        capture_output=True, text=True,
                    )
                    if zr.returncode == 0:
                        subprocess.run(["unzip", "-q", "/tmp/_repro_repo.zip", "-d", "/tmp/_repro_unzip"],
                                       capture_output=True)
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
            self.on_log("┌─ 发给 AI agent 的复现指令(prompt)─────────────")
            for pl in prompt.strip().split("\n"):
                self.on_log("│ " + redact_sensitive_log_value(pl))
            self.on_log("└──────────────────────────────────────────────")
            self.on_log("")
            exec_cmd = self.build_exec_command()
            _env = dict(os.environ)
            _env.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8"})
            self.proc = subprocess.Popen(
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
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    if self.proc.poll() is not None:
                        break
                    continue
                clean = redact_sensitive_log_value(strip_ansi(line.rstrip("\n")))
                self.on_log(clean)
                self._tail.append(clean)
                self._full_output.append(clean)
                if len(self._tail) > 40:
                    self._tail.pop(0)
                timeout_limit = WEB_CONTAINER_TIMEOUT if self.web_port else CONTAINER_TIMEOUT
                elapsed = time.time() - start_ts
                if elapsed > timeout_limit:
                    report = enforce_report_acceptance(extract_report("\n".join(self._full_output)))
                    if report:
                        final_status = task_status_from_report(report)
                        self.on_log("✓ 已在报告宽限阶段取得结构化报告")
                        self._stop_agent_process()
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
                        report_status = task_status_from_report(report, fallback="partial")
                        final_status = "failed" if report_status == "failed" else "partial"
                        self.on_log("⏱ Agent 流程超时,容器保活;未完成核心验收时只能标记部分复现")
                        self._stop_agent_process()
                        self._set_status(final_status, report=report,
                                         result="agent 流程超时,容器保活;核心可用性需要继续验证")
                    else:
                        self.on_log("⏱ 超时,停止容器")
                        self.stop()
                        self._set_status("timeout", report=report)
                    return
            rc = self.proc.wait()
            full = "\n".join(self._full_output)
            result_summary = "\n".join(self._tail[-20:])
            report = enforce_report_acceptance(extract_report(full))
            # ★ 适配点:去掉旧 v1 的 import db + db.update_item_web_class 调用
            #   原 v1 在这里通过 on_status 回调通知外部，由外部处理 DB 回写
            #   （is_web 修正逻辑移到 on_status 回调处理）
            if not self.web_port:
                subprocess.run(["docker", "stop", self.container_name], capture_output=True)
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

    def _wait_dockerd(self):
        """等容器内 docker 守护进程就绪（最多 DOCKERD_WAIT 秒）。"""
        deadline = time.time() + DOCKERD_WAIT
        while time.time() < deadline:
            chk = subprocess.run(
                ["docker", "exec", self.container_name, "docker", "info"],
                capture_output=True, text=True,
            )
            if chk.returncode == 0:
                return True
            time.sleep(2)
        return False

    # ---- sysbox 端口代理（替代 docker -p）----
    def _start_port_proxy(self):
        """在宿主机启动 socat 代理，通过 docker exec 转发到容器端口。
        原因:sysbox 容器使用 user namespace 隔离，docker -p 端口映射的 docker-proxy
        无法通过 ARP 到达容器 IP，导致连接被 reset。docker exec 不需要宿主机 root 权限。"""
        self._proxy_proc = None
        self._proxy_log_handle = None
        if not self.web_port:
            return
        try:
            bridge_script = """import os
import socket
import threading

sock = socket.create_connection((\"127.0.0.1\", 8080), timeout=10)
sock.settimeout(None)

def upload():
    try:
        while True:
            chunk = os.read(0, 65536)
            if not chunk:
                break
            sock.sendall(chunk)
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

thread = threading.Thread(target=upload, daemon=True)
thread.start()
while True:
    chunk = sock.recv(65536)
    if not chunk:
        break
    os.write(1, chunk)
thread.join(timeout=1)
sock.close()
"""
            install_bridge = subprocess.run(
                ["docker", "exec", "-i", self.container_name, "sh", "-c", "cat > /tmp/repro_tcp_bridge.py"],
                input=bridge_script,
                capture_output=True,
                text=True,
            )
            if install_bridge.returncode != 0:
                self.on_log(f"⚠ 安装端口桥接脚本失败: {install_bridge.stderr.strip()}")
                return
            proxy_cmd = [
                "socat",
                f"TCP-LISTEN:{self.web_port},fork,reuseaddr",
                f"EXEC:docker exec -i {self.container_name} python3 /tmp/repro_tcp_bridge.py",
            ]
            proxy_log = self.workspace / "port-proxy.log"
            self._proxy_log_handle = proxy_log.open("a", encoding="utf-8")
            self._proxy_proc = subprocess.Popen(
                proxy_cmd,
                stdout=subprocess.DEVNULL,
                stderr=self._proxy_log_handle,
            )
            time.sleep(0.3)
            if self._proxy_proc.poll() is not None:
                self._proxy_log_handle.flush()
                error = proxy_log.read_text(encoding="utf-8", errors="replace").strip()
                self.on_log(f"⚠ 端口代理启动失败: {error[-500:] or 'socat exited'}")
                self._proxy_log_handle.close()
                self._proxy_log_handle = None
                self._proxy_proc = None
                return
            self.on_log(f"✓ 端口代理已启动: 宿主机:{self.web_port} → 容器:8080 (docker exec)")
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
        if getattr(self, '_proxy_log_handle', None):
            self._proxy_log_handle.close()
            self._proxy_log_handle = None

    def _stop_agent_process(self):
        if not self.proc or self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def stop(self):
        self._stop_port_proxy()
        subprocess.run(["docker", "stop", self.container_name], capture_output=True)
        self._set_status("stopped")

    def cleanup(self):
        self._stop_port_proxy()
        subprocess.run(["docker", "rm", "-f", self.container_name], capture_output=True)
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


def redact_sensitive_log_value(value: str) -> str:
    if REPRO_LLM_API_KEY:
        value = value.replace(REPRO_LLM_API_KEY, "<redacted>")
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "<redacted>", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "<redacted-jwt>", value)
    return value


def enforce_report_acceptance(report: dict | None) -> dict | None:
    if not isinstance(report, dict):
        return report

    normalized = copy.deepcopy(report)
    status = normalized.get("status")
    if status not in ("success", "partial", "failed"):
        normalized["status"] = "failed"
        status = "failed"

    if not normalized.get("is_web"):
        return normalized

    issues: list[str] = []
    if not normalized.get("web_started"):
        issues.append("Web 服务未成功启动或未验证")

    workflow = normalized.get("core_workflow")
    if not isinstance(workflow, dict):
        workflow = {}
    if workflow.get("verified") is not True:
        issues.append("未完成核心业务闭环验证")
    mode = str(workflow.get("mode") or "").strip().lower()
    if mode != "real":
        issues.append("核心功能未使用真实模式验证")
    if not workflow.get("steps"):
        issues.append("核心业务闭环缺少实测步骤")
    if not workflow.get("evidence"):
        issues.append("核心业务闭环缺少真实结果证据")
    if not str(workflow.get("result") or "").strip():
        issues.append("核心业务闭环缺少结果说明")

    if issues and status == "success":
        normalized["status"] = "failed" if not normalized.get("web_started") else "partial"

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
    if isinstance(normalized, dict) and normalized.get("status") in ("success", "partial", "failed"):
        return normalized["status"]
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

    def cleanup_task(
        self,
        task_id: int,
        container_name: str | None = None,
        workspace_path: str | None = None,
        web_port: int | None = None,
    ) -> bool:
        """清理:删容器 + 删产物。runner 可能不在内存（server 重启），
        所以支持传入 container_name/workspace_path 直接清理。"""
        r = self.runners.get(task_id)
        if r:
            r.cleanup()
            self.runners.pop(task_id, None)
            return True
        if container_name:
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        if web_port:
            _stop_orphan_proxy(web_port)
        if workspace_path:
            p = Path(workspace_path)
            if p.exists():
                shutil.rmtree(p, ignore_errors=True)
        return True


# 全局单例（API 层 import 它）
manager = ReproManager()


def _stop_orphan_proxy(web_port: int) -> None:
    marker = f"TCP-LISTEN:{web_port},"
    for proc_dir in Path("/proc").glob("[0-9]*"):
        try:
            cmdline = (proc_dir / "cmdline").read_bytes().split(b"\0")
            if not cmdline or b"socat" not in Path(cmdline[0].decode(errors="ignore")).name.encode():
                continue
            if any(marker in part.decode(errors="ignore") for part in cmdline[1:]):
                os.kill(int(proc_dir.name), 15)
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
