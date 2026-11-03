#!/usr/bin/env python3
"""适配 agent: 把一个第三方工具探成一份 recipe(D 阶段)。

为什么要它: 每个被测工具的形态都不一样(CLI / 服务 / 要宿主 agent), 手写适配器等于
每个工具写一份会随时失效的代码; 但**每轮都让 agent 现探**又会让同一份工具两次跑出的
口径不同。所以只让 agent 探**一次**, 产物冻成 recipe, 之后每轮按脚本执行(PRD §9.3)。

三条边界, 都是结构性的而不是靠提示词自觉:

1. **真值到不了这里**。平台只发题面与被审文件(`sample_packets` 的白名单投影),
   容器里根本不存在 `truth/` —— 提示词里那句"不许读"是第二道锁, 不是唯一一道。
2. **模型调用走平台代理**。这里没有任何模型密钥, 要模型能力就去
   `POST /api/internal/eval/llm`(平台侧带自己的降级链)。容器被攻破也带不走 key。
3. **探完必须真跑一遍才许交 recipe**。只在纸上写装的步骤, 交出来的就是一份
   "看起来能跑"的配置 —— 而它会在下一轮变成一条假的低分。

只依赖标准库, 与 `runner.py` 同理。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

API_BASE = os.environ.get("EVAL_API_BASE", "http://ai4sec:8100").rstrip("/")
TOKEN = os.environ.get("EVAL_TOKEN", "")
PROMPT_PATH = Path(os.environ.get(
    "EVAL_ADAPTER_PROMPT", str(Path(__file__).resolve().parent / "prompts" / "adapter.md")))
PROFILE = os.environ.get("EVAL_ADAPT_PROFILE", "capability_eval_adapter")

MAX_STEPS = int(os.environ.get("EVAL_ADAPT_MAX_STEPS", "40"))
STEP_TIMEOUT = int(os.environ.get("EVAL_ADAPT_STEP_TIMEOUT", "600"))
MAX_OBS_CHARS = int(os.environ.get("EVAL_ADAPT_MAX_OBS_CHARS", "4000"))
HISTORY_KEPT = 6                 # 完整回放的最近步数, 更早的压成一行

VALID_PARSERS = {"json", "sarif", "agent_translate", "exit_code", "none"}

# 可以进被测工具子进程的 EVAL_* 变量(L5)。其余 EVAL_*(尤其 EVAL_TOKEN)一律剥掉。
_LLM_ENV_ALLOWED = {"EVAL_LLM_BASE_URL", "EVAL_LLM_TOKEN", "EVAL_LLM_MODEL"}

# 平台发的模型令牌前缀(与 `domains/capabilities/eval/llm_tokens.py` 的 TOKEN_PREFIX 一致)。
# 这里用常量而不是读环境: 执行位要能独立起, 它不需要知道令牌从哪来, 只需要认得出形状。
TOKEN_PREFIX = "caev1_"

# `_run` 用 124 表示"我们把它杀掉了"(与 coreutils 的 timeout 同口径)。它永远不是
# 工具给出的结论, 所以不允许被 recipe 声明成"成功的退出码"。
TIMEOUT_RC = 124

GIVE_UP_REASONS = {
    "needs_paid_key", "needs_gpu", "needs_external_service", "unsupported_os",
    "repo_unavailable", "install_failed", "build_failed", "start_failed",
    "no_output", "tests_failed", "timeout", "resource_limit", "agent_gave_up",
}


def log(message: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {message}", flush=True)


class AdapterError(RuntimeError):
    """适配过程本身出了问题(提示词缺失 / 模型返回不是 JSON)。不是"工具无法适配"。"""


class AdapterPlatformError(AdapterError):
    """平台自己有问题(令牌不对 / 服务不可用 / 没配模型)。

    这**不是**工具的错, 不能落成"无法适配"的终态 —— 那会让一次平台故障变成 20 个工具
    的评价结论。调用方应当把它当成"这一轮没跑成", 保持 run 可重试。
    """


# ── 平台侧接口 ────────────────────────────────────────────────────────────────

def _post(path: str, payload: dict[str, Any], *, timeout: int = 600) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"{API_BASE}{path}", data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Repro-Token": TOKEN},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8") or "{}")


def ask(profile: str, prompt: str, payload: dict[str, Any]) -> dict[str, Any]:
    """要一次模型判断, 走平台代理。返回模型给的 JSON 对象。"""
    try:
        result = _post("/api/internal/eval/llm",
                       {"profile": profile, "prompt": prompt, "payload": payload})
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        error = AdapterPlatformError if exc.code in (401, 403, 503) else AdapterError
        raise error(f"模型代理 {exc.code}: {detail}") from exc
    record_serving(profile, result)
    parsed = result.get("parsed")
    if not isinstance(parsed, dict):
        raise AdapterError(f"模型返回的不是 JSON 对象: {str(parsed)[:200]}")
    return parsed


# ── 实际服务方台账 ────────────────────────────────────────────────────────────
# 一份分数要能回答"它是哪家模型跑出来的"。平台在 `/llm` 的响应里带回了网关响应头
# (`serving`: 真实模型 / 组 / 上游地址 / 降级次数)与 token 用量, 这里按轮累计,
# 收尾时整块写进 run 的 `cost_json`。
#
# 为什么是这里记而不是平台记: 平台不知道一次调用属于哪一轮(它不接 run_id 上下文),
# 而执行位天然是一轮一进程。台账因此只在**本轮进程**里有效 —— `run_once` 开头清空。
_SERVING: list[dict[str, Any]] = []


def reset_serving() -> None:
    _SERVING.clear()


def record_serving(profile: str, result: Any) -> None:
    """记一条模型调用的归属。**拿不到也记** —— "不知道是谁答的"本身就是要进报告的事实。"""
    result = result if isinstance(result, dict) else {}
    serving = result.get("serving")
    serving = serving if isinstance(serving, dict) else {}
    usage = result.get("usage")
    _SERVING.append({
        "profile": str(profile),
        # 平台侧读不到网关头时会明写 unknown; 这里只做搬运, 不替它猜
        "upstream_model": str(serving.get("upstream_model") or "unknown"),
        "upstream_group": str(serving.get("upstream_group") or ""),
        "upstream_api_base": str(serving.get("upstream_api_base") or ""),
        "source": str(serving.get("source") or "unverified"),
        "fallbacks": serving.get("attempted_fallbacks"),
        "usage": usage if isinstance(usage, dict) else {},
    })


def serving_summary() -> dict[str, Any]:
    """本轮调用的归属汇总。空台账只回 `{"calls": 0}` —— 没调模型 ≠ 用了某个模型。"""
    if not _SERVING:
        return {"calls": 0}
    models: dict[str, int] = {}
    groups: dict[str, int] = {}
    upstreams: dict[str, int] = {}
    profiles: dict[str, int] = {}
    tokens = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    unverified = 0
    fallback_calls = 0
    for entry in _SERVING:
        model = entry["upstream_model"]
        models[model] = models.get(model, 0) + 1
        if entry["upstream_group"]:
            groups[entry["upstream_group"]] = groups.get(entry["upstream_group"], 0) + 1
        if entry["upstream_api_base"]:
            base = entry["upstream_api_base"]
            upstreams[base] = upstreams.get(base, 0) + 1
        profiles[entry["profile"]] = profiles.get(entry["profile"], 0) + 1
        if entry["source"] != "gateway_header":
            unverified += 1
        if isinstance(entry["fallbacks"], int) and entry["fallbacks"] > 0:
            fallback_calls += 1
        for key in tokens:
            value = entry["usage"].get(key)
            if isinstance(value, int):
                tokens[key] += value
    return {
        "calls": len(_SERVING),
        "models": models,
        "groups": groups,
        "upstream_api_bases": upstreams,
        "profiles": profiles,
        # 没有网关头的调用数: 这些调用的真实模型**不可核验**
        "unverified": unverified,
        "fallback_calls": fallback_calls,
        # 单一模型 + 全部可核验 + 没走过降级 ⇔ 这一轮的分数能跟同名模型的另一轮直接比
        "consistent": (len(models) == 1 and "unknown" not in models
                       and unverified == 0 and fallback_calls == 0),
        "tokens": tokens,
    }


# ── recipe ────────────────────────────────────────────────────────────────────

def render_argv(argv: list[str], values: dict[str, str]) -> list[str]:
    """占位符替换。**逐个参数**替换, 不拼 shell 字符串 —— 文件名是外部数据。

    与 `runner.render` 是同一条规则; 两处各留一份是因为执行位要能单独起
    (只跑 runner 时不依赖 adapter)。`test_capability_eval_adapter.py` 锁住两者一致。
    """
    out = []
    for part in argv:
        for key, value in values.items():
            part = part.replace("{" + key + "}", value)
        out.append(part)
    return out


# 只认最粗的那一种伪造: 直接把答案 `echo` / `printf` 出去。更隐蔽的伪造(包装脚本里
# 按文件名分支返回固定结论)**查不出来** —— 所以真正兜底的是 D5 的人工抽检, 不是这里。
# 这条检查的价值在于: 它把"连装都懒得装"的那类挡在入库之前。
_FAKE_ANSWER = re.compile(r"\b(?:echo|printf)\b[^\n]*\{\s*[\"']?found")


def validate_recipe(recipe: Any) -> list[str]:
    """返回问题列表; 空列表 = 结构上可执行。**只查结构, 不查它能不能真跑** ——
    后者由 `smoke()` 真跑一遍来回答。
    """
    if not isinstance(recipe, dict):
        return ["recipe 不是对象"]
    problems: list[str] = []
    if not str(recipe.get("tool_version") or "").strip():
        problems.append("缺 tool_version(工具变了就没法判断 recipe 是否失效)")
    install = recipe.get("install") or []
    if not isinstance(install, list) or any(not isinstance(x, str) for x in install):
        problems.append("install 必须是字符串数组")

    invoke = recipe.get("invoke")
    http = recipe.get("invoke_http")
    if not invoke and not http:
        problems.append("invoke 与 invoke_http 至少要有一个")
    if invoke is not None:
        if not isinstance(invoke, list) or not invoke or any(not isinstance(x, str) for x in invoke):
            problems.append("invoke 必须是非空字符串数组")
        elif _FAKE_ANSWER.search(" ".join(invoke)):
            # 把答案直接写进命令 = 伪造评测结果, 不是适配
            problems.append("invoke 里出现了写死的答案 JSON")

    parser = recipe.get("output_parser")
    kind = parser.get("kind") if isinstance(parser, dict) else parser
    if kind not in VALID_PARSERS:
        problems.append(f"output_parser 不支持: {kind!r} (可选 {sorted(VALID_PARSERS)})")

    files = recipe.get("files")
    if files is not None:
        if not isinstance(files, dict):
            problems.append("files 必须是 {相对路径: 内容} 对象")
        else:
            for rel, content in files.items():
                if not isinstance(rel, str) or not rel.strip() or Path(rel).is_absolute() \
                        or ".." in Path(rel).parts:
                    problems.append(f"files 的键必须是工作目录内的相对路径: {rel!r}")
                if not isinstance(content, str):
                    problems.append(f"files[{rel!r}] 必须是字符串")

    codes = recipe.get("ok_exit_codes")
    if codes is not None:
        if not isinstance(codes, list) or not codes \
                or any(not isinstance(c, int) or isinstance(c, bool) for c in codes):
            problems.append("ok_exit_codes 必须是整数数组(默认 [0])")
        elif TIMEOUT_RC in codes:
            # 超时是被我们杀掉的, 不是工具给出的结论。允许它等于"发现了漏洞"
            # 会让一次跑不完的扫描变成一份"有发现的答卷"。
            problems.append(f"ok_exit_codes 不能包含 {TIMEOUT_RC}(超时)")

    # D4-5: "不覆盖"的声明。写错一个格式就等于没写 —— 于是"没覆盖"又被记成"没找到",
    # 而这个错误在报表上完全看不出来, 所以宁可在收件时拒掉。
    excluded = recipe.get("exclude_exit_codes")
    if excluded is not None:
        if isinstance(excluded, dict):
            if any(not str(k).isdigit() or not isinstance(v, str) or not v.strip()
                   for k, v in excluded.items()):
                problems.append('exclude_exit_codes 必须是 {"退出码": "原因"} 且原因为非空字符串')
            elif str(TIMEOUT_RC) in excluded:
                problems.append(f"exclude_exit_codes 不能包含 {TIMEOUT_RC}(超时)")
        elif isinstance(excluded, list):
            if not excluded or any(not isinstance(c, int) or isinstance(c, bool) for c in excluded):
                problems.append("exclude_exit_codes 必须是整数数组或 {退出码: 原因}")
            elif TIMEOUT_RC in excluded:
                problems.append(f"exclude_exit_codes 不能包含 {TIMEOUT_RC}(超时)")
        else:
            problems.append("exclude_exit_codes 必须是整数数组或 {退出码: 原因}")

    if recipe.get("needs_host_agent") and not str(recipe.get("host_model") or "").strip():
        problems.append("needs_host_agent=true 时 host_model 必填(换了宿主模型就是另一次实验)")

    # L5: 令牌不许进 recipe。它是**这一轮**的凭证, 抄进配置就等于下一轮还在用上一轮的,
    # 而且 recipe 会被冻结、复用、在页面上展示 —— 那是把凭证连同配置一起发出去。
    # 值由 `{llm_api_key}` 在调用时替换, 不经过这里。
    if TOKEN_PREFIX in json.dumps(recipe, ensure_ascii=False):
        problems.append(f"recipe 里写进了模型令牌({TOKEN_PREFIX}…): 用 {{llm_api_key}} 占位符")
    return problems


def parser_kind(recipe: dict[str, Any]) -> str:
    parser = recipe.get("output_parser")
    if isinstance(parser, dict):
        return str(parser.get("kind") or "none")
    return str(parser or "none")


def exit_ok(recipe: dict[str, Any], code: int) -> bool:
    """这个退出码算不算"这次跑成功了"?

    默认只有 0。但有些扫描器**用非零退出码表示"发现了漏洞"**(OpenAnt 明写
    0=干净 / 1=有发现 / 2=跑挂), 把它一律当失败, 会让一次成功的扫描连自检都过不了
    —— 这正是 README 里警告过的 CI 误判。这类工具的语义由 recipe 显式声明
    (`ok_exit_codes`), 不靠我们猜。超时永远是失败, 与声明无关。
    """
    if code == TIMEOUT_RC:
        return False
    codes = recipe.get("ok_exit_codes")
    if not isinstance(codes, list) or not codes:
        return code == 0
    return code in [c for c in codes if isinstance(c, int) and not isinstance(c, bool)]


def exclude_reason(recipe: dict[str, Any], code: int) -> str | None:
    """工具在说"这一类样本我不覆盖"吗? 是则返回原因串。

    与 `runner.exclude_reason` 是同一条规则(执行位要能单独起, 所以两处各留一份);
    分歧会让"自检判成功、实跑被排除"这种事发生。
    """
    if code == TIMEOUT_RC:
        return None
    codes = recipe.get("exclude_exit_codes")
    if isinstance(codes, dict):
        reason = codes.get(str(code))
        return str(reason) if reason else None
    if isinstance(codes, list):
        flat = [c for c in codes if isinstance(c, int) and not isinstance(c, bool)]
        return f"rc={code}" if code in flat else None
    return None


# 模型给不出真版本号时会写的占位。这些值一旦进库, "换了版本就换新 recipe" 的语义就废了:
# 同一个工具的两份**不同**配置会挤在本同一条行上互相覆盖, 旧配置无声消失。
_VERSION_PLACEHOLDERS = {"", "unknown", "n/a", "na", "none", "null", "?", "-", "latest"}

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env",
              ".mypy_cache", ".pytest_cache", "dist", "build", "target", "site-packages"}


def _tree_digest(root: Path, *, max_files: int = 2000) -> str:
    """目录结构指纹(路径 + 大小)。不用 mtime: 装依赖会改 mtime, 同一份工具会一路换版本。"""
    digest = hashlib.sha1()
    seen = 0
    for path in sorted(root.rglob("*")):
        if seen >= max_files:
            break
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        digest.update(f"{rel.as_posix()}:{size}\n".encode("utf-8"))
        seen += 1
    return digest.hexdigest()[:12]


def _tool_version(tool_dir: Path) -> tuple[str, str]:
    """工具目录的版本标识, 返回 (版本, 来源: git|tree)。"""
    code, out, _ = _run(["git", "-C", str(tool_dir), "rev-parse", "--short=12", "HEAD"],
                        cwd=tool_dir, timeout=30)
    if code == 0 and (out or "").strip():
        return f"git:{out.strip()}", "git"
    return f"tree:{_tree_digest(tool_dir)}", "tree"


def stamp_version(recipe: Any, tool_dir: Path) -> Any:
    """模型没给出真版本号时, 用工具目录指纹顶上。

    为什么不让 "unknown" 过去: 版本号是 recipe 的主键语义(同版本=修正, 换版本=新版),
    全填 "unknown" 等于所有工具共用一行 —— 换了配置也不会留下旧的那份。
    模型报的版本(如 v1.2.3)优先, 它是工具自己的说法, 比指纹更能说明"升级了没有"。
    """
    if not isinstance(recipe, dict):
        return recipe
    current = str(recipe.get("tool_version") or "").strip()
    if current.lower() not in _VERSION_PLACEHOLDERS:
        return recipe
    version, source = _tool_version(tool_dir)
    stamped = dict(recipe)
    stamped["tool_version"] = version
    # 写清这个版本号是谁给的: 指纹只能说明"目录变了", 不是工具声称的版本
    stamped["tool_version_source"] = source if not current else f"{source}(模型给的是 {current!r})"
    return stamped


# ── 执行一个动作 ──────────────────────────────────────────────────────────────

def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def read_file(tool_dir: Path, path: str, limit: int = 20000) -> str:
    target = (tool_dir / path).resolve()
    if not _within(tool_dir, target):
        return f"拒绝: {path} 不在工具目录内"
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"读不到: {exc}"
    return text[:limit] + ("\n…(截断)" if len(text) > limit else "")


def run_shell(command: str, cwd: Path, timeout: int = STEP_TIMEOUT) -> dict[str, Any]:
    """执行 agent 给的命令。**这不是沙箱** —— 容器本身才是边界(无密钥、无真值、
    无平台数据库)。这里只挡住"明显越界"的两类输入和无限输出。
    """
    if not command.strip():
        return {"rc": 1, "output": "空命令"}
    if "truth/" in command or "ground_truth" in command:
        # 容器里本就没有这些文件; 真的出现了, 说明平台侧的白名单投影漏了 ——
        # 这时候停下比继续探更安全。
        return {"rc": 1, "output": "拒绝: 命令涉及真值文件, 适配中止"}
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(
            ["bash", "-lc", command], cwd=str(cwd), capture_output=True,
            text=True, timeout=timeout, env=_shell_env(),
        )
        output = (proc.stdout or "") + (("\n---stderr---\n" + proc.stderr) if proc.stderr else "")
        return {"rc": proc.returncode, "output": output[:MAX_OBS_CHARS],
                "seconds": round((datetime.now(timezone.utc) - started).total_seconds(), 1)}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "output": f"超时({timeout}s), 已被杀掉", "seconds": timeout}
    except OSError as exc:
        return {"rc": 127, "output": f"起不来: {exc}"}


def _shell_env() -> dict[str, str]:
    """给工具一个干净环境: 继承 PATH/HOME, 但**不把 EVAL_TOKEN 带进被测工具的子进程**。

    例外是 `EVAL_LLM_*` 那三个: 它是平台**特意**发给这一轮的模型入口(只认这一轮、有
    上限、收尾即吊销), 被测工具要模型能力就得用它。自检与实跑必须拿到同一份环境,
    否则"自检过了、实跑连不上模型"会变成一个查不出原因的失败。
    """
    env = {k: v for k, v in os.environ.items()
           if not k.upper().startswith("EVAL_") or k.upper() in _LLM_ENV_ALLOWED}
    env.setdefault("HOME", "/root")
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


# ── 交上去之前的自检: 真跑一遍 ────────────────────────────────────────────────

def smoke(recipe: dict[str, Any], *, sample: dict[str, Any], workdir: Path,
          render: Callable[[list[str], dict[str, str]], list[str]] = render_argv,
          timeout: int | None = None) -> tuple[bool, str]:
    """用给的样本把 `invoke` 真跑一遍。

    这是**唯一**能区分"探通了"和"看起来探通了"的动作。装的步骤在 agent 探索时已经
    跑过(它是在同一个目录里装的), 这里不重装 —— 重装会把探到的东西抹掉。
    """
    values = {
        "sample_file": str(sample["file"]), "sample_key": sample["sample_key"],
        "file_name": sample["file"].name,
        "relative_path": sample.get("relative_path") or sample["file"].name,
        "workdir": str(workdir), "tool_dir": str(sample.get("tool_dir") or ""),
        "prompt": str(sample.get("prompt_path") or ""),
    }
    invoke = recipe.get("invoke") or []
    if not invoke:
        return False, "没有 invoke 可跑(invoke_http 的自检尚未实现)"
    argv = render(list(invoke), values)
    code, out, err = _run(argv, workdir, timeout or int(recipe.get("timeout_seconds") or 300))
    if code == TIMEOUT_RC:
        return False, "自检超时"
    excluded = exclude_reason(recipe, code)
    if excluded is not None:
        # 自检的样本就是工具**必须**能审的那一个。它被声明成"不覆盖", 说明这份 recipe
        # 对这个样本不成立 —— 不能拿它证明适配成功, 也不能把自检算成工具的失败。
        return False, (f"自检退出码 {code} 被 recipe 声明为「不覆盖」({excluded})："
                       "工具不认这个样本，换一个它支持的语言的样本再自检")
    if parser_kind(recipe) != "exit_code" and not exit_ok(recipe, code):
        return False, f"自检退出码 {code}: {(err or out)[:300]}"
    if not (out or err).strip():
        # 工具能跑但一个字都不说: 那是 no_output, 不是"没发现问题"
        return False, "自检无输出"
    if parser_kind(recipe) in ("json", "sarif", "none") and _looks_translatable(recipe, out) is False:
        return False, f"自检输出解析不出契约格式: {out.strip()[:200]}"
    return True, ""


def _run(argv: list[str], cwd: Path, timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                              timeout=timeout, env=_shell_env())
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError as exc:
        return 127, "", f"command not found: {exc}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def _looks_translatable(recipe: dict[str, Any], text: str) -> bool | None:
    """自检用的粗判: 输出里能不能解出东西来。不追求和判分脚本完全一致 ——
    判分脚本在平台侧, 这里只回答"这条路走不走得通"。
    """
    kind = parser_kind(recipe)
    if kind == "sarif":
        return '"runs"' in text
    if kind in ("json", "none"):
        return "{" in text and "}" in text
    return None


# ── 观察 ──────────────────────────────────────────────────────────────────────

_MANIFESTS = (
    "README.md", "README.rst", "README", "pyproject.toml", "setup.py", "requirements.txt",
    "package.json", "Cargo.toml", "go.mod", "pom.xml", "Makefile", "Dockerfile",
)


def snapshot(tool_dir: Path) -> dict[str, Any]:
    """给 agent 的第一眼: 目录里有什么、有哪些装法线索。不做深层遍历 ——
    几万文件的大仓一次列出来只会把上下文撑爆。
    """
    try:
        entries = sorted(p.name + ("/" if p.is_dir() else "") for p in tool_dir.iterdir())[:200]
    except OSError as exc:
        return {"error": f"读不到工具目录: {exc}"}
    manifests = {}
    for name in _MANIFESTS:
        candidate = tool_dir / name
        if candidate.is_file():
            manifests[name] = read_file(tool_dir, name, limit=2000)
    return {"top_level": entries, "manifests": manifests}


# ── 主循环 ────────────────────────────────────────────────────────────────────

def _load_prompt() -> str:
    try:
        return PROMPT_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise AdapterError(f"适配提示词读不到: {PROMPT_PATH} ({exc})") from exc


def _summarize(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """步数多了以后, 老步骤只留一行。全量回放会把上下文撑爆, 而撑爆的后果是
    agent 忘记自己要干什么 —— 它会在第 30 步重新 `ls`。"""
    if len(history) <= HISTORY_KEPT:
        return history
    old = [{"step": h["step"], "action": h["action"], "result": str(h.get("result", ""))[:120]}
           for h in history[:-HISTORY_KEPT]]
    return [{"earlier": old}, *history[-HISTORY_KEPT:]]


def adapt(
    *,
    run: dict[str, Any],
    tool_dir: Path,
    sample: dict[str, Any],
    sample_pool: list[dict[str, Any]] | None = None,
    workdir: Path,
    render: Callable[[list[str], dict[str, str]], list[str]] = render_argv,
    ask_fn: Callable[[str, str, dict[str, Any]], dict[str, Any]] = ask,
    freeze: bool = True,
) -> tuple[dict[str, Any] | None, str, dict[str, Any]]:
    """探一次。返回 (recipe, 来源说明, 摘要)。

    失败返回 `(None, 失败原因, 摘要)` —— 原因是 PRD §8 的枚举值之一,
    调用方应当把它落成 run 的终态(R9: 适配失败不重试)。
    """
    prompt = _load_prompt()
    history: list[dict[str, Any]] = []
    obs = snapshot(tool_dir)
    steps = 0
    # 自检样本默认是第一份, 但**不强制**: 2026-11-03 run 5 就是因为这一条卡死的 ——
    # 那一轮 packets[0] 是 C 文件, 而被测工具只认 .py, 于是"排除这条样本"和
    # "自检必须过"互相矛盾, 一个本来能评 4 条 Python 样本的工具被判成无法适配。
    pool = list(sample_pool or [sample])
    pool_by_key = {str(s["sample_key"]): s for s in pool}

    while steps < MAX_STEPS:
        steps += 1
        payload = {
            "objective": "把 tool_dir 里的工具探成一份 recipe",
            "contract_answers": {"found": "bool", "findings": [
                {"file": "relative_path", "function": "str|null", "line_start": "int|null",
                 "line_end": "int|null", "type_cwe": "str|null", "evidence": "str"}]},
            "tool_dir": str(tool_dir),
            "sample": {"sample_key": sample["sample_key"],
                       "relative_path": sample.get("relative_path"),
                       "file_name": sample["file"].name},
            # 让 agent 看见本轮一共有哪些样本(只要文件名和扩展名, 不含内容):
            # 工具只覆盖部分语言时, 它得知道有哪些语言可挑, 否则只能盲猜。
            "sample_pool": [{"sample_key": str(s["sample_key"]),
                             "file_name": s["file"].name,
                             "relative_path": s.get("relative_path")}
                            for s in pool[:80]],
            "initial_snapshot": obs if steps == 1 else None,
            "history": _summarize(history),
            "steps_left": MAX_STEPS - steps + 1,
        }
        reply = ask_fn(PROFILE, prompt, payload)
        action = str(reply.get("action") or "").strip()

        if action == "give_up":
            reason = str(reply.get("reason") or "agent_gave_up")
            if reason not in GIVE_UP_REASONS:
                reason = "agent_gave_up"
            log(f"适配放弃: {reason} — {reply.get('detail', '')}")
            return None, reason, {"steps": steps, "detail": str(reply.get("detail") or "")[:500]}

        if action == "recipe":
            # 版本号在自检之前就补齐: 模型常写 "unknown", 而库里的版本语义靠它区分
            recipe = stamp_version(reply.get("recipe"), tool_dir)
            problems = validate_recipe(recipe)
            if problems:
                history.append({"step": steps, "action": "recipe(被拒)",
                                "result": "; ".join(problems)})
                continue
            smoke_key = str(reply.get("smoke_sample") or "").strip()
            smoke_sample = pool_by_key.get(smoke_key) if smoke_key else sample
            if smoke_sample is None:
                history.append({"step": steps, "action": "recipe(被拒)",
                                "result": f"smoke_sample {smoke_key!r} 不在本轮样本里; "
                                          f"可选: {sorted(pool_by_key)[:10]}"})
                continue
            ok, why = smoke(recipe, sample=smoke_sample, workdir=workdir, render=render)
            if not ok:
                history.append({"step": steps, "action": "recipe(自检失败)", "result": why})
                continue
            if freeze:
                _freeze(run, recipe, note=str(reply.get("exploit_note") or recipe.get("notes") or ""))
            log(f"适配成功: {recipe.get('tool_version')} parser={parser_kind(recipe)} steps={steps}")
            return recipe, f"adapted:{recipe.get('tool_version')}", {
                "steps": steps, "smoke_sample": str(smoke_sample["sample_key"])}

        if action == "bash":
            command = str(reply.get("command") or "")
            log(f"step {steps}: bash {command[:160]}")
            result = run_shell(command, tool_dir)
            history.append({"step": steps, "action": f"bash {command[:300]}",
                            "result": f"rc={result['rc']}\n{result['output']}"})
            continue

        if action == "read":
            path = str(reply.get("path") or "")
            log(f"step {steps}: read {path}")
            history.append({"step": steps, "action": f"read {path}",
                            "result": read_file(tool_dir, path)})
            continue

        # 模型给了一个不认识的 action: 告诉它一声, 不要当成功也不要当失败
        history.append({"step": steps, "action": str(action)[:60],
                        "result": f"未知 action {action!r}; 只能是 bash/read/recipe/give_up"})

    return None, "timeout", {"steps": steps, "detail": f"超过 {MAX_STEPS} 步仍未交出 recipe"}


def _freeze(run: dict[str, Any], recipe: dict[str, Any], *, note: str) -> dict[str, Any]:
    """把 recipe 落进 `capability_eval_recipes`(旧版保留, 靠 superseded_by 指向新版)。"""
    try:
        return _post("/api/internal/eval/recipes", {
            "item_id": int(run["item_id"]), "category": run["category"],
            "tool_version": str(recipe.get("tool_version") or "unknown"),
            "recipe": recipe, "exploit_note": note[:2000],
        })
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        error = AdapterPlatformError if exc.code in (401, 403, 503) else AdapterError
        raise error(f"recipe 落库失败 {exc.code}: {detail}") from exc
