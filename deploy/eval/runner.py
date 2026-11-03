#!/usr/bin/env python3
"""评测执行位: 领活 → 按 recipe 跑样本 → 交卷 → 收尾。

为什么是反向轮询而不是平台下发: 平台容器里没有 docker CLI/套接字, 它既起不了这个容器,
也探不到它的活的; 这个容器反过来也没有平台的数据库。所以由**这里**主动去
`/api/internal/eval/*` 领活、交卷、收尾, 平台只负责记账与判分(与 repro 的 gc 轮询同一套模型)。

四条不变量:

1. **真值到不了这里**。领活只发题面与被审文件, 判分在平台侧做。谁能看见 `truth/`,
   谁就能把分数做上去 —— 所以这条不是"注意一下", 是结构上的隔离。
2. **逐样本交卷**。中途崩了重来时, 平台侧已有答卷(`has_answers`), 已花的预算不白烧。
3. **两道预算闸**: 次数 + 墙钟。超任何一条都落 `budget_exceeded` 终态 —— 不静默截断成
   "跑了 12 个样本的成功评测", 那种报表比没有报表更坏。
4. **原生输出与翻译结果分两列**(R8 + D3)。parser 只说它翻译成了什么, 不覆盖工具原话。

这个文件**只依赖标准库**: 执行位里跑的是第三方工具, 它自己的依赖(以及版本冲突)
不该影响调度循环本身能不能起来。
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

# ── 配置 ──────────────────────────────────────────────────────────────────────

API_BASE = os.environ.get("EVAL_API_BASE", "http://ai4sec:8100").rstrip("/")
TOKEN = os.environ.get("EVAL_TOKEN", "")
POLL_SECONDS = float(os.environ.get("EVAL_POLL_SECONDS", "30"))
WORK_ROOT = Path(os.environ.get("EVAL_WORK_ROOT", "/work/runs"))
RECIPE_DIR = Path(os.environ.get("EVAL_RECIPE_DIR", "/opt/eval/recipes"))
# 兜底 recipe 只给夹具冒烟用。生产环境留空 —— 有它就会"什么工具都能跑", 而这正是
# 我们最不想要的那种方便。
FALLBACK_RECIPE = os.environ.get("EVAL_FALLBACK_RECIPE", "")
KEEP_FAILED_DAYS = float(os.environ.get("EVAL_KEEP_FAILED_DAYS", "7"))

# L5: 被测工具的模型入口。令牌由平台在 claim 里发(只认这一轮、有次数与 token 上限、
# 收尾即吊销), 执行位只负责把它交给工具。网关的地址与 key 这里根本没有 ——
# 工具能连的只有平台自己那一层。
LLM_BASE_PATH = "/api/internal/eval/v1"
LLM_ENV = ("EVAL_LLM_BASE_URL", "EVAL_LLM_TOKEN", "EVAL_LLM_MODEL")

DEFAULT_MAX_CALLS = int(os.environ.get("EVAL_MAX_MODEL_CALLS", "30"))
DEFAULT_MAX_SECONDS = int(os.environ.get("EVAL_MAX_SECONDS", "1800"))
DEFAULT_CALL_TIMEOUT = int(os.environ.get("EVAL_CALL_TIMEOUT", "300"))

# 我们杀超时时用的退出码(与 adapter.py 同一个常量)。它不是工具给出的结论,
# 所以不能被 `ok_exit_codes` 认成"成功"。下面 `code == TIMEOUT_RC` 的分支都读它。
TIMEOUT_RC = 124

# 没有 recipe 时要不要现场适配(D 阶段)。默认开: 只有"探一次"才有下一轮的低成本复跑;
# 关掉意味着这个工具永远跑不了 —— 两条路都有代价, 但静默跳过最糟。
ADAPTER_ENABLED = os.environ.get("EVAL_ADAPTER_ENABLED", "1") == "1"
TOOL_ROOT = Path(os.environ.get("EVAL_TOOL_ROOT", "/work/tools"))
TRANSLATE_PROFILE = os.environ.get("EVAL_TRANSLATE_PROFILE", "capability_eval_translate")

# 当前这一轮的 id。翻译节点也要带上它, 否则它的模型调用同样是账外成本
# (`/api/internal/eval/llm` 靠这个字段把用量记进该轮预算)。
RUN_ID: int | None = None
READY_TIMEOUT = int(os.environ.get("EVAL_READY_TIMEOUT", "120"))


def log(message: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat(timespec='seconds')}] {message}", flush=True)


# ── 平台侧接口 ────────────────────────────────────────────────────────────────

class PlatformError(RuntimeError):
    """平台明确回的错(401/503/409)。这类错误重试一万次也不会好, 直接退出让人来看。"""


def _post(path: str, payload: dict[str, Any], *, timeout: int = 120) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"{API_BASE}{path}", data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Repro-Token": TOKEN},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        if exc.code in (401, 403, 503):
            raise PlatformError(f"{path} -> {exc.code}: {detail}") from exc
        raise


def claim() -> dict[str, Any]:
    return _post("/api/internal/eval/claim", {})


def llm_bundle(claimed: Mapping[str, Any]) -> dict[str, str]:
    """claim 里的令牌块 → 工具要的三个值 (base_url / api_key / model)。

    没发令牌时返回空 dict —— 那时 invoke 里的 `{llm_*}` 占位符会原样留着, 工具自己会报
    参数不对。这比"塞一个假的 base_url 让它连不上"好查: 前者一眼看出是没发令牌,
    后者会表现成一串连接超时。
    """
    block = claimed.get("llm") or {}
    token = str(block.get("token") or "")
    if not token:
        return {}
    return {"base_url": f"{API_BASE}{LLM_BASE_PATH}", "api_key": token,
            "model": str(block.get("model") or "")}


def apply_llm_env(llm: Mapping[str, str]) -> None:
    """把令牌放进本进程环境, 由 install/invoke/适配 shell 继承。

    **不落盘**: 不写进 recipe.json、不写进工作目录 —— 那个目录会作为证据留 7 天,
    而凭证留在证据目录里就是纯泄漏。也没有任何一行日志打印它。
    """
    for name in LLM_ENV:
        os.environ.pop(name, None)
    if not llm.get("api_key"):
        return
    os.environ["EVAL_LLM_BASE_URL"] = str(llm.get("base_url") or "")
    os.environ["EVAL_LLM_TOKEN"] = str(llm.get("api_key") or "")
    os.environ["EVAL_LLM_MODEL"] = str(llm.get("model") or "")


def _reject_secret(recipe: Mapping[str, Any], llm: Mapping[str, str]) -> None:
    """recipe 里不许出现令牌明文。

    适配 agent 很自然地会"把刚才跑通的那条命令照抄进 recipe", 而那条命令里可能带着
    `{llm_api_key}` 的**真实值**。recipe 会被冻结、复用、在页面上展示 —— 令牌进去就等于
    下一轮跑的还是上一轮的凭证, 而且它会跟着配置一起被看见。
    """
    token = str(llm.get("api_key") or "")
    if token and token in json.dumps(recipe, ensure_ascii=False):
        raise RuntimeError("recipe 里写进了模型令牌: 用 {llm_api_key} 占位符, 不要把值抄进去")


def deliver(run_id: int, answers: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return _post(f"/api/internal/eval/runs/{run_id}/answers", {"answers": answers})


def finish(run_id: int, status: str, **payload: Any) -> dict[str, Any]:
    return _post(f"/api/internal/eval/runs/{run_id}/finish", {"status": status, **payload}, timeout=300)


# ── recipe ────────────────────────────────────────────────────────────────────

def resolve_recipe(run: dict[str, Any], claimed: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """平台库里的 recipe 优先; 其次是按 item 命名的本地文件; 最后才是夹具兜底。

    返回 (recipe, 来源说明)。来源要写进 cost_json —— 事后看一条分数时,
    第一个该问的问题是"它到底按哪份 recipe 跑的"。
    """
    record = claimed.get("recipe") or {}
    if record.get("recipe"):
        return record["recipe"], f"db:{record.get('tool_version', '')}"

    item_file = RECIPE_DIR / f"item-{run['item_id']}.json"
    if item_file.is_file():
        return json.loads(item_file.read_text(encoding="utf-8")), f"file:{item_file}"

    if FALLBACK_RECIPE and Path(FALLBACK_RECIPE).is_file():
        return json.loads(Path(FALLBACK_RECIPE).read_text(encoding="utf-8")), f"fallback:{FALLBACK_RECIPE}"
    return None, ""


def render(argv: list[str], values: dict[str, str]) -> list[str]:
    """`{sample_file}` 这类占位符替换。**逐个参数**替换, 不拼成一个 shell 字符串 ——
    拼字符串就得过 shell, 而文件名/代码路径是外部数据。
    """
    out = []
    for part in argv:
        for key, value in values.items():
            part = part.replace("{" + key + "}", value)
        out.append(part)
    return out


def exit_ok(recipe: dict[str, Any], code: int) -> bool:
    """退出码算不算"跑成功了"。默认只有 0; 扫描器自报的语义写在 `ok_exit_codes`。

    与 `adapter.exit_ok` 是同一条规则(执行位要能单独起, 所以两处各留一份);
    分歧会让"自检过了、实跑记失败"这种事发生 —— `test_capability_eval_adapter.py`
    用同一张判定表锁住两者一致。
    """
    if code == TIMEOUT_RC:
        return False
    codes = recipe.get("ok_exit_codes")
    if not isinstance(codes, list) or not codes:
        return code == 0
    return code in [c for c in codes if isinstance(c, int) and not isinstance(c, bool)]


def exclude_reason(recipe: dict[str, Any], code: int) -> str | None:
    """这个退出码是不是工具在说"**这一类样本我根本不覆盖**"? 是则返回原因串。

    与"跑失败"是两件事, 必须分开记(D4-5):
      · 跑失败(超时/崩溃) —— 分数归工具, 交一份空答卷即可;
      · 不覆盖(语言不支持/平台不支持) —— 这条样本**不进分母**。把它记成 miss 或
        invalid_output, 等于拿"我们挑了一个它不认的语言"去扣它的分。

    声明写在 recipe 的 `exclude_exit_codes` 里, 两种写法:
        [3]                                  -> 原因记成 "rc=3"
        {"3": "language_not_supported"}      -> 原因原样记下, 报表按原因分组
    超时永远不是"不覆盖": 一个跑不完的工具是跑不完, 不是不支持。
    与 `adapter.exclude_reason` 是同一条规则(执行位要能单独起), 由单测锁住一致。
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


# ── 翻译(D3 的可执行部分) ──────────────────────────────────────────────────────

_JSON_FENCE = re.compile(r"```(?:json)?\s*(.+?)```", re.S)


def _first_json_object(text: str) -> Any:
    """从一堆输出里抠出第一个完整 JSON 对象。

    模型的典型毛病是"JSON 外面裹一段解释"或"包在 ``` 里" —— 这不是答错题,
    所以先尽力抠; 抠不出来才算 invalid。
    """
    text = (text or "").strip()
    for candidate in [text, *(m.group(1).strip() for m in _JSON_FENCE.finditer(text))]:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    while start != -1:
        depth = 0
        for index in range(start, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:index + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    return None


def parser_kind(parser: Any) -> str:
    """recipe 里 parser 两种写法都认: 字符串(PRD §9.3)与 `{"kind": ...}`(夹具)。"""
    if isinstance(parser, Mapping):
        return str(parser.get("kind") or "none")
    return str(parser or "none") or "none"


def _from_sarif(text: str) -> Any:
    """SARIF → 契约格式。工具原生支持 SARIF 时就该走这条路, 别让它落到 agent_translate:
    翻译节点每块都会多一次失真机会, 而 SARIF 里本来就写好了文件和行号。
    """
    payload = _first_json_object(text)
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        return None
    findings: list[dict[str, Any]] = []
    for run in payload["runs"]:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict) or len(findings) >= 5:
                continue
            locations = result.get("locations") or []
            physical = (locations[0] or {}).get("physicalLocation") if locations else None
            physical = physical if isinstance(physical, dict) else {}
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            file = str(artifact.get("uri") or "")
            if not file:
                continue
            rule = str(result.get("ruleId") or "")
            message = result.get("message")
            text_message = message.get("text") if isinstance(message, dict) else message
            start = region.get("startLine")
            findings.append({
                "file": file, "function": str(result.get("symbol") or ""),
                "line_start": start, "line_end": region.get("endLine") or start,
                # 只有 ruleId 本身就是 CWE 编号时才当 CWE —— 猜一条类型是编事实
                "type_cwe": rule if rule.upper().startswith("CWE-") else None,
                "evidence": str(text_message or "")[:200],
            })
    return {"found": bool(findings), "findings": findings}


_TRANSLATE_PROMPT: str | None = None


def _translate_prompt() -> str:
    global _TRANSLATE_PROMPT
    if _TRANSLATE_PROMPT is None:
        path = Path(__file__).resolve().parent / "prompts" / "translate.md"
        _TRANSLATE_PROMPT = path.read_text(encoding="utf-8")
    return _TRANSLATE_PROMPT


def translate_answer(raw: str, context: Mapping[str, Any], returncode: int) -> Any:
    """调平台上的模型把散文翻成契约格式(盲翻译: 只给它工具的输出, 不给真值)。

    返回 None 表示翻译失败 —— 判分按 invalid_output 算。**不推断**: 模型回
    `found=null`(它自己认输)与接口报错, 都是 None, 不给一个"看起来像结论"的默认值。
    """
    body: dict[str, Any] = {
        "profile": TRANSLATE_PROFILE, "prompt": _translate_prompt(),
        "payload": {"tool_output": raw[:MAX_TRANSLATE_CHARS],
                    "file": context.get("relative_path") or context.get("file_name", ""),
                    "exit_code": returncode},
    }
    if RUN_ID is not None:
        body["run_id"] = RUN_ID
    try:
        result = _post("/api/internal/eval/llm", body, timeout=180)
    except Exception as exc:  # noqa: BLE001 —— 翻译失败不能带崩整轮
        log(f"翻译失败({context.get('sample_key', '?')}): {exc}")
        return None
    # 翻译节点也花模型调用, 同样要记进"这份分数是哪家模型跑的"
    _load_adapter().record_serving(TRANSLATE_PROFILE, result)
    parsed = result.get("parsed")
    if not isinstance(parsed, dict) or not isinstance(parsed.get("findings"), list):
        return None
    if parsed.get("found") is None:
        return None                      # 模型明确说"翻不了" → 不可判, 不是"没问题"
    return parsed


MAX_TRANSLATE_CHARS = int(os.environ.get("EVAL_TRANSLATE_MAX_CHARS", "12000"))


def parse_answer(parser: Any, raw: str, *, returncode: int,
                 context: Mapping[str, Any] | None = None,
                 translate: Any = None) -> tuple[Any, str]:
    """原生输出 → 契约 §3 的答案。返回 (answer, 说明)。

    `answer=None` 表示**翻译失败**, 判分会把它算成 invalid_output。
    绝不能在这里凭散文猜一个 found=false —— 那是替被测工具答题。

    `parser` 认三种写法: 字符串(`json`/`sarif`/`agent_translate`/`exit_code`/`none`)、
    `{"kind": ...}`、以及老 recipe 里的 `json_stdout`(等价 `json`)。
    """
    kind = parser_kind(parser)
    context = context or {}
    if kind in ("none", ""):
        # 没有 parser: 假设工具直出契约格式(夹具与少数原生支持的工具就是这样)
        return _first_json_object(raw), "no_parser"
    if kind in ("json", "json_stdout"):
        answer = _first_json_object(raw)
        return answer, "" if answer is not None else "no_json_in_stdout"
    if kind == "sarif":
        answer = _from_sarif(raw)
        return answer, "" if answer is not None else "no_sarif_in_stdout"
    if kind == "agent_translate":
        translator = translate or translate_answer
        answer = translator(raw, context, returncode)
        return answer, "" if answer is not None else "translate_failed"
    if kind == "exit_code":
        # 0 = 没发现问题, 非 0 = 有问题但位置未知。这类工具只配回答 found, 不能编位置。
        return ({"found": returncode != 0, "findings": []}, "exit_code")
    return None, f"unknown_parser:{kind}"


# ── 单次跑 ────────────────────────────────────────────────────────────────────

def _peak_rss_mb() -> float | None:
    """本进程的峰值常驻内存(`/proc/self/status` 的 `VmHWM`)。

    内核自己记的高水位, 不用采样线程去轮询 —— 轮询既抓不到尖峰, 又会在被测工具
    吃满 CPU 的时候和它抢时间片。
    """
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmHWM:"):
                    return round(int(line.split()[1]) / 1024.0, 1)
    except Exception:  # noqa: BLE001 —— 读不到就是读不到, 不该影响这一轮收尾
        return None
    return None


def _resource_snapshot() -> dict[str, float | None]:
    """资源快照。跑前跑后各取一次, 差值 = 这一轮真正花掉的 CPU。

    峰值内存**只能取高水位**, 不能做差(`ru_maxrss` 是"曾经最大", 不是"当前")。
    所以它记的是"进程/容器自启动以来的峰值", 多轮共用一个进程时含历史轮次 —— 这一点
    在 `_cost` 里如实标出来, 不假装是这一轮的数字。
    """
    import resource

    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "self_cpu_seconds": time.process_time(),
        "children_cpu_seconds": children.ru_utime + children.ru_stime,
        "children_max_rss_mb": round(children.ru_maxrss / 1024.0, 1),
        "self_peak_rss_mb": _peak_rss_mb(),
    }


def _resource_delta(start: dict[str, float | None]) -> dict[str, Any]:
    end = _resource_snapshot()
    return {
        # 差值: 这一轮的子进程 CPU(工具自己的进程都在这里)
        "children_cpu_seconds": round(
            float(end["children_cpu_seconds"] or 0) - float(start["children_cpu_seconds"] or 0), 1),
        "runner_cpu_seconds": round(
            float(end["self_cpu_seconds"] or 0) - float(start["self_cpu_seconds"] or 0), 1),
        # 高水位: 不是这一轮的增量, 是"到这一刻为止的最大值"
        "children_max_rss_mb": end["children_max_rss_mb"],
        "runner_peak_rss_mb": end["self_peak_rss_mb"],
        "peak_note": "峰值是进程生命周期内的最大值(无法按轮做差); CPU 是这一轮的差值",
    }


class Outcome:
    def __init__(self) -> None:
        self.answers: dict[str, list[dict[str, Any]]] = {}
        self.calls = 0
        self.failures = 0
        # 被工具自报"不覆盖"的调用数。与 failures 分开记: 它们不是失败的尝试,
        # 而是这条样本不该出现在这份分数的分母里(D4-5)。
        self.excluded = 0
        self.started = time.time()
        # 开跑那一刻的资源基线。`elapsed()` 是墙钟, 这个才是"花了多少 CPU / 吃多大内存"。
        self.res_baseline = _resource_snapshot()
        self.notes: list[str] = []

    def elapsed(self) -> float:
        return time.time() - self.started

    def resources(self) -> dict[str, Any]:
        return _resource_delta(self.res_baseline)


def _safe_join(root: Path, rel_path: str) -> Path:
    """把 recipe 里的相对路径拼到工作目录下。**绝对路径与 `..` 一律拒绝** ——
    recipe 是模型给的, 一个 `/etc/cron.d/x` 就是一次越界写入。
    """
    rel = str(rel_path or "").strip()
    if not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
        raise RuntimeError(f"recipe.files 的路径必须是工作目录内的相对路径: {rel_path!r}")
    target = (root / rel).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"recipe.files 越界: {rel_path!r}") from exc
    return target


def _prepare_samples(workdir: Path, packets: list[dict[str, Any]]) -> Path:
    """把样本落成执行位自己的只读副本, 顺手核对指纹。

    核对哈希不是形式主义: 数据集目录在平台侧是可写的, 落库之后被改动过的话,
    这一轮跑审的就是**另一份代码**, 而分数会挂在原来的结论上。
    """
    samples_dir = workdir / "samples"
    for packet in packets:
        sample_dir = samples_dir / packet["sample_key"]
        sample_dir.mkdir(parents=True, exist_ok=True)
        content = packet["file_content"]
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if digest != packet["artifact_hash"]:
            raise DatasetError(
                f"样本指纹不符: {packet['sample_key']} 期望 {packet['artifact_hash']} 实得 {digest}")
        (sample_dir / packet["file_name"]).write_text(content, encoding="utf-8")
        (sample_dir / "prompt.txt").write_text(packet["prompt"], encoding="utf-8")
        (sample_dir / "prompt.txt").chmod(0o444)
        (sample_dir / packet["file_name"]).chmod(0o444)
    return samples_dir


def _run_command(argv: list[str], *, cwd: Path, timeout: int) -> tuple[int, str, str, float]:
    started = time.time()
    try:
        proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or "", time.time() - started
    except FileNotFoundError as exc:
        return 127, "", f"command not found: {exc}", time.time() - started
    except subprocess.TimeoutExpired as exc:
        return 124, (exc.stdout or ""), f"timeout after {timeout}s", time.time() - started


def _render_tree(node: Any, values: Mapping[str, str]) -> Any:
    """HTTP 请求体里的占位符替换。结构与值分开处理 —— 只替换**字符串叶子**,
    不把整个 body 拼成一个字符串再去 parse(那样遇到引号就会坏)。
    """
    if isinstance(node, str):
        out = node
        for key, value in values.items():
            out = out.replace("{" + key + "}", str(value))
        return out
    if isinstance(node, list):
        return [_render_tree(item, values) for item in node]
    if isinstance(node, Mapping):
        return {key: _render_tree(value, values) for key, value in node.items()}
    return node


def _wait_ready(url: str, probe: str, timeout: int) -> tuple[bool, str]:
    """等自带 Web 界面的工具起来。`probe` 形如 `GET /`。

    没有这一步, 第一轮调用会撞在"服务还没起来"上 —— 那 6 次失败会被记成
    "工具没输出", 而它其实只是慢。
    """
    method, _, path = str(probe).strip().partition(" ")
    method = (method or "GET").upper()
    path = path.strip() or "/"
    parts = urllib.parse.urlsplit(url)
    target = f"{parts.scheme}://{parts.netloc}{path}"
    deadline = time.time() + timeout
    last = "未探测"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(target, method=method), timeout=5) as response:
                if response.status < 400:
                    return True, ""
                last = f"{target} -> {response.status}"
        except urllib.error.HTTPError as exc:
            last = f"{target} -> {exc.code}"
        except Exception as exc:  # noqa: BLE001 —— 没起来就是连接被拒/超时, 继续等
            last = f"{target} -> {exc}"
        time.sleep(1.0)
    return False, last


def _http_invoke(spec: Mapping[str, Any], values: Mapping[str, str],
                 timeout: int) -> tuple[int, str, str, float]:
    """`invoke_http` 形态(PRD §9.3): 自带 Web 界面的审计平台只能这么调。

    退出码口径与命令行一致: 2xx/3xx 记 0, 其余记 HTTP 状态码 —— 下游按"非 0 = 这次没跑好"
    处理, 不会因为它不是 shell 命令就另立一套。
    """
    started = time.time()
    url = str(_render_tree(str(spec.get("url") or ""), values))
    method = str(spec.get("method") or "POST").upper()
    probe = spec.get("ready_probe")
    if probe:
        ok, why = _wait_ready(url, str(probe), int(spec.get("ready_timeout") or READY_TIMEOUT))
        if not ok:
            return 124, "", f"ready_probe 未通过: {why}", time.time() - started

    body = _render_tree(spec.get("body") or {}, values)
    data = None
    headers = {"Content-Type": "application/json", **(spec.get("headers") or {})}
    if method not in ("GET", "HEAD"):
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8", "replace")
            return (0 if response.status < 400 else response.status), text, "", time.time() - started
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace")
        return exc.code, text, "", time.time() - started
    except Exception as exc:  # noqa: BLE001
        return 1, "", f"{type(exc).__name__}: {exc}", time.time() - started


class BudgetExceeded(RuntimeError):
    """次数或墙钟到顶。带着已经跑出来的答卷一起走, 不丢弃。"""


class DatasetError(RuntimeError):
    """样本本身有问题(指纹对不上/文件读不到)。这不是工具的问题, 归因不能算到工具头上。"""


def execute(run: dict[str, Any], recipe: dict[str, Any], packets: list[dict[str, Any]],
            workdir: Path, budget: dict[str, Any], outcome: Outcome,
            samples_dir: Path | None = None,
            llm: Mapping[str, str] | None = None) -> Outcome:
    llm = llm or {}
    repeats = int(run["repeats"])
    samples_dir = samples_dir or _prepare_samples(workdir, packets)
    raw_dir = workdir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    max_calls = int(budget.get("max_model_calls") or DEFAULT_MAX_CALLS)
    max_seconds = float(budget.get("max_seconds") or DEFAULT_MAX_SECONDS)
    call_timeout = int(recipe.get("timeout_seconds") or DEFAULT_CALL_TIMEOUT)

    # recipe 自带的辅助文件(转换脚本/配置模板)先落盘, install 与 invoke 才用得上。
    # 它们必须来自 recipe 而不是执行位的现写现用: 同一条分数要能回答"它按哪份逻辑算的"。
    for rel_path, content in (recipe.get("files") or {}).items():
        target = _safe_join(workdir, rel_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(content), encoding="utf-8")
        outcome.notes.append(f"file:{rel_path} {len(str(content))}B")

    # install 只跑一次, 失败即终态(装不上不是"某些样本失败", 是这轮跑不成)
    # 令牌也要在 install 里可用: 需要模型的工具通常在这一步就把端点写进自己的配置文件。
    #
    # `tool_dir`: 被测工具的源码目录(平台克隆下来的那份)。没有它, install 只能写死一个
    # 带 item 号的绝对路径 —— 换个工具就换一份 recipe, 而 recipe 是按工具版本冻结的。
    # 目录不在(卷被清、clone 失败)不是这里能修的: 让 install 以 rc 非 0 明确失败,
    # 记 install_failed, 比静默跳过安装、到最后一步报"找不到命令"更容易归因。
    tool_dir = TOOL_ROOT / f"item-{run['item_id']}"
    install_values = {"workdir": str(workdir), "tool_dir": str(tool_dir),
                      "llm_base_url": str(llm.get("base_url") or ""),
                      "llm_api_key": str(llm.get("api_key") or ""),
                      "llm_model": str(llm.get("model") or "")}
    for command in recipe.get("install") or []:
        # install 是**shell 字符串**(recipe 与适配提示词里都是这么写的), 不是 argv 数组。
        # 原来这里对字符串做 `list(command)` 会把它拆成一个个字符, 于是任何带 install 的
        # recipe 都以 rc=127 失败 —— 夹具的 install 恰好是空数组, 所以一直没暴露。
        # invoke 不走 shell: 那一条的参数是外部数据(样本路径), 拼字符串就是命令注入。
        argv = ["/bin/sh", "-c", render([str(command)], install_values)[0]]
        # 打日志前先把令牌抹掉: install 命令里常常把 key 直接写进配置, 原样打出来就是
        # 一条留在容器日志里的凭证 —— 容器日志比数据库更容易被随手看到。
        token = str(llm.get("api_key") or "")
        shown = [a.replace(token, "***") if token else a for a in argv]
        log(f"install: {' '.join(shlex.quote(a) for a in shown)}")
        code, out, err, seconds = _run_command(argv, cwd=workdir, timeout=max(call_timeout, 900))
        outcome.notes.append(f"install rc={code} {seconds:.1f}s")
        if code != 0:
            (workdir / "install.log").write_text(f"{out}\n---stderr---\n{err}", encoding="utf-8")
            raise RuntimeError(f"install_failed rc={code}")

    invoke = recipe.get("invoke") or []
    invoke_http = recipe.get("invoke_http")
    if not invoke and not invoke_http:
        raise RuntimeError("recipe 既没有 invoke 也没有 invoke_http, 无从执行")

    consecutive_timeouts = 0
    for repeat in range(repeats):
        for packet in packets:
            key = packet["sample_key"]
            if outcome.calls >= max_calls:
                raise BudgetExceeded(f"模型调用达到上限 {max_calls}")
            if outcome.elapsed() >= max_seconds:
                raise BudgetExceeded(f"墙钟达到上限 {max_seconds:.0f}s")

            sample_file = samples_dir / key / packet["file_name"]
            values = {
                "sample_file": str(sample_file),
                "sample_key": key,
                "file_name": packet["file_name"],
                # 原仓库相对路径: 工具报位置报的是这个, 盘上的 code.py 只是落盘口径
                "relative_path": packet.get("relative_path") or packet["file_name"],
                "workdir": str(workdir),
                "tool_dir": str(tool_dir),
                "prompt": str(samples_dir / key / "prompt.txt"),
                # 只有 HTTP 形态用得上; 值直接取准备样本时写下去的那份正文
                "sample_content": packet["file_content"],
                # L5: 工具自己调模型时用这几个占位符(没发令牌时为空串, 见 llm_bundle)
                "llm_base_url": str(llm.get("base_url") or ""),
                "llm_api_key": str(llm.get("api_key") or ""),
                "llm_model": str(llm.get("model") or ""),
            }
            if invoke_http:
                code, out, err, seconds = _http_invoke(invoke_http, values, call_timeout)
            else:
                argv = render(list(invoke), values)
                code, out, err, seconds = _run_command(argv, cwd=workdir, timeout=call_timeout)
            outcome.calls += 1

            (raw_dir / f"{key}.r{repeat + 1}.stdout").write_text(out, encoding="utf-8")
            (raw_dir / f"{key}.r{repeat + 1}.stderr").write_text(err, encoding="utf-8")

            # 先判"不覆盖": 它既不算成功也不算失败, 是这条样本压根不该进这份分数(D4-5)。
            excluded = exclude_reason(recipe, code)
            if code == TIMEOUT_RC:
                consecutive_timeouts += 1
                outcome.failures += 1
                outcome.notes.append(f"timeout {key} r{repeat + 1}")
                if consecutive_timeouts >= 3:
                    raise RuntimeError("连续 3 次调用超时")
            else:
                consecutive_timeouts = 0
                # 扫描器用非零退出码表示"发现了漏洞"时, recipe 会把它列进
                # ok_exit_codes —— 那是成功, 不能记成一次调用失败。
                if excluded is None and not exit_ok(recipe, code):
                    outcome.failures += 1

            # 空 stdout 时退回 stderr: 否则一次崩溃在库里只剩一个空字符串, 事后查不出原因
            raw = out if out.strip() else err

            if excluded is not None:
                outcome.excluded += 1
                outcome.notes.append(f"exclude:{key}:r{repeat + 1}:{excluded}")
                # answer 写 null + excluded 写原因: 平台据此**不生成答卷文件**,
                # 判分看到的是"这条被排除", 不是"交了一份空卷"。
                outcome.answers.setdefault(key, []).append(
                    {"raw": raw, "answer": None, "excluded": excluded})
                log(f"  {key} r{repeat + 1}: rc={code} 不覆盖({excluded})")
                try:
                    deliver(int(run["run_id"]), {key: outcome.answers[key]})
                except PlatformError:
                    raise
                except Exception as exc:  # 网络抖动: 收尾时会整体再交一次
                    outcome.notes.append(f"deliver_retry:{key}:r{repeat + 1}:{exc}")
                continue

            answer, why = parse_answer(
                recipe.get("output_parser"), out, returncode=code,
                context={"sample_key": key, "file_name": packet["file_name"],
                         "relative_path": values["relative_path"]})
            if why:
                outcome.notes.append(f"parse:{key}:r{repeat + 1}:{why}")
            outcome.answers.setdefault(key, []).append({"raw": raw, "answer": answer})

            log(f"  {key} r{repeat + 1}: rc={code} {seconds:.1f}s "
                f"answer={'ok' if answer is not None else 'none'}")

            # 逐样本交卷: 崩了重来时不用从头再烧一遍预算。
            # 交的是**这个样本到目前为止的全部轮次** —— 平台按列表下标认 repeat_index,
            # 只交当前这一轮会被当成第 1 轮覆盖掉前面的。
            try:
                deliver(int(run["run_id"]), {key: outcome.answers[key]})
            except PlatformError:
                raise
            except Exception as exc:  # 网络抖动: 不中断, 收尾时会整体再交一次
                outcome.notes.append(f"deliver_retry:{key}:r{repeat + 1}:{exc}")

    return outcome


def _cleanup_stale() -> None:
    """回收上一次运行留下的失败工作目录。成功的一律即时删, 这里的都是"留作证据"的。"""
    if not WORK_ROOT.is_dir():
        return
    cutoff = time.time() - KEEP_FAILED_DAYS * 86400
    for path in WORK_ROOT.iterdir():
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
                log(f"gc: 删除过期工作目录 {path}")
        except OSError:
            continue


_ADAPTER: Any = None


def _load_adapter() -> Any:
    """按路径加载同目录的 `adapter.py`。

    不用 `import adapter`: 这个文件会被测试用 importlib 从任意路径加载, 靠 sys.path
    找兄弟文件在那种场景下会失败。按 `__file__` 的目录算, 两种起法都对。
    """
    global _ADAPTER
    if _ADAPTER is None:
        path = Path(__file__).resolve().parent / "adapter.py"
        spec = importlib.util.spec_from_file_location("cap_eval_adapter", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["cap_eval_adapter"] = module
        spec.loader.exec_module(module)
        _ADAPTER = module
    return _ADAPTER


def _tool_dir(run: dict[str, Any], claimed: dict[str, Any]) -> Path | None:
    """被测工具的源码目录。平台带 `tool.repo_url` 来就克隆一次; 已有目录**不覆盖** ——
    探到一半的安装/venv 被冲掉, 等于把已经花掉的探索作废。
    """
    path = TOOL_ROOT / f"item-{run['item_id']}"
    if path.is_dir():
        return path
    repo = str((claimed.get("tool") or {}).get("repo_url") or "")
    if not repo:
        return None
    ref = str((claimed.get("tool") or {}).get("git_ref") or "")
    path.parent.mkdir(parents=True, exist_ok=True)
    argv = ["git", "clone", "--depth", "1", *(["--branch", ref] if ref else []), repo, str(path)]
    log(f"clone: {' '.join(shlex.quote(a) for a in argv)}")
    code, out, err, _ = _run_command(argv, cwd=path.parent, timeout=900)
    if code != 0:
        log(f"clone 失败 rc={code}: {(err or out)[:300]}")
        return None
    return path


def _recipe_needs_tool_dir(recipe: dict[str, Any]) -> bool:
    """recipe 里有没有用到 `{tool_dir}`。没有就不为它去克隆 —— 有些工具是 pip 装的,
    28 MB 的源码拉下来没人用, 还会让"这轮为什么多花了 10 秒"变成一个查不明白的问题。"""
    for key in ("install", "invoke"):
        if any("{tool_dir}" in str(item) for item in (recipe.get(key) or [])):
            return True
    return False


def _stamp_runtime_version(recipe: dict[str, Any], tool_dir: Path | None,
                           outcome: Outcome) -> dict[str, Any]:
    """用**盘上真实的工具目录**覆盖 recipe 里的版本号, 返回新 dict。

    为什么冻结时写的版本号不可信: runner 克隆用的是 `git clone --branch`, 而工具仓库
    常常既没有 tag 也没有 release(OpenAnt 实测两者皆空), 只能跟 master。冻结那一刻抄下的
    sha, 到了执行那一晚可能已经不是 master 了 —— 库里的版本号于是变成一句假话, 而它正是
    "换了版本要不要重探"的判据。

    版本号只在这次 run 的 `cost_json` 里被覆盖, **不改库里那份 recipe**: recipe 是配置,
    版本是这次执行的事实, 混在一起就再也说不清"这条分数按哪个版本跑的"。
    """
    if tool_dir is None or not tool_dir.is_dir():
        return recipe
    try:
        version, source = _load_adapter()._tool_version(tool_dir)
    except Exception as exc:  # noqa: BLE001 —— 版本号读不出来不该让整轮跑不成
        outcome.notes.append(f"tool_version: 读不出来({exc}); 沿用 recipe 里的值")
        return recipe
    frozen = str(recipe.get("tool_version") or "").strip()
    if version == frozen:
        return recipe
    outcome.notes.append(f"tool_version: {frozen or '(空)'} -> {version} ({source})")
    return {
        **recipe,
        "tool_version": version,
        # 来源写全: 冻结时那份是配置里的说法, 现在这个是盘上量出来的
        "tool_version_source": f"{source}(冻结时写的是 {frozen or '空'})",
    }


def _adapt(run: dict[str, Any], tool_dir: Path, workdir: Path, samples_dir: Path,
           packets: list[dict[str, Any]], outcome: Outcome
           ) -> tuple[dict[str, Any] | None, str, dict[str, Any]]:
    """就地适配一次, 返回 (recipe | None, 来源说明或失败原因, 摘要)。"""
    adapter = _load_adapter()
    if not packets:
        return None, "other", {"reason": "没有样本可供自检"}
    # 自检默认用第一份样本, 但把**整批**都交给适配 agent 挑: 工具只覆盖部分语言时,
    # 拿一条它不认的样本去自检会把"能评一部分"误判成"完全无法适配"(2026-11-03 run 5)。
    pool = [{
        "sample_key": packet["sample_key"],
        "file": samples_dir / packet["sample_key"] / packet["file_name"],
        "relative_path": packet.get("relative_path") or packet["file_name"],
        "prompt_path": samples_dir / packet["sample_key"] / "prompt.txt",
        "tool_dir": tool_dir,
    } for packet in packets]
    sample = pool[0]
    try:
        recipe, source, detail = adapter.adapt(
            run=run, tool_dir=tool_dir, sample=sample, sample_pool=pool,
            workdir=workdir, render=render)
    except adapter.AdapterBudgetError as exc:
        # 这一轮的钱花完了。既不是工具的错, 也不是平台故障 —— 落成 `model_budget_exceeded`,
        # 让报表能区分"适配不了"和"预算设小了"。返回而不是抛: 抛出去会从 main() 退出容器,
        # 那一轮就永远停在 running(平台没有僵尸 run 回收)。
        log(f"适配阶段模型预算用尽: {exc}")
        return None, "model_budget_exceeded", {"detail": str(exc)[:500]}
    except adapter.AdapterPlatformError as exc:
        # 平台自己的问题(令牌/模型不可用)不能记到工具头上
        raise PlatformError(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        log(f"适配过程异常: {exc}\n{traceback.format_exc()}")
        return None, "agent_gave_up", {"error": str(exc)[:500]}
    outcome.notes.append(f"adapt:{detail}")
    return recipe, source, detail


def run_once(claimed: dict[str, Any]) -> None:
    global RUN_ID
    run = claimed["run"]
    run_id = int(run["run_id"])
    RUN_ID = run_id
    # 模型归属台账是按进程累计的, 而执行位一个进程会连跑多轮 —— 不清就会把上一轮的
    # 模型混进这一轮的 cost_json, 那正是 L4 要防的"分数说不清是谁跑的"。
    _load_adapter().reset_serving()
    packets = claimed.get("samples") or []
    budget = dict(run.get("budget") or {})
    # 令牌先落到进程环境里: install/invoke/适配 shell 都继承它, 而它们中间的任何一个
    # 都不需要知道这是"哪一层"发的 —— 对工具来说它就是一个普通的 OpenAI 兼容端点。
    llm = llm_bundle(claimed)
    apply_llm_env(llm)
    recipe, source = resolve_recipe(run, claimed)

    log(f"领到 run {run_id}: item={run['item_id']} samples={len(packets)} "
        f"repeats={run['repeats']} recipe={source or '无'}")

    workdir = WORK_ROOT / f"run-{run_id}-{int(time.time())}"
    samples_dir = None
    outcome = Outcome()          # 先建好: 出任何岔子都要带着已跑出的答卷收尾

    if recipe is not None:
        # 冻结 recipe 这条路径**不经过适配**, 也就没人替它克隆工具源码 —— 而 `{tool_dir}`
        # 正是 install 的输入(`pip install {tool_dir}/libs/openant-core`)。不补这一步,
        # 用手冻的 recipe 跑每一轮都以 install_failed 收场, 而报错看起来像"工具装不上"。
        tool_dir = TOOL_ROOT / f"item-{run['item_id']}"
        if not tool_dir.is_dir() and _recipe_needs_tool_dir(recipe):
            tool_dir = _tool_dir(run, claimed)
            if tool_dir is None:
                outcome.notes.append("tool_dir: 缺失且克隆失败, install 会以 rc 非 0 失败")
        # 版本号取盘上的真值: 冻结时写的 sha 可能已经不是 master 了(见 _stamp_runtime_version)
        recipe = _stamp_runtime_version(recipe, tool_dir, outcome)

    if recipe is None:
        # 没有 recipe = 这个工具从没被适配过。不拿默认参数硬跑 —— 那样跑出来的数,
        # 既不代表工具也不代表契约, 只会污染页面。就地探一次(D 阶段), 探通了这个 run
        # 继续跑; 探不通就是终态(R9: 适配失败不重试)。
        if not ADAPTER_ENABLED:
            finish(run_id, "failed", failure_reason="no_recipe",
                   cost={"reason": "no_recipe", "samples": len(packets)})
            return
        tool_dir = _tool_dir(run, claimed)
        if tool_dir is None:
            finish(run_id, "failed", failure_reason="repo_unavailable",
                   cost={"reason": "repo_unavailable", "samples": len(packets)})
            return
        workdir.mkdir(parents=True, exist_ok=True)
        samples_dir = _prepare_samples(workdir, packets)
        recipe, failure, detail = _adapt(run, tool_dir, workdir, samples_dir, packets, outcome)
        if recipe is None:
            log(f"适配失败: {failure} {detail}")
            finish(run_id, "failed", failure_reason=failure or "agent_gave_up",
                   cost={**_cost(run, outcome, {}, "", workdir), "adapt": detail,
                         "tool_dir": str(tool_dir)},
                   work_dir=str(workdir))
            return
        source = failure            # 适配成功时第二个返回值是来源说明(adapted:<version>)
        try:
            _reject_secret(recipe, llm)
        except RuntimeError as exc:
            log(f"拒绝这份 recipe: {exc}")
            finish(run_id, "failed", failure_reason="agent_gave_up",
                   cost={**_cost(run, outcome, {}, source, workdir), "error": str(exc)[:500]},
                   work_dir=str(workdir))
            return
        (workdir / "recipe.json").write_text(
            json.dumps({"source": source, "recipe": recipe}, ensure_ascii=False, indent=2),
            encoding="utf-8")

    if not workdir.exists():
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "recipe.json").write_text(
            json.dumps({"source": source, "recipe": recipe}, ensure_ascii=False, indent=2),
            encoding="utf-8")

    try:
        # 库里存着的 recipe 也要过这一关: 上一轮如果真把令牌抄进去了, 这一轮不能照跑。
        _reject_secret(recipe, llm)
        execute(run, recipe, packets, workdir, budget, outcome, samples_dir=samples_dir, llm=llm)
    except BudgetExceeded as exc:
        log(f"预算超限: {exc}")
        _post_final_answers(run_id, outcome)
        finish(run_id, "budget_exceeded",
               cost={**_cost(run, outcome, recipe, source, workdir), "stopped_by": str(exc)},
               work_dir=str(workdir))
        return
    except PlatformError:
        raise                    # 平台侧拒绝(令牌/服务不可用): 整轮不归因给工具
    except Exception as exc:  # noqa: BLE001 —— 任何异常都必须落成终态, 不能卡在 running
        log(f"执行失败: {exc}\n{traceback.format_exc()}")
        _post_final_answers(run_id, outcome)
        if isinstance(exc, DatasetError):
            reason = "other"     # 样本坏了, 不是工具不行
        elif "install_failed" in str(exc):
            reason = "install_failed"
        else:
            reason = "agent_gave_up"
        finish(run_id, "failed", failure_reason=reason,
               cost={**_cost(run, outcome, recipe, source, workdir), "error": str(exc)[:500]},
               work_dir=str(workdir))
        return

    _post_final_answers(run_id, outcome)
    log(f"交卷: {outcome.calls} 次调用 / {outcome.elapsed():.1f}s / 失败 {outcome.failures}"
        f" / 不覆盖 {outcome.excluded}")
    finish(run_id, "success", cost=_cost(run, outcome, recipe, source, workdir))
    # 成功即回收: 原生输出已经在库里(R8), 工作目录没有留存的理由
    shutil.rmtree(workdir, ignore_errors=True)


def _post_final_answers(run_id: int, outcome: Outcome) -> None:
    """整体再交一次, 补上中途网络抖动没送到的那些样本(平台侧是 upsert, 重复无副作用)。"""
    if not outcome.answers:
        return
    try:
        deliver(run_id, outcome.answers)
    except Exception as exc:  # noqa: BLE001
        log(f"补交答卷失败: {exc}")


def _cost(run: dict[str, Any], outcome: Outcome | None, recipe: dict[str, Any],
          source: str, workdir: Path) -> dict[str, Any]:
    return {
        "model_calls": outcome.calls if outcome else 0,
        "seconds": round(outcome.elapsed(), 1) if outcome else 0,
        "call_failures": outcome.failures if outcome else 0,
        "call_excluded": outcome.excluded if outcome else 0,
        "recipe_source": source,
        "tool_version": recipe.get("tool_version", ""),
        "work_dir": str(workdir),
        "notes": (outcome.notes if outcome else [])[:40],
        # 每次重放都记峰值内存与 CPU(PRD §12 第 12 条)。没有这组数, 10-29 那种
        # "评测把容器撑爆、复现页全 502"就只能靠人回忆, 事后分不清是谁吃掉的。
        "resources": outcome.resources() if outcome else {},
        # 分数由谁产生: 真实上游模型 / 组 / 上游地址 / 降级次数 / token 用量。
        # 与 `recipe_source` 同一个道理 —— 事后看一条分数时, 第一个该问的就是
        # "它按哪份 recipe、由哪个模型跑出来的"。
        "model_serving": _load_adapter().serving_summary(),
    }


def main() -> int:
    if not TOKEN:
        log("EVAL_TOKEN 未配置 —— 执行位拒绝启动(没有令牌就无法证明自己是合法调用方)")
        return 2
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    _cleanup_stale()
    log(f"执行位启动: api={API_BASE} work={WORK_ROOT} poll={POLL_SECONDS}s")

    while True:
        try:
            claimed = claim()
        except PlatformError as exc:
            log(f"平台拒绝服务: {exc}")
            return 3
        except Exception as exc:  # noqa: BLE001
            log(f"领活失败(稍后重试): {exc}")
            time.sleep(POLL_SECONDS)
            continue

        if not claimed.get("run"):
            time.sleep(POLL_SECONDS)
            continue

        try:
            run_once(claimed)
        except PlatformError as exc:
            log(f"平台拒绝服务(交卷/收尾阶段): {exc}")
            return 3
        except Exception as exc:  # noqa: BLE001
            log(f"这一轮出了意外: {exc}\n{traceback.format_exc()}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
