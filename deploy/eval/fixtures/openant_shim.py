#!/usr/bin/env python3
"""OpenAnt → 契约 v1 适配器(shim)。

为什么需要它, 而不是直接 `openant scan`:

1. **OpenAnt 的 `findings[].location` 只有 `{file, function}`, 没有行号**。契约 v1 要求
   `line_start/line_end` 是 >=1 的整数。行号在 OpenAnt 自己的 `dataset.json` 里 ——
   unit 的 id 就是 `file:function`(等于 reporter 的 `route_key`), `code.primary_origin`
   带 `{file_path, start_line, end_line, function_name}`。所以这里做的是**查表**,
   不是编数字: 交出去的是工具自己认定的函数区间。
   ⚠️ 语义后果: 我们的 `strict_hit` 在 OpenAnt 上等于"命中的那个函数**包含**真值行",
   不是"点到了那一行"。这条必须写进报告 caveat, 否则会和行级工具混着比。

2. **模型的地址/令牌要走平台发的这一轮令牌**, 而 OpenAnt 只从 `~/.config/openant/config.json`
   读 provider 配置。这里把它写出来 —— 令牌写在 **XDG_CONFIG_HOME 指向的临时目录**里,
   每份样本一个, 不落全局、不跨样本串味。

3. **输出要干净**: OpenAnt 的进度/日志会混进 stdout, 而契约要求 stdout 上只有一份 JSON。
   所以子进程的 stdout/stderr 全部转进 stderr, 只在最后打一份契约 JSON。

退出码(recipe 里 `ok_exit_codes` 默认 `[0]`, 所以正常路径恒 0):
    0  交出了一份答卷(有没有洞都算)
    2  跑挂了(装不上/模型连不上/输出缺失) —— 这是工具的问题, 该记失败
    3  这个文件的语言 OpenAnt 不支持 —— **不跑、也不判 miss**。recipe 里必须配
       `"exclude_exit_codes": {"3": "language_not_supported"}` 把这条声明出去, 否则
       平台会把它当成一次失败的调用(记 invalid_output), "没覆盖"就变成了"没找到"

这个文件是**执行位的一部分**(烘进镜像 `/opt/eval/fixtures/`), 不是被测工具的补丁:
它不含任何判定逻辑, 只做配置接线 + 输出翻译。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SHIM_VERSION = "openant-shim/1"

# 与 OpenAnt 的 `config/languages.json` 同一张表(2026-11-02, 实测 9143061)。
# 工具加了语言要同步这里 —— 少一条的后果是"明明支持却按不支持排除", 会静默缩小样本面。
EXTENSIONS = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript",
    ".go": "go",
    ".c": "c", ".h": "c", ".cc": "c", ".cpp": "c", ".cxx": "c",
    ".hh": "c", ".hpp": "c", ".hxx": "c",
    ".rb": "ruby", ".rake": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".swift": "swift",
    ".zig": "zig",
}

# 契约 §3: 只有这几种判定算"发现了漏洞"。Stage 1 的 `unverified` / `rejected`
# 不算 —— 那不是工具给出的结论, 把它算成命中等于替工具加分。
HIT_VERDICTS = {"confirmed", "agreed", "vulnerable", "bypassable"}

MAX_FINDINGS = 5
EXCLUDE_RC = 3
CRASH_RC = 2


def _die(message: str) -> int:
    print(f"[shim] {message}", file=sys.stderr)
    return CRASH_RC


def _arg(argv: list[str], name: str, *, required: bool = True) -> str | None:
    if name not in argv:
        if required:
            raise SystemExit(f"[shim] 缺参数 {name}")
        return None
    index = argv.index(name)
    if index + 1 >= len(argv):
        raise SystemExit(f"[shim] 参数 {name} 没有值")
    return argv[index + 1]


def _write_config(config_path: Path, *, base_url: str, api_key: str, model: str) -> None:
    """7 个 phase 全指向同一个 provider。

    OpenAnt 要求 profile **列满 7 个 phase**, 少一个就整份配置拒收 —— 这是它
    有意为之("no _default fallback")。我们把它们全指到平台网关, 因为这一轮
    要评的是"工具在同一个模型下的表现", 不是"工具挑模型的本事"。
    """
    phases = ("analyze", "enhance", "verify", "report", "dynamic_test", "llm_reach", "app_context")
    config = {
        "$schema_version": 2,
        "default_llm": "eval",
        "active_project": "sample",
        "llm_providers": {
            "gw": {"type": "openai", "base_url": base_url, "api_key": api_key},
        },
        "llm_configs": {
            "eval": {phase: {"provider": "gw", "model": model} for phase in phases},
        },
    }
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
    config_path.chmod(0o600)


def _dataset_index(out_dir: Path) -> dict[str, tuple[int, int]]:
    """`file:function` → (start_line, end_line)。

    unit id 与 reporter 的 route_key 是同一个串(实测 `app.py:run_cmd`);
    再补一条 (file_path, function_name) 的兜底, 因为 owner 版本改过 id 形态时
    route_key 可能不带 class 前缀。
    """
    path = out_dir / "dataset.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    index: dict[str, tuple[int, int]] = {}
    for unit in data.get("units") or []:
        if not isinstance(unit, dict):
            continue
        origin = ((unit.get("code") or {}).get("primary_origin") or {})
        start, end = origin.get("start_line"), origin.get("end_line")
        if not isinstance(start, int) or not isinstance(end, int) or start < 1:
            continue
        if end < start:
            end = start
        if unit.get("id"):
            index[str(unit["id"])] = (start, end)
        file_path, function_name = origin.get("file_path"), origin.get("function_name")
        if file_path and function_name:
            index.setdefault(f"{file_path}:{function_name}", (start, end))
    return index


def _normalize_file(reported: str, rel_path: str) -> str:
    """把工具报的路径归一到题面给的相对路径。

    只做两种**等价改写**: 去掉 `./` 前缀、去掉前面多出来的目录(工具从扫描根往下报,
    而我们的扫描根就是样本所在的临时目录, 正常情况下两者本来就相等)。
    名字对不上就原样返回 —— 交一个改过的文件名会让"报错了文件"变成"报对了文件"。
    """
    cleaned = reported[2:] if reported.startswith("./") else reported
    if cleaned == rel_path or cleaned.endswith("/" + rel_path):
        return rel_path
    return cleaned


def _to_findings(pipeline: dict, index: dict[str, tuple[int, int]], rel_path: str) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple] = set()
    for item in pipeline.get("findings") or []:
        if not isinstance(item, dict):
            continue
        verdict = str(item.get("stage2_verdict") or item.get("stage1_verdict") or "").lower()
        if verdict not in HIT_VERDICTS:
            continue
        location = item.get("location") if isinstance(item.get("location"), dict) else {}
        file = _normalize_file(str(location.get("file") or ""), rel_path)
        function = str(location.get("function") or "")
        if not file:
            continue
        lines = index.get(f"{file}:{function}")
        if lines is None and function:
            # owner 改过 unit id 形态时, 用简单名再试一次(只认文件对得上的)
            simple = function.rsplit(".", 1)[-1]
            lines = index.get(f"{file}:{simple}")
        if lines is None:
            # 查不到行号就**不交这条**: 编一个区间出来等于替工具定位,
            # 而定位正是本项目唯一要量的东西。
            continue
        start, end = lines
        key = (file, function, start, end)
        if key in seen:
            continue
        seen.add(key)
        finding: dict[str, object] = {
            "file": file,
            "function": function,
            "line_start": start,
            "line_end": end,
        }
        cwe = item.get("cwe_id")
        if isinstance(cwe, int) and cwe > 0:
            finding["type_cwe"] = f"CWE-{cwe}"
        evidence = item.get("description")
        if isinstance(evidence, str) and evidence.strip():
            finding["evidence"] = evidence.strip()
        findings.append(finding)
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


def main(argv: list[str]) -> int:
    try:
        sample_file = Path(_arg(argv, "--file") or "")
        rel_path = (_arg(argv, "--path") or "").lstrip("./")
        out_root = Path(_arg(argv, "--out") or "")
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return CRASH_RC

    if not sample_file.is_file():
        return _die(f"样本文件不存在: {sample_file}")
    if not rel_path:
        return _die("--path 为空: 无法给出契约要求的 file")

    language = EXTENSIONS.get(sample_file.suffix.lower())
    if language is None:
        detail = {
            "excluded": "language_not_supported",
            "suffix": sample_file.suffix.lower() or "(无扩展名)",
            "supported": sorted(set(EXTENSIONS.values())),
        }
        print(f"[shim] {json.dumps(detail, ensure_ascii=False)}", file=sys.stderr)
        return EXCLUDE_RC

    base_url = os.environ.get("EVAL_LLM_BASE_URL", "").strip()
    api_key = os.environ.get("EVAL_LLM_TOKEN", "").strip()
    model = os.environ.get("EVAL_LLM_MODEL", "").strip()
    if not (base_url and api_key and model):
        return _die("缺 EVAL_LLM_BASE_URL / EVAL_LLM_TOKEN / EVAL_LLM_MODEL: 这一轮没有模型凭证")

    out_dir = out_root.expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    # 同一份样本的多轮共用一个 `--out`(recipe 里按 sample_key 分目录)。不清掉上一轮的产物,
    # 本轮 scan 若在写文件前就挂了, 下面会读到**上一轮**的 pipeline_output.json ——
    # 于是"这一轮崩了"变成"这一轮和上一轮结论一样", 各轮一致性这个指标也就成了假的。
    for stale in ("pipeline_output.json", "dataset.json"):
        try:
            (out_dir / stale).unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            return _die(f"清不掉上一轮的产物 {stale}: {exc}")
    with tempfile.TemporaryDirectory(prefix="openant-") as tmp:
        tmp_dir = Path(tmp)
        # ① 只含该样本文件的目录, 且按原相对路径落盘 —— OpenAnt 报的位置就是仓库相对路径,
        #    这样它报出来的 file 和题面给的 relative_path 天然一致, 不用事后猜。
        repo_dir = tmp_dir / "repo"
        target = repo_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(sample_file.read_bytes())

        # ② 配置走 XDG_CONFIG_HOME, 每份样本一个 —— 并行跑多个样本时不会互相覆盖。
        xdg = tmp_dir / "xdg"
        _write_config(xdg / "openant" / "config.json",
                      base_url=base_url, api_key=api_key, model=model)

        env = dict(os.environ)
        env["XDG_CONFIG_HOME"] = str(xdg)
        # OpenAnt 会按需从环境里读 key; 让它只能看到这一轮的令牌。
        env.pop("ANTHROPIC_API_KEY", None)
        env.pop("OPENAI_API_KEY", None)

        cmd = [
            sys.executable, "-m", "openant", "scan", str(repo_dir),
            "-l", language,
            "-o", str(out_dir),
            "--no-report",      # 报告是给人看的 HTML; 我们要的是 pipeline_output.json
            "--no-enhance",     # 增强是"把依赖内联进来" —— 单文件样本没有依赖可内联
            "--no-context",     # 应用上下文是仓库级的, 单文件样本上纯属多烧预算
            "--level", "all",   # 默认的 reachable 会按入口点过滤; 单文件样本没有入口,
                                # 用默认值会把要评的那个函数直接过滤掉(等于白跑)
            "--workers", "4",   # 契约的预算按调用次数算, 并发高只会更快撞上限
            "--llm-config", "eval",
        ]
        print(f"[shim] {SHIM_VERSION} lang={language} rel={rel_path}", file=sys.stderr)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=900)
        except subprocess.TimeoutExpired:
            return _die("openant scan 超过 900s")
        except OSError as exc:
            return _die(f"起不来 openant: {exc}")

        # 子进程输出全进 stderr: stdout 只留契约 JSON(判分侧只读这一层)
        for stream, text in (("out", proc.stdout), ("err", proc.stderr)):
            for line in (text or "").splitlines():
                print(f"[openant:{stream}] {line}", file=sys.stderr)
        # OpenAnt: 0=干净 / 1=有发现(成功) / 2=跑挂。非 0 非 1 一律当失败。
        if proc.returncode not in (0, 1):
            return _die(f"openant scan 退出码 {proc.returncode}")

        pipeline_path = out_dir / "pipeline_output.json"
        if not pipeline_path.is_file():
            return _die(f"没有 pipeline_output.json: {pipeline_path}")
        try:
            pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _die(f"pipeline_output.json 读不了: {exc}")

        findings = _to_findings(pipeline, _dataset_index(out_dir), rel_path)

    answer = {"found": bool(findings), "findings": findings}
    print(json.dumps(answer, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
