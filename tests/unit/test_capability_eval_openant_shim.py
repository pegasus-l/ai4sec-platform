"""OpenAnt shim(`deploy/eval/fixtures/openant_shim.py`)—— D4-2。

这里守的是四件事, 它们决定了 D4 的分数**是不是工具的分数**:

  · 行号只能来自工具自己的 `dataset.json`; 查不到就不交那条, 绝不编一个区间;
  · 只有 `confirmed/agreed/vulnerable/bypassable` 算命中, `unverified/rejected` 不算;
  · 输出的 `file` 与题面给的相对路径一致(否则判分会把命中的文件当别的文件);
  · 不支持的语种**不跑也不判 miss**, 用独立的退出码交还给 runner。

夹具里的 `openant` 是一个**假的模块**(只写 pipeline_output.json / dataset.json),
不是真跑模型 —— 真跑需要网关令牌, 属于 D4-4。
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[2] / "deploy" / "eval" / "fixtures"
SHIM = FIXTURES / "openant_shim.py"

# 假 openant: 按 FAKE_PIPELINE / FAKE_DATASET 写两份产物, 退出码取 FAKE_RC。
FAKE_MAIN = '''
import json, os, sys
from pathlib import Path

args = sys.argv[1:]
out = Path(args[args.index("-o") + 1])
lang = args[args.index("-l") + 1]
out.mkdir(parents=True, exist_ok=True)
if os.environ.get("FAKE_SKIP_WRITE") == "1":
    sys.exit(int(os.environ.get("FAKE_RC", "2")))      # 崩在写产物之前
(out / "pipeline_output.json").write_text(json.dumps(json.loads(os.environ["FAKE_PIPELINE"])), encoding="utf-8")
(out / "dataset.json").write_text(json.dumps(json.loads(os.environ["FAKE_DATASET"])), encoding="utf-8")
(out / "argv.json").write_text(json.dumps(args), encoding="utf-8")
print("progress line that must not reach stdout")
sys.exit(int(os.environ.get("FAKE_RC", "0")))
'''


def _load_shim():
    spec = importlib.util.spec_from_file_location("openant_shim", SHIM)
    module = importlib.util.module_from_spec(spec)
    sys.modules["openant_shim"] = module
    spec.loader.exec_module(module)
    return module


def _packet(tmp_path: Path, name: str = "run_cmd.py") -> tuple[Path, str]:
    sample = tmp_path / "sample" / name
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    return sample, f"app/{name}"


def _run(tmp_path: Path, *, pipeline: dict, dataset: dict, rc: int = 0,
         env_llm: bool = True, sample: Path | None = None, rel: str | None = None,
         suffix: str = ".py", skip_write: bool = False) -> subprocess.CompletedProcess:
    fake = tmp_path / "fake" / "openant"
    fake.mkdir(parents=True, exist_ok=True)
    (fake / "__init__.py").write_text("", encoding="utf-8")
    (fake / "__main__.py").write_text(FAKE_MAIN, encoding="utf-8")
    if sample is None:
        sample = tmp_path / "sample" / f"run_cmd{suffix}"
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_text("import os\nos.system(cmd)\n", encoding="utf-8")
        rel = rel or f"app/run_cmd{suffix}"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp_path / "fake")
    env["FAKE_PIPELINE"] = json.dumps(pipeline)
    env["FAKE_DATASET"] = json.dumps(dataset)
    env["FAKE_RC"] = str(rc)
    env["FAKE_SKIP_WRITE"] = "1" if skip_write else "0"
    for key in ("EVAL_LLM_BASE_URL", "EVAL_LLM_TOKEN", "EVAL_LLM_MODEL"):
        env.pop(key, None)
    if env_llm:
        env.update({"EVAL_LLM_BASE_URL": "http://api/v1", "EVAL_LLM_TOKEN": "caev1_x",
                    "EVAL_LLM_MODEL": "m"})
    return subprocess.run(
        [sys.executable, str(SHIM), "--file", str(sample), "--path", str(rel),
         "--out", str(tmp_path / "out")],
        capture_output=True, text=True, env=env, timeout=120)


def _unit(unit_id: str, file: str, function: str, start: int, end: int) -> dict:
    return {"id": unit_id, "code": {"primary_code": "x", "primary_origin": {
        "file_path": file, "function_name": function, "start_line": start, "end_line": end,
        "deps_inlined": False, "files_included": [file]}}}


def _finding(file: str, function: str, verdict: str, cwe: int = 22) -> dict:
    return {"id": "VULN-1", "location": {"file": file, "function": function},
            "cwe_id": cwe, "cwe_name": "x", "stage1_verdict": verdict,
            "stage2_verdict": verdict, "description": "os.system 直接吃外部输入"}


def test_line_numbers_come_from_the_tools_own_dataset(tmp_path):
    proc = _run(
        tmp_path,
        pipeline={"findings": [_finding("app/run_cmd.py", "run_cmd", "vulnerable")]},
        dataset={"units": [_unit("app/run_cmd.py:run_cmd", "app/run_cmd.py", "run_cmd", 3, 4)]},
        rc=1,
    )
    assert proc.returncode == 0, proc.stderr
    answer = json.loads(proc.stdout)
    assert answer == {"found": True, "findings": [{
        "file": "app/run_cmd.py", "function": "run_cmd", "line_start": 3, "line_end": 4,
        "type_cwe": "CWE-22", "evidence": "os.system 直接吃外部输入"}]}
    # 子进程的进度行进了 stderr, 不许混进 stdout(否则判分侧读到的就不是一份干净 JSON)
    assert "progress line" not in proc.stdout
    assert "progress line" in proc.stderr


def test_finding_without_a_matching_unit_is_dropped_not_invented(tmp_path):
    """dataset 里查不到 = 不对这个位置下结论。编一个 1..1 出来就是替工具定位。"""
    proc = _run(
        tmp_path,
        pipeline={"findings": [_finding("app/run_cmd.py", "run_cmd", "vulnerable")]},
        dataset={"units": []},
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"found": False, "findings": []}


def test_only_disclosure_eligible_verdicts_count(tmp_path):
    pipeline = {"findings": [
        _finding("app/run_cmd.py", "clean", "rejected"),
        _finding("app/run_cmd.py", "unsure", "unverified"),
        _finding("app/run_cmd.py", "real", "confirmed"),
    ]}
    dataset = {"units": [
        _unit("app/run_cmd.py:clean", "app/run_cmd.py", "clean", 1, 2),
        _unit("app/run_cmd.py:unsure", "app/run_cmd.py", "unsure", 3, 4),
        _unit("app/run_cmd.py:real", "app/run_cmd.py", "real", 5, 6),
    ]}
    proc = _run(tmp_path, pipeline=pipeline, dataset=dataset)
    answer = json.loads(proc.stdout)
    assert [f["function"] for f in answer["findings"]] == ["real"]


def test_qualified_name_falls_back_to_the_simple_name(tmp_path):
    """owner 换过 unit id 形态时(带不带 class 前缀), 行号仍要查得到。"""
    proc = _run(
        tmp_path,
        pipeline={"findings": [_finding("app/run_cmd.py", "Runner.run_cmd", "vulnerable")]},
        dataset={"units": [_unit("app/run_cmd.py:run_cmd", "app/run_cmd.py", "run_cmd", 7, 9)]},
    )
    answer = json.loads(proc.stdout)
    assert answer["findings"][0]["line_start"] == 7


def test_unsupported_language_is_excluded_not_scored_as_a_miss(tmp_path):
    """Java 不在 OpenAnt 的 9 种语言里: 不跑、也不许交一份 `found:false`。"""
    proc = _run(tmp_path, pipeline={"findings": []}, dataset={}, suffix=".java")
    assert proc.returncode == 3
    assert proc.stdout.strip() == ""
    assert "language_not_supported" in proc.stderr


def test_missing_model_credentials_fail_loudly(tmp_path):
    proc = _run(tmp_path, pipeline={"findings": []}, dataset={}, env_llm=False)
    assert proc.returncode == 2
    assert "EVAL_LLM" in proc.stderr


def test_scan_is_invoked_with_the_settings_the_shim_documents(tmp_path):
    proc = _run(
        tmp_path,
        pipeline={"findings": []},
        dataset={"units": []},
    )
    assert proc.returncode == 0, proc.stderr
    argv = json.loads((tmp_path / "out" / "argv.json").read_text(encoding="utf-8"))
    for flag in ("--no-report", "--no-enhance", "--no-context", "--level", "all",
                 "--llm-config", "eval"):
        assert flag in argv, flag
    assert argv[argv.index("-l") + 1] == "python"


def test_tool_crash_is_a_failure_not_a_clean_answer(tmp_path):
    proc = _run(tmp_path, pipeline={"findings": []}, dataset={}, rc=2)
    assert proc.returncode == 2
    assert proc.stdout.strip() == ""


def test_stale_output_from_an_earlier_repeat_is_never_reused(tmp_path):
    """三轮共用同一个 `--out` 目录(recipe 按 sample_key 分目录)。

    本轮 scan 在写产物之前就崩了, 若不去读上一轮留在盘上的 pipeline_output.json,
    这次崩溃就会被读成"和上一轮一样的结论" —— 各轮一致性这项指标从此不可信,
    而且错的方向是**让工具显得更稳定**。
    """
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    stale = {"findings": [_finding("app/run_cmd.py", "run_cmd", "vulnerable")]}
    (out / "pipeline_output.json").write_text(json.dumps(stale), encoding="utf-8")
    (out / "dataset.json").write_text(json.dumps(
        {"units": [_unit("app/run_cmd.py:run_cmd", "app/run_cmd.py", "run_cmd", 3, 4)]}),
        encoding="utf-8")

    proc = _run(tmp_path, pipeline={}, dataset={}, rc=2, skip_write=True)
    assert proc.returncode == 2
    assert proc.stdout.strip() == ""          # 不许把上一轮的答案当本轮的答卷


def test_extension_map_matches_every_language_openant_advertises():
    """少一条的后果是"明明支持却按不支持排除", 会静默缩小样本面。"""
    shim = _load_shim()
    assert set(shim.EXTENSIONS.values()) == {
        "python", "javascript", "go", "c", "ruby", "php", "rust", "swift", "zig"}
    assert shim.EXTENSIONS[".tsx"] == "javascript"
    assert shim.EXTENSIONS[".hh"] == "c"


def test_answer_passes_the_contract_schema(tmp_path):
    """契约 v1 的 schema 是 additionalProperties:false —— 多一个键就整份答卷作废。"""
    schema_path = Path("/mnt/d/漏洞挖掘/洞察工具/洞察平台改进/ai4sec-eval-contracts/v1"
                       "/class1_llm_audit.schema.json")
    if not schema_path.is_file():
        import pytest
        pytest.skip("契约文件不在这台机器上")
    jsonschema = __import__("pytest").importorskip("jsonschema")
    proc = _run(
        tmp_path,
        pipeline={"findings": [_finding("app/run_cmd.py", "run_cmd", "vulnerable")]},
        dataset={"units": [_unit("app/run_cmd.py:run_cmd", "app/run_cmd.py", "run_cmd", 3, 4)]},
    )
    jsonschema.validate(json.loads(proc.stdout),
                        json.loads(schema_path.read_text(encoding="utf-8")))
