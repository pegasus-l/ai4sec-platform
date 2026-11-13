"""T5.1:从复现报告抽出 recipe(怎么跑)与 pattern(怎么找)。

固化这一层最容易出的错不是"抽不出来", 而是**抽出来一条看起来能跑、其实没跑过的路径**:

- 把 `curl` 拼出来的命令当成"应该这么跑" ⇒ 复用它的人照着走, 走不通也不知道是谁的问题;
- 把 `ls` / `cd` 收进 recipe ⇒ 三步里两步是废话, 真正的 trigger 被稀释;
- `partial` 的路径和 `success` 的路径长得一模一样 ⇒ 下一个人以为这条被验证过;
- 同一条素材重抽一次就多一行 ⇒ "这个写法危险"被数重了一倍;
- 报告重新生成后规律不再成立, 旧 pattern 还留着 ⇒ 下游拿旧结论当新结论。

所以下面的用例逐条对着这些"看起来对"的失败方式。**每条 recipe 步骤都必须能回指报告第 3 节
的命令编号** —— 这是这一层唯一能自证的诚实性约束。
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.writeup_repro import recipes as recipes_module
from ai4sec_platform.domains.capabilities.writeup_repro import report as report_module
from ai4sec_platform.domains.capabilities.writeup_repro import tasks

ARTICLE = """# fastecdsa 2.3.1 double free

在 Python 3.11.8 上运行下面的 PoC, 会打印 free(): invalid pointer 并 SIGABRT:

    from fastecdsa import curve
    print(curve.curvemath_mul(...))
"""

#: 一条真跑过的命令序列(取自 CVE-2024-21502 的第三遍 rerun, 略去无关步骤)。
COMMANDS = [
    "ls -la",
    "git clone https://github.com/AntonKueltz/fastecdsa",
    "cd fastecdsa && python3 -m venv .venv3118",
    "source .venv3118/bin/activate && pip install -e .",
    "echo 'from fastecdsa import curve' > poc.py",
    "python3 poc.py",
    "python3 poc.py",
]
PROBE = "python3 poc.py"


def _evidence(matched: bool | None = True) -> dict:
    return {
        "version": 1,
        "commands": [
            {"cmd": cmd, "exit_code": 134 if cmd == PROBE else 0,
             "stdout_sha1": f"{i:040x}", "stdout_tail": "free(): invalid pointer",
             "completed": True}
            for i, cmd in enumerate(COMMANDS, start=1)
        ],
        "probe": {
            "spec_cmd": PROBE, "success_signal": "stdout 包含 free(): invalid pointer",
            "found": True, "cmd": PROBE, "exit_code": 134, "shell_exit_code": 134,
            "exit_code_source": "printed", "stdout_sha1": "f" * 40,
            "stdout_tail": "free(): invalid pointer", "matched": matched,
            "checks": [], "why": "", "occurrences": 2,
        },
        "egress": {}, "guard": {"allowed": True},
        "agent_claim": {}, "duration_seconds": 182, "tool_calls": 17,
    }


def _task(verdict: str = "success", reason: str = "", **over) -> dict:
    task = {
        "id": 3,
        "material_id": 132734,
        "status": verdict,
        "verdict": verdict,
        "failure_reason": reason,
        "claim": "fastecdsa 2.3.1 在 Python 3.11.8 上 double free",
        "claim_quote": "会打印 free(): invalid pointer 并 SIGABRT",
        "target_kind": "package",
        "target_repo": "github:AntonKueltz/fastecdsa",
        "target_version": "2.3.1",
        "attempt": 3,
        "duration_seconds": 182,
        "tool_calls": 17,
        "spec_json": {
            "claim": "double free",
            "target": {"kind": "package", "repo": "github:AntonKueltz/fastecdsa", "ref": "2.3.1"},
            "steps": [{"run": PROBE, "expect": "崩溃"}],
            "probe": {"cmd": PROBE, "success_signal": "stdout 包含 free(): invalid pointer"},
        },
    }
    task.update(over)
    return task


def _candidate(**over) -> dict:
    row = {
        "material_id": 132734,
        "poc_lang": "python",
        "target_kind": "package",
        "claimed_effect": "堆上的内存破坏, 可导致远程代码执行",
        "evidence_quote": "free(): invalid pointer",
    }
    row.update(over)
    return row


def _section(evidence: dict) -> dict:
    return report_module.execution_section(evidence)


def _report(
    *,
    verdict: str = "success",
    reason: str = "",
    verified: bool = True,
    pattern: bool = True,
    evidence: dict | None = None,
) -> dict:
    """一份**形状与 report.build_report 一致**的报告(键名逐一对齐, 见下方集成用例)。"""
    evidence = evidence or _evidence()
    section = _section(evidence)
    observed = report_module.observed_section(evidence, _candidate())
    pattern_json = {}
    if pattern:
        pattern_json = {
            "speaker": "model",
            "invariant": "乘法入口在曲线阶为 0 时不得写回未初始化的结果",
            "code_feature": "curvemath_mul 里 result 未初始化就参与模乘",
            "audit_entry": "对阶为 0 / 非素数的曲线调用 curvemath_mul, 看结果指针",
            "discriminator": "原生扩展里的未初始化写入在 Python 层看不到, 只有 glibc 会报",
            "generalization": "language",
            "provenance": "from_repro",
            "confidence": 0.8,
            "evidence_refs": [6],
            "root_cause_provenance": "llm_extracted",
            "verified": verified,
            "blockers": [] if verified else ["第 6 节未通过位置校验"],
        }
    return {
        "task_id": 3,
        "material_id": 132734,
        "verdict": verdict,
        "failure_reason": reason,
        "claim_json": report_module.claim_section(_task(verdict), {}, _candidate()),
        "observed_json": observed,
        "attribution_json": {},
        "root_cause_json": {},
        "pattern_json": pattern_json,
        "evidence_json": {
            "section": section,
            "pack": evidence,
            "generation": {
                "version": report_module.REPORT_VERSION,
                "root_cause_verified": verified,
                "pattern_verified": verified,
            },
        },
        "caveats": ["环境版本敏感: 必须在 Python 3.11.8 上跑, 3.11.2 只 SIGSEGV", "第 5–7 节由模型撰写, 尚未人工复核"],
        "generated_by": "hybrid",
    }


# ---------------------------------------------------------------- 分段

def test_every_recipe_step_points_at_a_real_command() -> None:
    """这一层唯一的自证手段: 步骤里的 index 拿到报告第 3 节里去查, 必查得到。"""
    recipe, reasons = recipes_module.build_recipe(_task(), _report(), _candidate())

    assert reasons == []
    evidence_indices = {row["index"] for row in _section(_evidence())["commands"]}
    steps = [item for key in ("setup", "acquire", "trigger") for item in recipe[key]]
    steps.append(recipe["probe"])

    assert steps, "命令都在, 不该一条都抽不出来"
    for step in steps:
        assert step["index"] in evidence_indices, step


def test_a_command_chain_is_judged_by_each_subcommand() -> None:
    """`cd x && source ... && pip install -e .` 是准备环境, 不是触发。"""
    recipe, _ = recipes_module.build_recipe(_task(), _report(), _candidate())

    setup = [item["cmd"] for item in recipe["setup"]]
    assert "source .venv3118/bin/activate && pip install -e ." in setup
    assert "cd fastecdsa && python3 -m venv .venv3118" in setup
    assert all("pip install" not in item["cmd"] for item in recipe["trigger"])


def test_acquire_wins_over_setup_when_a_command_does_both() -> None:
    """`git clone x && pip install -e .` 解决的是"目标从哪来", 归 acquire。"""
    assert recipes_module.classify_command("git clone https://g/x && pip install -e .") == "acquire"
    assert recipes_module.classify_command("curl -sL https://g/x.tar.gz -o x.tgz") == "acquire"


def test_a_chain_that_mixes_preparation_with_running_stays_a_trigger() -> None:
    """前半段像准备、后半段才是触发, 归成 setup 就把这一行最要紧的部分藏起来了。"""
    assert recipes_module.classify_command("rm -rf /w && ./run.sh") == "trigger"
    assert recipes_module.classify_command("mkdir -p /w && rm -rf /w") == "setup"
    assert recipes_module.classify_command(".venv/bin/pip install fastecdsa==2.3.1") == "setup"


def test_a_version_or_import_check_is_inspection_not_preparation() -> None:
    """`python3 --version` / `-c "import x"` 是**问环境**, 不是准备环境。

    ``--version`` 与 ``-c ...import`` 出现在命令中间 —— 判类若锚在开头就够不着它们,
    任务 3 实测把两条 `--version` 记成了触发步骤。
    """
    assert recipes_module.classify_command("python3 --version") == "noise"
    assert recipes_module.classify_command(
        "/root/.local/share/uv/python/cpython-3.11/bin/python3.11 --version"
    ) == "noise"
    assert recipes_module.classify_command('.venv/bin/python3 -c "import fastecdsa, sys"') == "noise"


def test_a_which_line_naming_build_tools_is_still_inspection() -> None:
    """`which uv pyenv gcc make wget curl; gcc --version | head -1` 在问"装没装", 不是在编译。

    这条是任务 3 第 10 号命令的原文: 先查 setup 会让它命中 ``make`` 那条特征, 于是一条
    纯巡检命令被记成"环境准备"。
    """
    cmd = (
        'which uv pyenv gcc make wget curl 2>/dev/null; echo "---"; '
        'gcc --version | head -1; make --version | head -1; nproc'
    )
    assert recipes_module.classify_command(cmd) == "noise"


def test_separators_inside_quotes_do_not_split_a_command() -> None:
    """引号里的 ``;`` / ``&&`` 属于那段脚本, 拆开就会凭空造出不存在的步骤。"""
    parts = recipes_module._subcommands('python3 -c "import sys; print(sys.version)"')
    assert parts == ['python3 -c "import sys; print(sys.version)"']

    # `bash -c '... && pip install ...'` 整体仍是准备: 被拆碎的话每一块都判不成 setup。
    assert recipes_module.classify_command("bash -c 'cd /w && pip install -e .'") == "setup"

    # 双引号里的转义引号不该提前结束引号。
    assert len(recipes_module._subcommands('echo "a \\" b; c" && ls')) == 2


def test_the_probe_exit_code_comes_from_the_platform_not_the_shell() -> None:
    """真跑里 probe 常是 `poc.py | tee out; echo EXIT=$?`: 第 3 节记 0, 判定用的是读回的 134。"""
    evidence = _evidence()
    evidence["commands"][6]["exit_code"] = 0          # 外层 shell
    evidence["probe"].update({"exit_code": 134, "shell_exit_code": 0, "exit_code_source": "printed"})
    recipe, _ = recipes_module.build_recipe(_task(), _report(evidence=evidence), _candidate())

    assert recipe["probe"]["exit_code"] == 134
    assert recipe["probe"]["shell_exit_code"] == 0
    assert recipe["probe"]["exit_code_source"] == "printed"


def test_navigation_noise_is_dropped_but_echo_is_not() -> None:
    """`ls` 是废话; `echo ... > poc.py` 是**把 PoC 写进文件**, 丢了就等于丢了 trigger。"""
    recipe, _ = recipes_module.build_recipe(_task(), _report(), _candidate())

    omitted = [item["cmd"] for item in recipe["omitted"]]
    assert omitted == ["ls -la"]
    assert any("poc.py" in item["cmd"] for item in recipe["trigger"])


def test_the_probe_is_the_last_run_and_earlier_runs_stay_as_trigger() -> None:
    """判定取最后一次(环境没对齐那几次不算数), 但它们确实是"怎么触发"的证据, 不丢。"""
    recipe, _ = recipes_module.build_recipe(_task(), _report(), _candidate())
    section = _section(_evidence())["commands"]

    assert recipe["probe"]["index"] == 7, "第 7 条才是判定的那一次"
    assert recipe["probe"]["occurrences"] == 2
    assert [item["index"] for item in recipe["trigger"]].count(6) == 1


def test_when_no_probe_was_found_the_recipe_says_so_instead_of_guessing() -> None:
    evidence = _evidence()
    evidence["probe"]["cmd"] = evidence["probe"]["spec_cmd"] = "python3 missing.py"
    recipe, _ = recipes_module.build_recipe(_task(), _report(evidence=evidence), _candidate())

    assert recipe["probe"]["index"] is None
    assert recipe["probe"]["index_found"] is False


def test_the_command_list_is_capped_and_reports_how_many_were_dropped() -> None:
    many = {"version": 1, "commands": [
        {"cmd": f"echo step{i} > f{i}.txt", "exit_code": 0} for i in range(200)
    ], "probe": {"found": False}, "guard": {"allowed": True}}
    recipe, _ = recipes_module.build_recipe(_task(), _report(evidence=many), _candidate())

    total = sum(len(recipe[key]) for key in ("setup", "acquire", "trigger"))
    assert total <= recipes_module.MAX_RECIPE_COMMANDS
    assert recipe["truncated"] > 0


# ---------------------------------------------------------------- 门槛

@pytest.mark.parametrize("verdict,reason", [
    ("failed", "env_error"),
    ("blocked", "online_target"),
    ("cannot_repro", "article_incomplete"),
])
def test_only_success_and_partial_produce_a_recipe(verdict: str, reason: str) -> None:
    """没跑成的那几类没有可复用的执行路径 —— 抽一条"应该这么跑"就是编的。"""
    recipe, reasons = recipes_module.build_recipe(_task(verdict, reason), _report(verdict=verdict, reason=reason))

    assert recipe is None
    assert reasons and "不产 recipe" in reasons[0]


def test_a_partial_is_marked_degraded_and_never_counted_as_a_success() -> None:
    report = _report(verdict="partial", reason="probe_not_matched")
    recipe, _ = recipes_module.build_recipe(_task("partial", "probe_not_matched"), report)

    assert recipe["degraded"] is True
    assert recipe["source"]["verdict"] == "partial"


def test_a_report_without_commands_produces_nothing() -> None:
    bare = {"version": 1, "commands": [], "probe": {"found": False}, "guard": {"allowed": True}}
    recipe, reasons = recipes_module.build_recipe(_task(), _report(evidence=bare))

    assert recipe is None
    assert "没有任何已执行命令" in reasons[0]


def test_a_pattern_can_come_out_of_a_cannot_repro_report() -> None:
    """复现失败否定的是我们的环境, 不否定根因分析(§13.7)。"""
    report = _report(verdict="cannot_repro", reason="version_mismatch")
    pattern, reasons = recipes_module.build_pattern(
        _task("cannot_repro", "version_mismatch"), report, _candidate(),
    )

    assert reasons == []
    assert pattern["invariant"].startswith("乘法入口")
    assert pattern["generalization"] == "language"


def test_an_unverified_pattern_writes_no_row_and_says_why() -> None:
    pattern, reasons = recipes_module.build_pattern(
        _task(), _report(verified=False), _candidate(),
    )

    assert pattern is None
    assert "第 6 节未通过位置校验" in reasons[0]


def test_a_pattern_needs_an_invariant() -> None:
    report = _report()
    report["pattern_json"]["invariant"] = ""
    pattern, reasons = recipes_module.build_pattern(_task(), report)

    assert pattern is None
    assert "没有不变量" in reasons[0]


# ---------------------------------------------------------------- 指纹

def test_the_fingerprint_holds_facts_but_not_the_repo() -> None:
    """放仓库名/版本, 指纹就退化成"只对这一个目标有效", 而复用的前提正好相反。"""
    tokens = recipes_module.build_fingerprint(_task(), _candidate(), _report()["pattern_json"])

    assert "lang:python" in tokens
    assert "target:package" in tokens
    assert "surface:memory_corruption" in tokens
    assert "gen:language" in tokens
    assert not any("fastecdsa" in token or "2.3.1" in token for token in tokens)


def test_an_unknown_language_or_target_adds_no_token() -> None:
    tokens = recipes_module.build_fingerprint(
        _task(target_kind="unknown"), _candidate(poc_lang=""), {},
    )
    assert not [token for token in tokens if token.startswith(("lang:", "target:"))]


def test_language_aliases_are_normalized_not_copied() -> None:
    assert recipes_module.normalize_lang("Python3") == "python"
    assert recipes_module.normalize_lang("C++") == "cpp"
    assert recipes_module.normalize_lang("随便写的") == ""


# ---------------------------------------------------------------- 落库: 幂等与覆盖

_URIS: dict[sqlite3.Connection, str] = {}


def _conn() -> sqlite3.Connection:
    uri = f"file:wrectest_{len(_URIS)}?mode=memory&cache=shared"
    conn = sqlite3.connect(uri, uri=True)
    _URIS[conn] = uri
    conn.row_factory = sqlite3.Row
    init_db(conn)
    conn.execute(
        "INSERT INTO domain_items (id, domain, item_type, title, status, source, source_url,"
        " primary_date, payload_json, created_at, updated_at)"
        " VALUES (132734, 'vulnerabilities', 'material', 'fastecdsa', 'active', 'src',"
        " 'http://blog/1', '2026-11-01', ?, 'now', 'now')",
        (json.dumps({"cleaned_text": ARTICLE}),),
    )
    conn.execute(
        "INSERT INTO writeup_repro_candidates (material_id, screenable, reject_reason, has_poc,"
        " poc_lang, target_kind, claimed_effect, evidence_quote, rule_json, screen_json,"
        " rule_version, screened_at) VALUES (132734, 1, 'screenable', 1, 'python', 'package',"
        " '内存破坏', 'free(): invalid pointer', '{}', '{}', 'v2', 'x')",
    )
    conn.execute("INSERT INTO writeup_repro_tasks (id, material_id, attempt, status, verdict,"
                 " failure_reason, claim, claim_quote, spec_json, created_at, updated_at)"
                 " VALUES (3, 132734, 3, 'success', 'success', '', 'c', 'q', ?, 'x', 'x')",
                 (json.dumps(_task()["spec_json"]),))
    conn.commit()
    report_module.save_report(conn, _report())
    return conn


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def test_extraction_writes_both_products() -> None:
    conn = _conn()
    result = recipes_module.extract_for_task(3, conn=conn)

    assert result["status"] == "ok"
    assert _count(conn, "writeup_repro_recipes") == 1
    assert _count(conn, "writeup_repro_patterns") == 1
    task = tasks.get_task(conn, 3)
    assert task["recipe_id"] == result["recipe"]["id"]
    assert conn.execute(
        "SELECT success_count FROM writeup_repro_recipes WHERE id = ?", (result["recipe"]["id"],)
    ).fetchone()[0] == 1


def test_extraction_is_idempotent() -> None:
    conn = _conn()
    first = recipes_module.extract_for_task(3, conn=conn)
    second = recipes_module.extract_for_task(3, conn=conn, regenerate=True)

    assert _count(conn, "writeup_repro_recipes") == 1
    assert _count(conn, "writeup_repro_patterns") == 1
    assert first["recipe"]["id"] == second["recipe"]["id"]


def test_a_second_call_without_regenerate_leaves_existing_rows_alone() -> None:
    conn = _conn()
    recipes_module.extract_for_task(3, conn=conn)
    again = recipes_module.extract_for_task(3, conn=conn, regenerate=False)

    assert again["status"] == "exists"
    assert _count(conn, "writeup_repro_recipes") == 1


def test_a_regenerated_report_that_no_longer_qualifies_removes_the_stale_rows() -> None:
    """结论降级了, 旧 pattern 不能还挂在库里被下游当新结论用。"""
    conn = _conn()
    recipes_module.extract_for_task(3, conn=conn)

    conn.execute("UPDATE writeup_repro_tasks SET status='failed', verdict='failed',"
                 " failure_reason='env_error' WHERE id = 3")
    conn.commit()
    report_module.save_report(conn, _report(verdict="failed", reason="env_error", verified=False))
    result = recipes_module.extract_for_task(3, conn=conn, regenerate=True)

    assert result["status"] == "no_products"
    assert _count(conn, "writeup_repro_recipes") == 0
    assert _count(conn, "writeup_repro_patterns") == 0
    assert tasks.get_task(conn, 3)["recipe_id"] is None


def test_no_report_means_nothing_to_extract() -> None:
    conn = _conn()
    conn.execute("DELETE FROM writeup_repro_reports")
    conn.commit()

    result = recipes_module.extract_for_task(3, conn=conn)

    assert result["status"] == "no_report"
    assert _count(conn, "writeup_repro_recipes") == 0


def test_products_can_be_listed_and_filtered_by_fingerprint() -> None:
    conn = _conn()
    recipes_module.extract_for_task(3, conn=conn)

    by_token, total = recipes_module.list_recipes(conn, fingerprint="surface:memory_corruption")
    assert total == 1 and by_token[0]["fingerprint_json"][0].startswith("lang:")
    other, other_total = recipes_module.list_recipes(conn, fingerprint="surface:rce")
    assert other == [] and other_total == 0

    patterns, ptotal = recipes_module.list_patterns(conn, generalization="language")
    assert ptotal == 1 and patterns[0]["fingerprint"] == by_token[0]["fingerprint_json"]


def test_stats_counts_products_and_degraded_recipes_separately() -> None:
    conn = _conn()
    recipes_module.extract_for_task(3, conn=conn)
    counts = recipes_module.counts(conn)

    assert counts == {"recipes": 1, "degraded_recipes": 0, "patterns": 1, "pattern_materials": 1}


# ---------------------------------------------------------------- 与报告层对表

def test_a_report_built_by_the_report_module_feeds_the_extractor() -> None:
    """集成: 键名/形状是这两层之间唯一的契约, 手写 fixture 对不上的话这里会先红。"""
    evidence = _evidence()
    task = _task()
    candidate = _candidate()
    built = report_module.build_report(
        task=task,
        material={"id": 132734, "title": "fastecdsa", "cleaned_text": ARTICLE},
        candidate=candidate,
        evidence=evidence,
        model_sections={
            "attribution": {"side": "", "reason": "", "evidence_refs": []},
            "root_cause": {
                "location": {"file": "", "function": "curvemath_mul", "lines": ""},
                "invariant": "结果指针写入前必须已初始化",
                "broken_by": "阶为 0 时跳过初始化",
                "preconditions": ["Python 3.11.8"],
                "code_quote": "会打印 free(): invalid pointer 并 SIGABRT",
            },
            "pattern": {
                "code_feature": "result 未初始化就参与模乘",
                "audit_entry": "对阶为 0 的曲线调用 curvemath_mul",
                "discriminator": "只有 glibc 会报, Python 层看不到",
                "generalization": "language",
                "provenance": "from_repro",
                "evidence_refs": [6],
                "confidence": 0.8,
            },
            "caveats": [],
        },
    )
    assert built["pattern_json"]["verified"] is True

    recipe, reasons = recipes_module.build_recipe(task, built, candidate)
    pattern, pattern_reasons = recipes_module.build_pattern(task, built, candidate)

    assert reasons == [] and pattern_reasons == []
    assert recipe["probe"]["index"] == 7
    assert recipe["applies_to"]["fingerprint"] == json.loads(pattern["fingerprint"])


# ---------------------------------------------------------------- 执行器接线

def test_finishing_a_task_also_extracts_the_products(monkeypatch) -> None:
    """执行器是主要入口: 结论落下 + 报告写好之后, 产物跟着出现。"""
    from ai4sec_platform.domains.capabilities.writeup_repro import executor

    conn = _conn()
    conn.execute("DELETE FROM writeup_repro_reports")
    conn.execute("UPDATE writeup_repro_tasks SET status='running', verdict='',"
                 " failure_reason='' WHERE id = 3")
    conn.commit()

    def reopen() -> sqlite3.Connection:
        fresh = sqlite3.connect(_URIS[conn], uri=True)
        fresh.row_factory = sqlite3.Row
        return fresh

    monkeypatch.setattr(executor, "_connect", reopen)
    monkeypatch.setattr(report_module, "_connect", reopen)
    monkeypatch.setattr(recipes_module, "_connect", reopen)
    monkeypatch.setattr(executor, "_log", lambda task_id, line: None)
    monkeypatch.setattr(report_module, "generate_model_sections", lambda payload: {
        "status": "success", "sections": {
            "attribution": {"side": "ours", "reason": "环境没装对", "evidence_refs": [1]},
            "root_cause": {
                "location": {"file": "", "function": "curvemath_mul", "lines": ""},
                "invariant": "结果指针写入前必须已初始化",
                "broken_by": "阶为 0 时跳过初始化",
                "preconditions": [], "code_quote": "会打印 free(): invalid pointer 并 SIGABRT",
            },
            "pattern": {
                "code_feature": "result 未初始化就参与模乘",
                "audit_entry": "对阶为 0 的曲线调用 curvemath_mul",
                "discriminator": "只有 glibc 会报",
                "generalization": "language", "provenance": "from_repro",
                "evidence_refs": [6], "confidence": 0.8,
            },
            "caveats": [],
        },
        "provider": "fake", "model": "fake-1",
    })

    executor._finish(3, "success", "", [], evidence=_evidence())

    assert tasks.get_task(conn, 3)["status"] == "success"
    assert _count(conn, "writeup_repro_reports") == 1
    assert _count(conn, "writeup_repro_recipes") == 1
    assert _count(conn, "writeup_repro_patterns") == 1


def test_a_broken_extractor_never_changes_the_verdict(monkeypatch) -> None:
    from ai4sec_platform.domains.capabilities.writeup_repro import executor

    conn = _conn()
    conn.execute("UPDATE writeup_repro_tasks SET status='running', verdict='',"
                 " failure_reason='' WHERE id = 3")
    conn.commit()

    def reopen() -> sqlite3.Connection:
        fresh = sqlite3.connect(_URIS[conn], uri=True)
        fresh.row_factory = sqlite3.Row
        return fresh

    logged: list[str] = []
    monkeypatch.setattr(executor, "_connect", reopen)
    monkeypatch.setattr(executor, "_log", lambda task_id, line: logged.append(line))
    monkeypatch.setattr(report_module, "_connect", reopen)
    monkeypatch.setattr(recipes_module, "extract_for_task",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))

    executor._finish(3, "partial", "probe_not_matched", [], evidence=_evidence())

    assert tasks.get_task(conn, 3)["status"] == "partial"
    assert any("recipe/pattern 抽取失败" in line for line in logged)
