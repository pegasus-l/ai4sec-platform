"""能力评测 E1 的存取层: 样本落库、run 生命周期、判分与报表。

三层分工(对应 PRD §9.2 的四个角色):
    出题 —— `samples.py` 造 samples/ + truth/, 库里只留路径与哈希
    执行 —— 评测容器里的适配 agent, 平台不管它怎么装怎么跑(C/D 阶段)
    判分 —— **只有** `contracts/v1/score.py` 一份实现。本模块负责把库里存着的
            原始答卷还原成 score.py 认的目录形状, 再原样调用它。

为什么判分要绕回文件: score.py 是契约的一部分, 它吃的是目录(answers/r1/…)。
在库里另写一套指标计算就等于有了两个真源 —— 复算、页面、对外口径迟早对不上。
所以这里宁可写临时目录、调完就删, 也不在 SQL 里算比率。

几条不许含糊的规矩:
  · 答卷**原样存**(能力评测不是"存翻译后的结论")。判分只读, 不回写。
  · 一个样本跑 >=3 轮(R11)。三轮回不一样就标 `unstable` —— 取多数会掩盖抖动,
    取最好会美化结果, 两种都是拿规则制造结论。
  · 报表没有样本数/时间窗/caveats 就落不了库(表级 CHECK)。空 caveats 的报表
    比没有报表更糟, 它看起来像结论。
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from ai4sec_platform.domains.capabilities.eval.contracts.v1 import score

CATEGORY_CLASS1 = "class1_llm_audit"

# 类别是代码里写死的, 不是配置: 一个类别 = 一份契约 + 一份判分脚本, 加类别就必须加代码。
CATEGORIES: list[dict[str, Any]] = [
    {
        "id": CATEGORY_CLASS1,
        "name": "LLM 代码审计 · 单文件定位",
        "contract_version": score.CONTRACT_VERSION,
        "what": "给一个文件, 问「这里有没有洞、在第几行、什么类型」。",
        "cannot": "测不出跨文件污点追踪、测不出真实仓库的噪声环境。",
    },
]

# run 的终态: 这三个都不再重试(G2)。running 之外的都算结束。
TERMINAL_STATUSES = ("success", "failed", "budget_exceeded")

# 判分目录里"哪些样本被工具声明为不覆盖"的清单文件名。以 `_` 开头: 判分脚本按 `*.json`
# 找答卷, 清单不能混进去。名字与 `contracts/v1/score.py` 的 `EXCLUDED_MANIFEST` 必须一致。
EXCLUDED_MANIFEST = "_excluded.json"

# 失败原因枚举(PRD §8)。空串 = 没失败。
FAILURE_REASONS = (
    "install_failed", "build_failed", "start_failed", "tests_failed", "no_output",
    "needs_paid_key", "needs_gpu", "needs_external_service", "unsupported_os",
    "repo_unavailable", "timeout", "resource_limit", "agent_gave_up",
    # 模型令牌的额度用尽(L5)。与"工具自己跑超时"分开: 一个是工具慢, 一个是它把预算烧完了
    "model_budget_exceeded",
    # 从没适配过(库里没有 recipe)与"适配过但跑不起来"是两件事, 混成一个原因就没法归因
    "no_recipe", "other",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# 样本
# --------------------------------------------------------------------------

def ingest_dataset(
    conn: sqlite3.Connection,
    dataset_dir: str | Path,
    *,
    category: str = CATEGORY_CLASS1,
) -> dict[str, Any]:
    """把一次构建出来的数据集写进 `capability_eval_samples`。

    只存**指针 + 哈希**: 代码留在文件系统里(评测容器只读挂载), 库里放路径和 sha256。
    落库前逐条核对文件哈希 —— 目录被人动过时, 这里就要当场拒绝, 而不是等指标
    算出来对不上再回头找。

    幂等: 同一对样本重跑只更新, 不新增(按 category + pair_key + polarity 定位)。
    """
    root = Path(dataset_dir)
    truth_dir = root / "truth"
    samples_dir = root / "samples"
    if not truth_dir.is_dir():
        raise ValueError(f"数据集缺 truth/ 目录: {truth_dir}")

    report: dict[str, Any] = {
        "category": category, "inserted": 0, "updated": 0,
        "skipped": 0, "skips": [], "samples": 0, "pairs": 0,
    }
    pair_keys: set[str] = set()

    for truth_path in sorted(truth_dir.glob("*.json")):
        try:
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _skip(report, truth_path.stem, "truth_unreadable", str(exc))
            continue

        sample_key = str(truth.get("sample_id") or truth_path.stem)
        variant = truth.get("variant")
        if variant not in ("pre", "post"):
            _skip(report, sample_key, "bad_variant", f"variant={variant!r}")
            continue

        sample_dir = samples_dir / sample_key
        codes = sorted(p for p in sample_dir.glob("code.*") if p.is_file())
        if len(codes) != 1:
            _skip(report, sample_key, "artifact_missing" if not codes else "multiple_code_files",
                  f"{sample_dir} 下的 code.* 有 {len(codes)} 个")
            continue
        code_path = codes[0]
        try:
            code = code_path.read_text(encoding="utf-8")
        except OSError as exc:
            _skip(report, sample_key, "artifact_unreadable", str(exc))
            continue

        try:
            manifest = json.loads((sample_dir / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _skip(report, sample_key, "manifest_missing", str(exc))
            continue
        if manifest.get("sample_id") not in (None, sample_key):
            _skip(report, sample_key, "manifest_mismatch",
                  f"manifest.sample_id={manifest.get('sample_id')!r}")
            continue
        if manifest.get("variant") not in (None, variant):
            _skip(report, sample_key, "manifest_mismatch",
                  f"manifest.variant={manifest.get('variant')!r} truth={variant!r}")
            continue

        digest = _sha256_text(code)
        if manifest.get("content_sha256") and manifest["content_sha256"] != digest:
            _skip(report, sample_key, "artifact_hash_mismatch",
                  "文件内容与构建时记录的 sha256 不一致(目录被改动过)")
            continue

        case_id = truth.get("case_id")
        if not isinstance(case_id, int) or case_id <= 0:
            _skip(report, sample_key, "truth_missing_case_id", f"case_id={case_id!r}")
            continue
        if "gt" not in truth:
            _skip(report, sample_key, "truth_missing_gt", "")
            continue

        pair_key = f"case-{case_id}"
        pair_keys.add(pair_key)
        row = (
            category, case_id, sample_key, pair_key, variant, digest,
            # 存绝对路径: 判分时要回头读 prompt.txt, 而库里没有"数据集根目录"这一项 ——
            # 存相对路径就得再猜一个根, 猜错时判分读到空文件比报错更难查。
            str(code_path.resolve()), json.dumps(truth, ensure_ascii=False),
            str(truth.get("published_at") or "")[:10] or None,
            str(truth.get("valid_until") or "")[:10] or None,
            _utc_now(),
        )

        existing = conn.execute(
            "SELECT id FROM capability_eval_samples"
            " WHERE category=? AND pair_key=? AND polarity=?", (category, pair_key, variant),
        ).fetchone()
        if existing:
            # sample_key 也可能被重建过, 单独查一次冲突: 两个样本抢同一个编号是构建出错
            clash = conn.execute(
                "SELECT id FROM capability_eval_samples"
                " WHERE category=? AND sample_key=? AND id<>?",
                (category, sample_key, existing[0]),
            ).fetchone()
            if clash:
                _skip(report, sample_key, "sample_key_taken", f"已被 id={clash[0]} 占用")
                continue
            conn.execute(
                "UPDATE capability_eval_samples SET case_id=?, sample_key=?, artifact_hash=?,"
                " artifact_path=?, ground_truth_json=?, published_at=?, valid_until=?,"
                " created_at=? WHERE id=?",
                (case_id, sample_key, digest, row[6], row[7], row[8], row[9], row[10],
                 existing[0]),
            )
            report["updated"] += 1
        else:
            try:
                conn.execute(
                    "INSERT INTO capability_eval_samples (category, case_id, sample_key,"
                    " pair_key, polarity, artifact_hash, artifact_path, ground_truth_json,"
                    " published_at, valid_until, created_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)", row)
            except sqlite3.IntegrityError as exc:
                _skip(report, sample_key, "unique_violation", str(exc))
                continue
            report["inserted"] += 1
        report["samples"] += 1
        report["pairs"] = len(pair_keys)

    conn.commit()
    return report


def _skip(report: dict[str, Any], sample_key: str, reason: str, detail: str) -> None:
    report["skipped"] += 1
    report["skips"].append({"sample": sample_key, "reason": reason, "detail": detail})


def list_samples(conn: sqlite3.Connection, category: str = CATEGORY_CLASS1) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, sample_key, pair_key, polarity, artifact_path, artifact_hash,"
        " ground_truth_json, published_at, valid_until"
        " FROM capability_eval_samples WHERE category=? ORDER BY sample_key", (category,),
    ).fetchall()
    out = []
    for row in rows:
        truth = json.loads(row["ground_truth_json"])
        out.append({
            "id": row["id"], "sample_key": row["sample_key"], "pair_key": row["pair_key"],
            "polarity": row["polarity"], "artifact_path": row["artifact_path"],
            "artifact_hash": row["artifact_hash"], "published_at": row["published_at"],
            "valid_until": row["valid_until"], "case_id": truth.get("case_id"),
            "canonical_id": truth.get("canonical_id", ""),
            "gt": truth.get("gt"), "patch_hunks": truth.get("patch_hunks", []),
        })
    return out


def _relative_path_of(code_path: Path) -> str:
    """样本在**原仓库**里的相对路径(来自同目录的 manifest.json)。

    读不到就退回文件名 —— 不猜目录结构: 猜出来的路径会让判分把 miss 认成 hit。
    """
    try:
        manifest = json.loads((code_path.parent / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return code_path.name
    return str(manifest.get("file_path") or code_path.name)


def sample_packets(conn: sqlite3.Connection, category: str = CATEGORY_CLASS1) -> list[dict[str, Any]]:
    """发给评测容器的一包东西: 题面 + 待审文件 + 指纹 —— **不含任何真值**
    (契约 §7 第 2 条: 适配 agent 不得读 truth/)。

    代码不是真值: 它就是被测工具本来要看的那个文件, 不给它就没法审。
    真值是"这个洞在第几行", 那三列(case_id/canonical_id/gt/patch_hunks)一个字都不出去。

    这里刻意用**投影白名单**, 而不是把 list_samples() 的结果删几个键:
    少写一个 dict.pop 就漏一次, 白名单漏不了。
    """
    rows = conn.execute(
        "SELECT sample_key, artifact_path, artifact_hash FROM capability_eval_samples"
        " WHERE category=? ORDER BY sample_key", (category,),
    ).fetchall()
    out = []
    for row in rows:
        code_path = Path(row["artifact_path"])
        try:
            prompt = (code_path.parent / "prompt.txt").read_text(encoding="utf-8")
            content = code_path.read_text(encoding="utf-8")
        except OSError as exc:
            # 数据集目录被搬走/清掉了。宁可整轮失败, 也不要让工具去审一个空文件 ——
            # 那会静默产出一批 invalid_output, 看起来像"工具不行"。
            raise ValueError(f"样本文件读不到: {code_path} ({exc})") from exc
        # 盘上文件叫 code.py(不保留原目录结构), 而工具报位置时报的是**原仓库相对路径**。
        # 不把这条路径给它, 判分时 path 对不上, 一次命中会被记成 miss。
        out.append({"sample_key": row["sample_key"], "prompt": prompt,
                    "file_name": code_path.name, "file_content": content,
                    "relative_path": _relative_path_of(code_path),
                    "artifact_hash": row["artifact_hash"]})
    return out


# --------------------------------------------------------------------------
# recipe
# --------------------------------------------------------------------------

PARSER_KINDS = ("json", "sarif", "agent_translate", "exit_code", "none")


def save_recipe(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    category: str,
    tool_version: str,
    recipe: Mapping[str, Any],
    exploit_note: str = "",
) -> dict[str, Any]:
    """把适配 agent 探出来的 recipe 冻进 `capability_eval_recipes`(D2)。

    版本语义: **同一个 tool_version 是"修正", 换版本号才是"新版"**。
      · 同版本再次提交 → 就地更新(探错了改一改, 不该在库里堆两条同版本配置);
      · 新版本 → 插新行, 并把同工具同类别里仍然有效的老行 `superseded_by` 指向它。
        老行**不删**: 一条分数要能回答"它当时是按哪份配置跑的"。

    这里再查一遍结构, 哪怕适配 agent 已经查过: 平台不把容器的自检当权威 ——
    缺 `invoke` 的 recipe 一旦进库, 下一轮就会以"工具没输出"的样子失败, 而真正的原因是配置。
    """
    problems: list[str] = []
    if not isinstance(recipe, Mapping):
        problems.append("recipe 不是对象")
    if not str(tool_version or "").strip():
        problems.append("缺 tool_version")
    if isinstance(recipe, Mapping):
        invoke = recipe.get("invoke")
        http = recipe.get("invoke_http")
        if not invoke and not http:
            problems.append("invoke 与 invoke_http 至少要有一个")
        if invoke is not None and (not isinstance(invoke, list) or not invoke):
            problems.append("invoke 必须是非空数组")
        parser = recipe.get("output_parser")
        kind = parser.get("kind") if isinstance(parser, Mapping) else parser
        if kind not in PARSER_KINDS:
            problems.append(f"output_parser 不支持: {kind!r}")
        if recipe.get("needs_host_agent") and not str(recipe.get("host_model") or "").strip():
            problems.append("needs_host_agent=true 时 host_model 必填")
    if problems:
        raise ValueError("recipe 不合规: " + "; ".join(problems))

    now = _utc_now()
    body = json.dumps(dict(recipe), ensure_ascii=False)
    existing = conn.execute(
        "SELECT id FROM capability_eval_recipes WHERE item_id=? AND tool_version=?",
        (item_id, tool_version),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE capability_eval_recipes SET category=?, recipe_json=?, exploit_note=?,"
            " verified_at=? WHERE id=?",
            (category, body, exploit_note, now, existing[0]),
        )
        conn.commit()
        return {"id": int(existing[0]), "created": False, "superseded": []}

    cur = conn.execute(
        "INSERT INTO capability_eval_recipes (item_id, category, tool_version, recipe_json,"
        " exploit_note, verified_at, created_at) VALUES (?,?,?,?,?,?,?)",
        (item_id, category, tool_version, body, exploit_note, now, now),
    )
    new_id = int(cur.lastrowid)
    stale = [int(r[0]) for r in conn.execute(
        "SELECT id FROM capability_eval_recipes WHERE item_id=? AND category=?"
        " AND superseded_by IS NULL AND id<>?", (item_id, category, new_id))]
    if stale:
        conn.executemany("UPDATE capability_eval_recipes SET superseded_by=? WHERE id=?",
                         [(new_id, rid) for rid in stale])
    conn.commit()
    return {"id": new_id, "created": True, "superseded": stale}


def list_recipes(
    conn: sqlite3.Connection, item_id: int, category: str = CATEGORY_CLASS1,
) -> list[dict[str, Any]]:
    """这个工具的全部 recipe 版本(含已被替换的), 新的在前。排障时先看这里。"""
    rows = conn.execute(
        "SELECT id, tool_version, recipe_json, exploit_note, verified_at, superseded_by,"
        " created_at FROM capability_eval_recipes WHERE item_id=? AND category=?"
        " ORDER BY verified_at DESC, id DESC", (item_id, category),
    ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["recipe"] = json.loads(item.pop("recipe_json"))
        except json.JSONDecodeError:
            item["recipe"] = None
        out.append(item)
    return out


def latest_recipe(
    conn: sqlite3.Connection, item_id: int, category: str = CATEGORY_CLASS1,
) -> dict[str, Any] | None:
    """这个工具当前有效的 recipe。`superseded_by` 非空的旧版一律不返回。

    工具改过版本就重探, 旧版留着但不参与执行 —— 拿旧 recipe 跑新工具,
    出来的分数既不代表旧版也不代表新版。
    """
    row = conn.execute(
        "SELECT id, tool_version, recipe_json, exploit_note, verified_at"
        " FROM capability_eval_recipes"
        " WHERE item_id=? AND category=? AND superseded_by IS NULL"
        " ORDER BY verified_at DESC, id DESC LIMIT 1",
        (item_id, category),
    ).fetchone()
    if row is None:
        return None
    out = dict(row)
    try:
        out["recipe"] = json.loads(out["recipe_json"])
    except json.JSONDecodeError:
        out["recipe"] = None
    return out


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------

def create_run(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    category: str = CATEGORY_CLASS1,
    tool_version: str = "",
    repeats: int = 3,
    budget: Mapping[str, Any] | None = None,
) -> int:
    """开一轮评测。建完就是 running —— 没有 queued 这个态(PRD §8 的枚举里没有),
    卡住靠 G3 的孤儿 run 回收, 不靠调度器记得改状态。"""
    if repeats < 1:
        raise ValueError("repeats 至少 1 轮")
    if category not in {c["id"] for c in CATEGORIES}:
        raise ValueError(f"未知类别: {category}")
    budget = dict(budget or {})
    cap = budget.get("max_model_calls")
    if cap is not None:
        # 开跑前挡住"预算注定不够"的轮次。跑到第 30 次才失败, 既烧掉了预算, 又会在页面上
        # 留下一条 budget_exceeded 终态 —— 那条记录读起来像"工具不行", 实际是配置写错了。
        n_samples = len(list_samples(conn, category))
        needed = n_samples * repeats
        if needed > int(cap):
            raise ValueError(
                f"预算不够: {n_samples} 个样本 × {repeats} 轮 = {needed} 次调用"
                f" > max_model_calls={cap}")
    now = _utc_now()
    cur = conn.execute(
        "INSERT INTO capability_eval_runs (item_id, category, tool_version, status,"
        " started_at, repeats, budget_json, cost_json, created_at)"
        " VALUES (?,?,?,'running',?,?,?,'{}',?)",
        (item_id, category, tool_version, now, repeats,
         json.dumps(budget, ensure_ascii=False), now),
    )
    conn.commit()
    return int(cur.lastrowid)


def save_answers(
    conn: sqlite3.Connection,
    run_id: int,
    answers: Mapping[str, Sequence[str | Mapping[str, Any]]],
) -> dict[str, Any]:
    """收一个 run 的答卷: `{sample_key: [第1轮, 第2轮, ...]}`。

    每一项三种形态:
      · 字符串 —— 工具直接吐契约格式(或根本没 parser 的夹具), 这时它同时是原生输出和答案;
      · `{"raw": ..., "answer": {...}}` —— 原生输出与翻译结果分开存(R8 + D3 两个角色各管一段)。
        `answer` 缺失/为 null 表示**翻译失败**, 判分按 invalid_output 算;
      · `{"raw": ..., "answer": null, "excluded": "<原因>"}` —— 工具自报「这类样本不覆盖」。
        它既不是答错也不是翻译失败, 存进 `excluded_reason`, 判分**不进分母**(D4-5)。

    这里**不校验答案格式**: 格式不对是被测工具的问题, 该由判分标 invalid_output;
    在这一层拦下来会把"工具不合规"记成"我们的管道坏了"。
    """
    run = get_run(conn, run_id)
    if run is None:
        raise ValueError(f"run 不存在: {run_id}")
    known = {s["sample_key"]: s["id"] for s in list_samples(conn, run["category"])}
    repeats = int(run["repeats"])

    saved, unknown, extra_repeats = 0, [], []
    now = _utc_now()
    for sample_key, raws in answers.items():
        sample_id = known.get(sample_key)
        if sample_id is None:
            unknown.append(sample_key)
            continue
        for index, raw in enumerate(list(raws)):
            if index >= repeats:
                extra_repeats.append({"sample": sample_key, "repeat_index": index})
                continue
            raw_text, answer_text, excluded_reason = _split_delivery(raw)
            conn.execute(
                "INSERT INTO capability_eval_answers"
                " (run_id, sample_id, repeat_index, raw_answer, answer_json,"
                "  excluded_reason, created_at)"
                " VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(run_id, sample_id, repeat_index) DO UPDATE SET"
                " raw_answer=excluded.raw_answer, answer_json=excluded.answer_json,"
                " excluded_reason=excluded.excluded_reason,"
                " created_at=excluded.created_at",
                (run_id, sample_id, index, raw_text, answer_text,
                 excluded_reason or None, now),
            )
            saved += 1
    conn.commit()

    delivered = {r[0] for r in conn.execute(
        "SELECT DISTINCT sample_id FROM capability_eval_answers WHERE run_id=?", (run_id,))}
    missing = sorted(k for k, sid in known.items() if sid not in delivered)
    return {"saved": saved, "unknown_samples": unknown,
            "too_many_repeats": extra_repeats, "missing_samples": missing}


def _split_delivery(raw: str | Mapping[str, Any]) -> tuple[str, str, str]:
    """把一条交付拆成 (原生输出, 契约答案, 排除原因)。前两者都**不可能是 None**。

    字符串形态下两者是同一份 —— 这是夹具/工具直出的情形, 不是"我省略了 raw"。
    `answer` 缺省(parser 翻译失败)写成**空串**: 判分把它读成 invalid_output,
    而不是拿原生散文去硬凑一个结论。

    第三种形态 `{"raw": ..., "answer": null, "excluded": "<原因>"}` 是 D4-5: 工具自报
    「这一类样本我根本不覆盖」(语言不支持/平台不支持)。它既不是答错也不是翻译失败,
    所以原因单独存一列, 判分据此**不进分母**。空串原因视同没有声明 —— 空字符串当
    "排除"会让一次漏填字段静默缩小分母。
    """
    if not isinstance(raw, Mapping):
        text = str(raw)
        return text, text, ""
    raw_text = raw.get("raw")
    raw_text = "" if raw_text is None else str(raw_text)
    reason = raw.get("excluded")
    reason = str(reason).strip() if isinstance(reason, (str, int, float)) else ""
    answer = raw.get("answer")
    if answer is None:
        return raw_text, "", reason
    if isinstance(answer, str):
        # parser 有时直接给 JSON 文本; 原样存, 判分读的就是它
        return raw_text, answer, reason
    return raw_text, json.dumps(answer, ensure_ascii=False), reason


def score_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """判分: 把库里的答卷还原成目录 → 调 `score.build_report` → 落 results + reports。

    重复调用是安全的: 先按 run 清掉旧的 results/report 再写, 不会留下两套结论。
    只有 status 还是 running 时才改成 success —— 已判失败的 run 不该被一次重算洗白。
    """
    run = get_run(conn, run_id)
    if run is None:
        raise ValueError(f"run 不存在: {run_id}")
    repeats = int(run["repeats"])
    samples = list_samples(conn, run["category"])
    by_id = {s["id"]: s for s in samples}
    # 判分读的是**翻译后**的答案。翻译失败时它是一个空串(见 _split_delivery), 判分把它标成
    # invalid_output; 原生输出留在 raw_answer 里, 谁都能回头查工具当时到底说了什么(R8)。
    answers: dict[tuple[str, int], str] = {}
    # 被工具声明为「不覆盖」的样本: `{repeat_index: {sample_key: 原因}}`。判分**不读**它们
    # 的答案(本来也没有), 而是据这份清单把它们整条移出分母(D4-5)。
    excluded: dict[int, dict[str, str]] = {}
    for row in conn.execute(
            "SELECT sample_id, repeat_index, raw_answer, answer_json, excluded_reason"
            " FROM capability_eval_answers WHERE run_id=?", (run_id,)):
        sample = by_id.get(row["sample_id"])
        if sample is None:
            continue
        key = sample["sample_key"]
        index = int(row["repeat_index"])
        reason = row["excluded_reason"]
        if reason:
            excluded.setdefault(index, {})[key] = str(reason)
            continue
        answers[(key, index)] = (row["answer_json"]
                                 if row["answer_json"] is not None else row["raw_answer"])
    if not answers and not excluded:
        raise ValueError(f"run {run_id} 还没有任何答卷, 无法判分")

    # X17：位置保真核对要**样本源码**（核对工具抄的片段是否真在它报的行号附近）。
    # 读不到就少这一条，该项判 content_na —— 它不参与任何分数，缺了不能影响判分。
    code_table: dict[str, str] = {}
    for sample in samples:
        try:
            code_table[sample["sample_key"]] = Path(sample["artifact_path"]).read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            continue

    work = Path(tempfile.mkdtemp(prefix="eval-score-"))
    try:
        truth_dir = work / "truth"
        truth_dir.mkdir()
        for sample in samples:
            # 原样写回: 判分读到的必须是构建时那份真值, 不能在这里被重新序列化过
            (truth_dir / f"{sample['sample_key']}.json").write_text(
                _truth_json(conn, sample["id"]), encoding="utf-8")
        for index in range(repeats):
            repeat_dir = work / "answers" / f"r{index + 1}"
            repeat_dir.mkdir(parents=True)
            for sample in samples:
                raw = answers.get((sample["sample_key"], index))
                if raw is not None:
                    (repeat_dir / f"{sample['sample_key']}.json").write_text(raw, encoding="utf-8")
            # 排除清单按**轮**落地: 同一工具可能这轮不支持、那轮又支持(例如依赖没装好),
            # 合成一份就没法如实表达。文件名以 `_` 开头, 判分把它当清单而不是答卷。
            if excluded.get(index):
                (repeat_dir / EXCLUDED_MANIFEST).write_text(
                    json.dumps(excluded[index], ensure_ascii=False, indent=2, sort_keys=True),
                    encoding="utf-8")
        try:
            report = score.build_report(work / "answers", truth_dir, code_table)
        except SystemExit as exc:  # score.py 用 SystemExit 报"目录里没东西"
            raise ValueError(f"判分失败: {exc}") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)

    _write_results(conn, run_id, samples, answers, report, repeats)

    metrics_json = json.dumps(report, ensure_ascii=False)
    caveats = "\n".join(report.get("caveats") or [])
    conn.execute(
        "INSERT INTO capability_eval_reports (run_id, metrics_json, caveats, created_at)"
        " VALUES (?,?,?,?)"
        " ON CONFLICT(run_id) DO UPDATE SET metrics_json=excluded.metrics_json,"
        " caveats=excluded.caveats, created_at=excluded.created_at",
        (run_id, metrics_json, caveats, _utc_now()),
    )
    if run["status"] == "running":
        conn.execute("UPDATE capability_eval_runs SET status='success', finished_at=?"
                     " WHERE id=?", (_utc_now(), run_id))
    conn.commit()
    return report


def _truth_json(conn: sqlite3.Connection, sample_id: int) -> str:
    return conn.execute("SELECT ground_truth_json FROM capability_eval_samples WHERE id=?",
                        (sample_id,)).fetchone()[0]


def _write_results(
    conn: sqlite3.Connection,
    run_id: int,
    samples: Sequence[dict[str, Any]],
    answers: Mapping[tuple[str, int], str],
    report: dict[str, Any],
    repeats: int,
) -> None:
    repeat_names = [f"r{i + 1}" for i in range(repeats)]
    labels: dict[str, dict[str, dict[str, Any]]] = {}
    for name in repeat_names:
        repeat = (report.get("per_repeat") or {}).get(name) or {}
        for row in repeat.get("samples") or []:
            labels.setdefault(row["sample_id"], {})[name] = row

    conn.execute("DELETE FROM capability_eval_results WHERE run_id=?", (run_id,))
    for sample in samples:
        key = sample["sample_key"]
        per_repeat = [
            {"repeat": name,
             "label": (labels.get(key, {}).get(name) or {}).get("label", "invalid_output"),
             "detail": (labels.get(key, {}).get(name) or {}).get("detail", "")}
            for name in repeat_names
        ]
        distinct = {item["label"] for item in per_repeat}
        if len(distinct) == 1:
            verdict = per_repeat[0]["label"]
            raw = answers.get((key, 0))
        else:
            verdict, raw = "unstable", None
        conn.execute(
            "INSERT INTO capability_eval_results (run_id, sample_id, verdict, location,"
            " detail_json) VALUES (?,?,?,?,?)",
            (run_id, sample["id"], verdict, _location(raw),
             json.dumps({"sample_key": key, "polarity": sample["polarity"],
                         "per_repeat": per_repeat}, ensure_ascii=False)),
        )


def _location(raw: str | None) -> str:
    """被测工具报的位置, 原样保留。解析不了的返回空串 —— 不猜。"""
    if not raw:
        return ""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return ""
    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not findings:
        return ""
    first = findings[0] if isinstance(findings[0], dict) else {}
    path = str(first.get("file") or "")
    start, end = first.get("line_start"), first.get("line_end")
    if path and start:
        return f"{path}:{start}-{end or start}"
    return path


def finish_run(
    conn: sqlite3.Connection,
    run_id: int,
    status: str,
    *,
    failure_reason: str = "",
    cost: Mapping[str, Any] | None = None,
    work_dir: str = "",
) -> None:
    """收尾。`failed` / `budget_exceeded` 是终态, 不自动重试(G2)。"""
    if status not in TERMINAL_STATUSES:
        raise ValueError(f"不是终态: {status} (可选 {TERMINAL_STATUSES})")
    if failure_reason and failure_reason not in FAILURE_REASONS:
        raise ValueError(f"未知失败原因: {failure_reason}")
    conn.execute(
        "UPDATE capability_eval_runs SET status=?, finished_at=?, failure_reason=?,"
        " cost_json=COALESCE(NULLIF(?, ''), cost_json), work_dir=COALESCE(NULLIF(?, ''), work_dir)"
        " WHERE id=?",
        (status, _utc_now(), failure_reason,
         json.dumps(dict(cost), ensure_ascii=False) if cost is not None else "",
         work_dir, run_id),
    )
    conn.commit()


# --------------------------------------------------------------------------
# 读
# --------------------------------------------------------------------------

def get_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM capability_eval_runs WHERE id=?", (run_id,)).fetchone()
    if row is None:
        return None
    out = dict(row)
    for key in ("budget_json", "cost_json"):
        try:
            out[key] = json.loads(out.get(key) or "{}")
        except json.JSONDecodeError:
            out[key] = {}
    report = conn.execute(
        "SELECT metrics_json, caveats, created_at FROM capability_eval_reports WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if report is not None:
        try:
            out["report"] = json.loads(report["metrics_json"])
        except json.JSONDecodeError:
            out["report"] = None
        out["caveats"] = report["caveats"]
        out["reported_at"] = report["created_at"]
    else:
        out["report"] = None
        out["caveats"] = ""
        out["reported_at"] = None
    return out


def get_results(conn: sqlite3.Connection, run_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT r.sample_id, r.verdict, r.location, r.detail_json, s.sample_key,"
        " s.polarity FROM capability_eval_results r"
        " JOIN capability_eval_samples s ON s.id = r.sample_id"
        " WHERE r.run_id=? ORDER BY s.sample_key", (run_id,),
    ).fetchall()
    out = []
    for row in rows:
        detail = json.loads(row["detail_json"] or "{}")
        out.append({
            "sample_id": row["sample_id"], "sample_key": row["sample_key"],
            "polarity": row["polarity"], "verdict": row["verdict"],
            "location": row["location"], "per_repeat": detail.get("per_repeat", []),
        })
    return out


def list_runs(
    conn: sqlite3.Connection,
    *,
    item_id: int | None = None,
    category: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    where, params = [], []
    if item_id is not None:
        where.append("item_id=?"); params.append(item_id)
    if category:
        where.append("category=?"); params.append(category)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    rows = conn.execute(
        f"SELECT * FROM capability_eval_runs {clause} ORDER BY started_at DESC, id DESC LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def list_categories(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """类别 + 各自的样本规模与已跑次数。数字全部现算, 不缓存。"""
    out = []
    for meta in CATEGORIES:
        samples = conn.execute(
            "SELECT COUNT(*) FROM capability_eval_samples WHERE category=?",
            (meta["id"],)).fetchone()[0]
        runs = conn.execute(
            "SELECT COUNT(*) FROM capability_eval_runs WHERE category=?",
            (meta["id"],)).fetchone()[0]
        out.append({**meta, "n_samples": samples, "n_runs": runs})
    return out
