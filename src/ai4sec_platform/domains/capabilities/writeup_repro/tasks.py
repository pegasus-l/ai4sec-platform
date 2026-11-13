"""T2.1 / T2.3:复现任务表 —— 状态机、幂等、结论配对。

一张任务 = "把这一篇素材真的跑一遍"。它比候选行多三样东西: **spec**(怎么算成功)、
**状态**(跑到哪一步)、**结论**(verdict + failure_reason)。

为什么状态机要写死
==================

状态散在管道各处随手更新, 最后一定会出现"库里写着 running 但进程早没了"的行 ——
平台已有的 `recovery.recover_orphaned_pipeline_runs()` 就是给这种事擦屁股的。
这里把允许的迁移写成一张表, 非法迁移**直接抛错**, 而不是静默写进去:

    pending → spec_ready → queued → running → success|partial|failed|cannot_repro|blocked
    任意非终态 → cancelled(人取消)

六个终态**不可再迁移**。要重跑同一条素材, 走 T3 的"重跑"入口重建任务行(带新的 trigger),
而不是把一条已完成的记录改回 running —— 否则证据包与结论会对不上(结论是上一次跑的,
证据被这一次覆盖)。

为什么 verdict 和 failure_reason 必须成对
========================================

这是整个方案最关键的诚实性设计(文档 §7.2): `cannot_repro` 是**原文的锅**(没写清 / 版本对
不上), `failed` 是**我们的锅**(环境起不来)。两者混着统计, "原文不可复现"会被读成
"我们做不出来", 反过来也一样。所以这里在**写库这一层**校验配对关系, 不靠调用方自觉。

为什么建任务要幂等
==================

同一篇素材被点两次"复现", 不该出现两条并行任务去抢同一个容器。``UNIQUE(material_id, attempt)``
加上"已有任务就返回当前那一遍", 重复创建返回**已有那一行** + `created=False`, 调用方据此决定是
"继续跑"还是"新开跑"。

要跑第二遍**不是**建一条同 attempt 的行(那会撞唯一键), 而是 `rerun()`: attempt+1 新建一行,
上一行原样留着。2026-11-12 用户拍板的口径 —— 见 `rerun()` 的 docstring。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from ai4sec_platform.domains.capabilities.writeup_repro import store

#: 未结束的状态。`pending` = 有素材有候选但还没 spec; `spec_ready` = spec 已生成且过了校验。
ACTIVE_STATES: tuple[str, ...] = ("pending", "spec_ready", "queued", "running")
#: 终态。到了这里就不能再动状态(见模块 docstring)。
#: ``spec_failed`` = 反复建不出可核对的 spec —— **我们的问题**, 既不是原文不可复现,
#: 也不是跑了没成功, 所以单列, 不和 cannot_repro / failed 混在一起。
TERMINAL_STATES: tuple[str, ...] = (
    "success", "partial", "failed", "cannot_repro", "blocked", "cancelled", "spec_failed",
)
STATES: tuple[str, ...] = ACTIVE_STATES + TERMINAL_STATES

#: 允许的迁移。终态不在表里 ⇒ 任何从终态出发的迁移都会被拒。
#: ``cancelled`` 从每个非终态都可达 —— 模块 docstring 写的就是"任意非终态 → cancelled",
#: 这里少了它的话, 用户点"停止"只会得到一句 400(排队中/执行中的任务恰恰最需要能停)。
#: ``blocked`` 从 ``spec_ready`` / ``queued`` 也直接可达: 安全边界在**开跑前**就拦下来的任务
#: 从未执行过, 不该先假装 running 再落 blocked。
_TRANSITIONS: dict[str, set[str]] = {
    "pending": {"spec_ready", "queued", "cannot_repro", "cancelled", "spec_failed"},
    "spec_ready": {"queued", "cannot_repro", "cancelled", "spec_failed", "blocked"},
    "queued": {"running", "failed", "cancelled", "blocked"},
    "running": {"success", "partial", "failed", "cannot_repro", "blocked", "cancelled"},
}

#: spec 生成连续失败几次就收成 ``spec_failed``。设上限是因为它会花模型调用,
#: 但**上限只在"模型说文章够了却给不出能对上的引用"时计数** —— 网关抖动不算(见 API 层)。
MAX_SPEC_ATTEMPTS = 3

#: 会带 verdict 的终态(它们必须能说清"成没成")。
VERDICT_STATES: tuple[str, ...] = ("success", "partial", "failed", "cannot_repro", "blocked")

#: 文档 §7.2 的配对表。成功必须**没有**归因; 其余每一个 verdict 只允许固定的几种归因。
VERDICT_FAILURES: dict[str, set[str]] = {
    "success": {""},
    "partial": {"probe_not_matched", "review_conflict", "degraded"},
    "cannot_repro": {"article_incomplete", "version_mismatch"},
    "failed": {"env_error"},
    "blocked": {"online_target"},
}

_JSON_COLUMNS = ("spec_json", "evidence_json", "recipe_json")


def now() -> str:
    """与候选表同一口径的时间戳(UTC, 秒级)。"""
    return store.now()


def _parse(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    out = dict(row)
    for key in _JSON_COLUMNS:
        try:
            out[key] = json.loads(out.get(key) or "{}")
        except (TypeError, ValueError):
            out[key] = {}
    return out


def get_task(conn: sqlite3.Connection, task_id: int) -> dict[str, Any] | None:
    conn.row_factory = conn.row_factory or sqlite3.Row
    row = conn.execute("SELECT * FROM writeup_repro_tasks WHERE id = ?", (int(task_id),)).fetchone()
    return _parse(row)


def get_task_by_material(conn: sqlite3.Connection, material_id: int) -> dict[str, Any] | None:
    """这条素材**当前这一遍**的任务(最新一遍)。历史几遍留在库里, 各带各的证据。"""
    conn.row_factory = conn.row_factory or sqlite3.Row
    row = conn.execute(
        "SELECT * FROM writeup_repro_tasks WHERE material_id = ?"
        " ORDER BY attempt DESC, id DESC LIMIT 1",
        (int(material_id),),
    ).fetchone()
    return _parse(row)


def next_attempt(conn: sqlite3.Connection, material_id: int) -> int:
    """这条素材下一遍是第几遍(空表 → 1)。"""
    value = conn.execute(
        "SELECT COALESCE(MAX(attempt), 0) FROM writeup_repro_tasks WHERE material_id = ?",
        (int(material_id),),
    ).fetchone()[0]
    return int(value or 0) + 1


def create_task(
    conn: sqlite3.Connection,
    material_id: int,
    *,
    case_id: int | None = None,
    created_by: str = "",
    trigger: str = "manual",
) -> tuple[dict[str, Any], bool]:
    """从一条**可复现**的候选建任务。返回 ``(任务行, 是否新建)``。

    幂等: 同一素材已存在任务时不再插新行, 直接返回它(``created=False``)。
    不可复现的素材会被拒 —— 让"被拒的稿子"也能建任务, 等于把两刀的结论绕过去。
    """
    candidate = store.get_candidate(conn, int(material_id))
    if candidate is None:
        raise ValueError(f"素材 {material_id} 还没有预筛结论, 先跑 capabilities.writeup_repro_prescreen")
    if not int(candidate.get("screenable") or 0):
        reason = candidate.get("reject_reason") or "unknown"
        raise ValueError(f"素材 {material_id} 不可复现({reason}), 不能建复现任务")

    existing = get_task_by_material(conn, material_id)
    if existing is not None:
        return existing, False

    stamp = now()
    attempt = next_attempt(conn, material_id)
    cur = conn.execute(
        "INSERT OR IGNORE INTO writeup_repro_tasks ("
        " material_id, attempt, case_id, subject_kind, claim, claim_quote, target_kind,"
        " target_repo, target_version, spec_json, spec_source, status,"
        " trigger, created_by, created_at, updated_at"
        ") VALUES (?, ?, ?, 'writeup_material', ?, ?, ?, ?, ?, '{}', '', 'pending', ?, ?, ?, ?)",
        (
            int(material_id),
            attempt,
            int(case_id) if case_id else None,
            str(candidate.get("claimed_effect") or ""),
            str(candidate.get("evidence_quote") or ""),
            str(candidate.get("target_kind") or "unknown"),
            str(candidate.get("target_repo") or ""),
            str(candidate.get("target_version") or ""),
            str(trigger or "manual"),
            str(created_by or ""),
            stamp,
            stamp,
        ),
    )
    if cur.rowcount == 0:
        # 并发下另一个请求刚插进去 —— 读回来那一行, 仍然是"没新建"。
        conn.commit()
        return get_task_by_material(conn, material_id), False  # type: ignore[return-value]
    conn.commit()
    return get_task(conn, int(cur.lastrowid)), True


def rerun(conn: sqlite3.Connection, task_id: int, *, created_by: str = "") -> dict[str, Any]:
    """把一条**终态**任务重跑一遍: 新开一行 ``attempt+1``, 上一行原样保留。

    为什么不是"归档证据 + 重置状态"(2026-11-12 用户拍板的 (material_id, attempt) 口径):

    - **会话跑完就 404**(opencode 不留 transcript), 重置会把唯一一次真实执行的记录冲掉;
    - "上一边判 partial、这一遍判 success"本身就是要留的事实, 覆盖掉等于把平台的判断
      变化藏起来 —— 这正是这套东西最不该做的事。

    新行带着上一遍的 spec(跑什么不改, 只是再跑一次), 所以它不是 ``pending`` 而是
    ``spec_ready``, 建完可以直接 ``POST /tasks/{id}/run``。``trigger='rerun'`` 让统计能
    把"第一次跑"和"重跑"分开看。
    """
    task = get_task(conn, task_id)
    if task is None:
        raise ValueError(f"任务 {task_id} 不存在")
    if task["status"] not in TERMINAL_STATES:
        raise ValueError(
            f"任务 {task_id} 还在 {task['status']}, 只有终态任务能重跑(在跑的请先 stop)"
        )

    spec = task.get("spec_json") or {}
    status = "spec_ready" if (spec.get("steps") or []) else "pending"
    attempt = next_attempt(conn, task["material_id"])
    stamp = now()
    cur = conn.execute(
        "INSERT INTO writeup_repro_tasks ("
        " material_id, attempt, case_id, subject_kind, claim, claim_quote, target_kind,"
        " target_repo, target_version, spec_json, spec_source, status,"
        " trigger, created_by, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'rerun', ?, ?, ?)",
        (
            int(task["material_id"]),
            attempt,
            task.get("case_id"),
            str(task.get("subject_kind") or "writeup_material"),
            str(task.get("claim") or ""),
            str(task.get("claim_quote") or ""),
            str(task.get("target_kind") or "unknown"),
            str(task.get("target_repo") or ""),
            str(task.get("target_version") or ""),
            json.dumps(spec, ensure_ascii=False),
            str(task.get("spec_source") or ""),
            status,
            str(created_by or ""),
            stamp,
            stamp,
        ),
    )
    new_id = int(cur.lastrowid)
    conn.commit()
    append_log(
        conn, new_id,
        f"↻ 重跑自任务 #{task_id}(第 {task.get('attempt') or 1} 遍, 结论 "
        f"{task.get('verdict') or task.get('status')}"
        f"{('/' + task['failure_reason']) if task.get('failure_reason') else ''})",
    )
    return get_task(conn, new_id) or {}


def set_spec(
    conn: sqlite3.Connection,
    task_id: int,
    spec: dict[str, Any],
    *,
    source: str = "llm",
    notes: list[str] | None = None,
) -> dict[str, Any]:
    """写入 ``verification_spec`` 并把状态推到 ``spec_ready``。

    spec 里的 claim / claim_quote / target 会**同步到任务行**, 页面上不必解 JSON 才能看到
    "这篇在说什么、复现谁"。``source`` 记 `llm` 还是 `human` —— 人工改过的 spec 判定时优先用
    (文档 §5.3), 所以要能区分。
    """
    task = get_task(conn, task_id)
    if task is None:
        raise ValueError(f"任务 {task_id} 不存在")
    if task["status"] in TERMINAL_STATES:
        raise ValueError(f"任务 {task_id} 已是终态 {task['status']}, 不能再改 spec")

    target = spec.get("target") or {}
    payload = dict(spec)
    if notes:
        payload["verification_notes"] = list(notes)
    stamp = now()
    conn.execute(
        "UPDATE writeup_repro_tasks SET spec_json = ?, spec_source = ?, claim = ?, claim_quote = ?,"
        " target_kind = ?, target_repo = ?, target_version = ?, status = ?, updated_at = ?"
        " WHERE id = ?",
        (
            json.dumps(payload, ensure_ascii=False),
            str(source or "llm"),
            str(spec.get("claim") or task["claim"]),
            str(spec.get("claim_quote") or task["claim_quote"]),
            str(target.get("kind") or task["target_kind"]),
            str(target.get("repo") or task["target_repo"]),
            str(target.get("ref") or task["target_version"]),
            "spec_ready",
            stamp,
            int(task_id),
        ),
    )
    conn.commit()
    return get_task(conn, task_id)  # type: ignore[return-value]


def bump_spec_attempt(conn: sqlite3.Connection, task_id: int) -> int:
    """记一次"模型说文章够了、但 spec 没通过校验"。返回累计次数。

    计数只增不清: 它的用途是"同一个任务反复建不出合格 spec"时收口成 ``spec_failed``。
    网关报错**不计** —— 那是环境抖动, 记进来会让一次故障把所有任务烧成终态。
    """
    conn.execute(
        "UPDATE writeup_repro_tasks SET spec_attempts = spec_attempts + 1, updated_at = ? WHERE id = ?",
        (now(), int(task_id)),
    )
    conn.commit()
    row = conn.execute("SELECT spec_attempts FROM writeup_repro_tasks WHERE id = ?", (int(task_id),)).fetchone()
    return int(row[0]) if row else 0


def transition(
    conn: sqlite3.Connection,
    task_id: int,
    to_state: str,
    *,
    verdict: str = "",
    failure_reason: str = "",
    **fields: Any,
) -> dict[str, Any]:
    """迁移状态。非法迁移 / 配对错误一律抛 ``ValueError``, 不静默写。

    可顺带更新的字段: `container_name` / `session_id` / `evidence_json` / `recipe_json` /
    `log` / `duration_seconds` / `tool_calls` / `review_verdict` / `review_reason` / `recipe_id`。
    """
    to_state = str(to_state or "").strip()
    if to_state not in STATES:
        raise ValueError(f"未知状态 {to_state!r}; 可选: {', '.join(STATES)}")
    task = get_task(conn, task_id)
    if task is None:
        raise ValueError(f"任务 {task_id} 不存在")
    current = str(task["status"])
    if current in TERMINAL_STATES:
        raise ValueError(f"任务 {task_id} 已是终态 {current}, 状态机不再迁移")
    if to_state not in _TRANSITIONS.get(current, set()):
        raise ValueError(f"任务 {task_id}: {current} → {to_state} 不是允许的迁移")

    final_verdict = str(verdict or "").strip()
    final_reason = str(failure_reason or "").strip()
    if to_state in VERDICT_STATES:
        final_verdict = final_verdict or to_state
        if final_verdict != to_state:
            raise ValueError(f"状态 {to_state} 与 verdict {final_verdict} 不一致")
        allowed = VERDICT_FAILURES.get(to_state, set())
        if final_reason not in allowed:
            raise ValueError(
                f"verdict={to_state} 只允许 failure_reason ∈ {sorted(allowed) or '(无)'}, "
                f"收到 {final_reason!r}"
            )
    else:
        # 非结论状态不允许带 verdict/归因 —— 那等于把结论提前写了一半。
        if final_verdict or final_reason:
            raise ValueError(f"状态 {to_state} 不是结论状态, 不能带 verdict/failure_reason")

    sets = ["status = ?", "updated_at = ?"]
    values: list[Any] = [to_state, now()]
    if to_state in VERDICT_STATES:
        sets += ["verdict = ?", "failure_reason = ?"]
        values += [final_verdict, final_reason]
    if to_state in TERMINAL_STATES:
        sets.append("finished_at = ?")
        values.append(now())
    # 调用方按语义传 evidence / recipe; 落库名带 _json 是存储细节, 不该外泄到 API 与测试里。
    evidence = fields.pop("evidence", None)
    recipe = fields.pop("recipe", None)
    if evidence is not None:
        fields["evidence_json"] = evidence
    if recipe is not None:
        fields["recipe_json"] = recipe
    allowed_fields = {
        "container_name", "session_id", "log", "duration_seconds", "tool_calls",
        "review_verdict", "review_reason", "recipe_id",
    }
    json_fields = {"evidence_json", "recipe_json"}
    for key, value in fields.items():
        if key in json_fields:
            sets.append(f"{key} = ?")
            values.append(json.dumps(value, ensure_ascii=False))
            continue
        if key not in allowed_fields:
            raise ValueError(f"transition 不支持更新字段 {key!r}")
        sets.append(f"{key} = ?")
        values.append(value)
    values.append(int(task_id))
    conn.execute(f"UPDATE writeup_repro_tasks SET {', '.join(sets)} WHERE id = ?", values)
    conn.commit()
    return get_task(conn, task_id)  # type: ignore[return-value]


def cancel(conn: sqlite3.Connection, task_id: int) -> dict[str, Any]:
    """人取消。终态任务再取消会抛错(而不是"看起来取消了")。"""
    return transition(conn, task_id, "cancelled")


#: 任务日志的保留上限(字符)。一次执行会落几千行(含提示词与命令输出), 不封顶的话
#: 单行能长到几十 MB, 详情接口跟着变慢 —— 只留尾部, 开头是早就没用的提示词。
LOG_LIMIT = 400_000


def append_log(conn: sqlite3.Connection, task_id: int, line: str) -> None:
    """追加一行日志。执行线程每 15 秒就会调一次, 所以必须轻。

    超过 ``LOG_LIMIT`` 时保留尾部: 出问题时要看的是**最后**发生了什么, 而不是开头的提示词。
    """
    text = f"{now()} {line}" if line else ""
    if not text:
        return
    conn.execute(
        "UPDATE writeup_repro_tasks SET log = substr(log || ? || char(10), -?) WHERE id = ?",
        (text, LOG_LIMIT, int(task_id)),
    )
    conn.commit()


_RUNTIME_FIELDS = frozenset({"session_id", "container_name", "duration_seconds", "tool_calls"})


def set_runtime(conn: sqlite3.Connection, task_id: int, **fields: Any) -> None:
    """执行途中更新运行时字段(会话 id / 耗时 / 工具调用数)。**不改状态**。

    与 ``transition`` 分开: 那些字段在任务还是 ``running`` 时就一直在变, 走状态机既啰嗦
    又容易写出非法迁移。
    """
    updates = {key: value for key, value in fields.items() if key in _RUNTIME_FIELDS}
    if not updates:
        return
    sets = ", ".join(f"{key} = ?" for key in updates)
    conn.execute(
        f"UPDATE writeup_repro_tasks SET {sets}, updated_at = ? WHERE id = ?",
        [*updates.values(), now(), int(task_id)],
    )
    conn.commit()


def link_recipe(conn: sqlite3.Connection, task_id: int, recipe_id: int | None) -> None:
    """把任务指向它固化出来的 recipe 行。``None`` = 摘掉指针。

    **只写指针, 不写 ``recipe_json``**: recipe 的内容归 ``recipes.py`` 那张表所有, 任务行只是
    从"这一遍跑的是什么"回指到"这一类怎么跑"。两处各存一份迟早会不一致。
    """
    conn.execute(
        "UPDATE writeup_repro_tasks SET recipe_id = ? WHERE id = ?",
        (int(recipe_id) if recipe_id else None, int(task_id)),
    )
    conn.commit()


def list_tasks(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    verdict: str | None = None,
    material_id: int | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """列表 + 总数。总数用与 WHERE 相同的条件单独 COUNT —— 不要拿 len(items) 当总数
    (2026-09-11 与 2026-10-23 各踩过一次: 卡片写着"共 20 条", 实际是当前页 3 条)。"""
    conn.row_factory = conn.row_factory or sqlite3.Row
    where: list[str] = []
    params: list[Any] = []
    if status:
        where.append("status = ?")
        params.append(str(status))
    if verdict:
        where.append("verdict = ?")
        params.append(str(verdict))
    if material_id:
        where.append("material_id = ?")
        params.append(int(material_id))
    clause = f" WHERE {' AND '.join(where)}" if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM writeup_repro_tasks{clause}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM writeup_repro_tasks{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [max(1, int(limit)), max(0, int(offset))],
    ).fetchall()
    return [_parse(r) for r in rows], int(total)  # type: ignore[misc]


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """任务漏斗: 各状态条数 + 终态按 verdict/归因拆开。

    ``cannot_repro`` 与 ``failed`` **必须分列** —— 一个是原文的锅, 一个是我们的锅。
    """
    by_status = {
        status or "unknown": count
        for status, count in conn.execute(
            "SELECT status, COUNT(*) FROM writeup_repro_tasks GROUP BY status"
        )
    }
    by_verdict = {
        verdict or "unknown": count
        for verdict, count in conn.execute(
            "SELECT verdict, COUNT(*) FROM writeup_repro_tasks WHERE verdict != '' GROUP BY verdict"
        )
    }
    by_failure = {
        reason or "(空)": count
        for reason, count in conn.execute(
            "SELECT failure_reason, COUNT(*) FROM writeup_repro_tasks "
            "WHERE verdict != '' AND verdict != 'success' GROUP BY failure_reason"
        )
    }
    total = sum(by_status.values())
    return {
        "total": total,
        "by_status": by_status,
        "by_verdict": by_verdict,
        "by_failure_reason": by_failure,
        "active": sum(by_status.get(s, 0) for s in ACTIVE_STATES),
        "spec_source": {
            source or "(无 spec)": count
            for source, count in conn.execute(
                "SELECT spec_source, COUNT(*) FROM writeup_repro_tasks GROUP BY spec_source"
            )
        },
    }
