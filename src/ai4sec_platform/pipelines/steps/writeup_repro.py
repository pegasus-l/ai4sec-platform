"""T1.3:把预筛接进流水线 —— 每晚增量、可重跑、按批落地。

为什么不能只留一个一次性脚本
============================

T1.2 的批量跑证实了"1218 条里 100 条能复现",但那次是脚本:结论在跑完时一次性 commit,
中途 kill 就全丢(实测为把并发从 4 提到 8 重启跑批,丢了前 16 条)。要变成每晚都跑的作业,
三条纪律必须落在代码里:

1. **规则层先行。** 规则层拒掉的(实测 75.7%)连模型都不调,这是省 token 的全部来源;
   顺序不能反 —— 先送模型再筛等于白花钱。
2. **模型报错不落库。** ``screen_material`` 返回 error / no_model 时什么都不写,这一条
   下一轮会被重新挑出来。把它记成"没有 PoC"是最难发现的一类谎(2026-10-29 降级评审
   灌 1941 条空壳的同型事故)。
3. **按批 flush。** 每 ``writeup_screen_flush`` 条 commit 一次,被杀只丢当前这一批。

增量与幂等靠 ``store.pending_materials`` 的 ``rule_version`` 过滤:同一条素材 + 同一个
规则版本只筛一次;规则层升级后旧结论自动失效、整批重筛,不会让两套口径混在一张表里。

为什么单独一条 pipeline
=======================

预筛只读素材、不产生能力条目。挂进 ``from_news_pipeline`` 的话,一次模型网关故障会连带
影响能力库当晚的产出,而它俩失败时的补救方式完全不同(预筛下一轮自动重挑,能力库要人工看)。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.writeup_repro import screener_rules, store
from ai4sec_platform.domains.capabilities.writeup_repro.cve_targets import (
    DEFAULT_MAX_LOOKUPS,
    CaseTargetResolver,
    LookupDeferred,
    TargetLookupUnavailable,
)
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult

#: 与 ``screener.MODEL_PROFILE`` 必须相同(单测锁死)。这里写字面量而不是导入,是为了让
#: 纯规则的使用方不必为此拉起模型路由 —— 只有真要调模型时才在 ``run()`` 里导入 ``screener``。
MODEL_PROFILE = "capability_writeup_screener"


def _empty_metrics(pending: int) -> dict[str, Any]:
    return {
        "pending": int(pending),
        "processed": 0,
        "written": 0,
        "rule_rejected": 0,
        "model_called": 0,
        "screenable": 0,
        "rejected": 0,
        "errors": 0,
        "skipped_no_model": 0,
        "provider_down": 0,
        "budget_exhausted": 0,
        "cve_resolved": 0,
        "cve_unresolved": 0,
        "lookup_deferred": 0,
        "lookup_unavailable": 0,
        "remaining": int(pending),
    }


def _bump(counter: dict[str, int], key: str) -> None:
    key = str(key or "unknown")
    counter[key] = counter.get(key, 0) + 1


def _screen_one(material: dict[str, Any], screener: Any) -> dict[str, Any]:
    """规则层 → (通过才)模型层。返回 ``kind`` ∈ rule_rejected / model。"""
    try:
        rule = screener_rules.screen_rules(
            str(material.get("cleaned_text") or ""),
            title=str(material.get("title") or ""),
            url=str(material.get("url") or ""),
        )
        if not rule.screenable:
            return {"kind": "rule_rejected", "rule": rule}
        started = time.perf_counter()
        # ``screen_material`` 内部会再算一遍规则(它要拿规则结论拼 payload)。这里先算一遍
        # 是为了"规则层拒掉的连模型都不调"——重复的那点正则在一次模型调用面前可以忽略。
        outcome = screener.screen_material(material)
        return {
            "kind": "model",
            "rule": rule,
            "outcome": outcome,
            "latency_ms": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:  # noqa: BLE001 - 单条异常只算这一条失败, 不拖垮整批
        return {
            "kind": "model",
            "rule": None,
            "outcome": {"status": "error", "reason": f"{type(exc).__name__}: {exc}"[:300], "result": {}},
            "latency_ms": 0,
        }


def _run_chunk(chunk: list[dict[str, Any]], concurrency: int, screener: Any) -> list[dict[str, Any]]:
    """一波并发。结果**按提交顺序**返回 —— 指标要能复算,不能用完成顺序。"""
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=min(concurrency, len(chunk))) as pool:
        futures = [pool.submit(_screen_one, m, screener) for m in chunk]
        return [f.result() for f in futures]


@dataclass
class ScreenWriteupMaterialsStep:
    """把还没按当前规则版本预筛过的素材筛一遍,结论写 ``writeup_repro_candidates``。

    可调参数(全部走 run params,改口径不用重建镜像):

    - ``writeup_screen_limit``:本轮最多挑多少条(默认 200,按 id 倒序 = 新素材优先)
    - ``writeup_screen_concurrency``:并发模型调用数(默认 4;实测网关 8 也稳)
    - ``writeup_screen_flush``:每多少条 commit 一次(默认 25)
    - ``writeup_screen_budget_seconds``:本轮时间预算(默认 900);到点收工,已筛的照常落库
    - ``writeup_screen_ids``:只筛指定素材(配合 ``writeup_screen_force`` 用来重筛)
    - ``writeup_screen_force``:忽略 ``rule_version`` 过滤,指定 id 一律重筛
    - ``writeup_screen_resolve_cve``:模型没给出仓库/版本时,拿它指认的 CVE 去案例库/OSV/NVD
      反查目标(默认开)。关掉 = 回到"无目标一律拒"的一刀切口径
    - ``writeup_screen_cve_lookups``:本轮最多查几条 CVE(默认 25);用完的素材**不落库**,
      下一轮重挑 —— 预算不够时宁可晚一轮,也不能用"没查"冒充"查不到"
    """

    name: str = "screen_writeup_materials"
    step_type: str = "llm_review"
    model_profile: str = MODEL_PROFILE

    def run(self, context: PipelineContext) -> StepResult:
        params = context.params
        limit = max(1, int(params.get("writeup_screen_limit", 200)))
        concurrency = max(1, int(params.get("writeup_screen_concurrency", 4)))
        flush_every = max(1, int(params.get("writeup_screen_flush", 25)))
        budget = float(params.get("writeup_screen_budget_seconds", 900))
        force = bool(params.get("writeup_screen_force", False))
        ids = [int(i) for i in (params.get("writeup_screen_ids") or [])]

        rule_version = screener_rules.SCREENER_VERSION
        rows = store.pending_materials(
            context.conn,
            limit=limit,
            rule_version=rule_version,
            material_ids=ids or None,
            force=force,
        )
        metrics = _empty_metrics(len(rows))
        if not rows:
            return StepResult(metrics=metrics)

        from ai4sec_platform.domains.capabilities.writeup_repro import screener

        resolver = None
        if bool(params.get("writeup_screen_resolve_cve", True)):
            resolver = CaseTargetResolver(
                context.conn,
                max_lookups=int(params.get("writeup_screen_cve_lookups", DEFAULT_MAX_LOOKUPS)),
            )

        reasons: dict[str, int] = {}
        error_kinds: dict[str, int] = {}
        screened_at = store.now()
        started = time.monotonic()
        since_commit = 0

        for start in range(0, len(rows), concurrency):
            # 预算只在**整波之间**检查: 每次调用自己有超时, 半波不会被无限拖住。
            if start and time.monotonic() - started >= budget:
                metrics["budget_exhausted"] = 1
                break
            chunk = rows[start:start + concurrency]
            outcomes = _run_chunk(chunk, concurrency, screener)

            attempted = sum(1 for o in outcomes if o["kind"] == "model")
            failed = sum(
                1 for o in outcomes
                if o["kind"] == "model" and (o["outcome"] or {}).get("status") == "error"
            )

            for material, outcome in zip(chunk, outcomes):
                metrics["processed"] += 1
                if outcome["kind"] == "rule_rejected":
                    rule = outcome["rule"]
                    store.upsert_candidate(
                        context.conn,
                        screener.build_rule_only_candidate(material["id"], screened_at, rule),
                    )
                    metrics["rule_rejected"] += 1
                    metrics["written"] += 1
                    _bump(reasons, rule.reject_reason)
                    continue

                result = outcome["outcome"] or {}
                status = str(result.get("status") or "")
                if status == "no_model":
                    # 没配模型(local_rules 兜底): 不是这篇的问题, 也不是结论 —— 不写。
                    metrics["skipped_no_model"] += 1
                    _bump(error_kinds, "no_model")
                    continue
                if status != "success":
                    # 模型报错 / 返回不是 JSON 对象 / 缺字段: **什么都不写**, 下一轮重挑。
                    metrics["errors"] += 1
                    _bump(error_kinds, "model_error")
                    repo.create_model_call(
                        context.conn,
                        run_id=context.run_id,
                        agent_name="writeup_prescreen",
                        model_profile=self.model_profile,
                        provider=str(result.get("provider") or ""),
                        status="failed",
                        input_payload={"material_id": material["id"], "title": material.get("title", "")},
                        output_payload={},
                        latency_ms=int(outcome.get("latency_ms") or 0),
                        error_message=str(result.get("reason") or "model failed")[:500],
                    )
                    continue

                metrics["model_called"] += 1
                try:
                    row = screener.build_candidate(
                        material["id"], screened_at, result, resolver=resolver,
                    )
                except LookupDeferred:
                    # 预算用完 = 这一条**没查**,不是查不到。一个字都不写,下一轮重挑;
                    # 写成 target_unknown 等于用"没查"冒充"没有"(最难发现的一类谎)。
                    metrics["lookup_deferred"] += 1
                    _bump(error_kinds, "cve_lookup_deferred")
                    continue
                except TargetLookupUnavailable:
                    # 外部源(OSV/NVD)挂了 —— 同上,不落库。
                    metrics["lookup_unavailable"] += 1
                    _bump(error_kinds, "cve_lookup_unavailable")
                    continue
                store.upsert_candidate(context.conn, row)
                metrics["written"] += 1
                if row["screenable"]:
                    metrics["screenable"] += 1
                    if row["target_source"] in ("db", "osv", "nvd"):
                        metrics["cve_resolved"] += 1
                else:
                    metrics["rejected"] += 1
                    _bump(reasons, row["reject_reason"])
                    if row["reject_reason"] == "target_unknown" and row.get("target_cve"):
                        metrics["cve_unresolved"] += 1
                repo.create_model_call(
                    context.conn,
                    run_id=context.run_id,
                    agent_name="writeup_prescreen",
                    model_profile=self.model_profile,
                    provider=str(result.get("provider") or ""),
                    status="success",
                    input_payload={"material_id": material["id"], "title": material.get("title", "")},
                    output_payload={"screenable": row["screenable"], "reject_reason": row["reject_reason"]},
                    latency_ms=int(outcome.get("latency_ms") or 0),
                )

            since_commit += len(chunk)
            if since_commit >= flush_every:
                context.conn.commit()
                since_commit = 0

            # 首波就全灭 = 网关不可用。此时后面的行大概率也一样,继续跑只会把整轮耗时
            # 拖成"每条一次重试退避";没轮到的行本来就还没写,原样留给下一轮。
            if start == 0 and attempted and failed == attempted:
                metrics["provider_down"] = 1
                break

        context.conn.commit()
        metrics["remaining"] = max(int(metrics["pending"]) - int(metrics["processed"]), 0)
        metrics["reject_reason"] = reasons
        if error_kinds:
            metrics["error_kinds"] = error_kinds
        context.outputs["writeup_repro_screened"] = metrics["written"]
        return StepResult(metrics=metrics)
