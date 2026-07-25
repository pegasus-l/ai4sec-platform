from __future__ import annotations

import hashlib
import json
import random
import re
import sqlite3
import time
import urllib.error
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.news import repository as news_repo
from ai4sec_platform.domains.news.tech_map import AgentTechMap
from ai4sec_platform.models.router import LLMRouter

GATE_PROMPT_VERSION = "news-tech-map-gate-v1"
REVIEW_PROMPT_VERSION = "news-deep-review-v3"
MODEL_MAX_ATTEMPTS = 3
MODEL_RETRY_BASE_SECONDS = 1.0
MODEL_RETRY_JITTER_SECONDS = 0.5
PROGRESS_LOG_INTERVAL = 5
CONCURRENCY = 10


def gate_candidates(
    conn: sqlite3.Connection,
    items: list[dict[str, Any]],
    *,
    run_id: str,
    project_root: Path,
    model_profile: str = "configured_model",
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    tech_map = AgentTechMap.load(project_root)
    router = LLMRouter()
    model_identity = router.active_config(model_profile)
    gate_prompt = _gate_prompt()
    resolved: dict[int, tuple[dict[str, Any], str]] = {}
    metrics = {"candidates": len(items), "model_calls": 0, "cache_hits": 0, "passed": 0, "needs_review": 0, "rejected": 0, "failed": 0}

    def _process_gate(index: int, item: dict[str, Any], input_payload: dict[str, Any], input_hash: str) -> dict[str, Any]:
        result, output_full, failed, provider, latency_ms, attempts = _call_model_api(router, model_profile=model_profile, prompt=gate_prompt, input_payload=input_payload)
        gate = _normalize_gate(result, item, tech_map) if not failed else _fallback_gate(item, tech_map, result.get("error", "model call failed"))
        return {"index": index, "item": item, "gate": gate, "input_hash": input_hash, "input_payload": input_payload, "output": output_full, "failed": failed, "provider": provider, "latency_ms": latency_ms, "attempts": attempts}

    if not items:
        return [], metrics
    pending = []
    for index, item in enumerate(items):
        input_payload = {**_gate_payload(item, tech_map), "model_identity": model_identity}
        input_hash = _input_hash(input_payload)
        gate = _cached_stage(conn, str(item.get("item_key") or ""), "gate_review", input_hash, GATE_PROMPT_VERSION)
        if not gate:
            cached_result = _cached_model_result(conn, "news_tech_map_gate", model_profile, input_payload)
            gate = _normalize_gate(cached_result, item, tech_map) if cached_result is not None else None
        if gate:
            metrics["cache_hits"] += 1
            resolved[index] = ({**item, "gate_review": {**gate, "input_hash": input_hash, "prompt_version": GATE_PROMPT_VERSION, "tech_map_version": tech_map.version, "model_identity": model_identity}}, "")
        else:
            pending.append((index, item, input_payload, input_hash))
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(_process_gate, *entry) for entry in pending]
        for idx, future in enumerate(as_completed(futures), 1):
            r = future.result()
            _record_attempts(conn, run_id=run_id, agent_name="news_tech_map_gate", model_profile=model_profile, provider=r["provider"], input_payload=r["input_payload"], attempts=r["attempts"])
            conn.commit()
            metrics["model_calls"] += 1
            metrics["failed"] += int(r["failed"])
            gate = {**r["gate"], "input_hash": r["input_hash"], "prompt_version": GATE_PROMPT_VERSION, "tech_map_version": tech_map.version, "model_identity": model_identity}
            resolved[r["index"]] = ({**r["item"], "gate_review": gate}, "")
            if idx % PROGRESS_LOG_INTERVAL == 0 or idx == len(pending):
                print(f"[gate] {idx}/{len(items)} calls={metrics['model_calls']} pass={metrics['passed']} review={metrics['needs_review']} reject={metrics['rejected']} failed={metrics['failed']}", flush=True)
    passed: list[dict[str, Any]] = []
    for index in range(len(items)):
        enriched, _ = resolved[index]
        decision = enriched["gate_review"]["decision"]
        if decision in {"pass", "needs_review"}:
            passed.append(enriched)
            metrics["passed" if decision == "pass" else "needs_review"] += 1
        else:
            metrics["rejected"] += 1
    conn.commit()
    return passed, metrics


def enrich_candidates(
    conn: sqlite3.Connection,
    items: list[dict[str, Any]],
    *,
    run_id: str,
    project_root: Path,
    model_profile: str = "configured_model",
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    tech_map = AgentTechMap.load(project_root)
    router = LLMRouter()
    model_identity = router.active_config(model_profile)
    review_prompt = _review_prompt()
    resolved: dict[int, dict[str, Any] | None] = {}
    metrics = {"candidates": len(items), "model_calls": 0, "cache_hits": 0, "selected": 0, "watch": 0, "rejected": 0, "failed": 0}

    def _process_enrich(index: int, item: dict[str, Any], input_payload: dict[str, Any], input_hash: str) -> dict[str, Any]:
        result, output_full, failed, provider, latency_ms, attempts = _call_model_api(router, model_profile=model_profile, prompt=review_prompt, input_payload=input_payload)
        if failed:
            return {"index": index, "item": item, "review": None, "input_hash": input_hash, "input_payload": input_payload, "output": output_full, "failed": True, "provider": provider, "latency_ms": latency_ms, "attempts": attempts}
        review = _normalize_deep_review(result, item, tech_map)
        return {"index": index, "item": item, "review": review, "input_hash": input_hash, "input_payload": input_payload, "output": output_full, "failed": False, "provider": provider, "latency_ms": latency_ms, "attempts": attempts}

    if not items:
        return [], metrics
    pending = []
    for index, item in enumerate(items):
        input_payload = {**_review_payload(item, tech_map), "model_identity": model_identity}
        input_hash = _input_hash(input_payload)
        review = _cached_stage(conn, str(item.get("item_key") or ""), "review", input_hash, REVIEW_PROMPT_VERSION)
        if not review:
            cached_result = _cached_model_result(conn, "news_deep_review", model_profile, input_payload)
            review = _normalize_deep_review(cached_result, item, tech_map) if cached_result is not None else None
        if review:
            metrics["cache_hits"] += 1
            resolved[index] = {**item, "review": {**review, "input_hash": input_hash, "prompt_version": REVIEW_PROMPT_VERSION, "tech_map_version": tech_map.version, "model_identity": model_identity}}
        else:
            pending.append((index, item, input_payload, input_hash))
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(_process_enrich, *entry) for entry in pending]
        for idx, future in enumerate(as_completed(futures), 1):
            r = future.result()
            _record_attempts(conn, run_id=run_id, agent_name="news_deep_review", model_profile=model_profile, provider=r["provider"], input_payload=r["input_payload"], attempts=r["attempts"])
            conn.commit()
            metrics["model_calls"] += 1
            if r["failed"]:
                metrics["failed"] += 1
                resolved[r["index"]] = None
                if idx % PROGRESS_LOG_INTERVAL == 0 or idx == len(pending):
                    print(f"[enrich] {idx}/{len(items)} calls={metrics['model_calls']} selected={metrics['selected']} watch={metrics['watch']} reject={metrics['rejected']} failed={metrics['failed']}", flush=True)
                continue
            review = {**r["review"], "input_hash": r["input_hash"], "prompt_version": REVIEW_PROMPT_VERSION, "tech_map_version": tech_map.version, "model_identity": model_identity}
            resolved[r["index"]] = {**r["item"], "review": review}
            if idx % PROGRESS_LOG_INTERVAL == 0 or idx == len(pending):
                print(f"[enrich] {idx}/{len(items)} calls={metrics['model_calls']} selected={metrics['selected']} watch={metrics['watch']} reject={metrics['rejected']} failed={metrics['failed']}", flush=True)
    selected: list[dict[str, Any]] = []
    for index in range(len(items)):
        enriched = resolved[index]
        if enriched is None:
            metrics["rejected"] += 1
            continue
        decision = enriched["review"]["decision"]
        metrics[decision] += 1
        if decision == "selected":
            selected.append(enriched)
    conn.commit()
    return selected, metrics


def _gate_prompt() -> str:
    return """
你是 AI Agent 技术情报门控审阅员。任务是高召回地判断候选是否值得进入深度评审，只输出 JSON，不生成摘要或宣传文案。

要求：
1. 候选必须与输入技术地图至少一个叶子技术点存在实质关联；仅泛泛提到 AI、Agent、Security 不算相关。
2. provisional_tech_paths 必须逐字选自技术地图，不得创造标签，并列出当前证据支持的所有路径。
3. map_relevance_score 和 potential_value_score 必须使用 0–100 的整数百分制，禁止 0–1 或 0–10 分制。
4. potential_value_score 评估是否值得继续投入，不能仅按 stars；新项目、稀缺技术点和显式论文—项目关联可以有高潜力。
5. decision 规则：相关性>=70且潜力>=55为 pass；相关性55–69或信息不足但潜力>=70为 needs_review；其余 reject。
6. match_evidence 必须引用输入事实，不能编造。

输出：
{
  "decision": "pass|reject|needs_review",
  "map_relevance_score": 0,
  "potential_value_score": 0,
  "information_sufficiency": 0.0,
  "provisional_tech_paths": [{"dimension": "", "category": "", "point": ""}],
  "match_evidence": ["输入中的匹配证据"],
  "reason": "门控理由",
  "confidence": 0.0
}
""".strip()


def _review_prompt() -> str:
    return """
你是 AI Agent 技术情报深度评审专家。候选已通过技术地图门控，请基于完整信息完成最终价值评估与中文内容生成，只输出 JSON。

要求：
1. tech_paths 必须逐字选自技术地图，重新核验并列出所有实际涉及的技术路径，不要只返回一个。
2. score_breakdown 必须完整保留示例中的七个英文字段名，不得改名、翻译、遗漏或增加字段；所有维度必须使用 0–100 的整数百分制，禁止 0–1 或 0–10 分制。
3. 项目综合真实代码、README、活跃度、关联论文、工程价值和可复现性，stars 只影响少量影响力分。
4. 论文综合地图相关性、新颖性、技术深度、实验可信度、工程价值和对技术地图的推进作用。
5. 中文摘要说明问题、方法、结果和价值，不得编造输入中没有的事实。
6. 必须生成工作名与技术定位：work_name 是条目的工作名、系统名、框架名、论文简称或项目名；优先从标题、摘要、仓库名中提取已有名称并保留原始大小写，例如 ScopeJudge、agentUniverse、GhidrAssistMCP。只有原始资料没有可用名称时，才生成不超过 4 个英文单词或 12 个汉字的可检索工作名，不能编造看似正式的论文缩写。
7. theme_descriptor 是不含 work_name 的中文技术定位，需说明核心对象、方法和技术价值；不得以 work_name 或冒号开头。平台会固定拼成“work_name：theme_descriptor”。例如 work_name=AHE，theme_descriptor=可观测性驱动的编码Agent编排层自动进化框架。
8. promo_line 说明“它是什么”；highlight_line 说明“为什么值得看”。中文摘要说明问题、方法、结果和价值，不得编造输入中没有的事实。
9. 不需要计算 final_score，平台会按各维度百分制分数和论文/项目权重确定最终分。

输出：
{
  "score_breakdown": {
    "map_relevance": 0,
    "novelty": 0,
    "technical_depth": 0,
    "engineering_value": 0,
    "reproducibility": 0,
    "influence": 0,
    "freshness": 0
  },
  "tech_paths": [{"dimension": "", "category": "", "point": ""}],
  "topic": "技术地图二级分类",
  "work_name": "工作名或项目名",
  "theme_descriptor": "不含工作名的中文技术定位",
  "summary_zh": "100到250字中文摘要",
  "promo_line": "宣传一句话",
  "highlight_line": "亮点一句话",
  "review_reason": "最终评审意见",
  "confidence": 0.0
}
""".strip()


def _gate_payload(item: dict[str, Any], tech_map: AgentTechMap) -> dict[str, Any]:
    return {
        "prompt_version": GATE_PROMPT_VERSION,
        "tech_map_version": tech_map.version,
        "tech_map": tech_map.catalog(),
        "candidate": _candidate_payload(item, include_readme=False),
    }


def _review_payload(item: dict[str, Any], tech_map: AgentTechMap) -> dict[str, Any]:
    return {
        "prompt_version": REVIEW_PROMPT_VERSION,
        "tech_map_version": tech_map.version,
        "tech_map": tech_map.catalog(),
        "gate_review": item.get("gate_review") or {},
        "candidate": _candidate_payload(item, include_readme=True),
    }


def _candidate_payload(item: dict[str, Any], *, include_readme: bool) -> dict[str, Any]:
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    payload = {
        "item_key": item.get("item_key"),
        "type": item.get("source_type"),
        "title": item.get("title"),
        "summary": item.get("summary"),
        "authors": item.get("authors"),
        "topics": item.get("topics"),
        "url": item.get("url"),
        "code_url": item.get("code_url"),
        "stars": item.get("stars"),
        "forks": item.get("forks"),
        "language": item.get("language"),
        "published_at": item.get("primary_date"),
        "updated_at": item.get("updated_at"),
        "description": raw.get("description"),
        "discovered_from": item.get("discovered_from"),
        "linked_item_keys": item.get("linked_item_keys"),
    }
    if include_readme:
        payload["readme"] = str(raw.get("readme") or raw.get("readme_text") or "")[:12000]
    return payload


def _normalize_gate(value: Any, item: dict[str, Any], tech_map: AgentTechMap) -> dict[str, Any]:
    result = _unwrap(value)
    if not isinstance(result, dict) or not any(key in result for key in {"decision", "map_relevance_score", "provisional_tech_paths"}):
        return _fallback_gate(item, tech_map, "model response did not contain gate schema")
    paths = tech_map.validate_paths(result.get("provisional_tech_paths"))
    relevance = _percentage(result.get("map_relevance_score"))
    potential = _percentage(result.get("potential_value_score"))
    decision = str(result.get("decision") or "reject")
    if decision not in {"pass", "reject", "needs_review"}:
        decision = "reject"
    if not paths:
        decision = "reject"
    elif relevance >= 70 and potential >= 55:
        decision = "pass"
    elif relevance >= 55 or potential >= 70:
        decision = "needs_review"
    else:
        decision = "reject"
    return {
        "decision": decision,
        "map_relevance_score": relevance,
        "potential_value_score": potential,
        "information_sufficiency": _fraction(result.get("information_sufficiency")),
        "provisional_tech_paths": paths,
        "match_evidence": _string_list(result.get("match_evidence")),
        "reason": str(result.get("reason") or "").strip(),
        "confidence": _fraction(result.get("confidence")),
    }


def _normalize_deep_review(value: Any, item: dict[str, Any], tech_map: AgentTechMap) -> dict[str, Any]:
    result = _unwrap(value)
    if not isinstance(result, dict) or not any(key in result for key in {"score_breakdown", "tech_paths", "summary_zh"}):
        return _fallback_review(item, tech_map, "model response did not contain deep review schema")
    paths = tech_map.validate_paths(result.get("tech_paths"))
    if not paths:
        paths = tech_map.validate_paths((item.get("gate_review") or {}).get("provisional_tech_paths"))
    breakdown = _normalize_breakdown(result.get("score_breakdown"))
    score = _weighted_score(str(item.get("source_type") or ""), breakdown)
    decision = "selected" if paths and score >= 70 else "watch" if paths and score >= 55 else "rejected"
    work_name = _work_name(result.get("work_name"), item)
    theme_descriptor = _theme_descriptor(result.get("theme_descriptor") or result.get("theme"), work_name, item)
    return {
        "decision": decision,
        "relevance_score": breakdown.get("map_relevance", 0),
        "score": score,
        "score_breakdown": breakdown,
        "tech_paths": paths,
        "topic": str(result.get("topic") or (paths[0]["category"] if paths else "")),
        "work_name": work_name,
        "theme_descriptor": theme_descriptor,
        "theme": _compose_theme(work_name, theme_descriptor),
        "summary_zh": str(result.get("summary_zh") or "").strip(),
        "promo_line": str(result.get("promo_line") or "").strip(),
        "highlight_line": str(result.get("highlight_line") or "").strip(),
        "review_reason": str(result.get("review_reason") or "").strip(),
        "technical_points": [path["point"] for path in paths],
        "confidence": _fraction(result.get("confidence")),
    }


def _fallback_gate(item: dict[str, Any], tech_map: AgentTechMap, reason: str) -> dict[str, Any]:
    paths = tech_map.fallback_paths(item)
    return {
        "decision": "needs_review" if paths else "reject",
        "map_relevance_score": 60 if paths else 0,
        "potential_value_score": 60 if paths else 0,
        "information_sufficiency": 0.3,
        "provisional_tech_paths": paths,
        "match_evidence": [],
        "reason": f"模型调用降级：{reason}",
        "confidence": 0.25 if paths else 0.0,
    }


def _fallback_review(item: dict[str, Any], tech_map: AgentTechMap, reason: str) -> dict[str, Any]:
    paths = tech_map.validate_paths((item.get("gate_review") or {}).get("provisional_tech_paths")) or tech_map.fallback_paths(item)
    title = " ".join(str(item.get("title") or "").split())
    topic = paths[0]["category"] if paths else ""
    breakdown = {"map_relevance": 70, "novelty": 65, "technical_depth": 65, "engineering_value": 70, "reproducibility": 70, "influence": 50, "freshness": 70} if paths else {}
    score = _weighted_score(str(item.get("source_type") or ""), breakdown) if paths else 0
    work_name = _work_name("", item)
    theme_descriptor = _theme_descriptor(title, work_name, item)
    return {
        "decision": "selected" if paths else "rejected",
        "relevance_score": breakdown.get("map_relevance", 0),
        "score": score,
        "score_breakdown": breakdown,
        "tech_paths": paths,
        "topic": topic,
        "work_name": work_name,
        "theme_descriptor": theme_descriptor,
        "theme": _compose_theme(work_name, theme_descriptor),
        "summary_zh": str(item.get("summary") or ""),
        "promo_line": f"该条目围绕「{topic}」展开：{title[:70]}" if paths else "",
        "highlight_line": "模型不可用，当前内容由技术地图降级匹配生成，建议人工复核。" if paths else "",
        "review_reason": f"模型调用降级：{reason}",
        "technical_points": [path["point"] for path in paths],
        "confidence": 0.25 if paths else 0.0,
    }


def _work_name(value: Any, item: dict[str, Any]) -> str:
    name = " ".join(str(value or "").split()).strip(" ：:")
    if name:
        return name[:80]
    title = " ".join(str(item.get("title") or "").split())
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    repo_name = str(item.get("repo_full_name") or raw.get("full_name") or "")
    if str(item.get("source_type")) == "project" and repo_name:
        return repo_name.rsplit("/", 1)[-1][:80]
    prefix = re.split(r"[:：]", title, maxsplit=1)[0].strip()
    return (prefix or title)[:80]


def _theme_descriptor(value: Any, work_name: str, item: dict[str, Any]) -> str:
    descriptor = " ".join(str(value or "").split()).strip(" ：:")
    if descriptor.startswith(work_name):
        descriptor = descriptor[len(work_name):].lstrip(" ：:")
    if not descriptor:
        title = " ".join(str(item.get("title") or "").split())
        descriptor = re.split(r"[:：]", title, maxsplit=1)[-1].strip() if re.search(r"[:：]", title) else title
    return descriptor[:160]


def _compose_theme(work_name: str, descriptor: str) -> str:
    if work_name and descriptor:
        return f"{work_name}：{descriptor}"
    return work_name or descriptor


def _call_model_api(router: LLMRouter, *, model_profile: str, prompt: str, input_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], bool, str, int, list[dict[str, Any]]]:
    """Pure API call with retries. Thread-safe — no DB access.
    Returns result, final output, failure flag, provider, final latency, and per-attempt audit records.
    """
    provider = str(router.active_config(model_profile).get("provider") or "unknown")
    overall_started = time.monotonic()
    attempts: list[dict[str, Any]] = []
    for attempt in range(1, MODEL_MAX_ATTEMPTS + 1):
        attempt_started = time.monotonic()
        try:
            output = router.complete_json(profile=model_profile, prompt=prompt, payload=input_payload)
            output = {**output, "retry_count": attempt - 1, "total_latency_ms": int((time.monotonic() - overall_started) * 1000)}
            result = output.get("result") or output.get("parsed") or {}
            latency_ms = int((time.monotonic() - attempt_started) * 1000)
            attempts.append({"status": "success", "output": output, "latency_ms": latency_ms, "error_message": ""})
            return result, output, False, str(output.get("provider") or provider), latency_ms, attempts
        except Exception as exc:
            error = str(exc)
            retryable = _is_retryable_model_error(exc)
            has_next_attempt = retryable and attempt < MODEL_MAX_ATTEMPTS
            latency_ms = int((time.monotonic() - attempt_started) * 1000)
            attempts.append({"status": "retryable_failure" if has_next_attempt else "failed", "output": {"attempt": attempt, "retryable": retryable}, "latency_ms": latency_ms, "error_message": error})
            if not has_next_attempt:
                error_output = {"error": error, "attempts": attempt, "retry_count": attempt - 1, "total_latency_ms": int((time.monotonic() - overall_started) * 1000)}
                return {"error": error, "attempts": attempt}, error_output, True, provider, latency_ms, attempts
            delay = MODEL_RETRY_BASE_SECONDS * (2 ** (attempt - 1)) + random.uniform(0, MODEL_RETRY_JITTER_SECONDS)
            time.sleep(delay)
    return {"error": "model retry loop exhausted"}, {"error": "exhausted"}, True, provider, 0, attempts


def _call_model(
    conn: sqlite3.Connection,
    router: LLMRouter,
    *,
    run_id: str,
    agent_name: str,
    model_profile: str,
    prompt: str,
    input_payload: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    provider = str(router.active_config(model_profile).get("provider") or "unknown")
    overall_started = time.monotonic()
    for attempt in range(1, MODEL_MAX_ATTEMPTS + 1):
        attempt_started = time.monotonic()
        try:
            output = router.complete_json(profile=model_profile, prompt=prompt, payload=input_payload)
            output = {**output, "retry_count": attempt - 1, "total_latency_ms": int((time.monotonic() - overall_started) * 1000)}
            repo.create_model_call(conn, run_id=run_id, agent_name=agent_name, model_profile=model_profile, provider=str(output.get("provider") or provider), status="success", input_payload=input_payload, output_payload=output, latency_ms=int((time.monotonic() - attempt_started) * 1000))
            return output.get("result") or output.get("parsed") or {}, False
        except Exception as exc:
            error = str(exc)
            retryable = _is_retryable_model_error(exc)
            has_next_attempt = retryable and attempt < MODEL_MAX_ATTEMPTS
            repo.create_model_call(conn, run_id=run_id, agent_name=agent_name, model_profile=model_profile, provider=provider, status="retryable_failure" if has_next_attempt else "failed", input_payload=input_payload, output_payload={"attempt": attempt, "retryable": retryable}, latency_ms=int((time.monotonic() - attempt_started) * 1000), error_message=error)
            if not has_next_attempt:
                return {"error": error, "attempts": attempt}, True
            delay = MODEL_RETRY_BASE_SECONDS * (2 ** (attempt - 1)) + random.uniform(0, MODEL_RETRY_JITTER_SECONDS)
            time.sleep(delay)
    return {"error": "model retry loop exhausted"}, True


def _record_model_call(conn: sqlite3.Connection, *, run_id: str, agent_name: str, model_profile: str, provider: str, input_payload: dict[str, Any], output: dict[str, Any], status: str, latency_ms: int, error_message: str = "") -> None:
    """DB write only. Called from main thread — serialized."""
    repo.create_model_call(conn, run_id=run_id, agent_name=agent_name, model_profile=model_profile, provider=provider, status=status, input_payload=input_payload, output_payload=output, latency_ms=latency_ms, error_message=error_message)


def _record_attempts(conn: sqlite3.Connection, *, run_id: str, agent_name: str, model_profile: str, provider: str, input_payload: dict[str, Any], attempts: list[dict[str, Any]]) -> None:
    for attempt in attempts:
        _record_model_call(conn, run_id=run_id, agent_name=agent_name, model_profile=model_profile, provider=provider, input_payload=input_payload, output=attempt["output"], status=attempt["status"], latency_ms=int(attempt["latency_ms"]), error_message=str(attempt["error_message"]))


def _is_retryable_model_error(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or 500 <= exc.code <= 599
    if isinstance(exc, (TimeoutError, socket.timeout, urllib.error.URLError, ConnectionError)):
        return True
    message = str(exc).lower()
    return any(marker in message for marker in ["timed out", "timeout", "connection reset", "connection aborted", "temporarily unavailable", "service unavailable", "http error 429", "http error 5", "rate limit"])


def _cached_stage(conn: sqlite3.Connection, item_key: str, field: str, input_hash: str, prompt_version: str) -> dict[str, Any] | None:
    item_id = news_repo.get_item_id_by_key(conn, item_key)
    if item_id is None:
        return None
    row = conn.execute("SELECT payload_json FROM domain_items WHERE id = ?", (item_id,)).fetchone()
    payload = repo.loads(row["payload_json"], {}) if row else {}
    value = payload.get(field) if isinstance(payload.get(field), dict) else None
    return value if value and value.get("input_hash") == input_hash and value.get("prompt_version") == prompt_version else None


def _cached_model_result(conn: sqlite3.Connection, agent_name: str, model_profile: str, input_payload: dict[str, Any]) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT output_json
        FROM model_calls
        WHERE agent_name = ? AND model_profile = ? AND status = 'success' AND input_json = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (agent_name, model_profile, repo.dumps(input_payload)),
    ).fetchone()
    output = repo.loads(row["output_json"], {}) if row else {}
    if not isinstance(output, dict):
        return None
    result = output.get("result") or output.get("parsed")
    return result if isinstance(result, dict) else None


def _normalize_breakdown(value: Any) -> dict[str, float]:
    if not isinstance(value, dict):
        return {}
    fields = ["map_relevance", "novelty", "technical_depth", "engineering_value", "reproducibility", "influence", "freshness"]
    aliases = {"engineering_value": ["ability_to_execute", "engineering_feasibility"]}
    return {field: _percentage(next((value.get(alias) for alias in [field, *aliases.get(field, [])] if value.get(alias) is not None), None)) for field in fields}


def _weighted_score(item_type: str, breakdown: dict[str, float]) -> float:
    if not breakdown:
        return 0.0
    weights = {
        "paper": {"map_relevance": 0.25, "novelty": 0.25, "technical_depth": 0.20, "engineering_value": 0.10, "reproducibility": 0.05, "influence": 0.05, "freshness": 0.10},
        "project": {"map_relevance": 0.25, "novelty": 0.10, "technical_depth": 0.15, "engineering_value": 0.20, "reproducibility": 0.15, "influence": 0.05, "freshness": 0.10},
    }.get(item_type, {"map_relevance": 0.25, "novelty": 0.20, "technical_depth": 0.15, "engineering_value": 0.15, "reproducibility": 0.10, "influence": 0.05, "freshness": 0.10})
    return round(sum(breakdown.get(field, 0) * weight for field, weight in weights.items()), 2)


def _unwrap(value: Any) -> Any:
    return value.get("result") if isinstance(value, dict) and isinstance(value.get("result"), dict) else value


def _percentage(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(number, 2) if 0 <= number <= 100 else 0.0


def _fraction(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(1.0, number)), 2)


def _string_list(value: Any) -> list[str]:
    return [str(item) for item in value if item] if isinstance(value, list) else []


def _input_hash(value: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
