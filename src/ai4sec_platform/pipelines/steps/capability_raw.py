"""新能力洞察 Pipeline Steps——5步1次LLM。
Build→CodeLink+Dedup→RuleFilter→FetchREADME→LLMReview→Store→WebClassify
"""
from __future__ import annotations

import json, os, time, urllib.request, base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.assessments import is_non_web_blocked


# ─────────────────── Step 1: Build（拉原始数据） ───────────────────

@dataclass
class BuildFromRawStep:
    name: str = "build_from_raw"
    step_type: str = "build"

    def run(self, context: PipelineContext) -> StepResult:
        from ai4sec_platform.domains.capabilities.adapters.raw_items_source import RawItemsSource
        source = RawItemsSource(context.conn)
        items = source.fetch_since(limit=int(context.params.get("raw_limit", 1000)))
        context.outputs["raw_items"] = items
        return StepResult(metrics={"fetched": len(items)})


# ─────────────────── Step 2: CodeLink + Dedup ───────────────────

@dataclass
class CodeLinkDedupStep:
    name: str = "code_link_dedup"
    step_type: str = "filter"

    def run(self, context: PipelineContext) -> StepResult:
        from ai4sec_platform.pipelines.steps.code_link import discover_code_url, dedup_items, extract_repo_key
        items = list(context.outputs.get("raw_items") or [])
        # 发现代码链接
        for item in items:
            if not item.get("code_url"):
                item["code_url"] = discover_code_url(item)
        # 去重
        before = len(items)
        items = dedup_items(items)
        context.outputs["deduped_items"] = items
        with_code = sum(1 for i in items if i.get("code_url"))
        return StepResult(metrics={"before_dedup": before, "after_dedup": len(items), "with_code": with_code})


# ─────────────────── Step 3: RuleFilter（分类+评分+过滤） ───────────────────

@dataclass
class RuleFilterStep:
    name: str = "rule_filter"
    step_type: str = "filter"

    def run(self, context: PipelineContext) -> StepResult:
        from ai4sec_platform.domains.news.classifiers import classify_item
        from ai4sec_platform.domains.news.scorers import score_candidate
        project_root = Path(context.settings.project_root) if hasattr(context.settings, 'project_root') else Path("/opt/ai-security-fusion-v2/ai4sec")

        items = list(context.outputs.get("deduped_items") or [])
        enter_llm: list[dict] = []
        news_only: list[dict] = []
        skipped = 0

        for item in items:
            # 分类
            classification = classify_item(item)
            item["classification"] = classification.as_payload() if hasattr(classification, 'as_payload') else classification
            item["category"] = item["classification"].get("category", "")
            item["confidence"] = item["classification"].get("confidence", 0.35)
            signals = item["classification"].get("signals", {})
            item["security_flag"] = signals.get("security_flag", False)
            item["security_topics"] = signals.get("security_topics", [])

            # 评分
            scoring = score_candidate(item, project_root)
            item["rule_score"] = scoring.score
            item["rule_breakdown"] = scoring.breakdown
            item["rule_decision"] = scoring.signals.get("decision", "news_only")

            if item["rule_decision"] == "skip":
                skipped += 1
            elif item["rule_decision"] == "news_only":
                news_only.append(item)
            else:  # enter_llm
                enter_llm.append(item)

        context.outputs["llm_candidates"] = enter_llm
        context.outputs["news_only_items"] = news_only
        return StepResult(metrics={
            "total": len(items), "enter_llm": len(enter_llm),
            "news_only": len(news_only), "skipped": skipped,
        })


# ─────────────────── Step 4: FetchREADME ───────────────────

@dataclass
class FetchReadmeStep:
    name: str = "fetch_readme"
    step_type: str = "enrich"

    def run(self, context: PipelineContext) -> StepResult:
        items = list(context.outputs.get("llm_candidates") or [])
        token = os.getenv("GITHUB_TOKEN", "")
        headers = {"Accept": "application/vnd.github.raw+json", "User-Agent": "ai4sec/1.0"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        fetched = 0
        for item in items:
            code_url = item.get("code_url", "")
            if not code_url:
                continue
            # 从 code_url 提取 owner/repo
            import re
            match = re.search(r"github\.com/([^/]+/[^/?]+)", code_url)
            if not match:
                continue
            repo_path = match.group(1)
            # 如果已经有 readme 在 raw 里，跳过
            raw = item.get("raw") or {}
            if raw.get("readme") or raw.get("readme_text"):
                item["readme"] = str(raw.get("readme") or raw.get("readme_text"))[:12000]
                fetched += 1
                continue
            # 从 GitHub API 拉 README
            try:
                req = urllib.request.Request(f"https://api.github.com/repos/{repo_path}/readme", headers=headers)
                with urllib.request.urlopen(req, timeout=15) as resp:
                    content = resp.read()
                    # 如果是 base64 编码的
                    try:
                        content = base64.b64decode(content).decode("utf-8", errors="replace")
                    except Exception:
                        content = content.decode("utf-8", errors="replace")
                    item["readme"] = content[:12000]
                    fetched += 1
            except Exception as e:
                # 用 description 兜底
                item["readme"] = str(item.get("summary") or raw.get("description") or "")[:2000]

        context.outputs["llm_candidates"] = items
        return StepResult(metrics={"readme_fetched": fetched, "total": len(items)})


# ─────────────────── Step 5: LLMReview（1次调用） ───────────────────

@dataclass
class LLMReviewStep:
    name: str = "llm_review"
    step_type: str = "llm_review"
    model_profile: str = "configured_model"

    def run(self, context: PipelineContext) -> StepResult:
        from ai4sec_platform.domains.news.reviewer import review_candidates
        project_root = Path(context.settings.project_root) if hasattr(context.settings, 'project_root') else Path("/opt/ai-security-fusion-v2/ai4sec")

        candidates = list(context.outputs.get("llm_candidates") or [])
        if not candidates:
            return StepResult(metrics={"candidates": 0, "selected": 0, "failed": 0})

        selected, metrics = review_candidates(
            context.conn,
            candidates,
            run_id=context.run_id,
            project_root=project_root,
            model_profile=str(context.params.get("model_profile") or self.model_profile),
            min_decision=str(context.params.get("min_decision") or "all"),
        )
        context.outputs["reviewed_items"] = selected
        return StepResult(metrics=metrics)


# ─────────────────── Step 5b: 降级评审重评（2026-10-29） ───────────────────

# 降级评审(模型不可用/回包不是评审 schema)不再写库, 候选进 capability_review_backlog 队列,
# 由本步骤在模型恢复后重评 —— 否则一次网关 403 就能灌进上千条没有内容的条目(2026-10-28 实测)。


def capability_status(decision: str, recommended: int) -> str:
    """评审结论 → 行状态。增量写库、StoreCapabilitiesStep、降级重评三处共用同一口径。"""
    if decision in ("selected", "watch") and recommended >= 4:
        return "待复现验证"
    if decision in ("selected", "watch"):
        return "待资料补齐"
    return "已淘汰"


def build_store_payload(item: dict[str, Any], review: dict[str, Any]) -> dict[str, Any]:
    """候选 + 评审结论 → 能力条目 payload(字段集是前端 V1 契约, 别随手改名)。"""
    recommended = int(review.get("recommended_score") or 0)
    display_title = review.get("theme") or f"{review.get('work_name', '')}：{review.get('theme_descriptor', '')}"
    display_summary = review.get("summary_zh", "")
    return {
        # review (LLM 完整输出)
        "review": review,
        # display fields (V1 兼容)
        "display_title": display_title,
        "display_summary": display_summary,
        "display_theme": review.get("theme_descriptor", ""),
        "display_topic": review.get("topic", ""),
        "display_work_name": review.get("work_name", ""),
        "promo_line": review.get("promo_line", ""),
        "highlight_line": review.get("highlight_line", ""),
        "one_liner": review.get("promo_line", ""),
        "highlight": review.get("highlight_line", ""),
        "overview": review.get("summary_zh", ""),
        "summary": review.get("summary_zh", ""),
        # review status
        "review_status": "enriched",
        # rule scoring
        "rule_score": item.get("rule_score", 0),
        "rule_breakdown": item.get("rule_breakdown", {}),
        "security_flag": item.get("security_flag", False),
        "security_topics": item.get("security_topics", []),
        "source_news_score": item.get("rule_score", 0),
        # assessment (V1 顶层字段)
        "security_value": review.get("security_value", ""),
        "reproducibility_assessment": review.get("reproducibility_assessment", ""),
        "application_advice": review.get("application_advice", ""),
        "code_quality": review.get("code_quality", ""),
        "score_reason": review.get("score_reason", ""),
        "capability_type": review.get("capability_type", ""),
        "application_scenarios": review.get("application_scenarios", []),
        "tech_points": [p.get("point", "") for p in review.get("tech_paths", [])],
        # source info
        "code_url": item.get("code_url", ""),
        "source_type": item.get("source_type", ""),
        "capability_scoring": item.get("rule_breakdown", {}),
        # assessment (嵌套，V1 兼容)
        "assessment": {
            "overview": review.get("summary_zh", ""),
            "security_value": review.get("security_value", ""),
            "reproducibility_assessment": review.get("reproducibility_assessment", ""),
            "application_advice": review.get("application_advice", ""),
            "recommended_score": recommended,
            "capability_type": review.get("capability_type", ""),
            "application_scenarios": review.get("application_scenarios", []),
            "score_reason": review.get("score_reason", ""),
        },
        "implementation_depth": {
            "has_real_code": bool(item.get("code_url")),
            "has_tests": False,
            "has_eval": False,
            "is_prompt_wrapper": False,
            "is_thin_mcp_wrapper": False,
        },
        "repro_status": "candidate",
        "conversion_status": "待评估",
        # source news item
        "source_news_item": {
            "title": item.get("title"),
            "summary": item.get("summary"),
            "url": item.get("url"),
            "code_url": item.get("code_url"),
            "stars": item.get("stars"),
            "published_at": item.get("published_at"),
            "source_type": item.get("source_type", ""),
        },
    }


@dataclass
class RetryDegradedReviewsStep:
    """把评审降级的候选在模型恢复后重评, 通过则落库。

    入队原因见 domains/capabilities/review_backlog.py。这里只做: 重评 → 落库(与
    StoreCapabilitiesStep 同一份 payload/状态口径) → 出队。

    两条硬规则:
    1. **整批都失败 = 探活失败**, 不烧 attempts。否则一次长宕机就能把队列耗成空。
    2. **created_at 回填成入队时的 first_seen_at**, 不写成今天 —— 补评上个月的候选不该
       把「今日能力」撑爆, 更不该假装它们是今天新发现的。
    """
    name: str = "retry_degraded_reviews"
    step_type: str = "llm_review"
    model_profile: str = "configured_model"

    def run(self, context: PipelineContext) -> StepResult:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from ai4sec_platform.domains.capabilities import review_backlog
        from ai4sec_platform.domains.news import reviewer
        from ai4sec_platform.domains.news.tech_map import AgentTechMap

        project_root = Path(context.settings.project_root) if hasattr(context.settings, 'project_root') else Path("/opt/ai-security-fusion-v2/ai4sec")
        limit = int(context.params.get("retry_limit", 100))
        rows = review_backlog.pending(context.conn, limit)
        if not rows:
            return StepResult(metrics={"pending": 0, "reviewed": 0, "stored": 0, "rejected": 0})

        model_profile = str(context.params.get("model_profile") or self.model_profile)
        tech_map = AgentTechMap.load(project_root)
        router = reviewer.LLMRouter()
        prompt = reviewer._review_prompt()

        def _work(row: dict[str, Any]) -> dict[str, Any]:
            result, _output, failed, provider, latency, attempts = reviewer._call_model_api(
                router, model_profile=model_profile, prompt=prompt, input_payload=row["input_payload"],
            )
            return {**row, "result": result, "failed": failed, "provider": provider,
                    "latency": latency, "attempts": attempts}

        # 分块跑 + 首块全灭即熔断: 网关宕机时每调用要耗满 3 次重试的退避, 整批一次性提交会把
        # 一个 15 分钟节拍的跑批拖成半小时, 还会连带饿死后面的步骤。首块 10 条(正好一波并发)
        # 全失败就认定探活失败 —— 没轮到的行原样留在队列里, 不烧 attempts。
        #
        # 按时间设预算(2026-10-29 实测): 单次重评约 110s, 100 条要跑 12.9 分钟, 整批 23.7 分钟 ——
        # 而且每存一条后面还要再多花 10s 做 web 分类, 所以这一段的真实成本不是"100 次调用"。
        # 预算不是为了让整批压进 15 分钟节拍(那会把排水拖到 5 天), 而是给网关抽风时的**上界**:
        # 每次调用耗满 3 次重试退避时, 没预算就是 10 块 × 9.5 分钟。到点收工, 处理过的照常落库。
        chunk_size = max(1, int(context.params.get("retry_chunk", 10)))
        budget_seconds = float(context.params.get("retry_budget_seconds", 600))
        results: list[dict[str, Any]] = []
        provider_down = False
        budget_exhausted = False
        started_at = time.monotonic()
        for start in range(0, len(rows), chunk_size):
            if results and time.monotonic() - started_at >= budget_seconds:
                budget_exhausted = True
                break
            chunk = rows[start:start + chunk_size]
            with ThreadPoolExecutor(max_workers=min(reviewer.CONCURRENCY, len(chunk))) as pool:
                chunk_results = [future.result() for future in as_completed([pool.submit(_work, row) for row in chunk])]
            results.extend(chunk_results)
            if start == 0 and all(r["failed"] for r in chunk_results):
                provider_down = True
                break

        if provider_down:
            # 探活失败: 模型整批不可用。保留队列原样, 下次再试, 不算这条候选的失败次数。
            return StepResult(metrics={"pending": len(rows), "reviewed": 0, "stored": 0, "rejected": 0,
                                       "provider_down": 1, "budget_exhausted": 0})

        stored = rejected = dropped = 0
        for r in results:
            # 重评的每次模型调用都记账(model_calls 是事后追查「这批条目是怎么来的」的唯一凭据)
            reviewer._record_attempts(context.conn, run_id=context.run_id, agent_name="degraded_review_retry",
                                      model_profile=model_profile, provider=r["provider"],
                                      input_payload=r["input_payload"], attempts=r["attempts"])
            if r["failed"]:
                if review_backlog.record_failure(context.conn, r["id"], str((r["result"] or {}).get("error") or "model failed")):
                    dropped += 1
                continue
            review = reviewer._normalize_review(r["result"], r["item"], tech_map)
            if review.get("degraded_reason"):
                # 模型回了话但不是评审 schema —— 算这条候选的一次失败, 不重复入队
                if review_backlog.record_failure(context.conn, r["id"], str(review["degraded_reason"])):
                    dropped += 1
                continue
            review = {**review, "prompt_version": reviewer.REVIEW_PROMPT_VERSION,
                      "tech_map_version": tech_map.version}
            decision = review.get("decision", "rejected")
            if decision not in ("selected", "watch"):
                review_backlog.remove(context.conn, r["id"])
                rejected += 1
                continue
            item = r["item"]
            code_url = str(item.get("code_url") or "").strip()
            existing = repo.get_domain_item_by_repo(context.conn, domain="capabilities", repo_url=code_url) if code_url else None
            if existing:
                # 库里已有这个仓库(主链路写过更新的一次评审) → 以库里那份为准, 只出队
                review_backlog.remove(context.conn, r["id"])
                continue
            item_id = repo.create_domain_item(
                context.conn,
                domain="capabilities",
                item_type="capability",
                title=str(item.get("title") or "未命名条目"),
                summary=review.get("summary_zh", ""),
                score=float(review.get("score") or 0),
                status=capability_status(decision, int(review.get("recommended_score") or 0)),
                source="asis_raw",
                source_url=str(item.get("url") or ""),
                tags=[t for t in (item.get("source_type", ""), review.get("topic", ""), review.get("capability_type", "")) if t],
                payload=build_store_payload(item, review),
            )
            first_seen = str(r.get("first_seen_at") or "")
            if first_seen:
                context.conn.execute("UPDATE domain_items SET created_at = ? WHERE id = ?", (first_seen, item_id))
            review_backlog.remove(context.conn, r["id"])
            stored += 1
        context.conn.commit()
        return StepResult(metrics={"pending": len(rows), "reviewed": len(results), "stored": stored,
                                   "rejected": rejected, "dropped": dropped, "provider_down": 0,
                                   "budget_exhausted": int(budget_exhausted)})


# ─────────────────── Step 6: Store（写库） ───────────────────

@dataclass
class StoreCapabilitiesStep:
    name: str = "store_capabilities"
    step_type: str = "store"

    def run(self, context: PipelineContext) -> StepResult:
        items = list(context.outputs.get("reviewed_items") or [])
        created = 0
        updated = 0
        item_ids: list[int] = []

        for item in items:
            review = item.get("review") or {}
            if not review:
                continue

            item_key = str(item.get("item_key") or "")
            title = str(item.get("title") or "未命名条目")
            score = float(review.get("score") or 0)
            decision = review.get("decision", "rejected")
            recommended = int(review.get("recommended_score") or 0)

            status = capability_status(decision, recommended)

            payload = build_store_payload(item, review)

            tags = [item.get("source_type", ""), review.get("topic", ""), review.get("capability_type", "")]
            tags = [t for t in tags if t]

            # 库级去重按仓库身份(code_url),不再按 item_key(信源ID每轮都变,从未命中过→重复入库)
            code_url = str(item.get("code_url") or "").strip()
            existing = repo.get_domain_item_by_repo(context.conn, domain="capabilities", repo_url=code_url) if code_url else None

            if existing:
                # 复用已有行时保留 repro 结果,避免重置回 candidate 造成重复复现
                prev_payload = existing.get("payload") or {}
                nonweb = is_non_web_blocked(prev_payload)
                if prev_payload.get("repro_status"):
                    payload["repro_status"] = prev_payload["repro_status"]
                if prev_payload.get("repro_result"):
                    payload["repro_result"] = prev_payload["repro_result"]
                if prev_payload.get("repro_skip_reason"):
                    payload["repro_skip_reason"] = prev_payload["repro_skip_reason"]
                # 非 web 把关(2026-09-15): 该 repo 此前已被判定非 web(且非 LOWCONF)时, 不得因资讯
                # 重扫再次入复现队列。上面 status 是按 review.recommended 重算的, 不看 is_web, 而同一
                # code_url 每晚都会被重新发现 → 已淘汰的条目被原样写回"待复现验证"; 又因
                # SelectUnclassifiedWebCandidatesStep 只挑没有 web_classify_ts 的条目, 分类过的永不
                # 再分类 → 一旦漂移就再无机会降级(实测 72 条漂移, 8/17 分类 / 9 月仍在队列)。
                if status == "待复现验证" and nonweb:
                    status = "已淘汰"
                # 非 web 条目不参与复现 → 落终态「无需复现」(2026-10-29 改口径, 原先是把 repro_status
                # 整键摘掉)。上面入库模板无条件带 "repro_status": "candidate", 而 update_domain_item
                # 对 payload 是浅 merge(永不删键), 所以这里必须显式改写成 not_supported —— 每 15 分钟的
                # 资讯重扫(capabilities.from_news_pipeline)都会走到这里, 摘空就会被下一次重算复活。
                # 只摘 repro_result: 非 web 没有「复现原文」可看, 留着卡片会挂「查看复现」。
                if nonweb:
                    payload["repro_status"] = "not_supported"
                    payload.setdefault("repro_skip_reason", "non_web")
                    payload.pop("repro_result", None)
                repo.update_domain_item(context.conn, item_id=existing["id"], status=status, score=score, payload=payload)
                if nonweb:
                    context.conn.execute(
                        "UPDATE domain_items SET payload_json = "
                        "json_remove(payload_json, '$.repro_result') WHERE id = ?",
                        (existing["id"],),
                    )
                item_ids.append(existing["id"])
                updated += 1
            else:
                item_id = repo.create_domain_item(
                    context.conn,
                    domain="capabilities",
                    item_type="capability",
                    title=title,
                    summary=display_summary,
                    score=score,
                    status=status,
                    source="asis_raw",
                    source_url=item.get("url", ""),
                    primary_date=item.get("primary_date", ""),
                    tags=tags,
                    metrics={"rule_score": item.get("rule_score", 0), "llm_score": score},
                    payload=payload,
                )
                if item_id:
                    item_ids.append(item_id)
                    created += 1

        context.outputs["capability_ids"] = item_ids
        return StepResult(metrics={"created": created, "updated": updated, "total": len(item_ids)})
