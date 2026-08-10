"""新能力洞察 Pipeline Steps——5步1次LLM。
Build→CodeLink+Dedup→RuleFilter→FetchREADME→LLMReview→Store→WebClassify
"""
from __future__ import annotations

import json, os, urllib.request, base64
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.db import repositories as repo


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

            # status 判定
            if decision in ("selected", "watch") and recommended >= 4:
                status = "待复现验证"
            elif decision in ("selected", "watch"):
                status = "待资料补齐"
            else:
                status = "已淘汰"

            display_title = review.get("theme") or f"{review.get('work_name', '')}：{review.get('theme_descriptor', '')}"
            display_summary = review.get("summary_zh", "")

            payload = {
                "review": review,
                "display_title": display_title,
                "display_summary": display_summary,
                "promo_line": review.get("promo_line", ""),
                "highlight_line": review.get("highlight_line", ""),
                "review_status": "enriched",
                "rule_score": item.get("rule_score", 0),
                "rule_breakdown": item.get("rule_breakdown", {}),
                "security_flag": item.get("security_flag", False),
                "security_topics": item.get("security_topics", []),
                "code_url": item.get("code_url", ""),
                "code_quality": review.get("code_quality", ""),
                "source_type": item.get("source_type", ""),
                "source_news_item": {
                    "title": item.get("title"),
                    "summary": item.get("summary"),
                    "url": item.get("url"),
                    "code_url": item.get("code_url"),
                    "stars": item.get("stars"),
                    "published_at": item.get("published_at"),
                },
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
            }

            tags = [item.get("source_type", ""), review.get("topic", ""), review.get("capability_type", "")]
            tags = [t for t in tags if t]

            existing = repo.get_domain_item_by_key(context.conn, domain="capabilities", item_key=item_key) if hasattr(repo, 'get_domain_item_by_key') else None

            if existing:
                repo.update_domain_item(context.conn, item_id=existing["id"], status=status, score=score, payload=payload)
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
