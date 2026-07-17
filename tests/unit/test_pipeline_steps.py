from __future__ import annotations

import sqlite3

from ai4sec_platform.artifacts.store import ArtifactStore
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.steps.audit import AuditStep
from ai4sec_platform.pipelines.steps.build_domain_item import BuildDomainItemStep
from ai4sec_platform.pipelines.steps.dedupe import DedupeStep
from ai4sec_platform.pipelines.steps.extract_evidence import ExtractEvidenceStep
from ai4sec_platform.pipelines.steps.fetch_content import FetchContentStep
from ai4sec_platform.pipelines.steps.llm_review import LlmReviewStep
from ai4sec_platform.pipelines.steps.normalize import NormalizeStep
from ai4sec_platform.pipelines.steps.render import RenderStep
from ai4sec_platform.pipelines.steps.select import SelectStep
from ai4sec_platform.pipelines.steps.summarize import SummarizeStep


def test_generic_pipeline_steps_execute_real_work(tmp_path) -> None:
    settings = load_settings()
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    repo.create_pipeline_run(conn, run_id="test_steps_run", domain="news", pipeline_name="test.generic_steps")
    context = PipelineContext(
        run_id="test_steps_run",
        pipeline_name="test.generic_steps",
        domain="news",
        settings=settings,
        conn=conn,
        artifact_store=ArtifactStore(tmp_path),
        params={"limit": 2},
        outputs={
            "items": [
                {"title": "A", "summary": "安全 LLM 项目", "url": "https://example.com/a"},
                {"title": "A duplicate", "summary": "重复", "url": "https://example.com/a"},
                {"title": "B", "summary": "漏洞分析", "url": "https://example.com/b"},
            ]
        },
    )
    SelectStep().run(context)
    NormalizeStep().run(context)
    DedupeStep().run(context)
    FetchContentStep(input_key="deduped_items").run(context)
    LlmReviewStep().run(context)
    BuildDomainItemStep(input_key="reviewed_items", item_type="test_item").run(context)
    ExtractEvidenceStep(items_key="reviewed_items").run(context)
    AuditStep().run(context)
    RenderStep(artifact_name="generic/render.json").run(context)
    SummarizeStep().run(context)

    assert len(context.outputs["selected_items"]) == 2
    assert len(context.outputs["deduped_items"]) == 1
    assert len(context.outputs["domain_item_ids"]) == 1
    assert context.outputs["summary"]["domain_item_ids"] == 1
    assert conn.execute("SELECT COUNT(*) FROM evidence_items").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM quality_audits").fetchone()[0] == 1
