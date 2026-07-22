from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class VulnerabilityMaterial(BaseModel):
    material_id: str = ""
    title: str
    url: str = ""
    source_host: str = ""
    source_type: str = "material"
    material_type: str = "unknown"
    status: str = "new"
    summary: str = ""
    cleaned_text_excerpt: str = ""
    crawled_at: str = ""
    published_at: str = ""
    relevance_score: float = 0.0
    extraction_confidence: float | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    key_findings: list[str] = Field(default_factory=list)
    search_keywords: str = ""
    event_id: str | None = None
    evidence_snippet_ids: list[str] = Field(default_factory=list)
    raw_artifact_id: int | None = None


class VulnerabilityEvent(BaseModel):
    event_id: str
    title: str
    kind: str
    cve_ids: list[str] = Field(default_factory=list)
    primary_cve_id: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    severity: str = "Unknown"
    affected_products: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    attack_entry: str = ""
    root_cause_summary: str = ""
    material_ids: list[int] = Field(default_factory=list)
    evidence_types: dict[str, int] = Field(default_factory=dict)
    aggregation_key: str
    aggregation_confidence: float = 0.0
    aggregation_reason: str = ""
    knowledge_completeness: float = 0.0
    status: str = "needs_review"
    latest_update_at: str = ""


class EvidenceSnippet(BaseModel):
    snippet_id: str
    material_id: int | str
    event_id: str | None = None
    snippet_type: str
    title: str
    content: str
    source_url: str = ""
    source_path: str = ""
    char_start: int | None = None
    char_end: int | None = None
    confidence: float = 0.0
    extracted_by: str = "rule"


class KnowledgeFieldReview(BaseModel):
    field_name: str
    model_value: Any = None
    current_value: Any = None
    status: str = "pending"
    reviewer: str = ""
    reviewed_at: str = ""
    reason: str = ""
    evidence_snippet_ids: list[str] = Field(default_factory=list)
    model_confidence: float | None = None


class VulnerabilityKnowledgeItem(BaseModel):
    knowledge_id: str = ""
    event_id: str = ""
    title: str
    status: str = "draft"
    vulnerability_type: str = "unknown"
    cwe_ids: list[str] = Field(default_factory=list)
    root_cause_pattern: str = ""
    trigger_condition: str = ""
    attack_entry: str = ""
    affected_components: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    key_functions_or_apis: list[str] = Field(default_factory=list)
    exploit_primitives: list[str] = Field(default_factory=list)
    exploit_steps: list[str] = Field(default_factory=list)
    mitigation_or_fix: str = ""
    transferable_stack: list[str] = Field(default_factory=list)
    code_search_keywords: list[str] = Field(default_factory=list)
    field_reviews: dict[str, KnowledgeFieldReview] = Field(default_factory=dict)
    evidence_refs: dict[str, list[str]] = Field(default_factory=dict)
    model_profile: str = ""
    model_call_id: int | None = None
    version: int = 1
