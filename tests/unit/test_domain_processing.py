from __future__ import annotations

from ai4sec_platform.domains.capabilities.scorers import score_capability_candidate
from ai4sec_platform.domains.news.classifiers import classify_news_item
from ai4sec_platform.domains.news.scorers import score_news_item
from ai4sec_platform.domains.threats.repo_vuln_extractors import extract_repo_vulnerability_signals
from ai4sec_platform.domains.threats.attack_surface_scoring import score_attack_surface
from ai4sec_platform.domains.threats.normalizers import normalize_huawei_item
from ai4sec_platform.domains.threats.risk_scoring import score_threat_item
from ai4sec_platform.domains.vulnerabilities.evidence_extractors import extract_material_evidence
from ai4sec_platform.domains.vulnerabilities.material_classifiers import classify_material
from ai4sec_platform.domains.vulnerabilities.relevance_scorers import score_material


def test_news_processing_classifies_and_scores_security_repo() -> None:
    item = {
        "source_type": "repo",
        "title": "LLM Agent Security Scanner",
        "summary": "Detect prompt injection and agent security issues for AI systems",
        "url": "https://github.com/acme/agent-security-scanner",
        "code_url": "https://github.com/acme/agent-security-scanner",
        "stars": 2400,
        "primary_date": "2026-07-10",
    }
    classification = classify_news_item(item)
    scoring = score_news_item({**item, "classification": classification.as_payload()})
    assert classification.category in {"Agent 安全", "安全工具与代码"}
    assert scoring.priority == "high"
    assert scoring.breakdown["code"] == 20


def test_capability_processing_scores_reproducible_repo() -> None:
    scoring = score_capability_candidate({"payload": {"source_news_item": {"title": "AI vulnerability scanner", "summary": "security repo with tests", "source_url": "https://github.com/a/b", "score": 80}}})
    assert 1 <= scoring.score <= 5
    assert scoring.signals["has_code"] is True


def test_threat_processing_extracts_history_cves_and_scores_risk() -> None:
    item = {
        "source_type": "repo_cve",
        "title": "huawei/example CVE 线索",
        "summary": "CVE-2024-12345 RCE exploit PoC",
        "risk_score": 20,
        "cves": [{"id": "CVE-2024-12345"}, {"cve": "CVE-2023-9999"}],
        "sa_items": [{"sa_id": "OpenHarmony-SA-2025-0001", "severity": "high", "description": "security advisory"}],
        "broad_sec_items": [{"severity": "critical", "description": "RCE crash in parser", "source_type": "project_issue"}],
        "raw": {"issues": [{"title": "security vulnerability"}], "description": "kernel parser security permission"},
    }
    signals = extract_repo_vulnerability_signals(item)
    attack_surface = score_attack_surface({"name": "kernel_parser", "summary": "kernel parser security permission", "stars": 80, "cve_count": 5})
    scoring = score_threat_item(item)
    assert signals["cve_count"] == 2
    assert signals["sa_count"] == 1
    assert signals["broad_sec_count"] == 1
    assert attack_surface.grade == "A"
    assert scoring.score >= 70
    assert scoring.signals["has_exploit_signal"] is True
    assert "attack_surface" in scoring.breakdown


def test_threat_cve_finding_title_does_not_claim_cve_when_none_found() -> None:
    item = {"org": "Ascend", "name": "kernel_launcher", "url": "https://gitcode.com/Ascend/kernel_launcher", "cve_count": 0, "sa_count": 0, "broad_sec_count": 0, "total_sec_items": 0}
    normalized = normalize_huawei_item("cve_findings", item)
    assert normalized["title"] == "Ascend/kernel_launcher 攻击面线索"
    assert "CVE 线索" not in normalized["title"]


def test_vulnerability_material_processing_judges_valid_material() -> None:
    item = {
        "title": "CVE-2025-1111 RCE PoC 复现",
        "summary": "包含 exploit payload、影响版本 <= 1.2.3 和修复建议 patch",
        "url": "https://example.com/poc",
        "confidence": 0.82,
        "markdown_length": 4200,
        "key_findings": ["RCE", "PoC", "影响版本 <= 1.2.3"],
        "raw": {"reason": "technical exploit analysis"},
    }
    classification = classify_material(item)
    evidence = extract_material_evidence(item)
    scoring = score_material({**item, "classification": classification.as_payload()})
    assert classification.category == "PoC/Exploit"
    assert evidence["has_poc"] is True
    assert evidence["has_mitigation"] is True
    assert scoring.priority == "high"
