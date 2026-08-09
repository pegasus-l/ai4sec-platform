from __future__ import annotations

import sqlite3

from ai4sec_platform.domains.capabilities.scorers import score_capability_candidate
from ai4sec_platform.domains.news.classifiers import classify_news_item
from ai4sec_platform.domains.news.scorers import score_news_item
from ai4sec_platform.domains.threats.attack_surface_scoring import score_attack_surface
from ai4sec_platform.domains.threats.builders import build_threat_items
from ai4sec_platform.domains.threats.normalizers import normalize_huawei_item
from ai4sec_platform.domains.threats.repo_vuln_extractors import extract_repo_vulnerability_signals
from ai4sec_platform.domains.threats.risk_scoring import score_threat_item
from ai4sec_platform.domains.vulnerabilities.evidence_extractors import extract_material_evidence
from ai4sec_platform.domains.vulnerabilities.material_classifiers import classify_material
from ai4sec_platform.domains.vulnerabilities.relevance_scorers import score_material
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db


def test_news_processing_classifies_and_scores_security_repo() -> None:
    item = {
        "source_type": "project",
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
    assert scoring.breakdown["reproducibility"] == 12


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
    assert signals["direct_cve_count"] == 2
    assert signals["coordination_cve_count"] == 0
    assert signals["sa_count"] == 1
    assert signals["broad_sec_count"] == 1
    assert attack_surface.grade == "A"
    assert scoring.score >= 70
    assert scoring.signals["has_exploit_signal"] is True
    assert "attack_surface" in scoring.breakdown


def test_threat_cve_finding_title_does_not_claim_cve_when_none_found() -> None:
    item = {"org": "Ascend", "name": "kernel_launcher", "url": "https://gitcode.com/Ascend/kernel_launcher", "cve_count": 0, "sa_count": 0, "broad_sec_count": 0, "total_sec_items": 0}
    normalized = normalize_huawei_item("cve_findings", item)
    assert normalized["title"] == "Ascend/kernel_launcher"
    assert normalized["security_title"] == "Ascend/kernel_launcher 攻击面线索"
    assert "CVE 线索" not in normalized["security_title"]


def test_release_management_legacy_cves_are_normalized_as_coordination() -> None:
    normalized = normalize_huawei_item(
        "cve_findings",
        {
            "org": "openeuler",
            "name": "release-management",
            "cves": [{"cve_id": "CVE-2026-12345", "source_type": "project_issue"}],
            "cve_count": 1,
            "total_sec_items": 1,
        },
    )

    assert normalized["cves"][0]["association_scope"] == "organization_coordination"
    assert normalized["direct_cve_count"] == 0
    assert normalized["coordination_cve_count"] == 1
    assert normalized["coordination_summary"]["target_projects"] == []


def test_release_management_security_materials_do_not_raise_project_risk() -> None:
    normalized = normalize_huawei_item(
        "cve_findings",
        {
            "org": "openeuler",
            "name": "release-management",
            "sa_items": [{"sa_id": "openEuler-SA-2026-0001", "severity": "critical", "source_type": "project_issue"}],
            "broad_sec_items": [{"description": "RCE exploit release note", "severity": "critical", "source_type": "project_issue"}],
            "sa_count": 1,
            "broad_sec_count": 1,
            "total_sec_items": 2,
        },
    )
    scoring = score_threat_item(normalized)

    assert normalized["direct_sa_count"] == 0
    assert normalized["coordination_sa_count"] == 1
    assert normalized["direct_broad_sec_count"] == 0
    assert normalized["coordination_broad_sec_count"] == 1
    assert scoring.breakdown["security_advisory"] == 0
    assert scoring.breakdown["broad_security"] == 0
    assert scoring.breakdown["exploit"] == 0


def test_threat_repo_and_cve_findings_merge_to_single_target(tmp_path) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    repo_item = normalize_huawei_item(
        "repos",
        {
            "org": "Cangjie",
            "name": "cangjie_stdx",
            "url": "https://gitcode.com/Cangjie/cangjie_stdx",
            "description": "Cangjie standard extension modules for networking and crypto",
            "star_count": 88,
        },
    )
    cve_item = normalize_huawei_item(
        "cve_findings",
        {
            "org": "Cangjie",
            "name": "cangjie_stdx",
            "url": "https://gitcode.com/Cangjie/cangjie_stdx",
            "cve_count": 2,
            "sa_count": 1,
            "broad_sec_count": 0,
            "total_sec_items": 3,
            "cves": [{"cve_id": "CVE-2026-12345", "severity": "high", "source_type": "security_repo_file"}],
        },
    )

    counts = build_threat_items(conn, [repo_item, cve_item], run_id="merge_test", enrich_repo_summaries=True, repo_summary_limit=5, repo_summary_cache_dir=tmp_path)
    rows = conn.execute("SELECT * FROM domain_items WHERE domain = 'threats' AND item_type = 'target'").fetchall()
    payload = repo.loads(rows[0]["payload_json"], {})

    assert counts["items"] == 1
    assert len(rows) == 1
    assert rows[0]["summary"].startswith("Cangjie/cangjie_stdx 代码仓")
    assert payload["description_original"].startswith("Cangjie standard")
    assert payload["security_summary"] == "CVE 2 条，安全公告 1 条，安全 issue 0 条。"
    assert payload["cve_count"] == 2
    assert payload["summary_zh"]
    assert payload["summary_source"] in {"model_translation", "local_rule_summary", "repo_description"}


def test_threat_high_risk_queue_resolves_when_score_drops(tmp_path) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    high_risk = normalize_huawei_item(
        "cve_findings",
        {
            "org": "test",
            "name": "kernel-parser",
            "url": "https://example.test/test/kernel-parser",
            "star_count": 100,
            "cves": [
                {"cve_id": f"CVE-2026-{99990 + index}", "severity": "critical", "description": "RCE exploit PoC", "source_type": "project_issue"}
                for index in range(5)
            ],
        },
    )
    build_threat_items(conn, [high_risk], run_id="high", repo_summary_cache_dir=tmp_path)
    pending = conn.execute("SELECT * FROM human_queue_items WHERE domain = 'threats'").fetchone()
    assert pending["status"] == "pending"
    assert pending["dedupe_key"]
    build_threat_items(conn, [high_risk], run_id="high-again", repo_summary_cache_dir=tmp_path)
    assert conn.execute("SELECT COUNT(*) FROM human_queue_items WHERE domain = 'threats'").fetchone()[0] == 1

    low_risk = normalize_huawei_item(
        "cve_findings",
        {
            "org": "test",
            "name": "kernel-parser",
            "url": "https://example.test/test/kernel-parser",
            "star_count": 100,
            "cves": [{"cve_id": "CVE-2026-99999", "severity": "critical", "association_scope": "organization_coordination"}],
        },
    )
    build_threat_items(conn, [low_risk], run_id="low", repo_summary_cache_dir=tmp_path)

    resolved = conn.execute("SELECT * FROM human_queue_items WHERE domain = 'threats'").fetchone()
    assert resolved["status"] == "resolved"


def test_threat_assets_use_stable_source_identity_for_upsert() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    assets = [
        normalize_huawei_item("ascendhub", {"hub_name": "mindie", "hub_downloads": 10}),
        normalize_huawei_item("ascendhub", {"hub_name": "mindformers", "hub_downloads": 20}),
        normalize_huawei_item("openx_huawei", {"filename": "NE40E_V800R023.zip", "download_url": "https://example.test/ne40e.zip"}),
        normalize_huawei_item("openx_huawei", {"filename": "AR_V300R022.zip", "download_url": "https://example.test/ar.zip"}),
    ]

    build_threat_items(conn, assets, run_id="asset_first")
    build_threat_items(conn, assets, run_id="asset_second")

    rows = conn.execute("SELECT title, payload_json FROM domain_items WHERE domain = 'threats' AND item_type = 'asset' ORDER BY title").fetchall()
    item_keys = {repo.loads(row["payload_json"], {})["item_key"] for row in rows}
    assert len(rows) == 4
    assert len(item_keys) == 4
    assert {row["title"] for row in rows} == {"mindie", "mindformers", "NE40E", "AR"}


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
