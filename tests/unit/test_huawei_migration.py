from __future__ import annotations

from ai4sec_platform.domains.threats.cve_scout import _security_pool_from_connector_materials, build_cve_scout_from_local_records
from ai4sec_platform.domains.threats.adapters.huawei_sources import DEFAULT_ASCENDHUB_TARGETS
from ai4sec_platform.pipelines.steps.threat_cve_scout import _coverage_audit
from ai4sec_platform.domains.threats.security_file_parsers import infer_severity, parse_security_file
from ai4sec_platform.domains.threats.security_repo_discovery import discover_security_repos, group_projects_by_org


def test_security_repo_discovery_finds_primary_repo() -> None:
    projects = [
        {"org": "openharmony", "name": "security", "url": "https://gitcode.com/openharmony/security", "description": "security disclosures", "star_count": 10},
        {"org": "openharmony", "name": "kernel_linux", "url": "https://gitcode.com/openharmony/kernel_linux", "description": "kernel", "star_count": 20},
    ]
    result = discover_security_repos(group_projects_by_org(projects))
    assert result["openharmony"]["has_security_repo"] is True
    assert result["openharmony"]["primary_repo"]["name"] == "security"


def test_security_repo_discovery_prefers_name_match_over_metadata_noise() -> None:
    projects = [
        {"org": "openharmony", "name": "high_star_docs", "url": "https://gitcode.com/openharmony/high_star_docs", "description": "security documentation", "star_count": 999},
        {"org": "openharmony", "name": "vuln_center", "url": "https://gitcode.com/openharmony/vuln_center", "description": "reports", "star_count": 1},
    ]
    result = discover_security_repos(group_projects_by_org(projects))
    repos = result["openharmony"]["security_repos"]
    assert repos[0]["name"] == "vuln_center"
    assert repos[0]["discovery_reason"] == "name_keyword"


def test_parse_security_markdown_extracts_cve_and_sa() -> None:
    content = """
| Component | ID | Severity | CVSS |
|---|---|---|---|
| kernel_linux | CVE-2024-12345 | Critical | 9.8 |
| kernel_linux | OpenHarmony-SA-2024-0001 | High | 8.1 |
"""
    items = parse_security_file(content, source_path="security.md", repo_names=["kernel_linux"])
    assert any(item.get("cve_id") == "CVE-2024-12345" for item in items)
    assert any(item.get("sa_id") == "OPENHARMONY-SA-2024-0001" for item in items)
    assert all("kernel_linux" in item.get("project_hints", []) for item in items)


def test_security_parser_aligns_old_severity_and_cvss_rules() -> None:
    assert infer_severity("kernel_linux 高危 vulnerability") == "high"
    assert infer_severity("CANN package version 8.1 release note") == "unknown"
    assert infer_severity("CVSS v3.1 base score 9.8") == "critical"
    assert infer_severity("| CVE-2026-11111 | 7.5 | CVSS v3.1 | telephony_sms_mms |") == "high"
    long_row = "| CVE-2026-11111 | 7.5 | " + " | ".join(["x" * 24 for _ in range(7)]) + " | CVSS v3.1 | telephony_sms_mms |"
    assert infer_severity(long_row) == "high"
    broad_items = parse_security_file("telephony_sms_mms 存在信息泄露风险", repo_names=["telephony_sms_mms"])
    assert broad_items[0]["is_broad_sec"] is True
    assert "信息泄露" in broad_items[0]["matched_keywords"]


def test_security_parser_dedupes_same_cve_across_sources_and_safe_source_repo_hint() -> None:
    items = parse_security_file("| ID | Severity |\n| CVE-2026-77777 | High |", source_url="https://example.com/file-a.md")
    items.extend(parse_security_file("| ID | Severity |\n| CVE-2026-77777 | High |", source_url="https://example.com/issue/1"))
    unique = {item["cve_id"] for item in items}
    assert unique == {"CVE-2026-77777"}
    assert len({(item.get("cve_id"), item.get("source_url")) for item in items}) == 2
    severity_only = parse_security_file("| Severity | ID |\n| High | CVE-2026-88888 |", source_url="https://example.com/security.md")
    assert severity_only[0].get("source_repo") == ""


def test_cve_scout_builds_old_style_org_output() -> None:
    projects = [
        {"org": "openharmony", "name": "security", "url": "https://gitcode.com/openharmony/security", "description": "security", "star_count": 10},
        {"org": "openharmony", "name": "kernel_linux", "url": "https://gitcode.com/openharmony/kernel_linux", "description": "kernel", "star_count": 30},
    ]
    result = build_cve_scout_from_local_records(projects, None)
    assert result["meta"]["total_projects_in"] == 2
    assert result["orgs"]["openharmony"]["projects"]["kernel_linux"]["cve_count"] == 0
    assert "openharmony" in result["meta"]["orgs_with_security_repo"]


def test_cve_scout_matches_security_repo_file_pool_to_project() -> None:
    projects = [
        {
            "org": "openharmony",
            "name": "security",
            "url": "https://gitcode.com/openharmony/security",
            "description": "security disclosure",
            "star_count": 10,
            "security_files": [
                {
                    "path": "zh/security-disclosure/2026-07.md",
                    "content": "| Component | ID | Severity |\n| kernel_linux | CVE-2026-12345 | Critical |",
                    "source_url": "https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026-07.md",
                }
            ],
        },
        {"org": "openharmony", "name": "kernel_linux", "url": "https://gitcode.com/openharmony/kernel_linux", "description": "kernel", "star_count": 30},
    ]
    result = build_cve_scout_from_local_records(projects, None)
    kernel = result["orgs"]["openharmony"]["projects"]["kernel_linux"]
    assert kernel["cve_count"] == 1
    assert kernel["cves"][0]["cve_id"] == "CVE-2026-12345"
    assert result["meta"]["total_cve_ids"] == 1


def test_cve_scout_uses_org_level_security_material_pool() -> None:
    projects = [
        {"org": "openharmony", "name": "security", "url": "https://gitcode.com/openharmony/security", "description": "security disclosure", "star_count": 10, "is_security_repo": True},
        {"org": "openharmony", "name": "telephony_sms_mms", "url": "https://gitcode.com/openharmony/telephony_sms_mms", "description": "telephony", "star_count": 30},
    ]
    materials = [
        {
            "org": "openharmony",
            "platform": "gitcode",
            "repo": "security",
            "material_type": "security_repo_file",
            "path": "zh/security-disclosure/2026-07.md",
            "content": "| Component | ID | Severity |\n| telephony_sms_mms | CVE-2026-54321 | 高危 |",
            "source_url": "https://gitcode.com/openharmony/security/blob/master/zh/security-disclosure/2026-07.md",
        }
    ]

    result = build_cve_scout_from_local_records(projects, None, materials)
    telephony = result["orgs"]["openharmony"]["projects"]["telephony_sms_mms"]
    assert telephony["scan_mode"] == "from_pool"
    assert telephony["cves"][0]["severity"] == "high"
    assert result["meta"]["org_security_materials"] == 1


def test_cve_scout_counts_same_cve_once_across_org_material_sources() -> None:
    projects = [
        {"org": "openharmony", "name": "security", "url": "https://gitcode.com/openharmony/security", "description": "security", "star_count": 10, "is_security_repo": True},
        {"org": "openharmony", "name": "kernel_linux", "url": "https://gitcode.com/openharmony/kernel_linux", "description": "kernel", "star_count": 30},
    ]
    materials = [
        {"org": "openharmony", "repo": "security", "material_type": "security_repo_issue", "title": "kernel_linux CVE-2026-99991", "description": "High", "html_url": "https://example.com/issues/1"},
        {"org": "openharmony", "repo": "security", "material_type": "security_repo_file", "content": "| Component | ID | Severity |\n| kernel_linux | CVE-2026-99991 | High |", "source_url": "https://example.com/security.md"},
    ]
    result = build_cve_scout_from_local_records(projects, None, materials)
    kernel = result["orgs"]["openharmony"]["projects"]["kernel_linux"]
    assert kernel["cve_count"] == 1
    assert result["meta"]["total_cve_ids"] == 1


def test_cve_scout_deduped_cve_keeps_multiple_source_repo_hints() -> None:
    projects = [
        {"org": "openharmony", "name": "security", "url": "https://gitcode.com/openharmony/security", "description": "security", "star_count": 10, "is_security_repo": True},
        {"org": "openharmony", "name": "component_b", "url": "https://gitcode.com/openharmony/component_b", "description": "component", "star_count": 30},
    ]
    materials = [
        {"org": "openharmony", "repo": "security", "material_type": "security_repo_file", "content": "| Component | ID | Severity |\n| component_a | CVE-2026-99992 | High |", "source_url": "https://example.com/a.md"},
        {"org": "openharmony", "repo": "security", "material_type": "security_repo_file", "content": "| Component | ID | Severity |\n| component_b | CVE-2026-99992 | High |", "source_url": "https://example.com/b.md"},
    ]
    result = build_cve_scout_from_local_records(projects, None, materials)
    project = result["orgs"]["openharmony"]["projects"]["component_b"]
    assert project["cve_count"] == 1
    assert "component_b" in project["cves"][0].get("source_repos", [])


def test_cve_scout_skips_security_repo_reparse_when_org_materials_present() -> None:
    projects = [
        {
            "org": "openharmony",
            "name": "security",
            "url": "https://gitcode.com/openharmony/security",
            "description": "security disclosure",
            "star_count": 10,
            "is_security_repo": True,
            "security_files": [{"content": "kernel_linux CVE-2026-00001", "source_url": "https://example.com/security.md"}],
        }
    ]
    assert _security_pool_from_connector_materials(projects, include_security_repo_projects=True)
    assert _security_pool_from_connector_materials(projects, include_security_repo_projects=False) == []


def test_cve_scout_matches_pool_source_repo_when_hints_missing() -> None:
    projects = [{"org": "openharmony", "name": "drivers_adapter", "url": "https://gitcode.com/openharmony/drivers_adapter", "description": "driver", "star_count": 30}]
    existing = {
        "openharmony": {
            "projects": {
                "security": {
                    "cves": [
                        {
                            "cve_id": "CVE-2026-22222",
                            "severity": "high",
                            "description": "monthly disclosure",
                            "source_type": "security_repo_file",
                            "source_repo": "drivers_adapter",
                            "project_hints": [],
                        }
                    ]
                }
            }
        }
    }

    result = build_cve_scout_from_local_records(projects, existing)
    project = result["orgs"]["openharmony"]["projects"]["drivers_adapter"]
    assert project["cve_count"] == 1
    assert project["scan_mode"] == "from_pool"


def test_cve_scout_reads_project_issue_items() -> None:
    projects = [
        {
            "org": "openharmony",
            "name": "kernel_linux",
            "url": "https://gitcode.com/openharmony/kernel_linux",
            "description": "kernel",
            "star_count": 30,
            "issues": [{"title": "CVE-2026-99999 kernel RCE", "description": "critical vulnerability"}],
        }
    ]
    result = build_cve_scout_from_local_records(projects, None)
    kernel = result["orgs"]["openharmony"]["projects"]["kernel_linux"]
    assert kernel["scan_mode"] == "scanned_local_materials"
    assert kernel["cve_count"] == 1
    assert kernel["cves"][0]["source_type"] == "project_issue"


def test_cve_coverage_audit_warns_when_security_repo_has_no_cve() -> None:
    audit = _coverage_audit({"meta": {"total_projects_in": 100, "total_sec_items": 0, "total_cve_ids": 0, "orgs_with_security_repo": ["openharmony"]}})
    assert audit["status"] == "warn"
    assert "未提取到明确 CVE" in audit["summary"]


def test_ascendhub_targets_cover_old_known_hub_list() -> None:
    assert len(DEFAULT_ASCENDHUB_TARGETS) == 86
    names = {item["name"] for item in DEFAULT_ASCENDHUB_TARGETS}
    assert {"mindie", "mindie-motor", "ascend-pytorch", "qwen3-32b"}.issubset(names)
