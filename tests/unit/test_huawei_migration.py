from __future__ import annotations

from ai4sec_platform.domains.threats.cve_scout import build_cve_scout_from_local_records
from ai4sec_platform.domains.threats.adapters.huawei_sources import DEFAULT_ASCENDHUB_TARGETS
from ai4sec_platform.pipelines.steps.threat_cve_scout import _coverage_audit
from ai4sec_platform.domains.threats.security_file_parsers import parse_security_file
from ai4sec_platform.domains.threats.security_repo_discovery import discover_security_repos, group_projects_by_org


def test_security_repo_discovery_finds_primary_repo() -> None:
    projects = [
        {"org": "openharmony", "name": "security", "url": "https://gitcode.com/openharmony/security", "description": "security disclosures", "star_count": 10},
        {"org": "openharmony", "name": "kernel_linux", "url": "https://gitcode.com/openharmony/kernel_linux", "description": "kernel", "star_count": 20},
    ]
    result = discover_security_repos(group_projects_by_org(projects))
    assert result["openharmony"]["has_security_repo"] is True
    assert result["openharmony"]["primary_repo"]["name"] == "security"


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
