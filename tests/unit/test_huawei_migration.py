from __future__ import annotations

from ai4sec_platform.domains.threats.comparators import compare_attack_surface_outputs, compare_cve_scout_outputs
from ai4sec_platform.domains.threats.cve_scout import build_cve_scout_from_local_records
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


def test_old_huawei_outputs_are_baseline_compare_only() -> None:
    old_cve = {"meta": {"total_projects_in": 1, "total_cve_ids": 1}, "orgs": {"openharmony": {"projects": {"kernel": {"cve_count": 1}}}}}
    new_cve = {"meta": {"total_projects_in": 1, "total_cve_ids": 0}, "orgs": {"openharmony": {"projects": {"kernel": {"cve_count": 0}}}}}
    cve_compare = compare_cve_scout_outputs(old_cve, new_cve)
    assert cve_compare["meta_diff"]["total_cve_ids"]["delta"] == -1
    assert cve_compare["project_diff_count"] == 1

    old_score = {"projects": [{"name": "kernel", "attack_surface_score": 87, "grade": "A", "filtered": False}]}
    new_score = [{"name": "kernel", "attack_surface_score": 70, "grade": "A", "filtered": False}]
    score_compare = compare_attack_surface_outputs(old_score, new_score)
    assert score_compare["diff_count"] == 1
