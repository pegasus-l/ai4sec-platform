import json
from types import SimpleNamespace

from ai4sec_platform.domains.threats.cve_authority import validate_high_fanout_cves
from ai4sec_platform.domains.threats.normalizers import normalize_huawei_item
from ai4sec_platform.domains.threats.pipelines import huawei_cve_scout_pipeline, huawei_full_migration_pipeline
from ai4sec_platform.domains.threats.risk_scoring import score_threat_item
from ai4sec_platform.pipelines.steps.threat_cve_authority import ValidateThreatCveAuthorityStep


def _scout() -> dict:
    return {
        "orgs": {
            "cann": {
                "projects": {
                    "ge": {
                        "cves": [
                            {
                                "cve_id": "CVE-2026-42033",
                                "description": "漏洞归属组件：boost 漏洞归属的版本：1.87.0 CVSS分值：7.5",
                                "source_url": "https://gitcode.com/cann/ge/issues/1",
                            }
                        ]
                    }
                }
            },
            "openUBMC": {
                "projects": {
                    "webui": {
                        "cves": [
                            {
                                "cve_id": "CVE-2026-42033",
                                "description": "漏洞归属组件：axios 漏洞归属的版本：1.12.0 CVSS分值：7.5",
                                "source_url": "https://gitcode.com/openUBMC/webui/issues/1",
                            }
                        ]
                    }
                }
            },
        }
    }


def test_cached_authority_marks_only_conflicting_association(tmp_path) -> None:
    cache_dir = tmp_path / "authority"
    cache_dir.mkdir()
    (cache_dir / "CVE-2026-42033.json").write_text(
        json.dumps(
            {
                "cveMetadata": {"state": "PUBLISHED"},
                "containers": {"cna": {"affected": [{"product": "axios"}]}},
            }
        ),
        encoding="utf-8",
    )
    scout = _scout()

    metrics = validate_high_fanout_cves(scout, cache_dir=cache_dir, mode="cache", min_fanout=2)

    conflicting = scout["orgs"]["cann"]["projects"]["ge"]["cves"][0]
    matching = scout["orgs"]["openUBMC"]["projects"]["webui"]["cves"][0]
    assert metrics["status_counts"] == {"authoritative_match": 1, "component_mismatch": 1}
    assert metrics["cache_hits"] == 1
    assert conflicting["risk_eligible"] is False
    assert conflicting["authority_validation"]["status"] == "component_mismatch"
    assert matching.get("risk_eligible", True) is True


def test_component_mismatch_is_retained_but_excluded_from_risk() -> None:
    normalized = normalize_huawei_item(
        "cve_findings",
        {
            "org": "cann",
            "name": "ge",
            "cves": [
                {"cve_id": "CVE-2026-42033", "severity": "critical", "risk_eligible": False},
                {"cve_id": "CVE-2026-00001", "severity": "high"},
            ],
        },
    )
    scoring = score_threat_item(normalized)

    assert normalized["cve_count"] == 2
    assert normalized["direct_cve_count"] == 1
    assert normalized["review_cve_count"] == 1
    assert scoring.breakdown["cve"] == 6
    assert scoring.signals["direct_max_severity"] == "high"
    assert any("待复核 CVE 1 个" in reason for reason in scoring.reasons)


def test_invalid_cache_does_not_mark_association_as_mismatch(tmp_path) -> None:
    cache_dir = tmp_path / "authority"
    cache_dir.mkdir()
    (cache_dir / "CVE-2026-42033.json").write_text("invalid", encoding="utf-8")
    scout = _scout()

    metrics = validate_high_fanout_cves(scout, cache_dir=cache_dir, mode="cache", min_fanout=2)

    assert metrics["status_counts"] == {"authority_missing": 2}
    for org_data in scout["orgs"].values():
        for project in org_data["projects"].values():
            assert project["cves"][0].get("risk_eligible", True) is True


def test_identifier_mismatch_is_local_and_does_not_require_fanout(tmp_path) -> None:
    scout = {
        "orgs": {
            "cann": {
                "projects": {
                    "ge": {
                        "cves": [
                            {
                                "cve_id": "CVE-2026-42040",
                                "description": "漏洞编号：CVE-2026-42033 漏洞归属组件：boost CVSS分值：7.5",
                            }
                        ]
                    }
                }
            }
        }
    }

    metrics = validate_high_fanout_cves(scout, cache_dir=tmp_path, mode="cache", min_fanout=5)

    finding = scout["orgs"]["cann"]["projects"]["ge"]["cves"][0]
    assert metrics["selected_cves"] == 0
    assert metrics["status_counts"] == {"identifier_mismatch": 1}
    assert finding["risk_eligible"] is False
    assert finding["authority_validation"]["declared_cve_ids"] == ["CVE-2026-42033"]


def test_explicit_cve_id_prevents_description_cross_counting() -> None:
    normalized = normalize_huawei_item(
        "cve_findings",
        {
            "org": "cann",
            "name": "ge",
            "cves": [
                {
                    "cve_id": "CVE-2026-42040",
                    "description": "正文错误引用 CVE-2026-42033",
                }
            ],
        },
    )

    scoring = score_threat_item(normalized)

    assert scoring.signals["cve_ids"] == ["CVE-2026-42040"]
    assert scoring.signals["direct_cve_count"] == 1


def test_authority_step_follows_scout_and_defaults_to_off() -> None:
    scout_steps = [step.name for step in huawei_cve_scout_pipeline().steps]
    full_steps = [step.name for step in huawei_full_migration_pipeline().steps]

    assert scout_steps == ["huawei_cve_scout", "validate_threat_cve_authority"]
    assert full_steps.index("validate_threat_cve_authority") == full_steps.index("huawei_cve_scout") + 1
    result = ValidateThreatCveAuthorityStep().run(SimpleNamespace(params={}))
    assert result.metrics == {"mode": "off", "skipped": True}
