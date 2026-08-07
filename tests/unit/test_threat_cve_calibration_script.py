import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).parents[2] / "scripts" / "audit_threat_cve_calibration.py"
_SPEC = importlib.util.spec_from_file_location("audit_threat_cve_calibration", _MODULE_PATH)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
classify = _MODULE.classify


def test_classify_separates_coordination_duplicates_and_fanout() -> None:
    rows = [
        {"org": "openeuler", "project": "release-management", "cve_id": "CVE-2026-10001", "source_type": "project_issue"},
        {"org": "openeuler", "project": "kernel", "cve_id": "CVE-2026-10001", "source_type": "project_issue"},
        {"org": "openeuler", "project": "kernel", "cve_id": "CVE-2026-10001", "source_type": "security_repo_issue"},
        {"org": "mindspore", "project": "mindspore", "cve_id": "CVE-2026-10001", "source_type": "project_issue"},
        {"org": "cann", "project": "ge", "cve_id": "CVE-2026-10001", "source_type": "project_issue"},
    ]

    report = classify(rows)

    assert report["rows"] == 5
    assert report["unique_cves"] == 1
    assert report["coordination_rows"] == 1
    assert report["multi_project_cves"] == 1
    assert report["fanout_distribution"] == {4: 1}
    assert report["duplicate_groups"] == [
        {"org": "openeuler", "project": "kernel", "cve_id": "CVE-2026-10001", "rows": 2}
    ]
    assert report["high_fanout"][0]["fanout"] == 4
