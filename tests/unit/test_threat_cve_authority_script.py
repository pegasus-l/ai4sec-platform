import importlib.util
from pathlib import Path


_MODULE_PATH = Path(__file__).parents[2] / "scripts" / "audit_threat_cve_authority.py"
_SPEC = importlib.util.spec_from_file_location("audit_threat_cve_authority", _MODULE_PATH)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


def test_compare_component_accepts_product_aliases_and_rejects_conflicts() -> None:
    assert _MODULE.compare_component("protobuf", ["protobuf-cpp", "protobuf-python"]) == "authoritative_match"
    assert _MODULE.compare_component("numpy", ["Picklescan"]) == "component_mismatch"
    assert _MODULE.compare_component("", ["axios"]) == "component_missing"


def test_build_report_marks_each_project_association() -> None:
    rows = [
        {
            "org": "cann",
            "project": "ge",
            "cve_id": "CVE-2026-42033",
            "description": "漏洞归属组件：boost 漏洞归属的版本：1.87.0 CVSS分值：7.5",
            "source_url": "https://gitcode.com/cann/ge/issues/1",
        },
        {
            "org": "openUBMC",
            "project": "webui",
            "cve_id": "CVE-2026-42033",
            "description": "漏洞归属组件：axios 漏洞归属的版本：1.12.0 CVSS分值：7.5",
            "source_url": "https://gitcode.com/openUBMC/webui/issues/1",
        },
    ]
    authority = {
        "CVE-2026-42033": {
            "cveMetadata": {"state": "PUBLISHED"},
            "containers": {"cna": {"affected": [{"product": "axios"}]}},
        }
    }

    report = _MODULE.build_report(rows, authority, min_fanout=2)

    assert report["reviewed_cves"] == 1
    assert report["status_counts"] == {"authoritative_match": 1, "component_mismatch": 1}
    associations = report["findings"][0]["associations"]
    assert associations[0]["status"] == "component_mismatch"
    assert associations[1]["status"] == "authoritative_match"
