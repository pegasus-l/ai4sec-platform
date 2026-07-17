from __future__ import annotations

from pathlib import Path

from ai4sec_platform.pipelines.registry import default_registry
from ai4sec_platform.sources.registry import SourceRegistry


ROOT = Path(__file__).resolve().parents[2]


def test_architecture_scaffold_files_exist() -> None:
    expected = [
        "src/ai4sec_platform/app/main.py",
        "src/ai4sec_platform/core/config.py",
        "src/ai4sec_platform/db/models/__init__.py",
        "src/ai4sec_platform/db/repositories/__init__.py",
        "src/ai4sec_platform/schemas/items.py",
        "src/ai4sec_platform/sources/base.py",
        "src/ai4sec_platform/artifacts/store.py",
        "src/ai4sec_platform/pipelines/runner.py",
        "src/ai4sec_platform/domains/news/pipelines.py",
        "src/ai4sec_platform/domains/capabilities/pipelines.py",
        "src/ai4sec_platform/domains/threats/pipelines.py",
        "src/ai4sec_platform/domains/threats/cve_scout.py",
        "src/ai4sec_platform/domains/threats/security_repo_discovery.py",
        "src/ai4sec_platform/domains/threats/security_file_parsers.py",
        "src/ai4sec_platform/sources/connectors/threats/gitcode.py",
        "src/ai4sec_platform/domains/vulnerabilities/pipelines.py",
        "src/ai4sec_platform/agents/base.py",
        "src/ai4sec_platform/models/router.py",
        "src/ai4sec_platform/ops/quality.py",
        "src/ai4sec_platform/cli/main.py",
    ]
    missing = [item for item in expected if not (ROOT / item).exists()]
    assert missing == []


def test_pipeline_registry_has_all_domain_entries() -> None:
    names = {item["name"] for item in default_registry().list()}
    assert "news.ai_for_sec_raw_pipeline" in names
    assert "news.ai_for_sec_local_raw_import" in names
    assert "capabilities.assessment_placeholder" not in names
    assert "threats.huawei_raw_pipeline" in names
    assert "threats.huawei_local_raw_import" in names
    assert "threats.huawei_cve_scout_pipeline" in names
    assert "threats.huawei_attack_surface_pipeline" in names
    assert "threats.huawei_asset_pipeline" in names
    assert "threats.huawei_full_migration_pipeline" in names
    assert "threats.risk_reasoning_pipeline" in names
    assert "vulnerabilities.material_raw_pipeline" in names
    assert "vulnerabilities.material_local_raw_import" in names
    assert "vulnerabilities.knowledge_extraction_pipeline" in names
    assert "legacy.sample_import" not in names


def test_source_registry_has_expected_connectors() -> None:
    registry_items = SourceRegistry().list()
    names = {item["connector_name"] for item in registry_items}
    assert {"arxiv", "github", "rss", "anysearch", "huawei_repo", "cve", "firmware", "gitcode", "atomgit", "hiascend", "huawei_mirror", "openx_huawei"}.issubset(names)
    assert {item["mode"] for item in registry_items} == {"local_raw_file_only"}
