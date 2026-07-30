from __future__ import annotations

import json

import pytest

from ai4sec_platform.cli.import_news_legacy_raw import _legacy_import_lock, import_news_legacy_raw, main
from ai4sec_platform.core.config import load_settings


def test_legacy_news_import_requires_explicit_confirmation(tmp_path) -> None:
    with pytest.raises(SystemExit):
        main(["--source-dir", str(tmp_path), "--date", "2026-07-10"])


def test_legacy_news_import_rejects_duplicate_success(tmp_path) -> None:
    raw_dir = tmp_path / "legacy-news"
    raw_dir.mkdir()
    (raw_dir / "github_20260710.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "id": 1,
                        "full_name": "security/research",
                        "html_url": "https://github.com/security/research",
                        "description": "AI agent evaluation benchmark with automated testing and security validation",
                        "topics": ["agent", "evaluation", "benchmark", "security"],
                        "stargazers_count": 100,
                        "updated_at": "2026-07-10T00:00:00Z",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="missing sources"):
        import_news_legacy_raw(raw_dir, "2026-07-10")

    first = import_news_legacy_raw(raw_dir, "2026-07-10", allow_missing_sources=True)

    assert first["status"] == "success"
    with pytest.raises(ValueError, match="already completed"):
        import_news_legacy_raw(raw_dir, "2026-07-10", allow_missing_sources=True)


def test_legacy_news_import_rejects_concurrent_execution(tmp_path) -> None:
    raw_dir = tmp_path / "legacy-news"
    raw_dir.mkdir()
    (raw_dir / "github_20260710.json").write_text("[]", encoding="utf-8")
    settings = load_settings()

    with _legacy_import_lock(settings):
        with pytest.raises(RuntimeError, match="already running"):
            import_news_legacy_raw(
                raw_dir,
                "2026-07-10",
                allow_missing_sources=True,
                settings=settings,
            )
