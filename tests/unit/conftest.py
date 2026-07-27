from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_unit_test_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("AI4SEC_DATABASE_PATH", str(tmp_path / "ai4sec-test.db"))
    monkeypatch.setenv("AI4SEC_OUTPUT_DIR", str(tmp_path / "output"))
