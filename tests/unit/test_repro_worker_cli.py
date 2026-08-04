from __future__ import annotations

from ai4sec_platform.cli import repro_worker


def test_check_config_uses_task_managed_model_token(monkeypatch, capsys) -> None:
    received: dict[str, object] = {}

    def fake_validate(**kwargs):
        received.update(kwargs)
        return None

    monkeypatch.setattr(repro_worker, "validate_repro_runtime_config", fake_validate)

    assert repro_worker.main(["--check-config", "--profile", "nested_docker"]) == 0
    assert received == {
        "check_image": True,
        "require_token": False,
        "execution_profile": "nested_docker",
    }
    assert '"ok": true' in capsys.readouterr().out
