from __future__ import annotations

from ai4sec_platform.cli import main as cli_main
from ai4sec_platform.cli import run_pipeline


def test_run_pipeline_cli_accepts_forwarded_arguments(monkeypatch, capsys) -> None:
    received: dict[str, object] = {}

    class FakeRunner:
        def run(self, pipeline_name, params):
            received.update({"pipeline_name": pipeline_name, "params": params})
            return {"run_id": "run-test", "status": "success"}

    monkeypatch.setattr(run_pipeline, "PipelineRunner", FakeRunner)

    result = cli_main.main([
        "run-pipeline",
        "--pipeline",
        "news.daily_pipeline",
        "--params",
        '{"mode":"shadow"}',
    ])

    assert result == 0
    assert received == {
        "pipeline_name": "news.daily_pipeline",
        "params": {"mode": "shadow", "reset": False},
    }
    assert '"run_id": "run-test"' in capsys.readouterr().out
