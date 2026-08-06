from __future__ import annotations

import argparse

from ai4sec_platform.cli import audit_run, database, init_db, inspect_run, news_acceptance, news_health, pipeline_control, pipeline_worker, repro_regression, repro_worker, run_pipeline, scheduler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI4SEC Platform CLI")
    parser.add_argument("command", choices=["init-db", "run-pipeline", "inspect-run", "audit-run", "news-health", "news-acceptance", "database", "pipeline-worker", "repro-regression", "repro-worker", "scheduler", "pipeline-control"])
    args, rest = parser.parse_known_args(argv)
    if args.command == "init-db":
        return init_db.main()
    if args.command == "run-pipeline":
        return run_pipeline.main(rest)
    if args.command == "inspect-run":
        return inspect_run.main(rest)
    if args.command == "audit-run":
        return audit_run.main(rest)
    if args.command == "news-health":
        return news_health.main(rest)
    if args.command == "news-acceptance":
        return news_acceptance.main(rest)
    if args.command == "database":
        return database.main(rest)
    if args.command == "pipeline-worker":
        return pipeline_worker.main(rest)
    if args.command == "repro-worker":
        return repro_worker.main(rest)
    if args.command == "repro-regression":
        return repro_regression.main(rest)
    if args.command == "scheduler":
        return scheduler.main(rest)
    if args.command == "pipeline-control":
        return pipeline_control.main(rest)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
