from __future__ import annotations

import argparse

from ai4sec_platform.cli import audit_run, database, init_db, inspect_run, pipeline_worker, repro_worker, run_pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description="AI4SEC Platform CLI")
    parser.add_argument("command", choices=["init-db", "run-pipeline", "inspect-run", "audit-run", "database", "pipeline-worker", "repro-worker"])
    args, rest = parser.parse_known_args()
    if args.command == "init-db":
        return init_db.main()
    if args.command == "run-pipeline":
        return run_pipeline.main()
    if args.command == "inspect-run":
        return inspect_run.main(rest)
    if args.command == "audit-run":
        return audit_run.main(rest)
    if args.command == "database":
        return database.main(rest)
    if args.command == "pipeline-worker":
        return pipeline_worker.main(rest)
    if args.command == "repro-worker":
        return repro_worker.main(rest)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
