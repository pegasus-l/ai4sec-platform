from __future__ import annotations

import argparse

from ai4sec_platform.cli import audit_run, import_legacy_samples, init_db, inspect_run, run_pipeline


def main() -> int:
    parser = argparse.ArgumentParser(description="AI4SEC Platform CLI")
    parser.add_argument("command", choices=["init-db", "import-legacy", "run-pipeline", "inspect-run", "audit-run"])
    args, rest = parser.parse_known_args()
    if args.command == "init-db":
        return init_db.main()
    if args.command == "import-legacy":
        return import_legacy_samples.main()
    if args.command == "run-pipeline":
        return run_pipeline.main()
    if args.command == "inspect-run":
        return inspect_run.main(rest)
    if args.command == "audit-run":
        return audit_run.main(rest)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
