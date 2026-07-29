from __future__ import annotations

import argparse
import json
import sys

from ai4sec_platform.domains.capabilities.repro_worker import CapabilityReproWorker
from ai4sec_platform.domains.capabilities.adapters.repro_runner import validate_repro_runtime_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the single-host persistent capability reproduction worker")
    parser.add_argument("--once", action="store_true", help="Process at most one queued task and exit")
    parser.add_argument("--task-id", type=int, help="With --once, claim only this task")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--recover-only", action="store_true", help="Reconcile interrupted tasks and exit")
    parser.add_argument("--check-config", action="store_true", help="Validate model gateway and Secret file configuration")
    args = parser.parse_args(argv)
    worker = CapabilityReproWorker()
    try:
        if args.check_config:
            token_path = validate_repro_runtime_config(check_image=True)
            print(json.dumps({"ok": True, "token_file": str(token_path)}, ensure_ascii=False))
            return 0
        if args.recover_only:
            print(json.dumps({"recovered": worker.recover()}, ensure_ascii=False))
            return 0
        if args.once:
            print(json.dumps(worker.run_once(task_id=args.task_id), ensure_ascii=False, default=str))
            return 0
        worker.serve_forever(poll_interval=max(args.poll_interval, 0.1))
        return 0
    except RuntimeError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
