from __future__ import annotations

import argparse
import json

from ai4sec_platform.pipelines.worker import PipelineWorker


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the single-host persistent AI4SEC pipeline worker")
    parser.add_argument("--once", action="store_true", help="Process at most one queued job and exit")
    parser.add_argument("--run-id", help="With --once, claim only this queued run")
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--recover-only", action="store_true", help="Mark only lease-expired running jobs failed and exit")
    args = parser.parse_args(argv)
    worker = PipelineWorker()
    if args.recover_only:
        print(json.dumps({"recovered": worker.recover()}, ensure_ascii=False))
        return 0
    if args.once:
        print(json.dumps(worker.run_once(run_id=args.run_id), ensure_ascii=False, default=str))
        return 0
    worker.serve_forever(poll_interval=max(args.poll_interval, 0.1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
