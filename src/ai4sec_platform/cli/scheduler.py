from __future__ import annotations

import argparse
import json

from ai4sec_platform.pipelines.scheduler import PipelineScheduler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Queue due AI4SEC pipeline schedules")
    parser.add_argument("--once", action="store_true", help="Evaluate schedules once and exit")
    parser.add_argument("--poll-interval", type=float, default=30.0)
    args = parser.parse_args(argv)
    scheduler = PipelineScheduler()
    if args.once:
        print(json.dumps(scheduler.tick(), ensure_ascii=False))
        return 0
    scheduler.serve_forever(poll_interval=args.poll_interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
