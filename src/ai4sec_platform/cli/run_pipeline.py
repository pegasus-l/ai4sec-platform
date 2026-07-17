from __future__ import annotations

import argparse
import json

from ai4sec_platform.pipelines.runner import PipelineRunner


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an AI4SEC platform pipeline")
    parser.add_argument("--pipeline", default="news.ai_for_sec_local_raw_import")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    result = PipelineRunner().run(args.pipeline, {"reset": args.reset})
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
