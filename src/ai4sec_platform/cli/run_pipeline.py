from __future__ import annotations

import argparse
import json

from ai4sec_platform.pipelines.runner import PipelineRunner


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an AI4SEC platform pipeline")
    parser.add_argument("--pipeline", default="news.legacy_raw_pipeline")
    parser.add_argument("--reset", action="store_true")
    parser.add_argument("--params", default="{}", help="JSON object merged into pipeline params")
    args = parser.parse_args()
    params = json.loads(args.params)
    if not isinstance(params, dict):
        raise SystemExit("--params must be a JSON object")
    params["reset"] = args.reset
    result = PipelineRunner().run(args.pipeline, params)
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
