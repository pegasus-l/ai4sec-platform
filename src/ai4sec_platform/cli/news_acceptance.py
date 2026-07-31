from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.news.acceptance import build_news_daily_acceptance, render_news_daily_acceptance_markdown
from ai4sec_platform.domains.news.adapters.sources import load_news_source_configs
from ai4sec_platform.models.router import LLMRouter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the three-cycle production acceptance report for news daily runs")
    parser.add_argument("--run-id", action="append", help="Specific news.daily_pipeline run; repeat for multiple cycles")
    parser.add_argument("--required-cycles", type=int, default=3)
    parser.add_argument("--no-write", action="store_true", help="Print JSON without writing acceptance files")
    args = parser.parse_args(argv)
    if args.required_cycles < 1 or args.required_cycles > 30:
        parser.error("--required-cycles must be between 1 and 30")
    settings = load_settings()
    source_configs = load_news_source_configs(settings.project_root)
    required_sources = [name for name, config in source_configs.items() if config.get("enabled", True)]
    disabled_sources = [name for name, config in source_configs.items() if not config.get("enabled", True)]
    with connect(settings) as conn:
        init_db(conn)
        report = build_news_daily_acceptance(
            conn,
            required_sources=required_sources,
            disabled_sources=disabled_sources,
            run_ids=args.run_id,
            required_cycles=args.required_cycles,
            current_model=LLMRouter().active_config("configured_model"),
        )
    if not args.no_write:
        output_dir = settings.output_dir / "acceptance" / "news"
        output_dir.mkdir(parents=True, exist_ok=True)
        generated_at = datetime.now(timezone.utc).isoformat()
        report["generated_at"] = generated_at
        json_path = output_dir / "news_daily_acceptance_latest.json"
        markdown_path = output_dir / "news_daily_acceptance_latest.md"
        report["output_files"] = [str(json_path), str(markdown_path)]
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        markdown_path.write_text(render_news_daily_acceptance_markdown(report), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
