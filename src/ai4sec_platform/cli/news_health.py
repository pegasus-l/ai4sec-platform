from __future__ import annotations

import argparse
import json

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.news.health import NEWS_SOURCES, probe_news_sources


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe news source connectivity, authentication, quota, and health")
    parser.add_argument("--source", choices=NEWS_SOURCES, action="append")
    parser.add_argument("--timeout-seconds", type=int, default=10)
    args = parser.parse_args(argv)
    if args.timeout_seconds < 1 or args.timeout_seconds > 120:
        parser.error("--timeout-seconds must be between 1 and 120")
    settings = load_settings()
    with connect(settings) as conn:
        init_db(conn)
        results = probe_news_sources(conn, settings, args.source, timeout_seconds=args.timeout_seconds)
    print(json.dumps({"items": results}, ensure_ascii=False, indent=2))
    return 0 if all(item["status"] in {"healthy", "disabled"} for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
