from __future__ import annotations

import argparse
import json

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db, reset_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.importers.seed_demo_data import import_all_legacy_samples


def main() -> int:
    parser = argparse.ArgumentParser(description="Import first-stage demo samples from existing legacy outputs")
    parser.add_argument("--reset", action="store_true", help="Reset database before importing")
    args = parser.parse_args()
    settings = load_settings()
    with connect(settings) as conn:
        if args.reset:
            reset_db(conn)
        else:
            init_db(conn)
        results = import_all_legacy_samples(conn, settings)
    print(json.dumps({"database": str(settings.database_path), "results": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
