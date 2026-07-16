from __future__ import annotations

import argparse

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db, reset_db
from ai4sec_platform.db.session import connect


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize AI4SEC platform SQLite database")
    parser.add_argument("--reset", action="store_true", help="Drop and recreate first-stage tables")
    args = parser.parse_args()
    settings = load_settings()
    with connect(settings) as conn:
        if args.reset:
            reset_db(conn)
        else:
            init_db(conn)
    print(settings.database_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
