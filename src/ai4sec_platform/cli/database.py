from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai4sec_platform.db.maintenance import backup_database, restore_database, verify_database


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Backup, verify, or restore the AI4SEC SQLite database")
    subparsers = parser.add_subparsers(dest="action", required=True)

    backup_parser = subparsers.add_parser("backup", help="Create a consistent online database backup")
    backup_parser.add_argument("--destination", type=Path)

    verify_parser = subparsers.add_parser("verify", help="Run SQLite integrity checks")
    verify_parser.add_argument("path", type=Path)

    restore_parser = subparsers.add_parser("restore", help="Restore a backup into a database file")
    restore_parser.add_argument("backup", type=Path)
    restore_parser.add_argument("--destination", type=Path, required=True)
    restore_parser.add_argument("--overwrite", action="store_true", help="Replace the destination; stop platform services first")

    args = parser.parse_args(argv)
    if args.action == "backup":
        path = backup_database(args.destination)
        print(json.dumps(verify_database(path), ensure_ascii=False))
        return 0
    if args.action == "verify":
        print(json.dumps(verify_database(args.path), ensure_ascii=False))
        return 0
    path = restore_database(args.backup, args.destination, overwrite=args.overwrite)
    print(json.dumps(verify_database(path), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
