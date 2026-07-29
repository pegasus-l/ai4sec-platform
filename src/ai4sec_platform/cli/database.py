from __future__ import annotations

import argparse
import json
from pathlib import Path

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.maintenance import BackupRetentionPolicy, backup_database, checkpoint_wal, prune_database_backups, restore_database, verify_database


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

    checkpoint_parser = subparsers.add_parser("checkpoint", help="Run a controlled SQLite WAL checkpoint")
    checkpoint_parser.add_argument("--mode", choices=["passive", "full", "restart", "truncate"], default="passive")

    args = parser.parse_args(argv)
    if args.action == "backup":
        settings = load_settings()
        path = backup_database(args.destination, settings)
        retention = BackupRetentionPolicy(
            daily_days=settings.backup_daily_retention_days,
            weekly_weeks=settings.backup_weekly_retention_weeks,
            monthly_months=settings.backup_monthly_retention_months,
        )
        removed = prune_database_backups(path.parent, retention)
        result = verify_database(path)
        result["retention"] = {
            "daily_days": retention.daily_days,
            "weekly_weeks": retention.weekly_weeks,
            "monthly_months": retention.monthly_months,
        }
        result["removed_backups"] = [str(item) for item in removed]
        print(json.dumps(result, ensure_ascii=False))
        return 0
    if args.action == "verify":
        print(json.dumps(verify_database(args.path), ensure_ascii=False))
        return 0
    if args.action == "checkpoint":
        print(json.dumps(checkpoint_wal(args.mode), ensure_ascii=False))
        return 0
    path = restore_database(args.backup, args.destination, overwrite=args.overwrite)
    print(json.dumps(verify_database(path), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
