from __future__ import annotations

import argparse
import json

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.jobs import EXECUTION_KILL_SWITCH, is_execution_kill_switch_active, set_execution_kill_switch


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect or change the platform execution kill switch")
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("status")
    stop_parser = subparsers.add_parser("stop")
    stop_parser.add_argument("--reason", required=True)
    subparsers.add_parser("resume")
    args = parser.parse_args(argv)
    with connect(load_settings()) as conn:
        init_db(conn)
        if args.action == "status":
            row = conn.execute(
                "SELECT enabled, reason, updated_at FROM platform_controls WHERE control_key = ?",
                (EXECUTION_KILL_SWITCH,),
            ).fetchone()
            result = {
                "enabled": is_execution_kill_switch_active(conn),
                "reason": str(row["reason"]) if row else "",
                "updated_at": str(row["updated_at"]) if row else "",
            }
        else:
            result = set_execution_kill_switch(
                conn,
                enabled=args.action == "stop",
                reason=args.reason if args.action == "stop" else "",
            )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
