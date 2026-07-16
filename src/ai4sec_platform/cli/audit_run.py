from __future__ import annotations

import argparse
import json

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.session import connect
from ai4sec_platform.ops.quality import record_quality_audit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a lightweight audit record for a run")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--domain", default="operations")
    args = parser.parse_args(argv)
    with connect() as conn:
        run = conn.execute("SELECT * FROM pipeline_runs WHERE run_id = ?", (args.run_id,)).fetchone()
        status = "pass" if run and run["status"] == "success" else "warn"
        record_quality_audit(conn, domain=args.domain, audit_type="manual_run_audit", status=status, summary=f"Run {args.run_id} status: {run['status'] if run else 'missing'}", details={"run_id": args.run_id})
        conn.commit()
        audits = repo.list_table(conn, "quality_audits", domain=args.domain, limit=5)
    print(json.dumps({"status": status, "audits": audits}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
