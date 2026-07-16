from __future__ import annotations

import argparse
import json

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.session import connect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect a pipeline run")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    with connect() as conn:
        row = conn.execute("SELECT * FROM pipeline_runs WHERE run_id = ?", (args.run_id,)).fetchone()
        if not row:
            print(json.dumps({"error": "run not found", "run_id": args.run_id}, ensure_ascii=False))
            return 1
        data = repo.row_to_dict(row)
        data["tasks"] = [repo.row_to_dict(item) for item in conn.execute("SELECT * FROM task_runs WHERE run_id = ? ORDER BY id", (args.run_id,)).fetchall()]
        data["artifacts"] = [repo.row_to_dict(item) for item in conn.execute("SELECT * FROM artifacts WHERE run_id = ? ORDER BY id", (args.run_id,)).fetchall()]
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
