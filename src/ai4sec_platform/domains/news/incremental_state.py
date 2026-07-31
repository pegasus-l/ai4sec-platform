from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo


def load_news_incremental_states(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        "SELECT source, state_json FROM source_incremental_states WHERE domain = 'news' AND state_key = 'default'"
    ).fetchall()
    return {str(row["source"]): repo.loads(row["state_json"], {}) for row in rows}


def save_news_incremental_state(conn: sqlite3.Connection, source: str, state: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO source_incremental_states(domain, source, state_key, state_json, updated_at)
        VALUES ('news', ?, 'default', ?, ?)
        ON CONFLICT(domain, source, state_key) DO UPDATE SET
            state_json = excluded.state_json,
            updated_at = excluded.updated_at
        """,
        (source, repo.dumps(state), utc_now()),
    )
