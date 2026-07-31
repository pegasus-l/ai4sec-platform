from __future__ import annotations

import sqlite3

from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.news.incremental_state import load_news_incremental_states, save_news_incremental_state


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def test_news_incremental_state_upserts_one_source_watermark() -> None:
    conn = connection()
    save_news_incremental_state(conn, "rss", {"scanned_ids": ["rss:1"]})
    save_news_incremental_state(conn, "rss", {"scanned_ids": ["rss:1", "rss:2"]})

    assert load_news_incremental_states(conn) == {"rss": {"scanned_ids": ["rss:1", "rss:2"]}}
    assert conn.execute("SELECT COUNT(*) FROM source_incremental_states").fetchone()[0] == 1


def test_news_incremental_state_participates_in_pipeline_transaction() -> None:
    conn = connection()
    save_news_incremental_state(conn, "rss", {"scanned_ids": ["rss:1"]})
    conn.commit()
    conn.execute("SAVEPOINT collect_news")
    save_news_incremental_state(conn, "rss", {"scanned_ids": ["rss:1", "rss:2"]})
    conn.execute("ROLLBACK TO SAVEPOINT collect_news")
    conn.execute("RELEASE SAVEPOINT collect_news")

    assert load_news_incremental_states(conn) == {"rss": {"scanned_ids": ["rss:1"]}}
