from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.services.domain_items import detail


def get_or_404_payload(conn: sqlite3.Connection, domain: str, item_id: int) -> dict[str, Any] | None:
    return detail(conn, domain, item_id)
