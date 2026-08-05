from __future__ import annotations

import os
import socket
import sqlite3


def allocate_repro_web_port(conn: sqlite3.Connection) -> int | None:
    base = int(os.environ.get("REPRO_WEB_PORT_BASE", "18000"))
    max_port = int(os.environ.get("REPRO_WEB_PORT_MAX", "18999"))
    rows = conn.execute(
        "SELECT DISTINCT web_port FROM capability_repro_tasks WHERE web_port IS NOT NULL AND status IN ('queued', 'running')"
    ).fetchall()
    used = {row["web_port"] for row in rows}
    for port in range(base, max_port + 1):
        if port not in used and _port_is_available(port):
            return port
    return None


def _port_is_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True
