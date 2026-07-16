from __future__ import annotations


def current_user() -> dict[str, str]:
    return {"id": "local", "name": "local-user", "role": "developer"}
