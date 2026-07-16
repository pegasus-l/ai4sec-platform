from __future__ import annotations


def identity_key(item: dict) -> str:
    return item.get("url") or item.get("title") or repr(item)
