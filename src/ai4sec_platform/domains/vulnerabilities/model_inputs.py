from __future__ import annotations

import os


def prepare_model_input(text: str, *, profile: str) -> tuple[str, bool]:
    profile_key = profile.upper().replace("-", "_")
    raw_limit = os.getenv(f"AI4SEC_{profile_key}_MAX_INPUT_CHARS", os.getenv("AI4SEC_MODEL_MAX_INPUT_CHARS", "0"))
    try:
        limit = int(raw_limit)
    except ValueError:
        limit = 0
    if limit > 0 and len(text) > limit:
        return text[:limit], True
    return text, False
