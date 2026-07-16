from __future__ import annotations

import json
from typing import Any


def to_json_text(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)
