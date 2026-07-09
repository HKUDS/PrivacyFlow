from __future__ import annotations

from typing import Any


def all_strings(data: Any) -> list[str]:
    found: list[str] = []
    if isinstance(data, str):
        found.append(data)
    elif isinstance(data, list):
        for item in data:
            found.extend(all_strings(item))
    elif isinstance(data, dict):
        for value in data.values():
            found.extend(all_strings(value))
    return found
