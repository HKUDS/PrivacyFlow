from __future__ import annotations

from urllib.parse import urlparse


def database_url_has_password(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme.lower() in {"postgres", "postgresql", "mysql", "mongodb", "redis"} and bool(parsed.password)
