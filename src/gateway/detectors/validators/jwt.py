from __future__ import annotations

import base64
import json


def jwt_header_valid(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header = _b64url_json(parts[0])
        payload = _b64url_json(parts[1])
    except Exception:
        return False
    return isinstance(header, dict) and isinstance(payload, dict) and ("alg" in header or "typ" in header)


def _b64url_json(value: str) -> object:
    padded = value + "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
