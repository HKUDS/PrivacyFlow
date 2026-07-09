from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: dict[str, Any]) -> None:
        safe = _scrub(event)
        safe.setdefault("timestamp", int(time.time()))
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(safe, sort_keys=True) + "\n")


def _scrub(value: Any, depth: int = 0) -> Any:
    if depth > 10:
        return "<max_depth>"
    if isinstance(value, dict):
        return {k: _scrub(v, depth + 1) for k, v in value.items() if k not in {"raw", "value", "secret"}}
    if isinstance(value, list):
        return [_scrub(v, depth + 1) for v in value]
    if isinstance(value, str):
        for marker in _SCRUB_MARKERS:
            if marker in value:
                return "<redacted>"
    return value


_SCRUB_MARKERS = (
    "sk-",            # OpenAI / general API key prefix
    "-----BEGIN",     # PEM private key header
    "Bearer ",         # Bearer token prefix
    "ghp_",            # GitHub personal access token
    "gho_",            # GitHub OAuth token
    "ghu_",            # GitHub user-to-server token
    "ghs_",            # GitHub server-to-server token
    "ghr_",            # GitHub refresh token
    "hf_",             # HuggingFace token
    "xoxb-",           # Slack bot token
    "xoxp-",           # Slack user token
    "xoxa-",           # Slack app token
    "xoxr-",           # Slack refresh token
    "xoxs-",           # Slack signing secret prefix
    "AKIA",            # AWS access key
    "eyJ",             # JWT header prefix
    "tss_",            # GitHub token prefix (undocumented format)
)
