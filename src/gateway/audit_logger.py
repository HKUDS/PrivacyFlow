from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def log(self, event: dict[str, Any]) -> None:
        safe = scrub_audit_value(event)
        safe.setdefault("timestamp", int(time.time()))
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(safe, sort_keys=True) + "\n")
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass


def scrub_audit_value(value: Any, depth: int = 0) -> Any:
    """Return an audit-safe copy without raw values or APG capabilities."""
    if depth > 10:
        return "<max_depth>"
    if isinstance(value, dict):
        return {
            k: scrub_audit_value(v, depth + 1)
            for k, v in value.items()
            if k not in {"raw", "value", "secret", "handle", "handle_id", "fingerprint"}
        }
    if isinstance(value, list):
        return [scrub_audit_value(v, depth + 1) for v in value]
    if isinstance(value, str):
        for marker in _SCRUB_MARKERS:
            if marker in value:
                return "<redacted>"
    return value


_SCRUB_MARKERS = (
    "<APG",           # Signed/legacy APG placeholders and redaction markers
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
