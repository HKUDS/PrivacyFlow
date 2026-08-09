from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gateway.mapping_store import MappingStore


class AuditLogger:
    def __init__(self, path: str, operation_store: MappingStore | None = None) -> None:
        self.path = Path(path)
        self.operation_store = operation_store
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def log(self, event: dict[str, Any]) -> None:
        source = dict(event)
        source.setdefault("timestamp", int(time.time()))
        operations = _collect_audit_operations(source)
        operation_error = False
        if operations and self.operation_store is not None:
            try:
                self.operation_store.record_audit_operations(
                    request_id=str(source.get("request_id") or ""),
                    session_id=str(source.get("session_id") or ""),
                    workspace_id=str(source.get("workspace_id") or ""),
                    endpoint=str(source.get("endpoint") or ""),
                    timestamp=int(source["timestamp"]),
                    operations=operations,
                )
            except (OSError, sqlite3.Error, TypeError, ValueError):
                operation_error = True
        safe = scrub_audit_value(source)
        if operation_error:
            safe["audit_operation_capture_error"] = True
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
            if k not in {
                "raw",
                "value",
                "secret",
                "handle",
                "handle_id",
                "fingerprint",
                "_audit_operation",
                "_audit_operations",
            }
        }
    if isinstance(value, list):
        return [scrub_audit_value(v, depth + 1) for v in value]
    if isinstance(value, str):
        for marker in _SCRUB_MARKERS:
            if marker in value:
                return "<redacted>"
    return value


_SCRUB_MARKERS = (
    "<APG",           # Signed APG placeholders and redaction markers
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


def _collect_audit_operations(value: Any) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            operation = node.get("_audit_operation")
            if isinstance(operation, dict):
                operations.append(operation)
            operation_list = node.get("_audit_operations")
            if isinstance(operation_list, list):
                operations.extend(item for item in operation_list if isinstance(item, dict))
            for key, item in node.items():
                if key not in {"_audit_operation", "_audit_operations"}:
                    walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return operations
