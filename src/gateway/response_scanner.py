from __future__ import annotations

from typing import Any

from gateway.redaction_engine import RedactionEngine


class ResponseScanner:
    def __init__(self, redaction_engine: RedactionEngine) -> None:
        self.redaction_engine = redaction_engine

    def scan_response_json(self, data: Any, session_id: str) -> tuple[Any, list[dict[str, Any]]]:
        # Pass 1: materialize exact valid placeholders in structured tool-call
        # arguments. Pass 2 scans all other response-visible strings; that
        # scanner restores valid placeholders for the local user while still
        # folding raw values echoed directly by the remote model.
        materialized, materialization_events = self.redaction_engine.materialize_local_tool_args_with_events(
            data,
            session_id,
        )
        sanitized, scan_events = self.redaction_engine.scan_local_json(materialized, session_id, skip_tool_args=True)
        return sanitized, [*materialization_events, *scan_events]
