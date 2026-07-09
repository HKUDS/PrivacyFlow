from __future__ import annotations

from typing import Any

from gateway.redaction_engine import RedactionEngine


class ResponseScanner:
    def __init__(self, redaction_engine: RedactionEngine) -> None:
        self.redaction_engine = redaction_engine

    def scan_response_json(self, data: Any, session_id: str) -> tuple[Any, list[dict[str, Any]]]:
        # Pass 1: materialize placeholders back to raw values ONLY inside
        # structured tool-call argument fields. This is the transparent path
        # that lets an agent harness receive real secrets to execute a tool.
        materialized = self.redaction_engine.materialize_local_tool_args(data, session_id)
        # Pass 2: redact any echoed secrets/PII in every other string field
        # (assistant-visible text, reasoning, etc.) but skip tool-call args
        # so the values we just materialized are not re-redacted away.
        return self.redaction_engine.sanitize_json(
            materialized, session_id, scope="response", alias_paths=False, skip_tool_args=True
        )