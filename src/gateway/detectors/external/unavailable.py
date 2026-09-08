from __future__ import annotations


class ExternalToolUnavailable(RuntimeError):
    """Built-in external scanner names are reserved but not implemented."""

    code = "external_tool_unavailable"

    def __init__(self, name: str = "") -> None:
        label = name or "external tool"
        super().__init__(f"{label} is not implemented")
        self.name = name
