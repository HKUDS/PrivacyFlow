from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Detection:
    span_start: int
    span_end: int
    type: str
    subtype: str
    risk: str
    detector_name: str
    suggested_action: str
    safe_preview: str = ""

    @property
    def kind(self) -> str:
        if self.type in {"secret", "path", "pii"}:
            return self.type
        # Unknown types: map MACHINE_SECRET-like types to "secret", others to "other"
        # This avoids silently treating non-sensitive detector output as secrets
        if self.type in {"CREDENTIAL_FILE", "APG_MARKER", "UNKNOWN_SECRET_CANDIDATE"}:
            return "secret"
        return "other"


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    action: str
    reason_code: str
    safe_user_message: str = ""
    retryable: bool = False
    next_action: str | None = None


@dataclass(frozen=True)
class MaterializationResult:
    allowed: bool
    value: str | None
    error_code: str | None = None
    retryable: bool = False
    next_action: str | None = None
