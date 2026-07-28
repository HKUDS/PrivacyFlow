from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

FindingType = Literal[
    "MACHINE_SECRET",
    "PII",
    "LOCAL_CONTEXT",
    "APG_MARKER",
    "CREDENTIAL_FILE",
    "UNKNOWN_SECRET_CANDIDATE",
]
Risk = Literal["low", "medium", "high", "critical"]
SuggestedAction = Literal["allow", "warn", "redact", "pseudonymize", "block", "require_approval", "secret_handle"]
SourceKind = Literal[
    "prompt",
    "file",
    "tool_result",
    "model_response",
    "tool_call_argument",
    "file_write_content",
    "audit_log",
    "json",
    "text",
]


@dataclass(frozen=True)
class SourceBlock:
    id: str
    text: str
    kind: SourceKind = "text"
    source_path: str | None = None
    json_pointer: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_text(
        cls,
        text: str,
        *,
        kind: SourceKind = "text",
        source_path: str | None = None,
        json_pointer: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "SourceBlock":
        fingerprint = hashlib.sha256(f"{kind}:{source_path}:{json_pointer}:{text[:256]}".encode("utf-8")).hexdigest()[:12]
        return cls(f"blk_{fingerprint}", text, kind, source_path, json_pointer, metadata or {})


@dataclass(frozen=True)
class Finding:
    id: str
    source_block_id: str
    original_start: int
    original_end: int
    normalized_start: int
    normalized_end: int
    type: FindingType
    subtype: str
    risk: Risk
    detectors: tuple[str, ...]
    validators: tuple[str, ...] = ()
    suggested_action: SuggestedAction = "warn"
    safe_preview: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def make(
        cls,
        *,
        source_block_id: str,
        original_start: int,
        original_end: int,
        normalized_start: int,
        normalized_end: int,
        type: FindingType,
        subtype: str,
        risk: Risk,
        detector: str,
        validators: tuple[str, ...] = (),
        suggested_action: SuggestedAction = "warn",
        safe_preview: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> "Finding":
        return cls(
            id=f"fnd_{uuid.uuid4().hex[:12]}",
            source_block_id=source_block_id,
            original_start=original_start,
            original_end=original_end,
            normalized_start=normalized_start,
            normalized_end=normalized_end,
            type=type,
            subtype=subtype,
            risk=risk,
            detectors=(detector,),
            validators=validators,
            suggested_action=suggested_action,
            safe_preview=safe_preview,
            metadata=metadata or {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_block_id": self.source_block_id,
            "original_start": self.original_start,
            "original_end": self.original_end,
            "normalized_start": self.normalized_start,
            "normalized_end": self.normalized_end,
            "type": self.type,
            "subtype": self.subtype,
            "risk": self.risk,
            "detectors": list(self.detectors),
            "validators": list(self.validators),
            "suggested_action": self.suggested_action,
            "safe_preview": self.safe_preview,
            "metadata": self.metadata,
        }


def safe_preview(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "<hidden>"
    return f"{value[:keep]}...{value[-keep:]}"


def merge_findings(primary: Finding, others: list[Finding]) -> Finding:
    all_findings = [primary, *others]
    detectors = tuple(dict.fromkeys(d for f in all_findings for d in f.detectors))
    validators = tuple(dict.fromkeys(v for f in all_findings for v in f.validators))
    risk_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    risk = max((f.risk for f in all_findings), key=lambda r: risk_order[r])
    return Finding(
        id=primary.id,
        source_block_id=primary.source_block_id,
        original_start=min(f.original_start for f in all_findings),
        original_end=max(f.original_end for f in all_findings),
        normalized_start=min(f.normalized_start for f in all_findings),
        normalized_end=max(f.normalized_end for f in all_findings),
        type=primary.type,
        subtype=primary.subtype,
        risk=risk,
        detectors=detectors,
        validators=validators,
        suggested_action=primary.suggested_action,
        safe_preview=primary.safe_preview,
        metadata={**primary.metadata, "merged_count": len(all_findings)},
    )
