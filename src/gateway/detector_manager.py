from __future__ import annotations

from contextvars import ContextVar
from typing import Any

from gateway.detectors.findings import Finding
from gateway.detectors.manager import HierarchicalDetectorManager
from gateway.models import Detection


class DetectorManager:
    def __init__(self, *, detectors_config: dict | None = None) -> None:
        config = detectors_config or {}
        self.core_guard_enabled = True
        self.hierarchical = HierarchicalDetectorManager(detectors_config=config)
        self._diagnostics: ContextVar[tuple[dict[str, Any], ...]] = ContextVar(
            f"pf_detector_diagnostics_{id(self)}",
            default=(),
        )

    def scan(self, text: str, *, kind: str = "text") -> list[Detection]:
        findings = self.scan_findings(text, kind=kind)
        return [_finding_to_detection(finding) for finding in findings]

    def scan_findings(self, text: str, *, kind: str = "text") -> list[Finding]:
        result = self.hierarchical.scan_text_with_diagnostics(text, kind=kind)
        self._merge_diagnostics([diagnostic.to_dict() for diagnostic in result.diagnostics])
        return result.findings

    def scan_findings_with_diagnostics(
        self,
        text: str,
        *,
        kind: str = "text",
    ) -> tuple[list[Finding], list[dict[str, Any]]]:
        """Run an isolated scan and return diagnostics in the same execution context."""

        self.reset_diagnostics()
        findings = self.scan_findings(text, kind=kind)
        return findings, self.diagnostics()

    def diagnostics(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._diagnostics.get()]

    def reset_diagnostics(self) -> None:
        self._diagnostics.set(())

    def _merge_diagnostics(self, diagnostics: list[dict[str, Any]]) -> None:
        merged = self.diagnostics()
        by_id = {str(item.get("id")): item for item in merged}
        status_priority = {
            "disabled": 0,
            "skipped": 1,
            "ok": 2,
            "unavailable": 3,
            "timeout": 4,
            "error": 5,
        }
        for diagnostic in diagnostics:
            module_id = str(diagnostic.get("id"))
            existing = by_id.get(module_id)
            if existing is None:
                stored = dict(diagnostic)
                merged.append(stored)
                by_id[module_id] = stored
                continue
            existing["elapsed_ms"] = round(
                float(existing.get("elapsed_ms", 0.0)) + float(diagnostic.get("elapsed_ms", 0.0)),
                3,
            )
            existing["findings"] = int(existing.get("findings", 0)) + int(diagnostic.get("findings", 0))
            current_status = str(existing.get("status", "ok"))
            incoming_status = str(diagnostic.get("status", "ok"))
            if status_priority.get(incoming_status, 5) > status_priority.get(current_status, 5):
                existing["status"] = incoming_status
                existing["error"] = diagnostic.get("error")
        self._diagnostics.set(tuple(merged))


def _finding_to_detection(finding: Finding) -> Detection:
    if finding.type == "PII":
        det_type = "pii"
    elif finding.type in {"LOCAL_CONTEXT", "CREDENTIAL_FILE"}:
        det_type = "path"
    else:
        det_type = "secret"
    subtype = "local_path" if finding.subtype == "credential_file" and det_type == "path" else finding.subtype
    action = finding.suggested_action
    if det_type == "path" and action in {"warn", "redact"}:
        action = "alias"
    return Detection(
        span_start=finding.original_start,
        span_end=finding.original_end,
        type=det_type,
        subtype=subtype,
        risk=finding.risk,
        detector_name="+".join(finding.detectors),
        suggested_action=action,
        safe_preview=finding.safe_preview,
    )
