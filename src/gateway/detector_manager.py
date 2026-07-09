from __future__ import annotations

from gateway.detectors.findings import Finding
from gateway.detectors.manager import HierarchicalDetectorManager
from gateway.models import Detection


class DetectorManager:
    def __init__(self, *, detectors_config: dict | None = None) -> None:
        self.hierarchical = HierarchicalDetectorManager(detectors_config=detectors_config)
        self.last_diagnostics: list[dict[str, Any]] = []

    def scan(self, text: str) -> list[Detection]:
        findings = self.scan_findings(text)
        return [_finding_to_detection(finding) for finding in findings]

    def scan_findings(self, text: str, *, kind: str = "text") -> list[Finding]:
        result = self.hierarchical.scan_text_with_diagnostics(text, kind=kind)
        self.last_diagnostics.extend(self.hierarchical.last_diagnostics)
        return result.findings

    def diagnostics(self) -> list[dict[str, Any]]:
        return list(self.last_diagnostics)

    def reset_diagnostics(self) -> None:
        self.last_diagnostics = []


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
        confidence=finding.confidence,
        risk=finding.risk,
        detector_name="+".join(finding.detectors),
        suggested_action=action,
        safe_preview=finding.safe_preview,
    )
