from __future__ import annotations

from collections import defaultdict

from gateway.detectors.findings import Finding, merge_findings

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class FindingAggregator:
    def aggregate(self, findings: list[Finding]) -> list[Finding]:
        grouped: dict[str, list[Finding]] = defaultdict(list)
        for finding in sorted(findings, key=lambda f: (f.source_block_id, f.normalized_start, -f.normalized_end)):
            grouped[finding.source_block_id].append(finding)

        merged: list[Finding] = []
        for block_findings in grouped.values():
            consumed: set[int] = set()
            for i, finding in enumerate(block_findings):
                if i in consumed:
                    continue
                overlaps = [
                    other
                    for j, other in enumerate(block_findings[i + 1 :], start=i + 1)
                    if j not in consumed and _overlaps(finding, other)
                ]
                overlap_group = [finding, *overlaps]
                primary = max(overlap_group, key=_finding_priority)
                others = [item for item in overlap_group if item is not primary]
                for other in overlaps:
                    consumed.add(block_findings.index(other))
                merged.append(score_finding(merge_findings(primary, others) if others else primary))
        return sorted(merged, key=lambda f: (f.source_block_id, f.normalized_start))


def score_finding(finding: Finding) -> Finding:
    confidence = finding.confidence
    risk = finding.risk
    suggested_action = finding.suggested_action

    if finding.subtype in {"private_key", "openai_api_key", "github_token", "slack_token", "credit_card"}:
        risk = "critical"
        confidence = max(confidence, 0.95)
        suggested_action = "block" if finding.subtype == "private_key" else "redact"
    elif finding.subtype == "database_url" and "database_url_password" in finding.validators:
        risk = "critical"
        suggested_action = "redact"
    elif finding.subtype == "jwt" and "rules.secrets" in finding.detectors:
        if "heuristic.entropy_context" in finding.detectors:
            confidence = max(confidence, 0.93)
        risk = "high" if risk != "critical" else risk
    elif finding.type == "PII" and finding.detectors and all(d.startswith("models.") for d in finding.detectors):
        risk = "medium"
        suggested_action = "pseudonymize"
    elif finding.type == "UNKNOWN_SECRET_CANDIDATE" and len(finding.detectors) >= 2:
        confidence = min(1.0, confidence + 0.12)
        risk = _raise_risk(risk)

    return Finding(
        id=finding.id,
        source_block_id=finding.source_block_id,
        original_start=finding.original_start,
        original_end=finding.original_end,
        normalized_start=finding.normalized_start,
        normalized_end=finding.normalized_end,
        type=finding.type,
        subtype=finding.subtype,
        confidence=confidence,
        risk=risk,  # type: ignore[arg-type]
        detectors=finding.detectors,
        validators=finding.validators,
        suggested_action=suggested_action,  # type: ignore[arg-type]
        safe_preview=finding.safe_preview,
        metadata=finding.metadata,
    )


def _overlaps(a: Finding, b: Finding) -> bool:
    return not (a.normalized_end <= b.normalized_start or b.normalized_end <= a.normalized_start)


def _raise_risk(risk: str) -> str:
    if risk == "low":
        return "medium"
    if risk == "medium":
        return "high"
    return risk


def _finding_priority(finding: Finding) -> tuple[int, int, float, int]:
    subtype_priority = {
        "private_key": 100,
        "openai_api_key": 95,
        "github_token": 95,
        "slack_token": 95,
        "database_url": 92,
        "jwt": 90,
        "bearer_token": 88,
        "redaction_marker": 86,
        "signed_placeholder": 84,
        "credit_card": 82,
        "credential_file": 81,
        "local_path": 80,
        "high_entropy_token": 70,
        "env_assignment": 55,
        "cookie": 54,
    }.get(finding.subtype, 50)
    return (
        subtype_priority,
        RISK_ORDER[finding.risk],
        finding.confidence,
        finding.normalized_end - finding.normalized_start,
    )
