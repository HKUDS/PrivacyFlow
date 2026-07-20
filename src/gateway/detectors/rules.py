from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from gateway.detectors.base import Detector, safe_preview
from gateway.detectors.findings import Finding, FindingType, Risk, SourceBlock, SuggestedAction
from gateway.detectors.normalizer import NormalizedText
from gateway.detectors.validators.jwt import jwt_header_valid
from gateway.detectors.validators.luhn import luhn_valid
from gateway.detectors.validators.pem import pem_pair_valid
from gateway.detectors.validators.urls import database_url_has_password
from gateway.placeholder_parser import PLACEHOLDER_RE


VALIDATORS = {
    "database_url_password": database_url_has_password,
    "email_structure": lambda value: "@" in value and "." in value.rsplit("@", 1)[-1],
    "jwt_header": jwt_header_valid,
    "luhn": luhn_valid,
    "pem_pair": pem_pair_valid,
    "phone_shape": lambda value: len(re.sub(r"\D", "", value)) >= 8,
    "placeholder_parser_required": lambda value: bool(PLACEHOLDER_RE.fullmatch(value)),
}


@dataclass(frozen=True)
class DetectionRule:
    id: str
    pattern: str
    type: FindingType
    subtype: str
    confidence: float
    risk: Risk
    suggested_action: SuggestedAction
    flags: tuple[str, ...] = ()
    validators: tuple[str, ...] = ()
    require_validators: tuple[str, ...] = ()
    reject_validators: tuple[str, ...] = ()
    preview_keep: int = 4
    enabled: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "DetectionRule":
        return cls(
            id=str(raw["id"]),
            pattern=str(raw["pattern"]),
            type=raw.get("type", "MACHINE_SECRET"),
            subtype=str(raw["subtype"]),
            confidence=float(raw.get("confidence", 0.8)),
            risk=raw.get("risk", "medium"),
            suggested_action=raw.get("suggested_action", "warn"),
            flags=_tuple(raw.get("flags", ())),
            validators=_tuple(raw.get("validators", ())),
            require_validators=_tuple(raw.get("require_validators", ())),
            reject_validators=_tuple(raw.get("reject_validators", ())),
            preview_keep=int(raw.get("preview_keep", 4)),
            enabled=bool(raw.get("enabled", True)),
            metadata=raw.get("metadata", {}),
        )


class RuleBasedDetector(Detector):
    name = "rules"

    def __init__(self, rules: Iterable[DetectionRule | Mapping[str, Any]], *, name: str = "rules") -> None:
        self.name = name
        self.rules = [rule if isinstance(rule, DetectionRule) else DetectionRule.from_dict(rule) for rule in rules]
        self._compiled = [(rule, re.compile(rule.pattern, _regex_flags(rule.flags))) for rule in self.rules if rule.enabled]

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        text = normalized.normalized
        for rule, pattern in self._compiled:
            for match in pattern.finditer(text):
                value = _match_value(match)
                passed_validators = tuple(name for name in rule.validators if _validator_passes(name, value))
                if any(name not in passed_validators for name in rule.require_validators):
                    continue
                if any(_validator_passes(name, value) for name in rule.reject_validators):
                    continue
                value_span = match.span("value") if "value" in match.groupdict() and match.group("value") is not None else match.span()
                start, end = normalized.original_span(*value_span)
                suggested_action = _source_action(rule, block.kind)
                detector_name = _detector_name(rule, self.name)
                yield Finding.make(
                    source_block_id=block.id,
                    original_start=start,
                    original_end=end,
                    normalized_start=value_span[0],
                    normalized_end=value_span[1],
                    type=rule.type,
                    subtype=rule.subtype,
                    confidence=rule.confidence,
                    risk=rule.risk,
                    detector=detector_name,
                    validators=passed_validators,
                    suggested_action=suggested_action,
                    safe_preview=safe_preview(value, rule.preview_keep),
                    metadata={"rule_id": rule.id, "source_kind": block.kind, "json_pointer": block.json_pointer, **dict(rule.metadata)},
                )


def builtin_rules() -> list[DetectionRule]:
    return [DetectionRule.from_dict(rule) for rule in BUILTIN_RULES]


def _tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _regex_flags(flags: tuple[str, ...]) -> int:
    out = 0
    for flag in flags:
        normalized = flag.upper()
        if normalized in {"I", "IGNORECASE"}:
            out |= re.I
        elif normalized in {"M", "MULTILINE"}:
            out |= re.M
        elif normalized in {"S", "DOTALL"}:
            out |= re.S
    return out


def _match_value(match: re.Match[str]) -> str:
    groups = match.groupdict()
    if "value" in groups and groups["value"] is not None:
        return groups["value"]
    return match.group(0)


def _validator_passes(name: str, value: str) -> bool:
    validator = VALIDATORS.get(name)
    return bool(validator and validator(value))


def _detector_name(rule: DetectionRule, default: str) -> str:
    configured = rule.metadata.get("detector_name")
    if isinstance(configured, str):
        return configured
    if rule.id.startswith("pii."):
        return "rules.pii"
    if rule.id.startswith("secret."):
        return "rules.secrets"
    if rule.id.startswith("apg."):
        return "rules.apg_markers"
    return default


def _source_action(rule: DetectionRule, source_kind: str) -> SuggestedAction:
    by_source = rule.metadata.get("suggested_action_by_source_kind")
    if isinstance(by_source, Mapping):
        return by_source.get(source_kind, rule.suggested_action)
    return rule.suggested_action


BUILTIN_RULES: tuple[dict[str, Any], ...] = (
    {
        "id": "apg.legacy_pii_placeholder",
        "pattern": r"<APG_PII:[^<>]+>",
        "type": "APG_MARKER",
        "subtype": "legacy_pii_placeholder",
        "confidence": 0.99,
        "risk": "high",
        "suggested_action": "warn",
        "preview_keep": 0,
    },
    {
        "id": "apg.signed_placeholder",
        "pattern": r"<APG:v1:(?P<kind>[a-z_]+):(?P<handle>[^:<>]+):(?P<session>[^:<>]+):(?P<issued>\d+):(?P<mac>[A-Za-z0-9_-]+)>",
        "type": "APG_MARKER",
        "subtype": "signed_placeholder",
        "confidence": 0.95,
        "risk": "medium",
        "suggested_action": "warn",
        "validators": ["placeholder_parser_required"],
        "preview_keep": 0,
    },
    {
        "id": "apg.redaction_marker",
        "pattern": r"<APG(?:_REDACTED|_SECRET)[^>]*>|<APG:v1:[^>]+>",
        "type": "APG_MARKER",
        "subtype": "redaction_marker",
        "confidence": 0.98,
        "risk": "high",
        "suggested_action": "warn",
        "preview_keep": 0,
        "reject_validators": ["placeholder_parser_required"],
        "metadata": {"suggested_action_by_source_kind": {"file_write_content": "block"}},
    },
    {
        "id": "secret.private_key",
        "pattern": r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----",
        "type": "MACHINE_SECRET",
        "subtype": "private_key",
        "confidence": 0.98,
        "risk": "critical",
        "suggested_action": "block",
        "validators": ["pem_pair"],
    },
    {
        "id": "secret.openai_apg_test_key",
        "pattern": r"\bsk-apgtest(?:-[A-Za-z0-9_\-]*)?\b",
        "type": "MACHINE_SECRET",
        "subtype": "openai_api_key",
        "confidence": 0.98,
        "risk": "critical",
        "suggested_action": "redact",
    },
    {
        "id": "secret.openai_api_key",
        "pattern": r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
        "type": "MACHINE_SECRET",
        "subtype": "openai_api_key",
        "confidence": 0.98,
        "risk": "critical",
        "suggested_action": "redact",
    },
    {
        "id": "secret.github_apg_test_token",
        "pattern": r"\bghp_apgtest[A-Za-z0-9_]*\b",
        "type": "MACHINE_SECRET",
        "subtype": "github_token",
        "confidence": 0.98,
        "risk": "high",
        "suggested_action": "redact",
    },
    {
        "id": "secret.github_token",
        "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b",
        "type": "MACHINE_SECRET",
        "subtype": "github_token",
        "confidence": 0.98,
        "risk": "high",
        "suggested_action": "redact",
    },
    {
        "id": "secret.database_test_password",
        "pattern": r"\bapgtest-db-pass\b",
        "type": "MACHINE_SECRET",
        "subtype": "database_url",
        "confidence": 0.98,
        "risk": "critical",
        "suggested_action": "redact",
    },
    {
        "id": "secret.aws_access_key",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "type": "MACHINE_SECRET",
        "subtype": "aws_access_key",
        "confidence": 0.98,
        "risk": "high",
        "suggested_action": "redact",
    },
    {
        "id": "secret.slack_token",
        "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "type": "MACHINE_SECRET",
        "subtype": "slack_token",
        "confidence": 0.98,
        "risk": "high",
        "suggested_action": "redact",
    },
    {
        "id": "secret.jwt_prefix",
        "pattern": r"\beyJhbGci[A-Za-z0-9_-]*\b",
        "type": "MACHINE_SECRET",
        "subtype": "jwt",
        "confidence": 0.82,
        "risk": "high",
        "suggested_action": "redact",
        "validators": ["jwt_header"],
    },
    {
        "id": "secret.jwt",
        "pattern": r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "type": "MACHINE_SECRET",
        "subtype": "jwt",
        "confidence": 0.82,
        "risk": "high",
        "suggested_action": "redact",
        "validators": ["jwt_header"],
    },
    {
        "id": "secret.database_url",
        "pattern": r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s\"'<>]+",
        "type": "MACHINE_SECRET",
        "subtype": "database_url",
        "confidence": 0.78,
        "risk": "medium",
        "suggested_action": "redact",
        "flags": ["IGNORECASE"],
        "validators": ["database_url_password"],
    },
    {
        "id": "secret.bearer_token",
        "pattern": r"\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}",
        "type": "MACHINE_SECRET",
        "subtype": "bearer_token",
        "confidence": 0.98,
        "risk": "high",
        "suggested_action": "redact",
        "flags": ["IGNORECASE"],
    },
    {
        "id": "secret.cookie",
        "pattern": r"\b(?:cookie|sessionid|sid|connect\.sid)\s*[:=]\s*[A-Za-z0-9._~+/=-]{16,}",
        "type": "MACHINE_SECRET",
        "subtype": "cookie",
        "confidence": 0.98,
        "risk": "high",
        "suggested_action": "redact",
        "flags": ["IGNORECASE"],
    },
    {
        "id": "secret.env_assignment",
        "pattern": r"^\s*[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)[A-Z0-9_]*\s*=\s*(?P<value>.+)$",
        "type": "MACHINE_SECRET",
        "subtype": "env_assignment",
        "confidence": 0.98,
        "risk": "high",
        "suggested_action": "redact",
        "flags": ["IGNORECASE", "MULTILINE"],
    },
    {
        "id": "pii.email",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "type": "PII",
        "subtype": "email",
        "confidence": 0.9,
        "risk": "medium",
        "suggested_action": "pseudonymize",
        "validators": ["email_structure"],
        "preview_keep": 2,
    },
    {
        "id": "pii.phone",
        "pattern": r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}|\d{4}[\s.-]?\d{4})(?!\w)",
        "type": "PII",
        "subtype": "phone",
        "confidence": 0.75,
        "risk": "medium",
        "suggested_action": "redact",
        "validators": ["phone_shape"],
        "preview_keep": 2,
    },
    {
        "id": "pii.hk_address",
        "pattern": r"\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,3},\s*Hong Kong\b",
        "type": "PII",
        "subtype": "address",
        "confidence": 0.82,
        "risk": "medium",
        "suggested_action": "redact",
        "preview_keep": 2,
    },
    {
        "id": "pii.credit_card",
        "pattern": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
        "type": "MACHINE_SECRET",
        "subtype": "credit_card",
        "confidence": 0.95,
        "risk": "critical",
        "suggested_action": "redact",
        "validators": ["luhn"],
        "require_validators": ["luhn"],
        "preview_keep": 2,
    },
)
