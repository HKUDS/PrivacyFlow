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
    "credential_assignment_value": lambda value: _credential_assignment_value(value),
    "database_url_password": database_url_has_password,
    "email_structure": lambda value: "@" in value and "." in value.rsplit("@", 1)[-1],
    "jwt_header": jwt_header_valid,
    "luhn": luhn_valid,
    "pem_pair": pem_pair_valid,
    "phone_shape": lambda value: _formatted_phone(value),
    "placeholder_parser_required": lambda value: bool(PLACEHOLDER_RE.fullmatch(value)),
    "mixed_case_secret": lambda value: _mixed_case_secret(value),
}


_SAFE_ASSIGNMENT_VALUES = re.compile(
    r"(?:"
    r"(?:true|false|yes|no|on|off|0|1)(?:/(?:true|false|yes|no|on|off|0|1))?"
    r"|null|none|unset|missing|present|configured|enabled|disabled"
    r"|\$(?:[A-Z_][A-Z0-9_]*|\{[A-Z_][A-Z0-9_]*\})"
    r"|your[-_][A-Z0-9_-]+[-_]here"
    r")",
    re.I,
)
_SAFE_ASSIGNMENT_EXPRESSION = re.compile(
    r"(?:"
    r"(?:bool|str|int|float|len)\([A-Z_][A-Z0-9_]*\)"
    r"|os\.(?:getenv|environ\.get)\((?:\"[A-Z_][A-Z0-9_]*\"|'[A-Z_][A-Z0-9_]*')\)"
    r")(?:\\[nr])*",
    re.I,
)
_SENSITIVE_ENV_NAME = re.compile(
    r"(?:^|_)(?:API_KEY|APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|CREDENTIAL|PRIVATE_KEY|DATABASE_URL)(?:_|$)",
    re.I,
)
_NON_SECRET_ENV_SUFFIXES = {
    "BUDGET",
    "CONFIGURED",
    "COUNT",
    "DISABLED",
    "ENABLED",
    "ENDPOINT",
    "FILE",
    "ID",
    "LENGTH",
    "LIMIT",
    "MAX",
    "MIN",
    "NAME",
    "PATH",
    "PRESENT",
    "SET",
    "SIZE",
    "STATUS",
    "TIMEOUT",
    "TYPE",
    "URI",
    "URL",
    "WINDOW",
}
_SHORT_SECRET_ASSIGNMENT_PREFIX = re.compile(
    r"(?:sk-|gh[opusr]_|xox[baprs]-|eyJ|svc[_-])",
    re.I,
)


@dataclass(frozen=True)
class DetectionRule:
    id: str
    pattern: str
    type: FindingType
    subtype: str
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
                if rule.id == "secret.env_assignment" and not _sensitive_env_assignment(match):
                    continue
                value, value_span = _match_value_and_span(rule, match)
                if rule.id == "pii.email" and _email_is_ssh_public_key_comment(text, value_span):
                    continue
                if rule.id == "pii.phone" and _span_is_hex_dump_columns(text, value_span):
                    continue
                passed_validators = tuple(name for name in rule.validators if _validator_passes(name, value))
                if any(name not in passed_validators for name in rule.require_validators):
                    continue
                if any(_validator_passes(name, value) for name in rule.reject_validators):
                    continue
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
                    subtype=_contextual_subtype(rule, text, value_span),
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


def _match_value_and_span(rule: DetectionRule, match: re.Match[str]) -> tuple[str, tuple[int, int]]:
    groups = match.groupdict()
    if "value" in groups and groups["value"] is not None:
        value = groups["value"]
        start, end = match.span("value")
        # Keep surrounding quotes in the source so replacing a protected value
        # cannot turn a valid shell/Python assignment into invalid syntax.
        if rule.id == "secret.env_assignment" and len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1], (start + 1, end - 1)
        return value, (start, end)
    return match.group(0), match.span()


def _validator_passes(name: str, value: str) -> bool:
    validator = VALIDATORS.get(name)
    return bool(validator and validator(value))


def _credential_assignment_value(value: str) -> bool:
    candidate = value.strip()
    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {"'", '"'}:
        candidate = candidate[1:-1].strip()
    return (
        bool(candidate)
        and _SAFE_ASSIGNMENT_VALUES.fullmatch(candidate) is None
        and _SAFE_ASSIGNMENT_EXPRESSION.fullmatch(candidate) is None
        and not _code_reference_value(candidate)
    )


def _code_reference_value(value: str) -> bool:
    candidate = value.rstrip(",")
    if candidate.startswith(("f\"", "f'", "r\"", "r'", "b\"", "b'")):
        return True
    return (
        re.match(r"[A-Za-z_][A-Za-z0-9_.]*[\[(]", candidate) is not None
        or candidate.startswith("[")
    )


def _sensitive_env_assignment(match: re.Match[str]) -> bool:
    name = match.groupdict().get("name")
    if name is None:
        return True
    normalized = name.upper()
    value = str(match.groupdict().get("value") or "").strip().strip("\"'")
    # Hex/ASCII dump tools can split `OPENAI_API_KEY=...` across display
    # rows, leaving a high-signal fragment such as `KEY=sk-...` in the ASCII
    # gutter. Treat only known credential prefixes as sensitive for this
    # otherwise-generic short name.
    if normalized == "KEY" and _SHORT_SECRET_ASSIGNMENT_PREFIX.match(value):
        return True
    marker = _SENSITIVE_ENV_NAME.search(normalized)
    while marker is not None:
        suffix = normalized[marker.end() :].lstrip("_").split("_", 1)[0]
        if not suffix or suffix not in _NON_SECRET_ENV_SUFFIXES:
            value = str(match.groupdict().get("value") or "").strip()
            exported = match.group(0).lstrip().lower().startswith("export")
            code_value = value.rstrip(",)]}")
            if not exported and name != normalized and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", code_value):
                return False
            return True
        marker = _SENSITIVE_ENV_NAME.search(normalized, marker.end())
    return False


def _mixed_case_secret(value: str) -> bool:
    return (
        any(char.islower() for char in value)
        and any(char.isupper() for char in value)
        and any(char.isdigit() for char in value)
    )


def _formatted_phone(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    return len(digits) >= 8 and any(char in value for char in "+() .-")


def _email_is_ssh_public_key_comment(text: str, span: tuple[int, int]) -> bool:
    line_start = text.rfind("\n", 0, span[0]) + 1
    line_end = text.find("\n", span[1])
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    value_start = span[0] - line_start
    prefix = line[:value_start]
    return bool(
        re.match(
            r"^[ \t]*(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+)[ \t]+[A-Za-z0-9+/=]{20,}[ \t]+$",
            prefix,
            re.I,
        )
    )


def _span_is_hex_dump_columns(text: str, span: tuple[int, int]) -> bool:
    line_start = text.rfind("\n", 0, span[0]) + 1
    line_end = text.find("\n", span[1])
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    if re.match(r"^[0-9A-Fa-f]{8}:[ \t]", line) is None:
        return False
    separator = re.search(r"[ \t]{2,}(?=\S)", line[9:])
    if separator is None:
        return False
    ascii_start = 9 + separator.end()
    return span[1] - line_start <= ascii_start


def _contextual_subtype(rule: DetectionRule, text: str, span: tuple[int, int]) -> str:
    if rule.id == "pii.email" and _email_precedes_credential_password(text, span):
        return "credential_username"
    return rule.subtype


def _email_precedes_credential_password(text: str, span: tuple[int, int]) -> bool:
    remainder = text[span[1] :]
    following = re.match(
        r"[ \t]*\r?\n[ \t]*(?P<password>[A-Za-z0-9!#$%&*+./:=?@^_~-]{8,128})[ \t]*(?:\r?\n|$)",
        remainder,
    )
    return bool(following and _mixed_case_secret(following.group("password")))


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
        "risk": "high",
        "suggested_action": "warn",
        "preview_keep": 0,
    },
    {
        "id": "apg.signed_placeholder",
        "pattern": r"<APG:v1:(?P<kind>[a-z_]+):(?P<handle>[^:<>]+):(?P<session>[^:<>]+):(?P<issued>\d+):(?P<mac>[A-Za-z0-9_-]+)>",
        "type": "APG_MARKER",
        "subtype": "signed_placeholder",
        "risk": "medium",
        "suggested_action": "warn",
        "validators": ["placeholder_parser_required"],
        "preview_keep": 0,
    },
    {
        "id": "apg.redaction_marker",
        "pattern": r"<APG[^\r\n>]*>",
        "type": "APG_MARKER",
        "subtype": "redaction_marker",
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
        "risk": "critical",
        "suggested_action": "block",
        "validators": ["pem_pair"],
    },
    {
        "id": "secret.openai_api_key",
        "pattern": r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b",
        "type": "MACHINE_SECRET",
        "subtype": "api_key",
        "risk": "critical",
        "suggested_action": "redact",
        "metadata": {"display_name": "API 密钥（sk- 格式）"},
    },
    {
        "id": "secret.github_token",
        "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b",
        "type": "MACHINE_SECRET",
        "subtype": "github_token",
        "risk": "high",
        "suggested_action": "redact",
    },
    {
        "id": "secret.aws_access_key",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "type": "MACHINE_SECRET",
        "subtype": "aws_access_key",
        "risk": "high",
        "suggested_action": "redact",
    },
    {
        "id": "secret.slack_token",
        "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "type": "MACHINE_SECRET",
        "subtype": "slack_token",
        "risk": "high",
        "suggested_action": "redact",
    },
    {
        "id": "secret.jwt",
        "pattern": r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "type": "MACHINE_SECRET",
        "subtype": "jwt",
        "risk": "high",
        "suggested_action": "redact",
        "validators": ["jwt_header"],
    },
    {
        "id": "secret.hex_dump_jwt_fragment",
        "pattern": r"^[0-9A-Fa-f]{8}:[ 0-9A-Fa-f]{24,}[ \t]{2,}[^\r\n]*?(?P<value>eyJhbGci[A-Za-z0-9_-]*)",
        "type": "MACHINE_SECRET",
        "subtype": "jwt",
        "risk": "high",
        "suggested_action": "redact",
        "flags": ["MULTILINE"],
        "metadata": {"display_name": "十六进制转储中的 JWT 片段"},
    },
    {
        "id": "secret.database_url",
        "pattern": r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s\"'<>]+",
        "type": "MACHINE_SECRET",
        "subtype": "database_url",
        "risk": "medium",
        "suggested_action": "redact",
        "flags": ["IGNORECASE"],
        "validators": ["database_url_password"],
    },
    {
        "id": "secret.bearer_token",
        # Eight characters is sufficient once the value is anchored to an
        # explicit Authorization: Bearer context. This also protects the
        # visible ASCII gutter when a hex dump splits a longer token.
        "pattern": r"\bAuthorization\s*:\s*Bearer\s+(?P<value>[A-Za-z0-9._~+/=-]{8,})",
        "type": "MACHINE_SECRET",
        "subtype": "bearer_token",
        "risk": "high",
        "suggested_action": "redact",
        "flags": ["IGNORECASE"],
    },
    {
        "id": "secret.cookie",
        "pattern": r"\b(?:cookie|sessionid|sid|connect\.sid)\s*[:=]\s*(?P<value>[A-Za-z0-9._~+/=-]{16,})",
        "type": "MACHINE_SECRET",
        "subtype": "cookie",
        "risk": "high",
        "suggested_action": "redact",
        "flags": ["IGNORECASE"],
    },
    {
        "id": "secret.ip_access_url_token",
        "pattern": r"\bhttps?://(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?/(?:[A-Za-z0-9._~-]+/)*(?P<value>[A-Za-z0-9_-]{16,})(?:/|[?#][^\s]*|$)",
        "type": "MACHINE_SECRET",
        "subtype": "access_url_token",
        "risk": "high",
        "suggested_action": "redact",
        "validators": ["mixed_case_secret"],
        "require_validators": ["mixed_case_secret"],
    },
    {
        "id": "secret.credential_pair_password",
        "pattern": r"^[ \t]*[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}[ \t]*\r?\n[ \t]*(?P<value>[A-Za-z0-9!#$%&*+./:=?@^_~-]{8,128})[ \t]*$",
        "type": "MACHINE_SECRET",
        "subtype": "credential_password",
        "risk": "high",
        "suggested_action": "redact",
        "flags": ["MULTILINE"],
        "validators": ["mixed_case_secret"],
        "require_validators": ["mixed_case_secret"],
        "preview_keep": 2,
        "metadata": {"display_name": "登录凭据密码"},
    },
    {
        "id": "secret.env_assignment",
        "pattern": r"(?<![A-Z0-9_])(?:export[ \t]+)?(?P<name>[A-Z][A-Z0-9_]*)[ \t]*=(?!=)[ \t]*(?P<value>\"(?:\\.|[^\"\\\r\n])*\"|'(?:\\.|[^'\\\r\n])*'|[^\s;]+)",
        "type": "MACHINE_SECRET",
        "subtype": "env_assignment",
        "risk": "high",
        "suggested_action": "redact",
        "flags": ["IGNORECASE", "MULTILINE"],
        "validators": ["credential_assignment_value"],
        "require_validators": ["credential_assignment_value"],
    },
    {
        "id": "pii.email",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "type": "PII",
        "subtype": "email",
        "risk": "medium",
        "suggested_action": "pseudonymize",
        "validators": ["email_structure"],
        "require_validators": ["email_structure"],
        "preview_keep": 2,
    },
    {
        "id": "pii.phone",
        "pattern": r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}|\d{4}[\s.-]?\d{4})(?!\w)",
        "type": "PII",
        "subtype": "phone",
        "risk": "medium",
        "suggested_action": "redact",
        "validators": ["phone_shape"],
        "require_validators": ["phone_shape"],
        "preview_keep": 2,
    },
    {
        "id": "pii.phone_labeled",
        "pattern": r"(?:phone|telephone|tel|mobile|联系电话|电话|手机)[ \t]*[:=：]?[ \t]*(?P<value>\+?\d(?:[\d .()-]{6,}\d))",
        "type": "PII",
        "subtype": "phone",
        "risk": "medium",
        "suggested_action": "redact",
        "flags": ["IGNORECASE"],
        "preview_keep": 2,
    },
    {
        "id": "pii.hk_address",
        "pattern": r"\b[A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+){0,3},\s*Hong Kong\b",
        "type": "PII",
        "subtype": "address",
        "risk": "medium",
        "suggested_action": "redact",
        "preview_keep": 2,
    },
    {
        "id": "pii.credit_card",
        "pattern": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
        "type": "MACHINE_SECRET",
        "subtype": "credit_card",
        "risk": "critical",
        "suggested_action": "redact",
        "validators": ["luhn"],
        "require_validators": ["luhn"],
        "preview_keep": 2,
    },
)
