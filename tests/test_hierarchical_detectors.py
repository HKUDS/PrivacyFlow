from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import pytest

from gateway.detectors.base import Detector
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.manager import HierarchicalDetectorManager, extract_text_blocks
from gateway.detectors.models.base_model_detector import BaseModelDetector, ModelDetectorConfig
from gateway.detectors.normalizer import NormalizedText, normalize_with_mapping
from gateway.detectors.scoring import FindingAggregator


def scan(text: str):
    return HierarchicalDetectorManager().scan_text(text)


def scan_with_entropy(text: str):
    return HierarchicalDetectorManager(detectors_config={"preset": "strict"}).scan_text(text)


def subtypes(text: str) -> set[str]:
    return {f.subtype for f in scan(text)}


def by_subtype(text: str, subtype: str) -> Finding:
    return next(f for f in scan(text) if f.subtype == subtype)


def test_pem_private_key_detected_as_critical() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    finding = by_subtype(text, "private_key")
    assert finding.risk == "critical"
    assert finding.suggested_action == "block"


def test_jwt_detected_and_validated() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    finding = by_subtype(token, "jwt")
    assert "jwt_header" in finding.validators


def test_bearer_token_detected() -> None:
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890"
    finding = by_subtype(text, "bearer_token")
    assert text[finding.original_start : finding.original_end] == "abcdefghijklmnopqrstuvwxyz1234567890"


def test_cookie_finding_covers_value_only() -> None:
    text = "sessionid=abcdefghijklmnopqrstuvwxyz1234567890"
    finding = by_subtype(text, "cookie")
    assert text[finding.original_start : finding.original_end] == "abcdefghijklmnopqrstuvwxyz1234567890"


def test_env_api_key_assignment_detected() -> None:
    assert "env_assignment" in subtypes("MY_API_KEY=x")
    assert "env_assignment" in subtypes('export SERVICE_TOKEN="secret-value"')
    assert "env_assignment" in subtypes('    42\u2192export SERVICE_TOKEN="secret-value"')


def test_env_assignment_finding_covers_value_only() -> None:
    text = "SERVICE_TOKEN=secret-value"
    finding = by_subtype(text, "env_assignment")
    assert text[finding.original_start : finding.original_end] == "secret-value"

    exported = 'export SERVICE_TOKEN="secret-value"'
    exported_finding = by_subtype(exported, "env_assignment")
    assert exported[exported_finding.original_start : exported_finding.original_end] == "secret-value"

    read_output = '    42\u2192export SERVICE_TOKEN="secret-value"'
    read_finding = by_subtype(read_output, "env_assignment")
    assert read_output[read_finding.original_start : read_finding.original_end] == "secret-value"


@pytest.mark.parametrize(
    "text",
    [
        "OPENAI_API_KEY_SET=true",
        "OPENAI_API_KEY_SET=true/false",
        "SERVICE_TOKEN='configured'",
        "DATABASE_URL=${DATABASE_URL}",
        "API_KEY=your-openai-api-key-here",
        "TOKEN_COUNT=42",
        "MAX_OUTPUT_TOKEN_COUNT=650000",
        "SERVICE_TOKEN_TIMEOUT=30",
        "OPENAI_API_KEY_NAME=primary",
        "PRIVATE_KEY_PATH=keys/service.pem",
        "api_key=os.getenv('API_KEY')",
        "api_key=body.get('api_key', '')",
        "signing_secret == 'configured'",
        "api_key=effective_api_key,",
    ],
)
def test_env_assignment_ignores_status_references_and_placeholders(text: str) -> None:
    assert "env_assignment" not in subtypes(text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("API_KEY=x", "x"),
        ("lowercase_api_key=real-short-value", "real-short-value"),
        ('SERVICE_TOKEN="secret value with spaces"', "secret value with spaces"),
        ("PASSWORD=p@ssword#part", "p@ssword#part"),
        ("AUTH_TOKEN_VALUE=real-token-value", "real-token-value"),
        ("PASSWORD_HASH=synthetic-hash-value", "synthetic-hash-value"),
        ('api_key="short-real-secret"', "short-real-secret"),
        ("TOKEN=secret-value; retry=true; status=401", "secret-value"),
    ],
)
def test_env_assignment_detects_real_values_without_consuming_suffix(text: str, expected: str) -> None:
    finding = by_subtype(text, "env_assignment")
    assert text[finding.original_start : finding.original_end] == expected


def test_database_url_with_password_detected() -> None:
    finding = by_subtype("DATABASE_URL=postgres://user:pass@example.com/db", "database_url")
    assert "database_url_password" in finding.validators
    assert finding.risk == "critical"


def test_email_detected() -> None:
    assert "email" in subtypes("howard@example.com")


def test_ssh_public_key_comment_is_not_email() -> None:
    text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICGbGKiJ8TBhWnykh1AW2xLIPjuBdP3MbpvNWLkhB developer@workstation.local"
    assert "email" not in subtypes(text)


def test_login_pair_is_classified_as_credentials() -> None:
    findings = scan("user123@cluster.example.org\nSyntheticPass649")
    assert {finding.subtype for finding in findings} == {"credential_username", "credential_password"}


def test_decoded_prefix_keeps_later_original_spans_exact() -> None:
    text = "节点：%20 🇭🇰\\u0020\nalice@example.com"
    normalized = normalize_with_mapping(text)
    start = normalized.normalized.index("alice@example.com")
    original_start, original_end = normalized.original_span(start, start + len("alice@example.com"))
    assert text[original_start:original_end] == "alice@example.com"


def test_phone_detected() -> None:
    assert "phone" in subtypes("+1 (415) 555-1212")
    assert "phone" in subtypes("电话：2345 6789")
    assert "phone" in subtypes("phone: 12345678")


@pytest.mark.parametrize("text", ["20260728", "build=12345678", "revision 38154239"])
def test_unformatted_eight_digit_values_are_not_phone_numbers(text: str) -> None:
    assert "phone" not in subtypes(text)


def test_operational_token_count_is_not_a_secret_assignment() -> None:
    assert "env_assignment" not in subtypes("CLAUDE_CODE_MAX_OUTPUT_TOKENS=650000")
    assert "env_assignment" in subtypes("ANTHROPIC_AUTH_TOKEN=synthetic-secret-value")


def test_hong_kong_address_detected() -> None:
    assert "address" in subtypes("Address: Kennedy Town, Hong Kong")


def test_credit_card_only_luhn_valid() -> None:
    valid = subtypes("card 4111 1111 1111 1111")
    invalid = subtypes("card 4111 1111 1111 1112")
    assert "credit_card" in valid
    assert "credit_card" not in invalid


def test_api_route_not_flagged_as_local_path() -> None:
    assert "local_path" not in subtypes("GET /api/v1/users")


def test_users_env_path_uses_the_same_local_path_policy() -> None:
    finding = by_subtype("/Users/alice/project/.env", "local_path")
    assert finding.type == "LOCAL_CONTEXT"
    assert finding.risk == "medium"
    assert finding.suggested_action == "alias"


def test_high_entropy_token_uses_fixed_risk_without_context() -> None:
    finding = next(
        finding
        for finding in scan_with_entropy("value abcdefghijklmnopqrstuvwxyzABCDEFGH1234567890")
        if finding.subtype == "high_entropy_token"
    )
    assert finding.risk == "medium"
    assert "sensitive_context" not in finding.metadata
    assert "weak_context" not in finding.metadata


@pytest.mark.parametrize(
    "text",
    [
        "SHA256 abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "checksum=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "commit abcdef1234567890abcdef1234567890abcdef12",
    ],
)
def test_labeled_digests_are_not_high_entropy_secrets(text: str) -> None:
    assert "high_entropy_token" not in {finding.subtype for finding in scan_with_entropy(text)}


def test_plain_schema_url_is_not_high_entropy_secret() -> None:
    assert "high_entropy_token" not in {
        finding.subtype for finding in scan_with_entropy("schema: https://json-schema.org/draft-07/schema#")
    }


def test_repository_script_path_is_not_high_entropy_secret() -> None:
    assert "high_entropy_token" not in {finding.subtype for finding in scan_with_entropy("run python scripts/validate_secret.py VALUE")}
    assert "high_entropy_token" not in {finding.subtype for finding in scan_with_entropy("ripts/validate_secret.py")}
    assert "high_entropy_token" not in {finding.subtype for finding in scan_with_entropy("inspect logs/assignment_edge.log")}


@pytest.mark.parametrize(
    "text",
    [
        "--kb-names calculus_volume_2_web_13_238",
        "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1",
        "google/gemini-3-flash-preview",
        "/opt/cisco/secureclient/bin/vpn",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICGbGKiJ8TBhWnykh1AW2xLIPjuBdP3MbpvNWLkhB developer@workstation.local",
    ],
)
def test_structured_identifiers_and_ssh_public_keys_are_not_high_entropy_tokens(text: str) -> None:
    assert "high_entropy_token" not in {finding.subtype for finding in scan_with_entropy(text)}


def test_realistic_benign_shell_fixture_has_no_findings() -> None:
    text = (Path(__file__).parent / "fixtures" / "detector_shell_benign.txt").read_text(encoding="utf-8")
    assert scan(text) == []
    assert scan_with_entropy(text) == []


def test_realistic_sensitive_shell_fixture_has_precise_findings() -> None:
    text = (Path(__file__).parent / "fixtures" / "detector_shell_sensitive.txt").read_text(encoding="utf-8")
    findings = scan(text)
    observed = [(finding.subtype, text[finding.original_start : finding.original_end]) for finding in findings]
    expected = [
        ("local_path", "~/.config/mihomo"),
        ("api_key", "sk-syntheticABCDEFGHIJKLMNOPQRSTUV"),
        ("access_url_token", "8pySFiZlBQ5b0Synthetic"),
        ("local_path", "~/.ssh/id_ed25519.pub"),
        ("credential_username", "u3629000@hpc2021.example"),
        ("credential_password", "SyntheticPass649"),
        ("api_key", "sk-syntheticZYXWVUTSRQPONMLKJIHGF"),
    ]
    assert observed == expected
    assert [
        (finding.subtype, text[finding.original_start : finding.original_end])
        for finding in scan_with_entropy(text)
    ] == expected


def test_local_path_span_excludes_sentence_punctuation() -> None:
    text = "Read /private/tmp/project/private/path_probe.txt."
    finding = by_subtype(text, "local_path")
    assert text[finding.original_start : finding.original_end] == "/private/tmp/project/private/path_probe.txt"


def test_fake_context_does_not_downgrade_provider_token() -> None:
    finding = by_subtype("fake example key sk-proj-abcdefghijklmnopqrstuvwxyz123456", "api_key")
    assert finding.risk == "critical"


class MockStarPII(BaseModelDetector):
    name = "models.starpii"

    def load(self) -> None:
        self._loaded = True
        self._available = True

    def detect_loaded(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        start = normalized.normalized.index("Alice")
        yield self.finding_from_span(block=block, normalized=normalized, start=start, end=start + 5, label="name")


class MockPiiranha(BaseModelDetector):
    name = "models.piiranha"

    def load(self) -> None:
        self._loaded = True
        self._available = True

    def detect_loaded(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        start = normalized.normalized.index("张三")
        yield self.finding_from_span(block=block, normalized=normalized, start=start, end=start + 2, label="name")


class FailingModel(BaseModelDetector):
    name = "models.failing"

    def load(self) -> None:
        raise RuntimeError("model unavailable")


def test_mocked_starpii_returns_code_adjacent_pii() -> None:
    manager = HierarchicalDetectorManager(model_detectors=[MockStarPII(ModelDetectorConfig(enabled=True))])
    findings = manager.scan_text("const owner = 'Alice';")
    assert any(f.subtype == "name" and "models.starpii" in f.detectors for f in findings)


def test_mocked_piiranha_returns_multilingual_pii() -> None:
    manager = HierarchicalDetectorManager(model_detectors=[MockPiiranha(ModelDetectorConfig(enabled=True))])
    findings = manager.scan_text("联系人：张三")
    assert any(f.subtype == "name" and "models.piiranha" in f.detectors for f in findings)


def test_model_detector_failure_does_not_crash_manager() -> None:
    manager = HierarchicalDetectorManager(model_detectors=[FailingModel(ModelDetectorConfig(enabled=True))])
    assert manager.scan_text("hello") == []


def test_model_findings_merge_with_rule_findings() -> None:
    manager = HierarchicalDetectorManager(model_detectors=[MockStarPII(ModelDetectorConfig(enabled=True))])
    findings = manager.scan_text("Alice alice@example.com")
    assert any("rules.pii" in f.detectors for f in findings)
    assert any("models.starpii" in f.detectors for f in findings)


def test_overlapping_jwt_and_entropy_merge_into_one() -> None:
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = [f for f in scan_with_entropy("TOKEN=" + token) if f.subtype == "jwt"]
    assert len(findings) == 1
    assert "heuristic.entropy_context" in findings[0].detectors


class LowRiskPrivateKeyModel(Detector):
    name = "models.low_risk"

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        yield Finding.make(
            source_block_id=block.id,
            original_start=0,
            original_end=len(normalized.original),
            normalized_start=0,
            normalized_end=len(normalized.normalized),
            type="PII",
            subtype="name",
            risk="low",
            detector=self.name,
            suggested_action="warn",
        )


def test_rule_private_key_overrides_low_risk_model_finding() -> None:
    text = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    manager = HierarchicalDetectorManager(model_detectors=[LowRiskPrivateKeyModel()])
    finding = manager.scan_text(text)[0]
    assert finding.subtype == "private_key"
    assert finding.risk == "critical"


def test_model_only_name_is_medium_pii_not_critical() -> None:
    manager = HierarchicalDetectorManager(detectors_config={"flow": {"modules": []}}, model_detectors=[MockStarPII(ModelDetectorConfig(enabled=True))])
    finding = manager.scan_text("Alice")[0]
    assert finding.type == "PII"
    assert finding.risk == "medium"


class WeakSecretSignal(Detector):
    def __init__(self, name: str) -> None:
        self.name = name

    def detect(self, block: SourceBlock, normalized: NormalizedText) -> Iterable[Finding]:
        yield Finding.make(
            source_block_id=block.id,
            original_start=0,
            original_end=10,
            normalized_start=0,
            normalized_end=10,
            type="UNKNOWN_SECRET_CANDIDATE",
            subtype="opaque_token",
            risk="low",
            detector=self.name,
            suggested_action="warn",
        )


def test_multiple_weak_signals_raise_risk() -> None:
    findings = FindingAggregator().aggregate([*WeakSecretSignal("weak.a").detect(SourceBlock.from_text("abcdefghij"), NormalizedText("abcdefghij", "abcdefghij", tuple(range(10)))), *WeakSecretSignal("weak.b").detect(SourceBlock.from_text("abcdefghij"), NormalizedText("abcdefghij", "abcdefghij", tuple(range(10))))])
    assert findings[0].risk == "medium"


def test_detector_output_suggests_action_but_does_not_redact() -> None:
    text = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    finding = by_subtype(text, "api_key")
    assert finding.suggested_action == "redact"
    assert text[finding.original_start : finding.original_end].startswith("sk-proj-")


def test_apg_placeholder_detected_for_parser_validation() -> None:
    placeholder = "<APG:v1:path:path_123:sess_abc:1234567890:abcdef>"
    finding = by_subtype(placeholder, "signed_placeholder")
    assert "placeholder_parser_required" in finding.validators


def test_redaction_marker_detected_in_file_write_content() -> None:
    manager = HierarchicalDetectorManager()
    findings = manager.scan_text("OPENAI_API_KEY=<APG_REDACTED:SECRET>", kind="file_write_content")
    finding = next(f for f in findings if f.subtype == "redaction_marker")
    assert finding.suggested_action == "block"


def test_incomplete_apg_marker_does_not_span_lines() -> None:
    assert "redaction_marker" not in subtypes('print("<APG")\nif value > limit: pass')


@pytest.mark.parametrize(
    "example",
    ["<APG:v1:pii:...>", "<APG:v1:secret:...>", "<APG_PII:handle>"],
)
def test_canonical_placeholder_format_examples_are_not_findings(example: str) -> None:
    assert scan(example) == []


def test_json_extraction_preserves_pointer() -> None:
    blocks = extract_text_blocks({"messages": [{"content": "hello"}]})
    assert blocks[0].json_pointer == "/messages/0/content"


def test_custom_rule_detects_project_specific_pattern() -> None:
    manager = HierarchicalDetectorManager(
        detectors_config={
            "flow": {
                "modules": [
                    {
                        "id": "custom_rules",
                        "type": "regex_rules",
                        "rules": [
                            {
                                "id": "custom.customer_id",
                                "pattern": r"\bCUST-[0-9]{4}\b",
                                "type": "LOCAL_CONTEXT",
                                "subtype": "customer_id",
                                "risk": "medium",
                                "suggested_action": "redact",
                            }
                        ],
                    }
                ]
            }
        },
    )
    finding = manager.scan_text("case CUST-1234")[0]
    assert finding.subtype == "customer_id"
    assert finding.metadata["rule_id"] == "custom.customer_id"
