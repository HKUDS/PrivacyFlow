from __future__ import annotations

from collections.abc import Iterable

import pytest

from gateway.detectors.base import Detector
from gateway.detectors.findings import Finding, SourceBlock
from gateway.detectors.manager import HierarchicalDetectorManager, extract_text_blocks
from gateway.detectors.models.base_model_detector import BaseModelDetector, ModelDetectorConfig
from gateway.detectors.normalizer import NormalizedText
from gateway.detectors.scoring import FindingAggregator


def scan(text: str):
    return HierarchicalDetectorManager().scan_text(text)


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
    assert "bearer_token" in subtypes("Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890")


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
    assert exported[exported_finding.original_start : exported_finding.original_end] == '"secret-value"'

    read_output = '    42\u2192export SERVICE_TOKEN="secret-value"'
    read_finding = by_subtype(read_output, "env_assignment")
    assert read_output[read_finding.original_start : read_finding.original_end] == '"secret-value"'


@pytest.mark.parametrize(
    "text",
    [
        "OPENAI_API_KEY_SET=true",
        "OPENAI_API_KEY_SET=true/false",
        "SERVICE_TOKEN='configured'",
        "DATABASE_URL=${DATABASE_URL}",
        "API_KEY=your-openai-api-key-here",
    ],
)
def test_env_assignment_ignores_status_references_and_placeholders(text: str) -> None:
    assert "env_assignment" not in subtypes(text)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("API_KEY=x", "x"),
        ("lowercase_api_key=real-short-value", "real-short-value"),
        ('SERVICE_TOKEN="secret value with spaces"', '"secret value with spaces"'),
        ("PASSWORD=p@ssword#part", "p@ssword#part"),
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


def test_phone_detected() -> None:
    assert "phone" in subtypes("+1 (415) 555-1212")


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
    finding = by_subtype("value abcdefghijklmnopqrstuvwxyzABCDEFGH1234567890", "high_entropy_token")
    assert finding.risk == "medium"
    assert "sensitive_context" not in finding.metadata
    assert "weak_context" not in finding.metadata


def test_high_entropy_sha256_uses_same_context_free_risk() -> None:
    finding = by_subtype("SHA256 abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890", "high_entropy_token")
    assert finding.risk == "medium"


def test_plain_schema_url_is_not_high_entropy_secret() -> None:
    assert "high_entropy_token" not in subtypes("schema: https://json-schema.org/draft-07/schema#")


def test_repository_script_path_is_not_high_entropy_secret() -> None:
    assert "high_entropy_token" not in subtypes("run python scripts/validate_secret.py VALUE")
    assert "high_entropy_token" not in subtypes("ripts/validate_secret.py")
    assert "high_entropy_token" not in subtypes("inspect logs/assignment_edge.log")


def test_local_path_span_excludes_sentence_punctuation() -> None:
    text = "Read /private/tmp/project/private/path_probe.txt."
    finding = by_subtype(text, "local_path")
    assert text[finding.original_start : finding.original_end] == "/private/tmp/project/private/path_probe.txt"


def test_fake_context_does_not_downgrade_provider_token() -> None:
    finding = by_subtype("fake example key sk-proj-abcdefghijklmnopqrstuvwxyz123456", "openai_api_key")
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
    findings = [f for f in scan("TOKEN=" + token) if f.subtype == "jwt"]
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
    finding = by_subtype(text, "openai_api_key")
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
