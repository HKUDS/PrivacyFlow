from __future__ import annotations

from gateway.models import Detection
from gateway.policy_engine import PolicyEngine


def test_policy_secret_redact() -> None:
    det = Detection(0, 5, "secret", "api_key", 0.9, "high", "test", "redact")
    assert PolicyEngine().decision_for_detection(det).action == "redact"


def test_policy_block_rejects_forwarding() -> None:
    det = Detection(0, 24, "secret", "private_key", "critical", "rules.secret.private_key", "block")
    decision = PolicyEngine().decision_for_detection(det)
    assert decision.allowed is False
    assert decision.action == "block"
    assert decision.retryable is False
    assert decision.reason_code == "block_private_key"
