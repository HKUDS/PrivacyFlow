from __future__ import annotations

from gateway.models import Detection
from gateway.policy_engine import PolicyEngine


def test_policy_secret_redact() -> None:
    det = Detection(0, 5, "secret", "api_key", 0.9, "high", "test", "redact")
    assert PolicyEngine().decision_for_detection(det).action == "redact"
