from __future__ import annotations

import pytest

from gateway.config import load_config
from gateway.mapping_store import MappingStore
from gateway.placeholder_parser import PlaceholderSigner
from gateway.policy_engine import PolicyEngine
from gateway.redaction_engine import RedactionEngine
from gateway.detector_manager import DetectorManager


def test_strict_mode_rejects_default_api_key(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("APG_LOCAL_API_KEYS", raising=False)
    monkeypatch.delenv("APG_SIGNING_SECRET", raising=False)
    cfg_path = tmp_path / "policy.yaml"
    cfg_path.write_text("strict_mode: true\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="APG_STRICT_LOCAL_KEY"):
        load_config(str(cfg_path))


def test_strict_mode_rejects_default_signing_secret(tmp_path, monkeypatch) -> None:
    cfg_path = tmp_path / "policy.yaml"
    cfg_path.write_text(
        "strict_mode: true\nlocal_api_keys:\n  - real-key\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("APG_SIGNING_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="APG_STRICT_SIGNING_SECRET"):
        load_config(str(cfg_path))


def test_strict_mode_disabled_warns_instead_of_raising(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("APG_LOCAL_API_KEYS", raising=False)
    monkeypatch.delenv("APG_SIGNING_SECRET", raising=False)
    cfg_path = tmp_path / "policy.yaml"
    cfg_path.write_text("strict_mode: false\n", encoding="utf-8")
    cfg = load_config(str(cfg_path))  # no exception
    assert cfg.strict_mode is False


def test_pii_mode_pseudonymize_uses_apg_pii_placeholder(tmp_path) -> None:
    pol = PolicyEngine(pii_mode="pseudonymize")
    store = MappingStore(str(tmp_path / "s.sqlite3"))
    signer = PlaceholderSigner("s", "ws")
    red = RedactionEngine(DetectorManager(), store, signer, pol, "ws")
    out, ev = red.sanitize_text("contact me at alice@example.com please", session_id="sess")
    assert "<APG_PII:" in out
    assert "alice@example.com" not in out
    assert ev and ev[0]["action"] == "pseudonymize"


def test_pii_mode_redact_treats_pii_as_secret(tmp_path) -> None:
    pol = PolicyEngine(pii_mode="redact")
    store = MappingStore(str(tmp_path / "s.sqlite3"))
    signer = PlaceholderSigner("s", "ws")
    red = RedactionEngine(DetectorManager(), store, signer, pol, "ws")
    out, ev = red.sanitize_text("contact alice@example.com", session_id="sess")
    # No <APG_PII:...> marker; a signed secret placeholder is issued instead.
    assert "<APG_PII:" not in out
    assert "<APG:v1:secret:" in out
    assert "alice@example.com" not in out
    assert ev and ev[0]["action"] == "redact"
    # Stored mapping kind is "secret" so materialization is gated to local_tool only.
    import re

    placeholder = re.search(r"<APG:v1:secret:(?P<handle>[^:]+):", out).group("handle")
    rec = store.get(placeholder)
    assert rec.kind == "secret" and rec.materialization_class == "secret"


def test_pii_mode_allow_passes_pii_through(tmp_path) -> None:
    pol = PolicyEngine(pii_mode="allow")
    store = MappingStore(str(tmp_path / "s.sqlite3"))
    signer = PlaceholderSigner("s", "ws")
    red = RedactionEngine(DetectorManager(), store, signer, pol, "ws")
    out, ev = red.sanitize_text("contact alice@example.com", session_id="sess")
    assert "alice@example.com" in out
    assert ev and ev[0]["action"] == "allow"


def test_invalid_pii_mode_raises() -> None:
    with pytest.raises(ValueError, match="Invalid pii_mode"):
        PolicyEngine(pii_mode="garble")