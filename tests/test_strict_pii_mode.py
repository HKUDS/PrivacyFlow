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


def test_pii_mode_pseudonymize_uses_signed_placeholder_and_restores_locally(tmp_path) -> None:
    pol = PolicyEngine(pii_mode="pseudonymize")
    store = MappingStore(str(tmp_path / "s.sqlite3"))
    signer = PlaceholderSigner("s", "ws")
    red = RedactionEngine(DetectorManager(), store, signer, pol, "ws")
    out, ev = red.sanitize_text("contact me at alice@example.com please", session_id="sess")
    assert "<APG:v1:pii:" in out
    assert "alice@example.com" not in out
    assert ev and ev[0]["action"] == "pseudonymize"
    local, local_events = red.scan_local_text(out, "sess")
    assert local == "contact me at alice@example.com please"
    assert any(event.get("sink") == "local_user" and event.get("action") == "materialize" for event in local_events)


def test_legacy_pii_placeholder_is_folded_not_materialized(tmp_path) -> None:
    red = RedactionEngine(
        DetectorManager(),
        MappingStore(str(tmp_path / "legacy.sqlite3")),
        PlaceholderSigner("s", "ws"),
        PolicyEngine(),
        "ws",
    )
    local, events = red.scan_local_text("contact <APG_PII:pii_forged>", "sess")
    assert local == "contact APG-managed protected value"
    assert any(event.get("action") == "fold" for event in events)


def test_raw_pii_echo_is_visible_locally_without_exposing_apg_handle(tmp_path) -> None:
    red = RedactionEngine(
        DetectorManager(),
        MappingStore(str(tmp_path / "echo.sqlite3")),
        PlaceholderSigner("s", "ws"),
        PolicyEngine(),
        "ws",
    )
    local, _ = red.scan_local_text("Contact alice@example.com", "sess")
    assert local == "Contact alice@example.com"
    assert "<APG" not in local


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
    # Stored mapping kind is "secret", so it can be restored only at local
    # user/tool sinks and never into upstream traffic.
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


def test_strict_mode_rejects_pii_allow(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("APG_LOCAL_API_KEYS", "local")
    monkeypatch.setenv("APG_SIGNING_SECRET", "secret")
    cfg_path = tmp_path / "policy.yaml"
    cfg_path.write_text("strict_mode: true\npii_mode: allow\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="APG_STRICT_PII_ALLOW"):
        load_config(str(cfg_path))


def test_config_expands_exact_environment_references(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("APG_LOCAL_API_KEYS", "local")
    monkeypatch.setenv("APG_SIGNING_SECRET", "secret")
    monkeypatch.setenv("TEST_UPSTREAM_KEY", "resolved-key")
    cfg_path = tmp_path / "policy.yaml"
    cfg_path.write_text(
        "strict_mode: true\nupstream:\n  api_key: ${TEST_UPSTREAM_KEY}\n",
        encoding="utf-8",
    )
    assert load_config(str(cfg_path)).upstream.api_key == "resolved-key"


def test_strict_config_rejects_unresolved_environment_reference(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("APG_LOCAL_API_KEYS", "local")
    monkeypatch.setenv("APG_SIGNING_SECRET", "secret")
    monkeypatch.delenv("MISSING_UPSTREAM_KEY", raising=False)
    cfg_path = tmp_path / "policy.yaml"
    cfg_path.write_text(
        "strict_mode: true\nupstream:\n  api_key: ${MISSING_UPSTREAM_KEY}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="APG_CONFIG_ENV_UNRESOLVED"):
        load_config(str(cfg_path))
