from __future__ import annotations

from pathlib import Path

from gateway.config import UpstreamConfig, load_config
from gateway.upstream_client import UpstreamClient


def test_deepseek_can_strip_local_v1_path() -> None:
    client = UpstreamClient(UpstreamConfig(base_url="https://api.deepseek.com", api_key="x", strip_local_v1=True))
    assert client.upstream_path("/v1/chat/completions") == "/chat/completions"
    assert client.upstream_path("/v1/models") == "/models"


def test_default_upstream_keeps_local_v1_path() -> None:
    client = UpstreamClient(UpstreamConfig(base_url="https://api.openai.com", api_key="x", strip_local_v1=False))
    assert client.upstream_path("/v1/chat/completions") == "/v1/chat/completions"


def test_detector_custom_preset_loaded_from_config(tmp_path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
strict_mode: false
detectors:
  preset: custom_minimal
  presets:
    custom_minimal:
      modules:
        - id: custom_rules
          type: regex_rules
          rules:
            - id: custom.ticket
              pattern: "\\\\bTICKET-[0-9]{6}\\\\b"
              type: LOCAL_CONTEXT
              subtype: ticket
              risk: medium
              suggested_action: redact
""",
        encoding="utf-8",
    )
    config = load_config(str(path))
    assert config.detectors_config["preset"] == "custom_minimal"
    assert config.detectors_config["presets"]["custom_minimal"]["modules"][0]["id"] == "custom_rules"


def test_shipped_policy_templates_are_runnable_with_documented_environment(monkeypatch) -> None:
    monkeypatch.setenv("PF_LOCAL_API_KEYS", "local-key")
    monkeypatch.setenv("PF_SIGNING_SECRET", "signing-secret")
    monkeypatch.setenv("PF_UPSTREAM_API_KEY", "upstream-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "deepseek-key")

    default = load_config(str(Path("config/example_policy.yaml")))
    monkeypatch.delenv("PF_UPSTREAM_API_KEY")
    deepseek = load_config(str(Path("config/deepseek_policy.example.yaml")))

    assert default.local_api_keys == {"local-key"}
    assert default.audit_log_max_bytes == 16 * 1024 * 1024
    assert default.audit_log_backups == 5
    assert default.history_retention_seconds == 30 * 86_400
    assert deepseek.upstream.api_key == "deepseek-key"
