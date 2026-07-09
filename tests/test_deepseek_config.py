from __future__ import annotations

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
    config = tmp_path / "policy.yaml"
    config.write_text(
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
              confidence: 0.8
              risk: medium
              suggested_action: redact
""",
        encoding="utf-8",
    )
    cfg = load_config(str(config))
    assert cfg.detectors_config["preset"] == "custom_minimal"
    assert cfg.detectors_config["presets"]["custom_minimal"]["modules"][0]["id"] == "custom_rules"
