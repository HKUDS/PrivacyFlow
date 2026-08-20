from __future__ import annotations

import pytest

from gateway.config import UpstreamConfig, load_config
from gateway.upstream_client import UpstreamClient


def test_deepseek_can_strip_local_v1_path() -> None:
    client = UpstreamClient(UpstreamConfig(base_url="https://api.deepseek.com", api_key="x", strip_local_v1=True))
    assert client.upstream_path("/v1/chat/completions") == "/chat/completions"
    assert client.upstream_path("/v1/models") == "/models"


def test_default_upstream_keeps_local_v1_path() -> None:
    client = UpstreamClient(UpstreamConfig(base_url="https://api.openai.com", api_key="x", strip_local_v1=False))
    assert client.upstream_path("/v1/chat/completions") == "/v1/chat/completions"


def test_removed_detector_section_is_ignored_with_visible_warning(tmp_path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("strict_mode: false\ndetectors:\n  preset: strict\n", encoding="utf-8")

    with pytest.warns(FutureWarning, match="fixed built-in protection pipeline"):
        config = load_config(str(path))

    assert not hasattr(config, "detectors_config")
