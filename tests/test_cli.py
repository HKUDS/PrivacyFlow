from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gateway.cli import LauncherConfigError, apply_launcher_environment, prepare_launcher_config


def test_first_interactive_start_creates_private_reusable_config(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    config = prepare_launcher_config(
        path,
        environ={},
        prompt=lambda _: "sk-test-provider-key",
        interactive=True,
    )

    assert config["_resolved_upstream_api_key"] == "sk-test-provider-key"
    assert config["local_api_key"] == "apg-local"
    assert config["admin_api_key"] == "apg-local"
    assert config["upstream_base_url"] == "https://api.deepseek.com"
    assert config["strip_local_v1"] is True
    assert len(config["signing_secret"]) >= 32
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["upstream_api_key"] == "sk-test-provider-key"
    assert "_resolved_upstream_api_key" not in stored

    reused = prepare_launcher_config(path, environ={}, interactive=False)
    assert reused["signing_secret"] == config["signing_secret"]
    assert reused["_resolved_upstream_api_key"] == "sk-test-provider-key"


def test_noninteractive_start_requires_an_upstream_key(tmp_path: Path) -> None:
    with pytest.raises(LauncherConfigError, match="No upstream API key configured"):
        prepare_launcher_config(tmp_path / ".apg" / "launcher.json", environ={}, interactive=False)


def test_environment_overrides_launcher_defaults_without_persisting_provider_key(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    config = prepare_launcher_config(
        path,
        environ={"APG_UPSTREAM_API_KEY": "ephemeral-provider-key"},
        interactive=False,
    )
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert "upstream_api_key" not in stored

    environment = {
        "APG_UPSTREAM_API_KEY": "environment-wins",
        "APG_LOCAL_API_KEYS": "custom-local-key",
    }
    config["_resolved_upstream_api_key"] = environment["APG_UPSTREAM_API_KEY"]
    apply_launcher_environment(config, environ=environment)
    assert environment["APG_UPSTREAM_API_KEY"] == "environment-wins"
    assert environment["APG_LOCAL_API_KEYS"] == "custom-local-key"
    assert environment["APG_ADMIN_API_KEYS"] == "apg-local"
    assert environment["APG_UPSTREAM_STRIP_LOCAL_V1"] == "true"
