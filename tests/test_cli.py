from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gateway.cli import (
    LauncherConfigError,
    apply_launcher_environment,
    normalize_upstream_base_url,
    prepare_launcher_config,
    save_launcher_upstream_configuration,
)


def test_first_start_creates_private_reusable_config_without_prompting_for_upstream_key(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    config = prepare_launcher_config(path, environ={})

    assert config["_resolved_upstream_api_key"] == ""
    assert config["_resolved_upstream_base_url"] == ""
    assert config["_launcher_config_path"] == str(path.resolve())
    assert config["local_api_key"] == "apg-local"
    assert config["admin_api_key"] == "apg-local"
    assert config["upstream_base_url"] == ""
    assert config["strip_local_v1"] is True
    assert len(config["signing_secret"]) >= 32
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert "upstream_api_key" not in stored
    assert "_resolved_upstream_api_key" not in stored

    reused = prepare_launcher_config(path, environ={})
    assert reused["signing_secret"] == config["signing_secret"]
    assert reused["_resolved_upstream_api_key"] == ""


def test_saved_webui_upstream_key_is_private_and_reused(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    prepare_launcher_config(path, environ={})

    save_launcher_upstream_configuration(path, "https://api.example.com/v1/", "saved-provider-key")

    assert os.stat(path).st_mode & 0o777 == 0o600
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["upstream_base_url"] == "https://api.example.com/v1"
    assert stored["upstream_api_key"] == "saved-provider-key"
    reused = prepare_launcher_config(path, environ={})
    assert reused["_resolved_upstream_base_url"] == "https://api.example.com/v1"
    assert reused["_resolved_upstream_api_key"] == "saved-provider-key"


def test_environment_overrides_launcher_defaults_without_persisting_provider_key(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    config = prepare_launcher_config(
        path,
        environ={
            "APG_UPSTREAM_BASE_URL": "https://environment.example/v1",
            "APG_UPSTREAM_API_KEY": "ephemeral-provider-key",
        },
    )
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert "upstream_api_key" not in stored

    environment = {
        "APG_UPSTREAM_BASE_URL": "https://environment.example/v1",
        "APG_UPSTREAM_API_KEY": "environment-wins",
        "APG_LOCAL_API_KEYS": "custom-local-key",
    }
    config["_resolved_upstream_api_key"] = environment["APG_UPSTREAM_API_KEY"]
    apply_launcher_environment(config, environ=environment)
    assert environment["APG_UPSTREAM_API_KEY"] == "environment-wins"
    assert environment["APG_UPSTREAM_BASE_URL"] == "https://environment.example/v1"
    assert environment["APG_LOCAL_API_KEYS"] == "custom-local-key"
    assert environment["APG_ADMIN_API_KEYS"] == "apg-local"
    assert environment["APG_UPSTREAM_STRIP_LOCAL_V1"] == "true"
    assert environment["APG_LAUNCHER_CONFIG_PATH"] == str(path.resolve())


@pytest.mark.parametrize(
    "value",
    [
        "",
        "api.example.com/v1",
        "ftp://api.example.com",
        "https://user:pass@api.example.com",
        "https://api example.com/v1",
        "https://api.example.com:not-a-port/v1",
        "https://[::1/v1",
        "https://api.example.com/v1?token=secret",
        "https://api.example.com/v1#fragment",
    ],
)
def test_upstream_base_url_rejects_unsafe_or_incomplete_values(value: str) -> None:
    with pytest.raises(LauncherConfigError):
        normalize_upstream_base_url(value)
