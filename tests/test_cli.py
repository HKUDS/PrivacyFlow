from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gateway.cli import (
    LauncherConfigError,
    activate_launcher_upstream_profile,
    apply_launcher_environment,
    delete_launcher_upstream_profile,
    normalize_upstream_base_url,
    prepare_launcher_config,
    save_launcher_upstream_configuration,
    save_launcher_upstream_profile,
)
from gateway.upstream_protocol import ANTHROPIC_MESSAGES, OPENAI_CHAT_COMPLETIONS


def test_first_start_creates_private_reusable_config_without_prompting_for_upstream_key(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    config = prepare_launcher_config(path, environ={})

    assert config["_resolved_upstream_api_key"] == ""
    assert config["_resolved_upstream_base_url"] == ""
    assert config["_resolved_upstream_protocol"] == ""
    assert config["_launcher_config_path"] == str(path.resolve())
    assert config["local_api_key"].startswith("apg_local_")
    assert "admin_api_key" not in config
    assert config["upstream_profiles"] == []
    assert config["active_upstream_profile_id"] == ""
    assert config["strip_local_v1"] is True
    assert len(config["signing_secret"]) >= 32
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(path.parent).st_mode & 0o777 == 0o700

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert "upstream_api_key" not in stored
    assert "_resolved_upstream_api_key" not in stored

    reused = prepare_launcher_config(path, environ={})
    assert reused["signing_secret"] == config["signing_secret"]
    assert reused["local_api_key"] == config["local_api_key"]
    assert reused["_resolved_upstream_api_key"] == ""


def test_saved_webui_upstream_key_is_private_and_reused(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    prepare_launcher_config(path, environ={})

    save_launcher_upstream_configuration(path, "anthropic", "https://api.example.com/anthropic/", "saved-provider-key")

    assert os.stat(path).st_mode & 0o777 == 0o600
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["active_upstream_profile_id"] == stored["upstream_profiles"][0]["id"]
    assert stored["upstream_profiles"][0]["protocol"] == ANTHROPIC_MESSAGES
    assert stored["upstream_profiles"][0]["base_url"] == "https://api.example.com/anthropic"
    assert stored["upstream_profiles"][0]["api_key"] == "saved-provider-key"
    reused = prepare_launcher_config(path, environ={})
    assert reused["_resolved_upstream_protocol"] == ANTHROPIC_MESSAGES
    assert reused["_resolved_upstream_base_url"] == "https://api.example.com/anthropic"
    assert reused["_resolved_upstream_api_key"] == "saved-provider-key"


def test_environment_overrides_launcher_defaults_without_persisting_provider_key(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    config = prepare_launcher_config(
        path,
        environ={
            "APG_UPSTREAM_BASE_URL": "https://environment.example/v1",
            "APG_UPSTREAM_API_KEY": "ephemeral-provider-key",
            "APG_UPSTREAM_PROTOCOL": "anthropic",
        },
    )
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert "upstream_api_key" not in stored

    environment = {
        "APG_UPSTREAM_BASE_URL": "https://environment.example/v1",
        "APG_UPSTREAM_API_KEY": "environment-wins",
        "APG_UPSTREAM_PROTOCOL": "anthropic",
        "APG_LOCAL_API_KEYS": "custom-local-key",
    }
    config["_resolved_upstream_api_key"] = environment["APG_UPSTREAM_API_KEY"]
    apply_launcher_environment(config, environ=environment)
    assert environment["APG_UPSTREAM_API_KEY"] == "environment-wins"
    assert environment["APG_UPSTREAM_BASE_URL"] == "https://environment.example/v1"
    assert environment["APG_UPSTREAM_PROTOCOL"] == "anthropic"
    assert environment["APG_LOCAL_API_KEYS"] == "custom-local-key"
    assert "APG_ADMIN_API_KEYS" not in environment
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


def test_existing_launcher_connection_migrates_to_openai_chat_completions_protocol(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    path.parent.mkdir()
    path.write_text(
        json.dumps(
            {
                "upstream_base_url": "https://api.example.com/v1",
                "upstream_api_key": "provider-key",
            }
        ),
        encoding="utf-8",
    )

    config = prepare_launcher_config(path, environ={})

    assert config["_resolved_upstream_protocol"] == OPENAI_CHAT_COMPLETIONS
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["upstream_profiles"][0]["protocol"] == OPENAI_CHAT_COMPLETIONS
    assert "upstream_protocol" not in stored


@pytest.mark.parametrize(
    ("legacy", "canonical"),
    [
        ("openai", OPENAI_CHAT_COMPLETIONS),
        ("anthropic", ANTHROPIC_MESSAGES),
    ],
)
def test_existing_legacy_protocol_is_migrated(tmp_path: Path, legacy: str, canonical: str) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    path.parent.mkdir()
    path.write_text(
        json.dumps(
            {
                "upstream_protocol": legacy,
                "upstream_base_url": "https://api.example.com",
                "upstream_api_key": "provider-key",
            }
        ),
        encoding="utf-8",
    )

    config = prepare_launcher_config(path, environ={})

    assert config["_resolved_upstream_protocol"] == canonical
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["upstream_profiles"][0]["protocol"] == canonical
    assert "upstream_protocol" not in stored


def test_multiple_upstream_profiles_can_be_saved_activated_and_deleted(tmp_path: Path) -> None:
    path = tmp_path / ".apg" / "launcher.json"
    prepare_launcher_config(path, environ={})

    first = save_launcher_upstream_profile(
        path,
        profile_id="",
        name="OpenAI production",
        protocol=OPENAI_CHAT_COMPLETIONS,
        base_url="https://openai.example/v1",
        api_key="openai-key",
    )
    second = save_launcher_upstream_profile(
        path,
        profile_id="",
        name="Anthropic production",
        protocol=ANTHROPIC_MESSAGES,
        base_url="https://anthropic.example",
        api_key="anthropic-key",
    )

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert len(stored["upstream_profiles"]) == 2
    assert stored["active_upstream_profile_id"] == second["id"]
    assert {profile["name"] for profile in stored["upstream_profiles"]} == {
        "OpenAI production",
        "Anthropic production",
    }

    activated = activate_launcher_upstream_profile(path, first["id"])
    assert activated["api_key"] == "openai-key"
    prepared = prepare_launcher_config(path, environ={})
    assert prepared["_resolved_upstream_api_key"] == "openai-key"

    remaining = delete_launcher_upstream_profile(path, first["id"])
    assert remaining is not None
    assert remaining["id"] == second["id"]
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert [profile["id"] for profile in stored["upstream_profiles"]] == [second["id"]]
    assert stored["active_upstream_profile_id"] == second["id"]
