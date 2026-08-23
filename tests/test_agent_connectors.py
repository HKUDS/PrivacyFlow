from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
import shutil
import stat
import threading
from pathlib import Path

import pytest
import tomlkit
from ruamel.yaml import YAML

from gateway.agent_connectors import AgentConnectorService, ConnectorError
from gateway.cli.launcher import (
    LauncherConfigError,
    apply_launcher_environment,
    load_connector_api_key,
    prepare_launcher_config,
)


def service(tmp_path: Path, *, installed: bool = True) -> AgentConnectorService:
    return AgentConnectorService(
        tmp_path / ".apg",
        tmp_path / ".apg" / "launcher.json",
        environ={
            "CODEX_HOME": str(tmp_path / ".codex"),
            "CLAUDE_CONFIG_DIR": str(tmp_path / ".claude"),
            "DSH_HOME": str(tmp_path / ".dsh"),
        },
        home=tmp_path,
        which=(lambda _: "/usr/local/bin/agent" if installed else None),
    )


@pytest.mark.parametrize("connector_id", ["codex", "claude-code", "deepseek-harness", "nanobot"])
def test_connect_and_restore_missing_files_exactly(tmp_path: Path, connector_id: str) -> None:
    manager = service(tmp_path)
    connected = manager.connect(connector_id, "model-a", ["model-a", "model-b"])
    assert connected["status"] == "connected"
    assert connected["model"] == "model-a"
    assert all(Path(path).exists() for path in connected["paths"])
    assert all(stat.S_IMODE(Path(path).stat().st_mode) == 0o600 for path in connected["paths"])
    key = load_connector_api_key(tmp_path / ".apg" / "launcher.json", connector_id)
    assert key.startswith("apg_local_")
    assert key not in json.dumps(manager.list())

    restored = manager.restore(connector_id)
    assert restored["status"] == "ready"
    assert not any(Path(path).exists() for path in connected["paths"])
    with pytest.raises(LauncherConfigError):
        load_connector_api_key(tmp_path / ".apg" / "launcher.json", connector_id)


def test_restore_remains_successful_when_completed_transaction_cleanup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = service(tmp_path)
    connected = manager.connect("nanobot", "model-a", ["model-a"])
    monkeypatch.setattr(
        manager,
        "_prune_transaction_dirs",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cleanup failed")),
    )

    restored = manager.restore("nanobot")

    assert restored["status"] == "ready"
    assert not any(Path(path).exists() for path in connected["paths"])
    with pytest.raises(LauncherConfigError):
        load_connector_api_key(tmp_path / ".apg" / "launcher.json", "nanobot")


def test_restore_rejects_snapshot_path_outside_connector_state(tmp_path: Path) -> None:
    manager = service(tmp_path)
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_text('model = "original"\n', encoding="utf-8")
    manager.connect("codex", "model-a", ["model-a"])
    connected = config.read_bytes()
    outside = tmp_path / "outside.snapshot"
    outside.write_bytes(b"attacker-controlled")
    state = json.loads(manager.index_path.read_text(encoding="utf-8"))
    state["active"]["codex"]["files"][0]["snapshot"] = str(outside)
    manager.index_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ConnectorError) as exc_info:
        manager.restore("codex")

    assert exc_info.value.code == "CONNECTOR_STATE_INVALID"
    assert config.read_bytes() == connected
    assert outside.read_bytes() == b"attacker-controlled"


def test_codex_preserves_comments_and_uses_credential_command(tmp_path: Path) -> None:
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    original = b'# keep this comment\napproval_policy = "on-request"\n'
    config.write_bytes(original)
    os.chmod(config, 0o640)
    manager = service(tmp_path)

    manager.connect("codex", "gpt-test", ["gpt-test"])
    rendered = config.read_text("utf-8")
    value = tomlkit.parse(rendered)
    assert "# keep this comment" in rendered
    assert value["approval_policy"] == "on-request"
    assert value["model_provider"] == "pf"
    assert value["model_providers"]["pf"]["wire_api"] == "responses"
    assert value["model_providers"]["pf"]["auth"]["command"] == "privacyflow"
    assert "apg_local_" not in rendered

    manager.restore("codex")
    assert config.read_bytes() == original
    assert stat.S_IMODE(config.stat().st_mode) == 0o640


def test_claude_maps_all_model_families_and_preserves_fields(tmp_path: Path) -> None:
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"permissions": {"allow": ["Read"]}, "env": {"KEEP": "yes"}}))
    manager = service(tmp_path)
    manager.connect("claude-code", "upstream/model", ["upstream/model"])
    value = json.loads(path.read_text())
    assert value["permissions"]["allow"] == ["Read"]
    assert value["env"]["KEEP"] == "yes"
    for name in ("ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_DEFAULT_FABLE_MODEL"):
        assert value["env"][name] == "upstream/model"


def test_dsh_preserves_yaml_comments_and_writes_complete_catalog(tmp_path: Path) -> None:
    settings = tmp_path / ".dsh" / "settings.yaml"
    credentials = tmp_path / ".dsh" / ".credentials.yaml"
    settings.parent.mkdir()
    settings.write_text("# keep\ntheme: dark\n")
    credentials.write_text("OTHER_KEY: existing\n")
    manager = service(tmp_path)
    manager.connect("deepseek-harness", "m2", ["m1", "m2"])
    yaml = YAML(typ="safe")
    parsed = yaml.load(settings.read_text())
    creds = yaml.load(credentials.read_text())
    assert "# keep" in settings.read_text()
    assert parsed["theme"] == "dark"
    assert [item["id"] for item in parsed["llm-pi-ai"]["providers"]["pf"]["models"]] == ["m1", "m2"]
    assert parsed["llm-pi-ai"]["providers"]["pf"]["api"] == "openai-completions"
    assert parsed["llm-pi-ai"]["providers"]["pf"]["apiKeyEnv"] == "PF_DSH_API_KEY"
    assert parsed["llm-pi-ai"]["providers"]["pf"]["models"][0]["input"] == ["text"]
    assert parsed["agent-default-model"] == {"provider": "pf", "model": "m2"}
    assert creds["OTHER_KEY"] == "existing"
    assert creds["PF_DSH_API_KEY"].startswith("apg_local_")


def test_nanobot_preserves_fields_and_sets_pf_preset(tmp_path: Path) -> None:
    path = tmp_path / ".nanobot" / "config.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"channels": {"telegram": {"enabled": False}}}))
    manager = service(tmp_path)
    manager.connect("nanobot", "model-z", ["model-z"])
    value = json.loads(path.read_text())
    assert value["channels"]["telegram"]["enabled"] is False
    assert value["providers"]["pf"]["apiType"] == "chat_completions"
    assert value["modelPresets"]["PF"] == {"provider": "pf", "model": "model-z"}
    assert value["agents"]["defaults"]["modelPreset"] == "PF"


def test_external_change_requires_confirmation_and_creates_safety_backup(tmp_path: Path) -> None:
    manager = service(tmp_path)
    manager.connect("nanobot", "model-z", ["model-z"])
    path = tmp_path / ".nanobot" / "config.json"
    path.write_text('{"changed": true}\n')
    with pytest.raises(ConnectorError) as caught:
        manager.restore("nanobot")
    assert caught.value.status_code == 409
    assert caught.value.paths == [str(path)]
    assert path.exists()
    manager.restore("nanobot", confirm_external_changes=True)
    assert not path.exists()
    backups = list((tmp_path / ".apg" / "agent-connection-transactions" / "nanobot" / "safety").glob("*/0.backup"))
    assert len(backups) == 1
    assert backups[0].read_text() == '{"changed": true}\n'


def test_rejects_reserved_collision_symlink_and_not_installed(tmp_path: Path) -> None:
    path = tmp_path / ".nanobot" / "config.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"providers": {"apg": {"unknown": True}}}))
    with pytest.raises(ConnectorError, match="reserved"):
        service(tmp_path).connect("nanobot", "m", ["m"])
    path.unlink()
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    path.symlink_to(target)
    with pytest.raises(ConnectorError, match="symbolic link"):
        service(tmp_path).connect("nanobot", "m", ["m"])
    with pytest.raises(ConnectorError) as caught:
        service(tmp_path, installed=False).connect("codex", "m", ["m"])
    assert caught.value.code == "CONNECTOR_NOT_INSTALLED"


def test_atomic_write_rechecks_target_after_symlink_race(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager = service(tmp_path)
    path = tmp_path / ".codex" / "config.toml"
    path.parent.mkdir()
    path.write_text("original", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    original_check = manager._validate_target_at
    checks = 0

    def inject_symlink(parent_fd, name, display_path, *, allow_missing=True):
        nonlocal checks
        result = original_check(parent_fd, name, display_path, allow_missing=allow_missing)
        checks += 1
        if checks == 1:
            path.unlink()
            path.symlink_to(outside)
        return result

    monkeypatch.setattr(manager, "_validate_target_at", inject_symlink)

    with pytest.raises(ConnectorError) as exc_info:
        manager._atomic_write(path, b"replacement", 0o600)

    assert exc_info.value.code == "CONNECTOR_PATH_UNSAFE"
    assert outside.read_text(encoding="utf-8") == "outside"


def test_rejects_existing_claude_apg_environment_keys_without_transaction(tmp_path: Path) -> None:
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir()
    original = json.dumps({"env": {"ANTHROPIC_MODEL": "user-managed-model"}}).encode() + b"\n"
    path.write_bytes(original)
    with pytest.raises(ConnectorError) as caught:
        service(tmp_path).connect("claude-code", "m", ["m"])
    assert caught.value.code == "CONNECTOR_CONFIG_CONFLICT"
    assert caught.value.requires_confirmation is True
    assert caught.value.paths == [str(path)]
    assert json.loads(path.read_text())["env"]["ANTHROPIC_MODEL"] == "user-managed-model"


def test_confirmed_existing_claude_config_is_snapshotted_and_restorable(tmp_path: Path) -> None:
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir()
    original = b'{"permissions":{"allow":["Read"]},"env":{"ANTHROPIC_MODEL":"user-managed-model"}}\n'
    path.write_bytes(original)
    manager = service(tmp_path)

    connected = manager.connect(
        "claude-code",
        "m",
        ["m"],
        confirm_existing_config=True,
    )
    assert connected["status"] == "connected"
    assert json.loads(path.read_text())["env"]["ANTHROPIC_MODEL"] == "m"
    assert json.loads(path.read_text())["permissions"] == {"allow": ["Read"]}

    restored = manager.restore("claude-code")
    assert restored["status"] == "ready"
    assert path.read_bytes() == original


def test_dsh_detection_uses_user_install_paths_when_apg_path_is_minimal(tmp_path: Path) -> None:
    bin_dir = tmp_path / ".npm-global" / "bin"
    bin_dir.mkdir(parents=True)
    executable = bin_dir / "dsh"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o700)
    manager = AgentConnectorService(
        tmp_path / ".apg",
        tmp_path / ".apg" / "launcher.json",
        environ={"PATH": "/usr/bin"},
        home=tmp_path,
        which=shutil.which,
    )
    status = next(item for item in manager.list()["connectors"] if item["id"] == "deepseek-harness")
    assert status["installed"] is True
    assert status["executable"] == str(executable)
    assert status["detection"] == "path"


def test_dsh_detection_reads_official_global_package_when_bin_shim_is_missing(tmp_path: Path) -> None:
    package = tmp_path / ".npm-global" / "lib" / "node_modules" / "@deepseek-ai" / "dsh"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "@deepseek-ai/dsh", "bin": {"dsh": "dist/cli.js"}}))
    (package / "dist").mkdir()
    (package / "dist" / "cli.js").write_text("#!/usr/bin/env node\n")
    manager = AgentConnectorService(
        tmp_path / ".apg",
        tmp_path / ".apg" / "launcher.json",
        environ={"PATH": "/usr/bin"},
        home=tmp_path,
        which=lambda command, path=None: None,
    )
    status = next(item for item in manager.list()["connectors"] if item["id"] == "deepseek-harness")
    assert status["installed"] is True
    assert status["detection"] == "package"
    assert status["executable"].endswith("@deepseek-ai/dsh/dist/cli.js")


def test_dsh_detection_reads_official_npx_cache_without_global_shim(tmp_path: Path) -> None:
    package = tmp_path / ".npm" / "_npx" / "opaque-cache" / "node_modules" / "@deepseek-ai" / "dsh"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "@deepseek-ai/dsh", "bin": "dist/cli.js"}))
    (package / "dist").mkdir()
    (package / "dist" / "cli.js").write_text("#!/usr/bin/env node\n")
    manager = AgentConnectorService(
        tmp_path / ".apg",
        tmp_path / ".apg" / "launcher.json",
        environ={"PATH": "/usr/bin"},
        home=tmp_path,
        which=lambda command, path=None: None,
    )
    status = next(item for item in manager.list()["connectors"] if item["id"] == "deepseek-harness")
    assert status["installed"] is True
    assert status["detection"] == "package"
    assert status["executable"].endswith("@deepseek-ai/dsh/dist/cli.js")


def test_active_connect_is_idempotent_but_changed_model_is_blocked(tmp_path: Path) -> None:
    manager = service(tmp_path)
    first = manager.connect("codex", "m1", ["m1", "m2"])
    second = manager.connect("codex", "m1", ["m1", "m2"])
    assert second["model"] == first["model"]
    with pytest.raises(ConnectorError) as caught:
        manager.connect("codex", "m2", ["m1", "m2"])
    assert caught.value.status_code == 409


def test_independent_services_serialize_connect_transactions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first = service(tmp_path)
    second = service(tmp_path)
    first_state_started = threading.Event()
    release_first_state = threading.Event()
    second_lock_attempted = threading.Event()
    second_state_written = threading.Event()
    original_first_write_state = first._write_state
    original_second_write_state = second._write_state
    original_second_transaction_lock = second._transaction_lock

    def hold_first_state(state: dict) -> None:
        first_state_started.set()
        assert release_first_state.wait(timeout=5)
        original_first_write_state(state)

    def record_second_state(state: dict) -> None:
        second_state_written.set()
        original_second_write_state(state)

    @contextmanager
    def observe_second_transaction_lock():
        second_lock_attempted.set()
        with original_second_transaction_lock():
            yield

    monkeypatch.setattr(first, "_write_state", hold_first_state)
    monkeypatch.setattr(second, "_write_state", record_second_state)
    monkeypatch.setattr(second, "_transaction_lock", observe_second_transaction_lock)

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(first.connect, "codex", "model-codex", ["model-codex"])
        assert first_state_started.wait(timeout=5)
        second_future = executor.submit(second.connect, "nanobot", "model-nanobot", ["model-nanobot"])
        assert second_lock_attempted.wait(timeout=5)
        # Without the transaction lock, the second instance can write its
        # stale state while the first transaction is paused at its state write.
        assert not second_state_written.wait(timeout=0.2)
        release_first_state.set()
        first_result = first_future.result(timeout=5)
        second_result = second_future.result(timeout=5)

    assert second_state_written.is_set()

    assert {first_result["id"], second_result["id"]} == {"codex", "nanobot"}
    state = json.loads((tmp_path / ".apg" / "agent-connections.json").read_text())
    assert set(state["active"]) == {"codex", "nanobot"}
    transaction_dirs = [
        path
        for connector_id in ("codex", "nanobot")
        for path in (tmp_path / ".apg" / "agent-connection-transactions" / connector_id).iterdir()
        if path.is_dir() and path.name != "safety"
    ]
    assert len(transaction_dirs) == 2
    launcher = json.loads((tmp_path / ".apg" / "launcher.json").read_text())
    assert set(launcher["connector_api_keys"]) == {"codex", "nanobot"}
    assert stat.S_IMODE((tmp_path / ".apg" / "agent-connections.lock").stat().st_mode) == 0o600

    first.restore("codex")
    second.restore("nanobot")
    assert not Path(first_result["paths"][0]).exists()
    assert not Path(second_result["paths"][0]).exists()


def test_multifile_restore_failure_rolls_back_connected_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = tmp_path / ".dsh" / "settings.yaml"
    credentials = tmp_path / ".dsh" / ".credentials.yaml"
    settings.parent.mkdir()
    settings.write_bytes(b"theme: original\n")
    credentials.write_bytes(b"OTHER: original\n")
    manager = service(tmp_path)
    manager.connect("deepseek-harness", "m1", ["m1"])
    connected_settings = settings.read_bytes()
    connected_credentials = credentials.read_bytes()
    original_atomic_write = manager._atomic_write
    calls = 0

    def fail_second(path: Path, content: bytes, mode: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected restore failure")
        original_atomic_write(path, content, mode)

    monkeypatch.setattr(manager, "_atomic_write", fail_second)
    with pytest.raises(OSError, match="injected"):
        manager.restore("deepseek-harness")
    assert settings.read_bytes() == connected_settings
    assert credentials.read_bytes() == connected_credentials
    assert manager.list()["connectors"][2]["status"] == "connected"
    assert load_connector_api_key(tmp_path / ".apg" / "launcher.json", "deepseek-harness")


def test_state_write_failure_rolls_back_restore_and_keeps_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manager = service(tmp_path)
    manager.connect("nanobot", "m1", ["m1"])
    path = tmp_path / ".nanobot" / "config.json"
    connected = path.read_bytes()
    key = load_connector_api_key(tmp_path / ".apg" / "launcher.json", "nanobot")
    original_write_state = manager._write_state

    def fail_completed_state(state: dict) -> None:
        if "nanobot" not in state["active"]:
            raise OSError("injected state failure")
        original_write_state(state)

    monkeypatch.setattr(manager, "_write_state", fail_completed_state)
    with pytest.raises(OSError, match="injected state failure"):
        manager.restore("nanobot")
    assert path.read_bytes() == connected
    assert load_connector_api_key(tmp_path / ".apg" / "launcher.json", "nanobot") == key
    assert manager.list()["connectors"][3]["status"] == "connected"


def test_launcher_merges_connector_keys_with_explicit_runtime_keys(tmp_path: Path) -> None:
    manager = service(tmp_path)
    manager.connect("codex", "m1", ["m1"])
    launcher = tmp_path / ".apg" / "launcher.json"
    connector_key = load_connector_api_key(launcher, "codex")
    config = prepare_launcher_config(launcher, environ={})
    environment = {"APG_LOCAL_API_KEYS": "runtime-main,runtime-secondary"}
    apply_launcher_environment(config, environ=environment)
    assert environment["APG_LOCAL_API_KEYS"].split(",") == ["runtime-main", "runtime-secondary", connector_key]
    assert environment["PF_PRIMARY_LOCAL_API_KEY"] == "runtime-main"
    assert "APG_PRIMARY_LOCAL_API_KEY" not in environment


def test_connector_service_does_not_chmod_an_arbitrary_state_parent(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o755)

    AgentConnectorService(tmp_path, tmp_path / "launcher.json", home=tmp_path, environ={}, which=lambda *_args, **_kwargs: None)

    assert os.stat(tmp_path).st_mode & 0o777 == 0o755
    assert os.stat(tmp_path / "agent-connection-transactions").st_mode & 0o777 == 0o700


def test_rejects_wrong_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text("{}")
    monkeypatch.setattr(os, "getuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(ConnectorError) as caught:
        service(tmp_path).connect("claude-code", "m1", ["m1"])
    assert caught.value.code == "CONNECTOR_PATH_UNSAFE"


def test_multifile_connect_failure_restores_originals_and_revokes_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = tmp_path / ".dsh" / "settings.yaml"
    credentials = tmp_path / ".dsh" / ".credentials.yaml"
    settings.parent.mkdir()
    settings.write_bytes(b"theme: original\n")
    credentials.write_bytes(b"OTHER: original\n")
    manager = service(tmp_path)
    original_atomic_write = manager._atomic_write
    target_calls = 0

    def fail_second_target(path: Path, content: bytes, mode: int) -> None:
        nonlocal target_calls
        if path in {settings, credentials}:
            target_calls += 1
            if target_calls == 2:
                raise OSError("injected connect failure")
        original_atomic_write(path, content, mode)

    monkeypatch.setattr(manager, "_atomic_write", fail_second_target)
    with pytest.raises(OSError, match="injected connect failure"):
        manager.connect("deepseek-harness", "m1", ["m1"])
    assert settings.read_bytes() == b"theme: original\n"
    assert credentials.read_bytes() == b"OTHER: original\n"
    with pytest.raises(LauncherConfigError):
        load_connector_api_key(tmp_path / ".apg" / "launcher.json", "deepseek-harness")
    assert manager.list()["connectors"][2]["status"] == "ready"


def test_concurrent_change_after_snapshot_is_not_overwritten(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_bytes(b'{"before": true}\n')
    manager = service(tmp_path)
    original_replace_all = manager._replace_all

    def change_before_replace(prepared, snapshots) -> None:
        path.write_bytes(b'{"concurrent": true}\n')
        original_replace_all(prepared, snapshots)

    monkeypatch.setattr(manager, "_replace_all", change_before_replace)
    with pytest.raises(ConnectorError) as caught:
        manager.connect("claude-code", "m1", ["m1"])
    assert caught.value.code == "CONNECTOR_CONCURRENT_CHANGE"
    assert path.read_bytes() == b'{"concurrent": true}\n'
    with pytest.raises(LauncherConfigError):
        load_connector_api_key(tmp_path / ".apg" / "launcher.json", "claude-code")


@pytest.mark.parametrize(
    ("connector_id", "relative_path", "content"),
    [
        ("codex", ".codex/config.toml", 'model_providers = "invalid"\n'),
        ("claude-code", ".claude/settings.json", '{"env": []}\n'),
        ("deepseek-harness", ".dsh/settings.yaml", "llm-pi-ai: []\n"),
        ("nanobot", ".nanobot/config.json", '{"providers": []}\n'),
    ],
)
def test_invalid_nested_configuration_is_rejected_without_writes(
    tmp_path: Path,
    connector_id: str,
    relative_path: str,
    content: str,
) -> None:
    path = tmp_path / relative_path
    path.parent.mkdir()
    path.write_text(content)
    manager = service(tmp_path)
    with pytest.raises(ConnectorError) as caught:
        manager.connect(connector_id, "m1", ["m1"])
    assert caught.value.code == "CONNECTOR_CONFIG_INVALID"
    assert path.read_text() == content
