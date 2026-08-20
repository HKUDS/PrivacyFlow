from __future__ import annotations

import json
import os
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gateway.compat import LegacyNamespaceWarning, NamespaceConflictError, get_env, translate_value
from gateway.agent_connectors import AgentConnectorService, ConnectorError
from gateway.cli.launcher import main as launcher_main
from gateway.config import GatewayConfig, UpstreamConfig
from gateway.migration import MigrationError, migrate_state, rollback_migration
from gateway.server import APG_UPSTREAM_SYSTEM_PROMPT, PF_UPSTREAM_SYSTEM_PROMPT, create_app
from ruamel.yaml import YAML


class _EchoUpstream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    async def request_json(self, method: str, path: str, payload: dict | None = None):
        self.calls.append((method, path, payload or {}))
        return 200, {"content-type": "application/json"}, {"choices": [{"message": {"content": "ok"}}]}


def test_pf_environment_wins_and_conflicts_fail_closed() -> None:
    assert get_env("PORT", environ={"PF_PORT": "9000", "APG_PORT": "9000"}) == "9000"
    with pytest.raises(NamespaceConflictError, match="PF_PORT and APG_PORT"):
        get_env("PORT", environ={"PF_PORT": "9000", "APG_PORT": "8765"})


def test_legacy_environment_warning_is_visible_once_without_value_leakage() -> None:
    code = """
import warnings
from gateway.compat import LegacyNamespaceWarning, get_env
warnings.simplefilter('default', LegacyNamespaceWarning)
environment = {'APG_UPSTREAM_API_KEY': 'must-not-appear'}
get_env('UPSTREAM_API_KEY', environ=environment)
get_env('UPSTREAM_API_KEY', environ=environment)
"""
    result = subprocess.run([sys.executable, "-c", code], text=True, capture_output=True, check=True)
    assert result.stderr.count("APG_UPSTREAM_API_KEY is deprecated") == 1
    assert "must-not-appear" not in result.stderr
    assert issubclass(LegacyNamespaceWarning, FutureWarning)


def test_state_migration_keeps_source_and_read_only_backup(tmp_path: Path) -> None:
    source = tmp_path / ".apg"
    source.mkdir(mode=0o700)
    runtime = source / "apg-runtime.json"
    runtime.write_text(json.dumps({"apg_enabled": True, "provider": "apg"}) + "\n", encoding="utf-8")
    os.chmod(runtime, 0o640)

    result = migrate_state(source, tmp_path / ".privacyflow")

    destination = tmp_path / ".privacyflow"
    assert source.exists()
    assert destination.exists()
    migrated = json.loads((destination / "pf-runtime.json").read_text(encoding="utf-8"))
    assert migrated == {"pf_enabled": True, "provider": "pf"}
    assert (destination / "pf-runtime.json").stat().st_mode & 0o777 == 0o640
    assert result.backup is not None
    assert result.backup.exists()
    assert result.backup.stat().st_mode & 0o222 == 0
    assert (result.backup / "apg-runtime.json").read_bytes() == runtime.read_bytes()


def test_state_migration_refuses_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / ".apg"
    source.mkdir()
    (source / "state.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".privacyflow").mkdir()
    with pytest.raises(MigrationError, match="already exists"):
        migrate_state(source, tmp_path / ".privacyflow")


def test_state_migration_does_not_remove_another_process_lock(tmp_path: Path) -> None:
    source = tmp_path / ".apg"
    source.mkdir()
    (source / "state.json").write_text("{}", encoding="utf-8")
    lock = tmp_path / ".privacyflow.migrate.lock"
    lock.write_text("active", encoding="utf-8")

    with pytest.raises(MigrationError) as exc_info:
        migrate_state(source, tmp_path / ".privacyflow")

    assert exc_info.value.code == "PF_MIGRATION_LOCKED"
    assert lock.read_text(encoding="utf-8") == "active"


def test_state_migration_keeps_distinct_safety_backups_on_retry(tmp_path: Path) -> None:
    source = tmp_path / ".apg"
    source.mkdir(mode=0o700)
    (source / "launcher.json").write_text("{}\n", encoding="utf-8")
    backup_root = tmp_path / ".apg.legacy"

    first = migrate_state(source, tmp_path / ".privacyflow-one", backup_root=backup_root)
    second = migrate_state(source, tmp_path / ".privacyflow-two", backup_root=backup_root)

    assert first.backup is not None and second.backup is not None
    assert first.backup != second.backup
    assert first.backup.exists() and second.backup.exists()


def test_outer_rollback_removes_read_only_attempt_without_touching_source(tmp_path: Path) -> None:
    source = tmp_path / ".apg"
    source.mkdir(mode=0o700)
    original = source / "launcher.json"
    original.write_text('{"local_api_key": "legacy"}\n', encoding="utf-8")

    result = migrate_state(source, tmp_path / ".privacyflow")
    assert result.backup is not None

    rollback_migration(result)

    assert original.read_text(encoding="utf-8") == '{"local_api_key": "legacy"}\n'
    assert not result.destination.exists()
    assert not result.backup.exists()


def test_cli_rolls_back_state_tree_when_connector_phase_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / ".apg"
    source.mkdir(mode=0o700)
    original = source / "launcher.json"
    original.write_text('{"local_api_key": "legacy"}\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def fail_connector_phase(_service: AgentConnectorService) -> dict[str, object]:
        raise OSError("injected connector failure")

    monkeypatch.setattr(AgentConnectorService, "migrate_legacy_namespace", fail_connector_phase)

    with pytest.raises(SystemExit) as exc_info:
        launcher_main(["migrate"])

    assert exc_info.value.code == 2
    assert original.read_text(encoding="utf-8") == '{"local_api_key": "legacy"}\n'
    assert not (tmp_path / ".privacyflow").exists()
    assert not any((tmp_path / ".apg.legacy").iterdir())


def test_state_migration_rewrites_connector_namespace_without_touching_notes(tmp_path: Path) -> None:
    source = tmp_path / ".apg"
    source.mkdir(mode=0o700)
    (source / "launcher.json").write_text(
        json.dumps({"connector_api_keys": {"codex": "apg_local_old"}, "note": "APG_UPSTREAM text"}) + "\n",
        encoding="utf-8",
    )
    (source / "agent-connections.json").write_text(
        json.dumps({"env": {"APG_DSH_API_KEY": "apg_local_old"}, "modelPresets": {"APG": {"provider": "apg"}}, "providers": {"apg": {}}}) + "\n",
        encoding="utf-8",
    )

    migrate_state(source, tmp_path / ".privacyflow")

    launcher = json.loads((tmp_path / ".privacyflow" / "launcher.json").read_text(encoding="utf-8"))
    settings = json.loads((tmp_path / ".privacyflow" / "agent-connections.json").read_text(encoding="utf-8"))
    # The original key must remain available until the external Agent files
    # have been migrated in the following all-or-nothing Connector phase.
    assert launcher["connector_api_keys"]["codex"] == "apg_local_old"
    assert launcher["note"] == "APG_UPSTREAM text"
    assert settings["env"] == {"PF_DSH_API_KEY": "apg_local_old"}
    assert "pf" in settings["providers"] and "apg" not in settings["providers"]
    assert "PF" in settings["modelPresets"] and "APG" not in settings["modelPresets"]


def _connector_service(root: Path, state_name: str) -> AgentConnectorService:
    environment = {
        "CODEX_HOME": str(root / ".codex"),
        "CLAUDE_CONFIG_DIR": str(root / ".claude"),
        "DSH_HOME": str(root / ".dsh"),
    }
    state_dir = root / state_name
    return AgentConnectorService(
        state_dir,
        state_dir / "launcher.json",
        environ=environment,
        home=root,
        which=lambda *_args, **_kwargs: "/usr/bin/true",
    )


def test_connector_namespace_migration_rotates_every_embedded_key_and_preserves_restore(tmp_path: Path) -> None:
    legacy = _connector_service(tmp_path, ".apg")
    connector_ids = ("codex", "claude-code", "deepseek-harness", "nanobot")
    for connector_id in connector_ids:
        legacy.connect(connector_id, "model-a", ["model-a", "model-b"])
    old_keys = {connector_id: legacy.credential(connector_id) for connector_id in connector_ids}

    migrate_state(tmp_path / ".apg", tmp_path / ".privacyflow")
    migrated = _connector_service(tmp_path, ".privacyflow")
    result = migrated.migrate_legacy_namespace()

    assert result["migrated_connectors"] == list(connector_ids)
    new_keys = {connector_id: migrated.credential(connector_id) for connector_id in connector_ids}
    assert all(value.startswith("pf_local_") for value in new_keys.values())
    assert all(new_keys[item] != old_keys[item] for item in connector_ids)

    claude = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    dsh_credentials = YAML(typ="safe").load((tmp_path / ".dsh" / ".credentials.yaml").read_text(encoding="utf-8"))
    nanobot = json.loads((tmp_path / ".nanobot" / "config.json").read_text(encoding="utf-8"))
    assert claude["env"]["ANTHROPIC_AUTH_TOKEN"] == new_keys["claude-code"]
    assert dsh_credentials["PF_DSH_API_KEY"] == new_keys["deepseek-harness"]
    assert nanobot["providers"]["pf"]["apiKey"] == new_keys["nanobot"]

    for connector_id in connector_ids:
        migrated.restore(connector_id)
    assert not (tmp_path / ".codex" / "config.toml").exists()
    assert not (tmp_path / ".claude" / "settings.json").exists()
    assert not (tmp_path / ".dsh" / "settings.yaml").exists()
    assert not (tmp_path / ".dsh" / ".credentials.yaml").exists()
    assert not (tmp_path / ".nanobot" / "config.json").exists()


def test_connector_namespace_migration_rolls_back_every_connector_on_final_commit_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = _connector_service(tmp_path, ".apg")
    legacy.connect("codex", "model-a", ["model-a"])
    legacy.connect("deepseek-harness", "model-a", ["model-a"])
    original_files = {
        path: path.read_bytes()
        for path in (
            tmp_path / ".codex" / "config.toml",
            tmp_path / ".dsh" / "settings.yaml",
            tmp_path / ".dsh" / ".credentials.yaml",
        )
    }

    migrate_state(tmp_path / ".apg", tmp_path / ".privacyflow")
    migrated = _connector_service(tmp_path, ".privacyflow")
    launcher_before = migrated.launcher_path.read_bytes()
    index_before = migrated.index_path.read_bytes()
    monkeypatch.setattr(migrated, "_write_state", lambda _state: (_ for _ in ()).throw(OSError("injected")))

    with pytest.raises(OSError, match="injected"):
        migrated.migrate_legacy_namespace()

    assert {path: path.read_bytes() for path in original_files} == original_files
    assert migrated.launcher_path.read_bytes() == launcher_before
    assert migrated.index_path.read_bytes() == index_before


def test_connector_namespace_migration_rejects_credential_transaction_mismatch(tmp_path: Path) -> None:
    legacy = _connector_service(tmp_path, ".apg")
    legacy.connect("nanobot", "model-a", ["model-a"])
    config_path = tmp_path / ".nanobot" / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["providers"]["pf"]["apiKey"] = "unmanaged-key"
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    index = json.loads(legacy.index_path.read_text(encoding="utf-8"))
    index["active"]["nanobot"]["files"][0]["connected_sha256"] = hashlib.sha256(config_path.read_bytes()).hexdigest()
    legacy.index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

    migrate_state(tmp_path / ".apg", tmp_path / ".privacyflow")
    migrated = _connector_service(tmp_path, ".privacyflow")

    with pytest.raises(ConnectorError) as exc_info:
        migrated.migrate_legacy_namespace()

    assert exc_info.value.code == "PF_MIGRATION_CONFIG_CONFLICT"
    assert config_path.read_text(encoding="utf-8").find("unmanaged-key") >= 0


def test_state_migration_rejects_reserved_provider_in_unknown_json(tmp_path: Path) -> None:
    source = tmp_path / ".apg"
    source.mkdir(mode=0o700)
    (source / "custom.json").write_text(json.dumps({"providers": {"apg": {}}}) + "\n", encoding="utf-8")

    with pytest.raises(MigrationError, match="reserved provider") as exc_info:
        migrate_state(source, tmp_path / ".privacyflow")
    assert exc_info.value.code == "PF_MIGRATION_UNKNOWN_CONFIG"
    assert not (tmp_path / ".privacyflow").exists()


def test_state_migration_normalizes_removed_custom_detector_state(tmp_path: Path) -> None:
    source = tmp_path / ".apg"
    source.mkdir(mode=0o700)
    (source / "detector-control.json").write_text(
        json.dumps({"version": 1, "builtin_ruleset_revision": 1, "apg_enabled": False, "configurations": [{"id": "legacy"}]}) + "\n",
        encoding="utf-8",
    )

    migrate_state(source, tmp_path / ".privacyflow")

    state = json.loads((tmp_path / ".privacyflow" / "detector-control.json").read_text(encoding="utf-8"))
    assert state["version"] == 3
    assert state["builtin_ruleset_revision"] == 4
    assert state["pf_enabled"] is False
    assert "apg_enabled" not in state
    assert "configurations" not in state
    assert "template_module_overrides" not in state


@pytest.mark.parametrize(
    ("name", "payload", "code"),
    [
        ("launcher.json", "not-json", "PF_MIGRATION_STATE_INVALID"),
        ("local-models.json", json.dumps({"version": 1, "manual_models": [], "records": {}}), "PF_MIGRATION_STATE_VERSION_UNSUPPORTED"),
    ],
)
def test_state_migration_rejects_unbootable_known_state(tmp_path: Path, name: str, payload: str, code: str) -> None:
    source = tmp_path / ".apg"
    source.mkdir(mode=0o700)
    (source / name).write_text(payload, encoding="utf-8")

    with pytest.raises(MigrationError) as exc_info:
        migrate_state(source, tmp_path / ".privacyflow")

    assert exc_info.value.code == code
    assert not (tmp_path / ".privacyflow").exists()


def test_response_namespace_translation_does_not_rewrite_model_text() -> None:
    payload = {"message": "APG_UPSTREAM is a model-generated token", "error": {"code": "PF_STREAM_PARSE_ERROR"}}
    assert translate_value(payload, legacy=False) == payload
    legacy = translate_value(payload, legacy=True)
    assert legacy["message"] == payload["message"]
    assert legacy["error"]["code"] == "APG_STREAM_PARSE_ERROR"


def test_new_and_legacy_routes_use_their_own_placeholder_namespace(tmp_path: Path) -> None:
    upstream = _EchoUpstream()
    config = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(base_url="https://upstream", api_key="provider"),
    )
    client = TestClient(create_app(config, upstream))

    canonical = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local"},
        json={"messages": [{"role": "user", "content": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"}]},
    )
    assert canonical.status_code == 200
    assert PF_UPSTREAM_SYSTEM_PROMPT in upstream.calls[0][2]["messages"][0]["content"]
    assert "<PF:v1:" in json.dumps(upstream.calls[0][2])
    assert "<APG:v1:" not in json.dumps(upstream.calls[0][2])

    legacy = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local", "X-APG-Model-Catalog": "rich"},
        json={"messages": [{"role": "user", "content": "sk-proj-abcdefghijklmnopqrstuvwxyz123456"}]},
    )
    assert legacy.status_code == 200
    assert APG_UPSTREAM_SYSTEM_PROMPT in upstream.calls[1][2]["messages"][0]["content"]
    assert "<APG:v1:" in json.dumps(upstream.calls[1][2])

    legacy_detect = client.post(
        "/v1/apg/detect",
        headers={"Authorization": "Bearer local"},
        json={"text": "token sk-proj-abcdefghijklmnopqrstuvwxyz123456"},
    )
    assert legacy_detect.status_code == 200
    assert "<APG_DETECTED:" in legacy_detect.json().get("sanitized_text", "")


def test_conflicting_namespace_headers_fail_closed(tmp_path: Path) -> None:
    config = GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="secret",
        local_api_keys={"local"},
        upstream=UpstreamConfig(base_url="https://upstream", api_key="provider"),
    )
    client = TestClient(create_app(config, _EchoUpstream()))
    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer local", "X-PF-Session-ID": "sess_a", "X-APG-Session-ID": "sess_b"},
        json={"messages": [{"role": "user", "content": "hello"}]},
    )
    assert response.status_code == 400
    assert "HEADER_NAMESPACE_CONFLICT" in response.text

    model_catalog = client.get(
        "/api/admin/upstream-configuration/models",
        headers={"X-PF-Model-Catalog": "compact", "X-APG-Model-Catalog": "rich"},
    )
    assert model_catalog.status_code == 400
    assert model_catalog.json()["detail"]["code"] == "PF_HEADER_NAMESPACE_CONFLICT"
