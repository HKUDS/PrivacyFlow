from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import gateway.server as server_module
from gateway.agent_connectors import AgentConnectorService
from gateway.config import GatewayConfig, UpstreamConfig
from gateway.server import create_app


class ConnectorUpstream:
    def __init__(self, *, fail_protocol: str = "") -> None:
        self.paths: list[str] = []
        self.fail_protocol = fail_protocol

    async def request_json(self, method, path, payload=None):
        self.paths.append(path)
        if path == "/v1/models":
            return 200, {"content-type": "application/json"}, {"data": [{"id": "model-a"}, {"id": "model-b"}]}
        if path == self.fail_protocol:
            return 400, {"content-type": "application/json"}, {"error": {"message": "unsupported protocol"}}
        if path == "/v1/responses":
            return 200, {"content-type": "application/json"}, {"id": "resp_1", "object": "response", "output": []}
        if path == "/v1/messages":
            return 200, {"content-type": "application/json"}, {"id": "msg_1", "type": "message", "role": "assistant", "content": []}
        return 200, {"content-type": "application/json"}, {"choices": [{"message": {"content": "ok"}}]}

    async def stream_request(self, method, path, payload=None):
        raise AssertionError("streaming is not used")


def _config(tmp_path: Path) -> GatewayConfig:
    return GatewayConfig(
        bind_host="127.0.0.1",
        bind_port=8765,
        database_path=str(tmp_path / ".apg" / "state.sqlite3"),
        audit_log_path=str(tmp_path / ".apg" / "audit.jsonl"),
        signing_secret="test-secret",
        local_api_keys={"main-key"},
        upstream=UpstreamConfig(base_url="https://upstream.example/v1", api_key="upstream-key"),
    )


def _install_isolated_service(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def factory(state_dir, launcher_path, **kwargs):
        return AgentConnectorService(
            Path(state_dir), Path(launcher_path),
            environ={
                "CODEX_HOME": str(tmp_path / ".codex"),
                "CLAUDE_CONFIG_DIR": str(tmp_path / ".claude"),
                "DSH_HOME": str(tmp_path / ".dsh"),
            },
            home=tmp_path,
            which=lambda _: "/usr/local/bin/agent",
            base_url=kwargs["base_url"],
        )
    monkeypatch.setattr(server_module, "AgentConnectorService", factory)


@pytest.mark.parametrize(
    ("connector_id", "expected_probe"),
    [
        ("codex", "/v1/responses"),
        ("claude-code", "/v1/messages"),
        ("deepseek-harness", "/v1/chat/completions"),
        ("nanobot", "/v1/chat/completions"),
    ],
)
def test_connector_api_uses_exact_protocol_and_restores_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    connector_id: str,
    expected_probe: str,
) -> None:
    _install_isolated_service(monkeypatch, tmp_path)
    upstream = ConnectorUpstream()
    with TestClient(create_app(_config(tmp_path), upstream), client=("127.0.0.1", 50000)) as client:
        initial = client.get("/api/admin/agent-connectors")
        assert initial.status_code == 200
        assert "api_key" not in initial.text.lower()
        upstream.paths.clear()
        connected = client.post(f"/api/admin/agent-connectors/{connector_id}/connect", json={"model": "model-a"})
        assert connected.status_code == 200, connected.text
        assert upstream.paths == ["/v1/models", expected_probe]
        assert connected.json()["status"] == "connected"
        assert "apg_local_" not in connected.text
        connector_keys = client.app.state.admin_service.config.local_api_keys - {"main-key"}
        assert len(connector_keys) == 1
        connector_key = connector_keys.pop()
        assert client.get("/v1/models", headers={"Authorization": f"Bearer {connector_key}"}).status_code == 200

        restored = client.post(
            f"/api/admin/agent-connectors/{connector_id}/restore",
            json={"confirm_external_changes": False},
        )
        assert restored.status_code == 200
        assert restored.json()["status"] == "ready"
        assert client.get("/v1/models", headers={"Authorization": f"Bearer {connector_key}"}).status_code == 401


def test_protocol_failure_leaves_disk_and_key_state_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_isolated_service(monkeypatch, tmp_path)
    upstream = ConnectorUpstream(fail_protocol="/v1/responses")
    with TestClient(create_app(_config(tmp_path), upstream), client=("127.0.0.1", 50000)) as client:
        response = client.post("/api/admin/agent-connectors/codex/connect", json={"model": "model-a"})
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "CONNECTOR_PROTOCOL_PROBE_FAILED"
        assert not (tmp_path / ".codex" / "config.toml").exists()
        launcher = tmp_path / ".apg" / "launcher.json"
        assert not launcher.exists()
        assert client.app.state.admin_service.config.local_api_keys == {"main-key"}


def test_existing_agent_config_requires_explicit_migration_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_isolated_service(monkeypatch, tmp_path)
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    original = b'{"env":{"ANTHROPIC_MODEL":"user-managed-model"}}\n'
    path.write_bytes(original)
    with TestClient(create_app(_config(tmp_path), ConnectorUpstream()), client=("127.0.0.1", 50000)) as client:
        invalid = client.post(
            "/api/admin/agent-connectors/claude-code/connect",
            json={"model": "model-a", "confirm_existing_config": "yes"},
        )
        assert invalid.status_code == 400
        assert invalid.json()["detail"]["code"] == "CONNECTOR_REQUEST_INVALID"

        conflict = client.post(
            "/api/admin/agent-connectors/claude-code/connect",
            json={"model": "model-a"},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"] == {
            "code": "CONNECTOR_CONFIG_CONFLICT",
            "message": "The reserved Claude Code APG environment keys already exist. Confirm migration before APG replaces them.",
            "paths": [str(path)],
            "requires_confirmation": True,
        }
        assert path.read_bytes() == original
        assert not (tmp_path / ".apg" / "launcher.json").exists()

        confirmed = client.post(
            "/api/admin/agent-connectors/claude-code/connect",
            json={"model": "model-a", "confirm_existing_config": True},
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["status"] == "connected"
        assert json.loads(path.read_text())["env"]["ANTHROPIC_MODEL"] == "model-a"

        restored = client.post(
            "/api/admin/agent-connectors/claude-code/restore",
            json={"confirm_external_changes": False},
        )
        assert restored.status_code == 200
        assert path.read_bytes() == original


def test_restore_external_change_returns_paths_then_confirms(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_isolated_service(monkeypatch, tmp_path)
    with TestClient(create_app(_config(tmp_path), ConnectorUpstream()), client=("127.0.0.1", 50000)) as client:
        assert client.post("/api/admin/agent-connectors/nanobot/connect", json={"model": "model-a"}).status_code == 200
        path = tmp_path / ".nanobot" / "config.json"
        path.write_text('{"user": "private-current-config-marker"}\n')
        conflict = client.post(
            "/api/admin/agent-connectors/nanobot/restore",
            json={"confirm_external_changes": False},
        )
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["paths"] == [str(path)]
        assert "private-current-config-marker" not in conflict.text
        confirmed = client.post(
            "/api/admin/agent-connectors/nanobot/restore",
            json={"confirm_external_changes": True},
        )
        assert confirmed.status_code == 200
        assert not path.exists()


def test_connector_mutations_require_loopback_bind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_isolated_service(monkeypatch, tmp_path)
    cfg = _config(tmp_path)
    cfg = GatewayConfig(**{**cfg.__dict__, "bind_host": "0.0.0.0"})
    with pytest.warns(RuntimeWarning), TestClient(
        create_app(cfg, ConnectorUpstream()), client=("127.0.0.1", 50000)
    ) as client:
        response = client.post("/api/admin/agent-connectors/codex/connect", json={"model": "model-a"})
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "CONNECTOR_LOCAL_ONLY"


def test_dsh_rejects_empty_model_catalog_without_writing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_isolated_service(monkeypatch, tmp_path)

    class EmptyCatalogUpstream(ConnectorUpstream):
        async def request_json(self, method, path, payload=None):
            if path == "/v1/models":
                return 200, {"content-type": "application/json"}, {"data": []}
            return await super().request_json(method, path, payload)

    with TestClient(
        create_app(_config(tmp_path), EmptyCatalogUpstream()), client=("127.0.0.1", 50000)
    ) as client:
        response = client.post(
            "/api/admin/agent-connectors/deepseek-harness/connect",
            json={"model": "manual-model"},
        )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "CONNECTOR_MODEL_LIST_EMPTY"
    assert not (tmp_path / ".dsh" / "settings.yaml").exists()


def test_rotating_primary_key_preserves_active_connector_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _install_isolated_service(monkeypatch, tmp_path)
    with TestClient(
        create_app(_config(tmp_path), ConnectorUpstream()), client=("127.0.0.1", 50000)
    ) as client:
        assert client.post("/api/admin/agent-connectors/codex/connect", json={"model": "model-a"}).status_code == 200
        connector_key = next(key for key in client.app.state.admin_service.config.local_api_keys if key != "main-key")
        rotated = client.post("/api/admin/connection/api-key")
        assert rotated.status_code == 200
        assert rotated.json()["api_key"] != connector_key
        assert rotated.json()["available_key_count"] == 2
        assert client.get("/v1/models", headers={"Authorization": f"Bearer {connector_key}"}).status_code == 200
        assert client.get("/v1/models", headers={"Authorization": "Bearer main-key"}).status_code == 401
