from __future__ import annotations

import os
import sqlite3

from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig, load_config
from gateway.server import create_app


class AdminFakeUpstream:
    async def request_json(self, method, path, payload=None):
        if path == "/v1/models":
            return 200, {"content-type": "application/json"}, {"data": []}
        return 200, {"content-type": "application/json"}, {"choices": [{"message": {"content": "Done."}}]}

    async def stream_request(self, method, path, payload=None):
        async def chunks():
            yield b'data: {"choices":[{"delta":{"content":"Done."}}]}\n\n'
            yield b"data: [DONE]\n\n"

        return 200, {"content-type": "text/event-stream"}, chunks()


def _config(tmp_path) -> GatewayConfig:
    return GatewayConfig(
        database_path=str(tmp_path / "state.sqlite3"),
        audit_log_path=str(tmp_path / "audit.jsonl"),
        signing_secret="test-signing-secret",
        local_api_keys={"agent-key"},
        admin_api_keys={"admin-key"},
        strict_mode=True,
        upstream=UpstreamConfig(base_url="https://upstream.example/v1", api_key="provider-key"),
    )


def _admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer admin-key"}


def test_webui_assets_and_admin_auth_are_separated(tmp_path) -> None:
    with TestClient(create_app(_config(tmp_path), AdminFakeUpstream())) as client:
        page = client.get("/ui/")
        assert page.status_code == 200
        assert "APG Control" in page.text
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        assert client.get("/ui/assets/app.js").status_code == 200
        assert client.get("/ui/assets/unknown.js").status_code == 404

        assert client.get("/api/admin/overview").status_code == 401
        assert client.get("/api/admin/overview", headers={"Authorization": "Bearer agent-key"}).status_code == 401
        assert client.get("/api/admin/overview", headers=_admin_headers()).status_code == 200


def test_admin_audit_and_protected_values_never_return_raw_capabilities(tmp_path) -> None:
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    cfg = _config(tmp_path)
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "test", "messages": [{"role": "user", "content": f"Use {secret}"}]},
        )
        assert response.status_code == 200

        protected = client.get("/api/admin/protected-values", headers=_admin_headers())
        assert protected.status_code == 200
        protected_text = protected.text
        assert secret not in protected_text
        assert "handle_id" not in protected_text
        assert "fingerprint" not in protected_text
        assert "<APG" not in protected_text
        records = protected.json()["records"]
        assert len(records) == 1
        assert records[0]["kind"] == "secret"
        assert records[0]["stored_locally"] is True

        audit = client.get("/api/admin/audit", headers=_admin_headers())
        assert audit.status_code == 200
        assert secret not in audit.text
        assert "<APG" not in audit.text
        assert "handle_id" not in audit.text
        assert audit.json()["events"][0]["session"].startswith("Session ")

        overview = client.get("/api/admin/overview", headers=_admin_headers()).json()
        assert overview["metrics"]["requests_24h"] == 1
        assert overview["metrics"]["interceptions_24h"] >= 1
        assert overview["metrics"]["active_protected_values"] == 1

        revoke = client.post(f"/api/admin/protected-values/{records[0]['id']}/revoke", headers=_admin_headers())
        assert revoke.status_code == 200
        assert revoke.json()["state"] == "revoked"

    with sqlite3.connect(cfg.database_path) as connection:
        row = connection.execute("SELECT state, value, session_id, fingerprint FROM mappings").fetchone()
    assert row == ("tombstoned", None, "", "")


def test_detector_control_hot_reload_and_persistence(tmp_path) -> None:
    cfg = _config(tmp_path)
    rule = {
        "id": "custom.partner_token",
        "pattern": r"\bpartner_live_[A-Za-z0-9_-]{8,}\b",
        "subtype": "partner_token",
        "type": "MACHINE_SECRET",
        "confidence": 0.9,
        "risk": "high",
        "suggested_action": "redact",
        "flags": [],
        "validators": [],
        "require_validators": [],
        "reject_validators": [],
        "preview_keep": 0,
        "enabled": True,
    }
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        catalog_response = client.get("/api/admin/detector-configurations", headers=_admin_headers())
        assert catalog_response.status_code == 200
        catalog = catalog_response.json()
        assert [item["name"] for item in catalog["templates"][:4]] == ["凭据与密钥", "个人信息", "本地开发环境", "全面保护"]
        assert client.get("/api/admin/detectors", headers=_admin_headers()).status_code == 404

        created = client.post(
            "/api/admin/detector-configurations",
            headers=_admin_headers(),
            json={"name": "Partner credentials", "source_id": "builtin.credentials"},
        )
        assert created.status_code == 201
        configuration = created.json()
        custom_module = {
            "id": "custom_rules",
            "name": "Partner rules",
            "type": "regex",
            "enabled": True,
            "timeout_ms": 100,
            "failure_mode": "closed",
            "editable": True,
            "config": {"rules": [rule]},
        }
        configuration["modules"].insert(0, custom_module)
        saved = client.put(
            f"/api/admin/detector-configurations/{configuration['id']}",
            headers=_admin_headers(),
            json={
                "revision": configuration["revision"],
                "name": configuration["name"],
                "description": configuration["description"],
                "core_guard_enabled": configuration["core_guard_enabled"],
                "flow_timeout_ms": configuration["flow_timeout_ms"],
                "content_tags": configuration["content_tags"],
                "modules": configuration["modules"],
            },
        )
        assert saved.status_code == 200
        configuration = saved.json()
        assert configuration["modules"][0]["id"] == "custom_rules"

        stale = client.put(
            f"/api/admin/detector-configurations/{configuration['id']}",
            headers=_admin_headers(),
            json={**configuration, "revision": 1},
        )
        assert stale.status_code == 409

        dry_run = client.post(
            f"/api/admin/detector-configurations/{configuration['id']}/test",
            headers=_admin_headers(),
            json={"text": "local-context-never-log credential=partner_live_abcdefghijkl"},
        )
        assert dry_run.status_code == 200
        assert any("rules.custom_rules" in finding["detectors"] for finding in dry_run.json()["findings"])
        assert [item["id"] for item in dry_run.json()["diagnostics"][:2]] == ["apg_core", "custom_rules"]
        assert "local-context-never-log" not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")

        invalid_configuration = {**configuration, "modules": [*configuration["modules"]]}
        invalid_configuration["modules"][0] = {**custom_module, "config": {"rules": [{**rule, "id": "custom.unsafe", "pattern": "(a+)+$"}]}}
        invalid = client.put(
            f"/api/admin/detector-configurations/{configuration['id']}",
            headers=_admin_headers(),
            json=invalid_configuration,
        )
        assert invalid.status_code == 400

        activated = client.post(f"/api/admin/detector-configurations/{configuration['id']}/activate", headers=_admin_headers())
        assert activated.status_code == 200
        assert client.delete(f"/api/admin/detector-configurations/{configuration['id']}", headers=_admin_headers()).status_code == 409

    state_path = tmp_path / "detector-control.json"
    assert state_path.exists()
    assert os.stat(state_path).st_mode & 0o777 == 0o600
    state_text = state_path.read_text(encoding="utf-8")
    assert "partner_live_abcdefghijkl" not in state_text
    assert '"version": 2' in state_text

    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        persisted = client.get("/api/admin/detector-configurations", headers=_admin_headers()).json()
        assert persisted["active_configuration_id"] == configuration["id"]
        loaded = client.get(f"/api/admin/detector-configurations/{configuration['id']}", headers=_admin_headers()).json()
        assert loaded["modules"][0]["config"]["rules"][0]["id"] == "custom.partner_token"
        assert client.post("/api/admin/detector-configurations/builtin.comprehensive/activate", headers=_admin_headers()).status_code == 200
        removed = client.delete(f"/api/admin/detector-configurations/{configuration['id']}", headers=_admin_headers())
        assert removed.status_code == 200


def test_audit_logger_scrubs_apg_handles_before_they_reach_webui(tmp_path) -> None:
    cfg = _config(tmp_path)
    marker = "<APG:v1:secret:secr_private:sess_private:123:mac_private>"
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        client.app.state.admin_service.audit.log(
            {
                "phase": "test",
                "handle_id": "secr_private",
                "detections": [{"type": "secret", "safe_preview": marker}],
            }
        )
        response = client.get("/api/admin/audit", headers=_admin_headers())
        assert response.status_code == 200
        assert marker not in response.text
        assert "secr_private" not in response.text
        assert "handle_id" not in response.text
        assert os.stat(cfg.audit_log_path).st_mode & 0o777 == 0o600


def test_admin_configuration_loads_from_environment(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("APG_CONFIG_PATH", raising=False)
    monkeypatch.setenv("APG_STRICT", "false")
    monkeypatch.setenv("APG_LOCAL_API_KEYS", "agent-one")
    monkeypatch.setenv("APG_ADMIN_API_KEYS", "admin-one,admin-two")
    monkeypatch.setenv("APG_ADMIN_ENABLED", "false")
    monkeypatch.setenv("APG_SIGNING_SECRET", "configured-signing-secret")
    monkeypatch.setenv("APG_DATABASE_PATH", str(tmp_path / "state.sqlite3"))
    monkeypatch.setenv("APG_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    cfg = load_config()
    assert cfg.admin_api_keys == {"admin-one", "admin-two"}
    assert cfg.admin_enabled is False


def test_admin_can_be_disabled(tmp_path) -> None:
    cfg = _config(tmp_path)
    cfg = GatewayConfig(**{**cfg.__dict__, "admin_enabled": False})
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        assert client.get("/ui/").status_code == 404
        assert client.get("/api/admin/overview", headers=_admin_headers()).status_code == 404
