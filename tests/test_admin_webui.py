from __future__ import annotations

import json
import os
import re
import sqlite3

from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig, load_config
from gateway.mapping_store import MappingStore
from gateway.server import create_app
from gateway.upstream_protocol import ANTHROPIC_MESSAGES, OPENAI_CHAT_COMPLETIONS


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


class AuditRoundTripUpstream(AdminFakeUpstream):
    async def request_json(self, method, path, payload=None):
        serialized = str(payload)
        placeholders = re.findall(r"<APG:v1:[^>]+>", serialized)
        placeholder = next((candidate for candidate in placeholders if candidate.startswith("<APG:v1:secret:")), None)
        assert placeholder is not None
        return 200, {"content-type": "application/json"}, {
            "choices": [{
                "message": {
                    "content": "Writing the protected value locally.",
                    "tool_calls": [{
                        "id": "call_audit",
                        "type": "function",
                        "function": {
                            "name": "Write",
                            "arguments": json.dumps({"content": placeholder}),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        }


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


def test_webui_assets_and_admin_api_require_no_authentication(tmp_path) -> None:
    with TestClient(create_app(_config(tmp_path), AdminFakeUpstream())) as client:
        page = client.get("/ui/")
        assert page.status_code == 200
        assert "APG Control" in page.text
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        app_js = client.get("/ui/assets/app.js")
        assert app_js.status_code == 200
        styles = client.get("/ui/assets/styles.css")
        assert styles.status_code == 200
        i18n_js = client.get("/ui/assets/i18n.js")
        assert i18n_js.status_code == 200
        lucide_js = client.get("/ui/assets/lucide.min.js")
        assert lucide_js.status_code == 200
        assert "@license lucide v1.27.0 - ISC" in lucide_js.text
        assert "Privacy operations overview" in i18n_js.text
        assert "Detectors" in i18n_js.text
        assert "apg:localechange" in i18n_js.text
        assert "ANTHROPIC_BASE_URL" in app_js.text
        assert "export ANTHROPIC_MODEL=deepseek-v4-pro[1m]" in app_js.text
        assert "export ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-v4-pro[1m]" in app_js.text
        assert "export CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash" in app_js.text
        assert "claude --setting-sources project,local" not in app_js.text
        assert client.get("/ui/assets/unknown.js").status_code == 404

        assert client.get("/api/admin/overview").status_code == 200
        assert client.get("/api/admin/overview", headers={"Authorization": "Bearer agent-key"}).status_code == 200
        assert client.get("/api/admin/overview", headers=_admin_headers()).status_code == 200
        assert client.get("/api/admin/audit/requests").status_code == 200
        assert client.get("/api/admin/audit/requests", headers={"Authorization": "Bearer agent-key"}).status_code == 200
        assert client.get("/api/admin/audit/operations?direction=replacement").status_code == 200
        assert client.get(
            "/api/admin/audit/operations?direction=replacement",
            headers={"Authorization": "Bearer agent-key"},
        ).status_code == 200
        assert client.get(
            "/api/admin/audit/operations?direction=all",
            headers=_admin_headers(),
        ).status_code == 400

        connection = client.get("/api/admin/connection", headers=_admin_headers())
        assert connection.status_code == 200
        assert connection.headers["cache-control"] == "no-store"
        assert connection.json() == {
            "api_key": "agent-key",
            "available_key_count": 1,
            "protocols": {"openai": {"base_path": "/v1"}, "anthropic": {"base_path": ""}},
        }
        assert client.get("/api/admin/connection", headers={"Authorization": "Bearer agent-key"}).status_code == 200
        assert "login-overlay" not in page.text
        assert "admin-key" not in page.text
        assert "Authorization" not in app_js.text

        assert "Agent 接入" in page.text
        assert "agent-api-key" in page.text
        assert '"agent-key"' not in page.text
        assert "data-copy-connection" in page.text
        assert "copy-claude-command" in page.text
        assert "复制接入命令" in page.text
        assert "配置上游模型" in page.text
        assert "upstream-base-url-input" in page.text
        assert 'id="upstream-protocol"' in page.text
        assert 'value="openai_chat_completions"' in page.text
        assert 'value="openai_responses"' in page.text
        assert 'value="anthropic_messages"' in page.text
        assert "data-connection-protocol" not in page.text
        assert "agent-openai-base-url" in page.text
        assert "agent-anthropic-base-url" in page.text
        assert 'api("/upstream-configuration"' in app_js.text
        assert 'data-locale="zh"' in page.text
        assert 'data-locale="en"' in page.text
        assert page.text.index("/ui/assets/i18n.js") < page.text.index("/ui/assets/app.js")
        assert page.text.index("/ui/assets/i18n.js") < page.text.index("/ui/assets/lucide.min.js") < page.text.index("/ui/assets/app.js")
        assert "https://unpkg.com" not in page.text
        assert "https://cdn.jsdelivr.net" not in page.text
        assert 'data-lucide="layout-dashboard"' in page.text
        assert 'data-lucide="scroll-text"' in page.text
        assert 'data-lucide="shield-check"' in page.text
        assert 'data-lucide="sliders-horizontal"' in page.text
        assert '<span class="brand-mark" aria-hidden="true"><i data-lucide="shield-check"></i></span>' in page.text
        assert '<span class="brand-mark" aria-hidden="true">A</span>' not in page.text
        detector_icons = {
            "regex": "regex-reference",
            "entropy": "gauge",
            "path": "folder-tree",
            "local_model": "brain-circuit",
            "deployment": "server-cog",
        }
        for detector_type, detector_icon in detector_icons.items():
            assert f'{detector_type}: "{detector_icon}"' in app_js.text
        assert "moduleTypeIcon" in app_js.text
        assert 'class="lucide detector-regex-icon"' in app_js.text
        assert '<circle cx="9" cy="13" r="1.15"' in app_js.text
        assert "type.slice(0, 2)" not in app_js.text
        assert ".brand-mark .lucide { display: block; width: 28px; height: 28px;" in styles.text
        assert ".module-symbol .lucide { display: block; width: 28px; height: 28px;" in styles.text
        assert styles.text.count("transform: translate(1px, 1px);") == 2
        icon_only_buttons = [
            button
            for button in re.findall(r'<button class="[^"]+"[^>]*>', page.text)
            if {"icon-button", "icon-action-button"}
            & set(re.search(r'class="([^"]+)"', button).group(1).split())
        ]
        assert icon_only_buttons
        assert all('aria-label="' in button and 'title="' in button for button in icon_only_buttons)
        assert "renderIcons" in app_js.text
        assert "setIconButton" in app_js.text
        assert "visibilityIcon" not in app_js.text
        assert 'iconMarkup(revealed ? "eye-off" : "eye")' in app_js.text
        for legacy_symbol in ("↻", "×", "↑", "↓", "＋"):
            assert legacy_symbol not in page.text
            assert legacy_symbol not in app_js.text
            assert legacy_symbol not in i18n_js.text
        assert 'data-audit-direction="replacement"' in page.text
        assert 'data-audit-direction="materialization"' in page.text
        assert "替换记录" in page.text
        assert "还原记录" in page.text
        assert "audit-activity" not in page.text
        assert 'api("/audit/operations?" + params)' in app_js.text
        assert "本地映射保留" in page.text
        assert "mapping-retention-enabled" in page.text
        assert "upstream-profile-select" in page.text
        assert "new-upstream-profile" in page.text
        assert "activate-upstream-profile" in page.text
        assert "protected-show-raw" in page.text
        assert "visibility-button" in page.text
        assert 'api("/protected-values/retention"' in app_js.text

        audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        assert "view_agent_connection_info" in audit_text
        assert "agent-key" not in audit_text
        assert "provider-key" not in audit_text


def test_webui_can_persist_and_hot_apply_first_run_upstream_key(tmp_path, monkeypatch) -> None:
    launcher_path = tmp_path / ".apg" / "launcher.json"
    launcher_path.parent.mkdir(mode=0o700)
    launcher_path.write_text(
        json.dumps(
            {
                "admin_api_key": "admin-key",
                "local_api_key": "agent-key",
                "signing_secret": "test-signing-secret",
                "strip_local_v1": True,
                "upstream_base_url": "https://api.deepseek.com",
            }
        ),
        encoding="utf-8",
    )
    os.chmod(launcher_path, 0o600)
    monkeypatch.setenv("APG_LAUNCHER_CONFIG_PATH", str(launcher_path))
    cfg = _config(tmp_path)
    cfg = GatewayConfig(
        **{
            **cfg.__dict__,
            "upstream": UpstreamConfig(
                base_url="https://api.deepseek.com",
                api_key="",
                strip_local_v1=True,
            ),
        }
    )

    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        status = client.get("/api/admin/upstream-configuration", headers=_admin_headers())
        assert status.status_code == 200
        status_body = status.json()
        assert status_body["configured"] is False
        assert status_body["base_url"] == "https://api.deepseek.com"
        assert status_body["protocol"] == OPENAI_CHAT_COMPLETIONS
        assert status_body["persistent"] is True
        assert len(status_body["profiles"]) == 1
        assert status_body["profiles"][0]["has_api_key"] is False
        assert status_body["profiles"][0]["active"] is True
        first_profile_id = status_body["active_profile_id"]
        assert '"api_key":' not in status.text

        unavailable = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert unavailable.status_code == 503
        assert unavailable.json()["error"]["code"] == "APG_UPSTREAM_NOT_CONFIGURED"

        missing_url = client.put(
            "/api/admin/upstream-configuration",
            headers=_admin_headers(),
            json={"name": "Primary", "api_key": "saved-provider-key"},
        )
        assert missing_url.status_code == 400

        invalid_url = client.put(
            "/api/admin/upstream-configuration",
            headers=_admin_headers(),
            json={"name": "Primary", "protocol": OPENAI_CHAT_COMPLETIONS, "base_url": "https://user:password@new.example/v1", "api_key": "saved-provider-key"},
        )
        assert invalid_url.status_code == 400
        assert "upstream_api_key" not in launcher_path.read_text(encoding="utf-8")

        invalid_protocol = client.put(
            "/api/admin/upstream-configuration",
            headers=_admin_headers(),
            json={"name": "Primary", "protocol": "auto", "base_url": "https://new.example/v1", "api_key": "saved-provider-key"},
        )
        assert invalid_protocol.status_code == 400

        configured = client.put(
            "/api/admin/upstream-configuration",
            json={"profile_id": first_profile_id, "name": "Anthropic primary", "protocol": ANTHROPIC_MESSAGES, "base_url": "https://new.example/anthropic/", "api_key": "saved-provider-key"},
        )
        assert configured.status_code == 200
        assert configured.json()["configured"] is True
        assert configured.json()["base_url"] == "https://new.example/anthropic"
        assert configured.json()["protocol"] == ANTHROPIC_MESSAGES
        assert configured.json()["active_profile_id"] == first_profile_id
        assert configured.json()["profiles"][0]["name"] == "Anthropic primary"
        assert "saved-provider-key" not in configured.text

        second = client.put(
            "/api/admin/upstream-configuration",
            headers=_admin_headers(),
            json={
                "name": "OpenAI backup",
                "protocol": OPENAI_CHAT_COMPLETIONS,
                "base_url": "https://backup.example/v1",
                "api_key": "backup-provider-key",
            },
        )
        assert second.status_code == 200
        assert len(second.json()["profiles"]) == 2
        second_profile_id = second.json()["active_profile_id"]
        assert second_profile_id != first_profile_id
        assert "backup-provider-key" not in second.text

        activated = client.post(
            f"/api/admin/upstream-configuration/{first_profile_id}/activate",
            headers=_admin_headers(),
        )
        assert activated.status_code == 200
        assert activated.json()["active_profile_id"] == first_profile_id
        assert activated.json()["protocol"] == ANTHROPIC_MESSAGES

        reactivated = client.post(
            f"/api/admin/upstream-configuration/{second_profile_id}/activate",
            headers=_admin_headers(),
        )
        assert reactivated.status_code == 200
        assert reactivated.json()["protocol"] == OPENAI_CHAT_COMPLETIONS

        deleted = client.delete(
            f"/api/admin/upstream-configuration/{second_profile_id}",
            headers=_admin_headers(),
        )
        assert deleted.status_code == 200
        assert len(deleted.json()["profiles"]) == 1
        assert deleted.json()["active_profile_id"] == first_profile_id
        assert deleted.json()["protocol"] == ANTHROPIC_MESSAGES

        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert response.status_code == 200

    assert os.stat(launcher_path).st_mode & 0o777 == 0o600
    stored_launcher = json.loads(launcher_path.read_text(encoding="utf-8"))
    assert stored_launcher["active_upstream_profile_id"] == first_profile_id
    assert len(stored_launcher["upstream_profiles"]) == 1
    assert stored_launcher["upstream_profiles"][0]["protocol"] == ANTHROPIC_MESSAGES
    assert stored_launcher["upstream_profiles"][0]["base_url"] == "https://new.example/anthropic"
    assert stored_launcher["upstream_profiles"][0]["api_key"] == "saved-provider-key"
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "configure_upstream_connection" in audit_text
    assert "saved-provider-key" not in audit_text


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


def test_admin_can_temporarily_reveal_active_protected_values(tmp_path) -> None:
    secret = "sk-proj-protected-reveal-abcdefghijklmnopqrstuvwxyz"
    cfg = _config(tmp_path)
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "test", "messages": [{"role": "user", "content": f"Use {secret}"}]},
        )
        assert response.status_code == 200

        hidden = client.get("/api/admin/protected-values", headers=_admin_headers())
        assert hidden.status_code == 200
        assert hidden.headers["cache-control"] == "no-store"
        assert hidden.json()["raw_values_included"] is False
        assert hidden.json()["records"][0]["original"] == "***"
        assert secret not in hidden.text

        revealed = client.get("/api/admin/protected-values?include_raw=true")
        assert revealed.status_code == 200
        assert revealed.headers["cache-control"] == "no-store"
        assert revealed.json()["raw_values_included"] is True
        record = revealed.json()["records"][0]
        assert record["original"] == secret
        assert "handle_id" not in revealed.text
        assert "fingerprint" not in revealed.text
        assert "<APG" not in revealed.text

        revoked = client.post(f"/api/admin/protected-values/{record['id']}/revoke", headers=_admin_headers())
        assert revoked.status_code == 200
        cleared = client.get("/api/admin/protected-values?include_raw=true", headers=_admin_headers())
        assert cleared.status_code == 200
        assert cleared.json()["records"] == []
        assert secret not in cleared.text

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "view_protected_raw_values" in audit_text
    assert secret not in audit_text


def test_admin_can_configure_mapping_retention_with_revision_protection(tmp_path) -> None:
    secret = "sk-proj-retention-abcdefghijklmnopqrstuvwxyz"
    cfg = _config(tmp_path)
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "test", "messages": [{"role": "user", "content": f"Use {secret}"}]},
        )
        assert response.status_code == 200

        protected = client.get("/api/admin/protected-values", headers=_admin_headers()).json()
        assert protected["retention_policy"]["enabled"] is False
        assert protected["retention_policy"]["idle_ttl_seconds"] == 86_400
        assert protected["retention_policy"]["revision"] == 0
        assert isinstance(protected["retention_policy"]["updated_at"], int)
        assert protected["records"][0]["auto_expires"] is False
        assert protected["records"][0]["expires_at"] is None

        enabled = client.put(
            "/api/admin/protected-values/retention",
            json={"enabled": True, "idle_ttl_seconds": 3600, "revision": 0},
        )
        assert enabled.status_code == 200
        assert enabled.headers["cache-control"] == "no-store"
        assert enabled.json()["enabled"] is True
        assert enabled.json()["revision"] == 1

        expiring = client.get("/api/admin/protected-values", headers=_admin_headers()).json()
        assert expiring["records"][0]["auto_expires"] is True
        assert expiring["records"][0]["expires_at"] is not None

        conflict = client.put(
            "/api/admin/protected-values/retention",
            headers=_admin_headers(),
            json={"enabled": False, "idle_ttl_seconds": 3600, "revision": 0},
        )
        assert conflict.status_code == 409

        disabled = client.put(
            "/api/admin/protected-values/retention",
            headers=_admin_headers(),
            json={"enabled": False, "idle_ttl_seconds": 3600, "revision": 1},
        )
        assert disabled.status_code == 200
        assert disabled.json()["enabled"] is False
        retained = client.get("/api/admin/protected-values", headers=_admin_headers()).json()
        assert retained["records"][0]["auto_expires"] is False
        assert retained["records"][0]["expires_at"] is None

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "update_mapping_retention_policy" in audit_text
    assert secret not in audit_text


def test_request_audit_pairs_replacement_and_materialization_without_persisting_raw(tmp_path) -> None:
    secret = "sk-proj-audit-readable-abcdefghijklmnopqrstuvwxyz"
    cfg = _config(tmp_path)
    with TestClient(create_app(cfg, AuditRoundTripUpstream())) as client:
        response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "test", "messages": [{"role": "user", "content": f"Write {secret} twice: {secret}"}]},
        )
        assert response.status_code == 200
        arguments = response.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        assert secret in arguments

        requests = client.get("/api/admin/audit/requests", headers=_admin_headers())
        assert requests.status_code == 200
        request_summary = requests.json()["requests"][0]
        assert request_summary["replacement_count"] == 2
        assert request_summary["replacement_unique_count"] == 1
        assert request_summary["materialization_count"] == 1
        assert request_summary["details_available"] is True

        request_id = request_summary["request_id"]
        replacement_list = client.get(
            "/api/admin/audit/operations?direction=replacement",
            headers=_admin_headers(),
        )
        assert replacement_list.status_code == 200
        assert replacement_list.headers["cache-control"] == "no-store"
        replacement_body = replacement_list.json()
        assert replacement_body["direction"] == "replacement"
        assert replacement_body["count"] == 1
        assert replacement_body["occurrence_count"] == 2
        assert replacement_body["operations"][0]["original"] == "***"
        assert replacement_body["operations"][0]["request_id"] == request_id
        assert replacement_body["operations"][0]["endpoint"] == "/v1/chat/completions"
        assert replacement_body["operations"][0]["session"].startswith("Session ")
        assert secret not in replacement_list.text

        materialization_list = client.get(
            "/api/admin/audit/operations?direction=materialization&query=Write",
            headers=_admin_headers(),
        )
        assert materialization_list.status_code == 200
        materialization_body = materialization_list.json()
        assert materialization_body["count"] == 1
        assert materialization_body["operations"][0]["direction"] == "materialization"
        assert materialization_body["operations"][0]["tool_name"] == "Write"
        assert all(item["direction"] != "replacement" for item in materialization_body["operations"])

        hidden = client.get(f"/api/admin/audit/requests/{request_id}", headers=_admin_headers())
        assert hidden.status_code == 200
        assert hidden.headers["cache-control"] == "no-store"
        hidden_body = hidden.json()
        assert hidden_body["replacements"][0]["original"] == "***"
        assert hidden_body["materializations"][0]["original"] == "***"
        placeholder = hidden_body["replacements"][0]["representation"]
        assert placeholder.startswith("<APG:v1:secret:")
        assert hidden_body["replacements"][0]["occurrence_count"] == 2
        assert hidden_body["materializations"][0]["representation"] == placeholder
        assert hidden_body["materializations"][0]["tool_name"] == "Write"
        assert hidden_body["replacements"][0]["protected_value_id"] == hidden_body["materializations"][0]["protected_value_id"]

        revealed = client.get(
            f"/api/admin/audit/requests/{request_id}?include_raw=true",
            headers=_admin_headers(),
        )
        assert revealed.status_code == 200
        assert revealed.headers["cache-control"] == "no-store"
        assert revealed.json()["replacements"][0]["original"] == secret
        assert revealed.json()["materializations"][0]["original"] == secret

        revealed_list = client.get(
            "/api/admin/audit/operations?direction=materialization&include_raw=true",
            headers=_admin_headers(),
        )
        assert revealed_list.status_code == 200
        assert revealed_list.json()["operations"][0]["original"] == secret

        stored_materialization = client.app.state.admin_service.store.audit_operations_for_request(
            request_id,
            cfg.workspace_id,
        )[-1]
        client.app.state.admin_service.store.record_audit_operations(
            request_id=request_id,
            session_id=stored_materialization.session_id,
            workspace_id=cfg.workspace_id,
            endpoint=stored_materialization.endpoint,
            timestamp=stored_materialization.timestamp + 1,
            operations=[{
                "direction": "materialization_failed",
                "handle_id": stored_materialization.handle_id,
                "kind": stored_materialization.kind,
                "subtype": stored_materialization.subtype,
                "risk": stored_materialization.risk,
                "detector": stored_materialization.detector,
                "action": "preserve",
                "sink": stored_materialization.sink,
                "result_code": "APG_POLICY_DENIED",
                "representation_type": stored_materialization.representation_type,
                "placeholder_session_id": stored_materialization.placeholder_session_id,
                "issued_at": stored_materialization.issued_at,
                "suffix": stored_materialization.suffix,
                "alias": stored_materialization.alias,
                "tool_name": stored_materialization.tool_name,
            }],
        )
        materializations_with_failure = client.get(
            "/api/admin/audit/operations?direction=materialization",
            headers=_admin_headers(),
        ).json()
        assert materializations_with_failure["count"] == 2
        assert {item["direction"] for item in materializations_with_failure["operations"]} == {
            "materialization",
            "materialization_failed",
        }

        protected_id = revealed.json()["replacements"][0]["protected_value_id"]
        revoked = client.post(f"/api/admin/protected-values/{protected_id}/revoke", headers=_admin_headers())
        assert revoked.status_code == 200
        cleared = client.get(
            f"/api/admin/audit/requests/{request_id}?include_raw=true",
            headers=_admin_headers(),
        ).json()
        assert cleared["replacements"][0]["original"] is None
        assert cleared["replacements"][0]["value_state"] == "revoked"
        cleared_list = client.get(
            "/api/admin/audit/operations?direction=replacement&include_raw=true",
            headers=_admin_headers(),
        ).json()
        assert cleared_list["operations"][0]["original"] is None
        assert cleared_list["operations"][0]["value_state"] == "revoked"

        safe_audit = client.get("/api/admin/audit", headers=_admin_headers())
        assert secret not in safe_audit.text
        assert "<APG:v1:" not in safe_audit.text

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert secret not in audit_text
    assert "<APG:v1:" not in audit_text
    assert "view_audit_raw_values" in audit_text
    with sqlite3.connect(cfg.database_path) as connection:
        operation_rows = connection.execute("SELECT * FROM audit_operations").fetchall()
    serialized_operations = repr(operation_rows)
    assert secret not in serialized_operations
    assert "<APG:v1:" not in serialized_operations


def test_request_audit_keeps_legacy_jsonl_as_summary_only(tmp_path) -> None:
    cfg = _config(tmp_path)
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        client.app.state.admin_service.audit.log(
            {
                "request_id": "req_abcdef123456",
                "session_id": "sess_legacy",
                "workspace_id": "default",
                "endpoint": "/v1/messages",
                "phase": "request",
                "detections": [{"type": "secret", "subtype": "legacy", "risk": "high", "action": "redact"}],
            }
        )
        summary = client.get("/api/admin/audit/requests", headers=_admin_headers()).json()["requests"][0]
        assert summary["replacement_count"] == 1
        assert summary["details_available"] is False
        detail = client.get(
            "/api/admin/audit/requests/req_abcdef123456",
            headers=_admin_headers(),
        ).json()
        assert detail["legacy_summary_only"] is True
        assert detail["replacements"] == []


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


def test_admin_projects_stream_summary_counters(tmp_path) -> None:
    cfg = _config(tmp_path)
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        client.app.state.admin_service.audit.log(
            {
                "phase": "response_stream_complete",
                "materialized": 8,
                "folded": 2,
                "termination": "completed",
            }
        )

        event = client.get("/api/admin/audit", headers=_admin_headers()).json()["events"][0]
        assert event["materialized_count"] == 8
        assert event["folded_count"] == 2

        overview = client.get("/api/admin/overview", headers=_admin_headers()).json()
        assert overview["metrics"]["materializations_24h"] == 8


def test_audit_operation_storage_merges_occurrences_and_caps_distinct_details(tmp_path) -> None:
    store = MappingStore(str(tmp_path / "state.sqlite3"))
    operations = [
        {
            "direction": "replacement",
            "handle_id": f"path_{index}",
            "kind": "path",
            "subtype": "local_path",
            "risk": "medium",
            "detector": "path",
            "action": "alias",
            "sink": "remote_llm",
            "result_code": "OK",
            "representation_type": "path_alias",
            "alias": f"/workspace/path-{index}",
        }
        for index in range(1002)
    ]
    store.record_audit_operations(
        request_id="req_123456789abc",
        session_id="sess",
        workspace_id="default",
        endpoint="/v1/chat/completions",
        timestamp=1,
        operations=operations,
    )
    records = store.audit_operations_for_request("req_123456789abc", "default")
    assert len(records) == 1000
    assert store.audit_operation_omitted_count("req_123456789abc", "default") == 2

    duplicate = {**operations[0], "occurrence_count": 3}
    store.record_audit_operations(
        request_id="req_123456789abc",
        session_id="sess",
        workspace_id="default",
        endpoint="/v1/chat/completions",
        timestamp=2,
        operations=[duplicate],
    )
    records = store.audit_operations_for_request("req_123456789abc", "default")
    assert records[0].occurrence_count == 4
    store.close()


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
