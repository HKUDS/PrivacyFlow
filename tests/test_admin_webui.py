from __future__ import annotations

import json
import os
import re
import sqlite3

import httpx
from fastapi.testclient import TestClient

from gateway.config import GatewayConfig, UpstreamConfig, load_config
from gateway.mapping_store import MappingStore
from gateway.server import create_app
from gateway.upstream_client import UpstreamClient
from gateway.upstream_protocol import (
    ANTHROPIC_MESSAGES,
    DEFAULT_UPSTREAM_PROTOCOLS,
    OPENAI_CHAT_COMPLETIONS,
    OPENAI_RESPONSES,
)


class AdminFakeUpstream:
    async def request_json(self, method, path, payload=None):
        if path == "/v1/models":
            return 200, {"content-type": "application/json"}, {"data": []}
        if path == "/v1/messages":
            return 200, {"content-type": "application/json"}, {
                "id": "msg_test",
                "type": "message",
                "role": "assistant",
                "content": [{"type": "text", "text": "Done."}],
                "stop_reason": "end_turn",
            }
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
        assert "Agent privacy gateway" in page.text
        assert ">Privacy gateway<" not in page.text
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        app_js = client.get("/ui/assets/app.js")
        assert app_js.status_code == 200
        styles = client.get("/ui/assets/styles.css")
        assert styles.status_code == 200
        i18n_js = client.get("/ui/assets/i18n.js")
        assert i18n_js.status_code == 200
        lucide_js = client.get("/ui/assets/lucide.min.js")
        assert lucide_js.status_code == 200
        brand_icon = client.get("/ui/assets/apg-icon.png")
        assert brand_icon.status_code == 200
        assert brand_icon.headers["content-type"] == "image/png"
        assert brand_icon.content.startswith(b"\x89PNG\r\n\x1a\n")
        for removed_agent_icon in ("claude-code.svg", "opencode.svg", "codex.svg"):
            assert client.get(f"/ui/assets/{removed_agent_icon}").status_code == 404
        assert "@license lucide v1.27.0 - ISC" in lucide_js.text
        assert "Privacy operations overview" in i18n_js.text
        assert "Detectors" in i18n_js.text
        assert "apg:localechange" in i18n_js.text
        assert "APG built-in safety guard" in i18n_js.text
        assert "ANTHROPIC_BASE_URL" not in app_js.text
        assert client.get("/ui/assets/unknown.js").status_code == 404

        assert client.get("/api/admin/overview").status_code == 200
        assert client.get("/api/admin/overview", headers={"Authorization": "Bearer agent-key"}).status_code == 200
        assert client.get("/api/admin/overview", headers=_admin_headers()).status_code == 200
        privacy_control = client.get("/api/admin/privacy-control")
        assert privacy_control.status_code == 200
        assert privacy_control.json()["enabled"] is True
        assert privacy_control.json()["effective"] is True
        assert privacy_control.json()["available"] is True
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
        assert "copy-claude-command" not in page.text
        assert "请在 Agent 中自行选择模型" in page.text
        assert "Choose the model in your Agent" in i18n_js.text
        assert "agent-quickstart" not in page.text
        assert "data-copy-agent-setup" not in page.text
        assert "data-agent-guide" not in page.text
        assert "agent-guide-modal" not in page.text
        assert "copyAgentSetup" not in app_js.text
        assert "agentSetupText" not in app_js.text
        assert "openAgentGuide" not in app_js.text
        assert "ANTHROPIC_AUTH_TOKEN" not in app_js.text
        assert "@ai-sdk/openai-compatible" not in app_js.text
        assert 'wire_api = "responses"' not in app_js.text
        assert "配置上游模型" in page.text
        assert 'id="privacy-control"' in page.text
        assert 'id="privacy-control-enabled"' in page.text
        assert "APG 总开关" in page.text
        assert "一键开启或关闭 APG 保护。" in page.text
        assert "Turn APG protection on or off with one click." in i18n_js.text
        assert 'api("/privacy-control")' in app_js.text
        assert 'method: "PUT"' in app_js.text
        assert "renderPrivacyControl" in app_js.text
        assert "APG master switch" in i18n_js.text
        assert ".privacy-control {" in styles.text
        assert 'overview: ["LOCAL CONTROL PLANE", "概览"' in app_js.text
        assert ".eyebrow, .section-kicker, .page-subtitle { display: none; }" in styles.text
        assert "配置已在本机保存，密钥不会回显。" in app_js.text
        assert "Saved locally; keys are never displayed." in i18n_js.text
        assert "填写 Base URL 和 API Key。" in app_js.text
        assert "已替换或折叠" in app_js.text
        assert "本地保存" in app_js.text
        assert '["工作区", "Workspace"]' in i18n_js.text
        assert '["严格模式", "Strict"]' in i18n_js.text
        assert 'system.strict_mode ? "开启" : "关闭"' in app_js.text
        assert "确认后临时显示，关闭显示即清除。" in page.text
        assert "upstream-base-url-input" in page.text
        assert 'name="upstream-protocol"' not in page.text
        assert 'id="upstream-protocol-value"' not in page.text
        assert "支持的 API 格式" not in page.text
        assert 'id="upstream-test-protocol"' not in page.text
        assert 'id="upstream-effective-endpoints"' not in page.text
        assert "const showingDefaults = editing && editingProfile && !editingProfile.persisted;" in app_js.text
        assert 'setup.classList.toggle("is-editing", editing);' in app_js.text
        assert "@media (min-width: 1100px)" in styles.text
        assert ".upstream-setup:not(.is-editing) .upstream-profile-toolbar { grid-column: 2;" in styles.text
        assert "nameInput.placeholder = showingDefaults" in app_js.text
        assert "baseUrlInput.placeholder = showingDefaults" in app_js.text
        assert "!selected.persisted" in app_js.text
        assert ".upstream-protocol-options" not in styles.text
        assert "input::placeholder, textarea::placeholder { color: var(--muted); opacity: 1; }" in styles.text
        assert "data-connection-protocol" not in page.text
        assert "agent-openai-base-url" in page.text
        assert "agent-anthropic-base-url" in page.text
        assert 'id="generate-agent-key"' in page.text
        assert 'data-lucide="dices"' in page.text
        assert 'aria-label="生成随机 API Key"' in page.text
        assert 'api("/connection/api-key", {method: "POST"})' in app_js.text
        assert "Generate random API key" in i18n_js.text
        assert 'api("/upstream-configuration"' in app_js.text
        assert 'id="test-upstream-connection"' in page.text
        assert 'id="fetch-upstream-models"' in page.text
        assert 'id="upstream-test-model-select"' in page.text
        assert 'id="upstream-model-select-shell"' in page.text
        assert 'data-lucide="chevron-down"' in page.text
        assert ".upstream-model-list-toggle[hidden] { display: none; }" in styles.text
        assert 'id="upstream-test-model-options"' not in page.text
        assert 'list="upstream-test-model-options"' not in page.text
        assert 'api("/upstream-configuration/test"' in app_js.text
        assert 'api("/upstream-configuration/models")' in app_js.text
        assert "renderUpstreamProtocolResults" in app_js.text
        assert "正在自动测试三种 API 格式…" in app_js.text
        assert "Automatically testing all three API formats" in i18n_js.text
        assert "APG_UPSTREAM_PROTOCOL_MISMATCH" in app_js.text
        assert app_js.text.index('<option value="__manual__">') < app_js.text.index('${models.map((model)')
        assert '$("#fetch-upstream-models").disabled = !selected?.active;' in app_js.text
        assert '$("#test-upstream-connection").disabled = !selected?.active;' in app_js.text
        assert 'resetUpstreamTestResult("请先启用所选配置后再测试。")' in app_js.text
        assert "Activate the selected configuration before testing it." in i18n_js.text
        assert "Fetch models" in i18n_js.text
        assert "Fetching the model list from the active upstream" in i18n_js.text
        assert "Open model list" in i18n_js.text
        assert "Effective endpoint" in i18n_js.text
        assert 'data-locale="zh"' in page.text
        assert 'data-locale="en"' in page.text
        assert page.text.index("/ui/assets/i18n.js") < page.text.index("/ui/assets/app.js")
        assert page.text.index("/ui/assets/i18n.js") < page.text.index("/ui/assets/lucide.min.js") < page.text.index("/ui/assets/app.js")
        assert "https://unpkg.com" not in page.text
        assert "https://cdn.jsdelivr.net" not in page.text
        assert 'data-lucide="layout-dashboard"' in page.text
        assert 'data-lucide="scroll-text"' in page.text
        assert 'data-lucide="shield-check"' in page.text
        assert '<button class="nav-item" type="button" data-view="protected">' in page.text
        assert '<i class="nav-icon" data-lucide="lock"></i><span>受保护值</span>' in page.text
        assert 'data-lucide="sliders-horizontal"' in page.text
        assert '<button class="nav-item" type="button" data-view="local-models">' in page.text
        assert 'data-lucide="hard-drive-download"' in page.text
        assert 'id="view-local-models"' in page.text
        assert 'id="manual-model-form"' in page.text
        assert 'id="prepare-all-models"' in page.text
        assert 'id="repair-model-runtime"' not in page.text
        assert '<option value="auto">自动识别</option>' in page.text
        assert '<option value="auto">自动选择</option>' in page.text
        assert "添加并准备" in page.text
        assert 'id="local-runtime-details"' in page.text
        assert '"local-models": loadLocalModels' in app_js.text
        assert 'api("/local-models/prepare"' in app_js.text
        assert 'state.capabilities.includes("local_models_v2")' in app_js.text
        assert "APG 需要重启或更新" in app_js.text
        assert 'prepare: true' in app_js.text
        assert '["inspect", "runtime", "download", "verify"]' in app_js.text
        assert "function renderLocalModels()" in app_js.text
        assert "function availableLocalModels()" in app_js.text
        assert 'model.status === "ready"' in app_js.text
        assert 'id="model-selection"' in app_js.text
        assert 'id="model-name"' not in app_js.text
        assert 'id="model-adapter"' not in app_js.text
        assert 'id="model-device"' not in app_js.text
        assert "请先准备并选择一个可用的本地模型" in app_js.text
        assert "Only models successfully prepared and verified" in i18n_js.text
        assert 'data-local-model-target=' in app_js.text
        assert "scrollIntoView" in app_js.text
        assert "Local model management" in i18n_js.text
        assert ".local-model-card {" in styles.text
        assert '<span class="brand-mark" aria-hidden="true"><img src="/ui/assets/apg-icon.png" alt=""></span>' in page.text
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
        assert "function findingModuleNames(finding)" in app_js.text
        assert 'diagnostics.filter((item) => item.id !== "apg_core")' in app_js.text
        assert "function showDetectionTooltip(mark, group, pinned)" in app_js.text
        assert 'mark.addEventListener("pointerenter"' in app_js.text
        assert 'mark.addEventListener("click"' in app_js.text
        assert 'mark.setAttribute("aria-label", `检测模块：' in app_js.text
        assert ".detection-tooltip {" in styles.text
        assert ".highlight-detail span:not(.detail-index)" in styles.text
        assert ".diagnostic-row > span:not(.diagnostic-order)" in styles.text
        assert ".detail-index, .diagnostic-order {" in styles.text
        assert "Hover or click a highlight to see its module" in i18n_js.text
        assert '<span>${escapeHtml(type)}</span>' in app_js.text
        assert '${escapeHtml(type)} · ${escapeHtml(module.id)}' not in app_js.text
        assert "module-meta" not in app_js.text
        assert ".module-meta" not in styles.text
        assert 'name="failure_mode"' in page.text
        assert "失败时跳过模块（Fail open）" in page.text
        assert "失败时中止流程（Fail closed）" in page.text
        assert "Skip module on failure (Fail open)" in i18n_js.text
        assert "Stop pipeline on failure (Fail closed)" in i18n_js.text
        assert 'module.editable === false ? "managed" : "activated"' in app_js.text
        assert 'status === "activated" ? "green"' in app_js.text
        assert "moduleStatusLabel(status)" in app_js.text
        assert 'activated: "已启用"' in app_js.text
        assert 'module.editable === false ? "managed" : "ready"' not in app_js.text
        assert 'data-module-drag="${index}"' in app_js.text
        assert '${dragControl}<span class="module-order"' in app_js.text
        assert 'iconMarkup("grip-vertical")' in app_js.text
        assert "beginModuleDrag" in app_js.text
        assert "reorderModule" in app_js.text
        assert "data-module-up" not in app_js.text
        assert "data-module-down" not in app_js.text
        assert '["拖动排序", "Drag to reorder"]' in i18n_js.text
        assert 'uiText(configuration.name)' in app_js.text
        assert "DETECTOR_TAG_LABELS" not in app_js.text
        assert "detectorTagLabel" not in app_js.text
        assert 'id="configuration-tags"' not in page.text
        assert 'function updateConfigurationFields(event)' in app_js.text
        assert 'class="lucide detector-regex-icon"' in app_js.text
        assert '<circle cx="9" cy="13" r="1.15"' in app_js.text
        assert "type.slice(0, 2)" not in app_js.text
        assert "<span>规则名称</span>" in app_js.text
        assert "<span>风险等级（仅用于审计）</span>" in app_js.text
        assert 'data-rule-field="name"' in app_js.text
        assert 'data-rule-field="id"' not in app_js.text
        assert "display_name: displayName" in app_js.text
        assert 'data-rule-field="subtype"' not in app_js.text
        assert 'data-rule-field="suggested_action"' not in app_js.text
        assert "riskActionFields" not in app_js.text
        assert "凭据文件名（逗号分隔）" not in app_js.text
        assert "凭据文件风险" not in app_js.text
        assert "普通路径动作" not in app_js.text
        assert "凭据文件动作" not in app_js.text
        assert "敏感上下文动作" not in app_js.text
        assert "无上下文动作" not in app_js.text
        assert "上下文窗口" not in app_js.text
        assert "敏感上下文词" not in app_js.text
        assert "误报提示词" not in app_js.text
        assert "sensitive_words" not in app_js.text
        assert "false_positive_hints" not in app_js.text
        assert 'riskField("path", "模块", config.path_risk)' in app_js.text
        assert 'riskField("entropy", "模块", config.risk || "medium")' in app_js.text
        assert "风险等级（仅用于审计）" in app_js.text
        assert "Module risk level (audit only)" in i18n_js.text
        assert '<details class="rule-advanced full-row"><summary>高级选项（选填）</summary>' in app_js.text
        advanced_rule_fields = app_js.text.split('<details class="rule-advanced full-row"><summary>高级选项（选填）</summary>', 1)[1].split("</details>", 1)[0]
        assert "Flags（逗号分隔）" in advanced_rule_fields
        assert '<details class="rule-advanced full-row" open>' not in app_js.text
        assert "Validators（选填）" in app_js.text
        assert "Required validators (optional)" in i18n_js.text
        assert 'id="module-name-field"' in page.text
        assert 'id="module-type-field"' in page.text
        assert '$("#module-type-field").hidden = editing;' in app_js.text
        assert '$("#module-name-field").classList.toggle("full-row", editing);' in app_js.text
        assert ".module-type-field[hidden] { display: none; }" in styles.text
        readonly_notice = "默认预设不可编辑，请复制或新建自定义配置。模块开关仍可直接调整。"
        assert readonly_notice in app_js.text
        assert readonly_notice in i18n_js.text
        assert "Default presets cannot be edited. Duplicate one or create a custom configuration; module switches remain adjustable." in i18n_js.text
        assert "只读模板" not in app_js.text
        assert "只读模板" not in i18n_js.text
        assert "Revision ${configuration.revision}" not in app_js.text
        assert "async function updateModuleEnabled(index, enabled)" in app_js.text
        assert "/modules/${encodeURIComponent(moduleId)}/enabled" in app_js.text
        assert '${readonly || module.editable === false ? "disabled" : ""}' not in app_js.text
        assert ".brand-mark { width: 34px; height: 34px; flex: 0 0 34px; display: grid; place-items: center; border: 0; background: transparent;" in styles.text
        assert ".brand-mark" not in "\n".join(
            line for line in styles.text.splitlines() if "border: 1px solid #4d7863" in line
        )
        assert ".brand-mark img { display: block; width: 34px; height: 34px; object-fit: contain; }" in styles.text
        assert ".module-symbol .lucide { display: block; width: 28px; height: 28px;" in styles.text
        assert ".module-row > .toggle { grid-column: 6; }" in styles.text
        assert ".module-drag-handle { padding: 0; border: 0;" in styles.text
        assert ".toggle span { position: absolute; inset: 0; margin: 0; border-radius: 12px; background: #cbd3cf; overflow: hidden;" in styles.text
        assert "transform: translateY(-50%);" in styles.text
        assert ".toggle input:checked + span::after { transform: translate(16px, -50%); }" in styles.text
        assert styles.text.count("transform: translate(1px, 1px);") == 1
        assert "configuration-core-guard" not in page.text
        assert "core-guard-warning" not in page.text
        assert "updateCoreGuard" not in app_js.text
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
        assert 'class="audit-type"' in app_js.text
        assert ".audit-operation-table .audit-type > * { grid-column: 2;" in styles.text
        assert "本地映射保留" in page.text
        assert "mapping-retention-enabled" in page.text
        assert "upstream-profile-select" in page.text
        assert "new-upstream-profile" in page.text
        assert "activate-upstream-profile" not in page.text
        assert "activate-configuration" not in page.text
        assert 'switchUpstreamProfile(event.target.value)' in app_js.text
        assert 'activateDetectorConfiguration(configurationId)' in app_js.text
        assert ".icon-action-button {\n  width: 36px;\n  min-width: 36px;\n  height: 36px;\n  min-height: 36px;\n  padding: 0;\n}" in styles.text
        assert ".row-action.icon-row-button { width: 30px; min-width: 30px; height: 30px; min-height: 30px; padding: 0; }" in styles.text
        assert "#upstream-status { width: max-content; max-width: 100%; justify-self: end; justify-content: center; flex-wrap: nowrap; white-space: nowrap;" in styles.text
        assert "minmax(220px, .85fr) max-content;" in styles.text
        assert "#edit-upstream-key { grid-column: 4; grid-row: 2; justify-self: end;" in styles.text
        assert '["暂无配置", "No saved configurations"]' in i18n_js.text
        assert "`${translateCore(name)} (Active)`" in i18n_js.text
        assert "protected-show-raw" in page.text
        assert "visibility-button" in page.text
        assert 'class="protected-cell-stack"' in app_js.text
        assert ".protected-values-table td > .protected-cell-stack" in styles.text
        assert ".metric-grid, .protected-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }" in styles.text
        assert ".modal > form { max-height: calc(100vh - 40px); display: grid;" in styles.text
        assert 'api("/protected-values/retention"' in app_js.text

        audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
        assert "view_agent_connection_info" in audit_text
        assert "agent-key" not in audit_text
        assert "provider-key" not in audit_text


def test_admin_can_regenerate_and_persist_agent_api_key(tmp_path, monkeypatch) -> None:
    launcher_path = tmp_path / "launcher.json"
    monkeypatch.setenv("APG_LAUNCHER_CONFIG_PATH", str(launcher_path))
    cfg = _config(tmp_path)

    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        rotated = client.post("/api/admin/connection/api-key")
        assert rotated.status_code == 200
        generated = rotated.json()["api_key"]
        assert re.fullmatch(r"apg_local_[A-Za-z0-9_-]{32}", generated)
        assert generated != "agent-key"
        assert rotated.json()["available_key_count"] == 1
        assert cfg.local_api_keys == {generated}

        assert client.get("/v1/models", headers={"Authorization": "Bearer agent-key"}).status_code == 401
        assert client.get("/v1/models", headers={"Authorization": f"Bearer {generated}"}).status_code == 200
        assert client.get("/api/admin/connection").json()["api_key"] == generated

    stored = json.loads(launcher_path.read_text(encoding="utf-8"))
    assert stored["local_api_key"] == generated
    assert os.stat(launcher_path).st_mode & 0o777 == 0o600
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "rotate_agent_api_key" in audit_text
    assert generated not in audit_text


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

        mismatched_response = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-key"},
            json={"model": "test", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert mismatched_response.status_code == 200

        response = client.post(
            "/v1/messages",
            headers={"x-api-key": "agent-key", "anthropic-version": "2023-06-01"},
            json={
                "model": "test",
                "max_tokens": 32,
                "messages": [{"role": "user", "content": "hello"}],
            },
        )
        assert response.status_code == 200
        assert response.json()["type"] == "message"

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


def test_webui_upstream_connectivity_test_checks_all_native_protocols_and_reports_safe_failures(tmp_path) -> None:
    class ConnectivityUpstream(AdminFakeUpstream):
        def __init__(self) -> None:
            self.calls = []

        async def request_json(self, method, path, payload=None):
            self.calls.append((method, path, payload))
            return 503, {
                "content-type": "application/json",
                "x-request-id": "up_req_test",
                "set-cookie": "must-not-be-returned",
            }, {
                "error": {
                    "type": "server_error",
                    "code": "concurrency_limit_exceeded",
                    "message": "Concurrency limit exceeded, retry later.",
                }
            }

    upstream = ConnectivityUpstream()
    base = _config(tmp_path)
    cfg = GatewayConfig(
        **{
            **base.__dict__,
            "upstream": UpstreamConfig(
                base_url="https://upstream.example/v1",
                api_key="provider-key",
                protocol=OPENAI_RESPONSES,
                strip_local_v1=True,
            ),
        }
    )
    with TestClient(create_app(cfg, upstream)) as client:
        response = client.post(
            "/api/admin/upstream-configuration/test",
            headers=_admin_headers(),
            json={"model": "gpt-test"},
        )
        assert response.status_code == 200
        result = response.json()
        assert result["ok"] is False
        assert result["all_ok"] is False
        assert result["supported_protocols"] == []
        assert [item["protocol"] for item in result["results"]] == list(DEFAULT_UPSTREAM_PROTOCOLS)
        for item in result["results"]:
            assert item["status_code"] == 503
            assert item["target_endpoint"] == f"https://upstream.example{item['endpoint']}"
            assert item["error"] == {
                "type": "server_error",
                "code": "concurrency_limit_exceeded",
                "message": "Concurrency limit exceeded, retry later.",
            }
            assert item["upstream_trace_headers"] == {"x-request-id": "up_req_test"}
        assert upstream.calls == [
            (
                "POST",
                "/v1/chat/completions",
                {
                    "model": "gpt-test",
                    "messages": [{"role": "user", "content": "Reply exactly with OK."}],
                    "max_tokens": 8,
                    "stream": False,
                },
            ),
            (
                "POST",
                "/v1/responses",
                {
                    "model": "gpt-test",
                    "input": "Reply exactly with OK.",
                    "max_output_tokens": 16,
                    "stream": False,
                },
            ),
            (
                "POST",
                "/v1/messages",
                {
                    "model": "gpt-test",
                    "messages": [{"role": "user", "content": "Reply exactly with OK."}],
                    "max_tokens": 8,
                    "stream": False,
                },
            ),
        ]

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "test_upstream_connection" in audit_text
    assert "Concurrency limit exceeded" not in audit_text
    assert "provider-key" not in response.text


def test_webui_upstream_connectivity_rejects_http_success_with_wrong_protocol_shape(tmp_path) -> None:
    class MismatchedUpstream(AdminFakeUpstream):
        async def request_json(self, method, path, payload=None):
            return 200, {"content-type": "application/json"}, {
                "choices": [{"message": {"role": "assistant", "content": "OK"}}]
            }

    with TestClient(create_app(_config(tmp_path), MismatchedUpstream())) as client:
        response = client.post(
            "/api/admin/upstream-configuration/test",
            headers=_admin_headers(),
            json={"model": "gpt-test"},
        )

    assert response.status_code == 200
    result = response.json()
    assert result["ok"] is True
    assert result["all_ok"] is False
    assert result["supported_protocols"] == [OPENAI_CHAT_COMPLETIONS]
    by_protocol = {item["protocol"]: item for item in result["results"]}
    assert by_protocol[OPENAI_CHAT_COMPLETIONS]["ok"] is True
    for protocol in (OPENAI_RESPONSES, ANTHROPIC_MESSAGES):
        assert by_protocol[protocol]["ok"] is False
        assert by_protocol[protocol]["status_code"] == 200
        assert by_protocol[protocol]["error"]["code"] == "APG_UPSTREAM_PROTOCOL_MISMATCH"


def test_webui_upstream_model_list_returns_only_safe_model_ids(tmp_path) -> None:
    class ModelListUpstream(AdminFakeUpstream):
        def __init__(self) -> None:
            self.calls = []

        async def request_json(self, method, path, payload=None):
            self.calls.append((method, path, payload))
            return 200, {
                "content-type": "application/json",
                "x-request-id": "up_models_test",
                "set-cookie": "must-not-be-returned",
            }, {
                "data": [
                    {"id": "gpt-a", "private_metadata": "must-not-be-returned"},
                    {"model": "gpt-b"},
                    {"name": "gpt-c"},
                    {"id": "gpt-a"},
                    {"id": "bad\nmodel"},
                    {"id": "x" * 257},
                    {"unrecognized": "ignored"},
                ],
                "provider_secret": "must-not-be-returned",
            }

    upstream = ModelListUpstream()
    base = _config(tmp_path)
    cfg = GatewayConfig(
        **{
            **base.__dict__,
            "upstream": UpstreamConfig(
                base_url="https://upstream.example/v1",
                api_key="provider-key",
                protocol=OPENAI_RESPONSES,
                strip_local_v1=True,
            ),
        }
    )
    with TestClient(create_app(cfg, upstream)) as client:
        response = client.get(
            "/api/admin/upstream-configuration/models",
            headers=_admin_headers(),
        )
        assert response.status_code == 200
        result = response.json()
        assert result == {
            "ok": True,
            "endpoint": "/v1/models",
            "target_endpoint": "https://upstream.example/v1/models",
            "status_code": 200,
            "latency_ms": result["latency_ms"],
            "models": ["gpt-a", "gpt-b", "gpt-c"],
            "truncated": False,
            "upstream_trace_headers": {"x-request-id": "up_models_test"},
            "error": None,
        }
        assert upstream.calls == [("GET", "/v1/models", None)]
        assert "must-not-be-returned" not in response.text
        assert "provider-key" not in response.text

    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    model_list_event = next(
        event
        for event in (json.loads(line) for line in audit_text.splitlines())
        if event.get("action") == "list_upstream_models"
    )
    assert model_list_event["model_count"] == 3
    assert "gpt-a" not in audit_text
    assert "provider-key" not in audit_text


def test_webui_upstream_model_list_uses_standard_v1_route_for_root_base_url(tmp_path) -> None:
    captured: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(
            200,
            headers={"x-request-id": "models_v1_route"},
            json={"data": [{"id": "gpt-test"}]},
        )

    base = _config(tmp_path)
    upstream_config = UpstreamConfig(
        base_url="https://upstream.example",
        api_key="provider-key",
        protocol=OPENAI_RESPONSES,
        strip_local_v1=True,
    )
    upstream = UpstreamClient(upstream_config, transport=httpx.MockTransport(handler))
    cfg = GatewayConfig(**{**base.__dict__, "upstream": upstream_config})

    with TestClient(create_app(cfg, upstream)) as client:
        response = client.get(
            "/api/admin/upstream-configuration/models",
            headers=_admin_headers(),
        )

    assert response.status_code == 200
    assert response.json()["target_endpoint"] == "https://upstream.example/v1/models"
    assert response.json()["models"] == ["gpt-test"]
    assert captured["url"] == "https://upstream.example/v1/models"


def test_webui_full_chat_completions_endpoint_resolves_models_and_test_as_siblings(tmp_path) -> None:
    captured: list[tuple[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append((request.method, str(request.url)))
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": "openai/gpt-test"}]})
        if request.url.path.endswith("/responses"):
            return httpx.Response(200, json={"id": "resp_test", "object": "response", "output": []})
        if request.url.path.endswith("/messages"):
            return httpx.Response(200, json={"id": "msg_test", "type": "message", "role": "assistant", "content": []})
        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": "OK"}}]},
        )

    base = _config(tmp_path)
    upstream_config = UpstreamConfig(
        base_url="https://openrouter.ai/api/v1/chat/completions",
        api_key="provider-key",
        protocol=OPENAI_CHAT_COMPLETIONS,
        strip_local_v1=True,
    )
    upstream = UpstreamClient(upstream_config, transport=httpx.MockTransport(handler))
    cfg = GatewayConfig(**{**base.__dict__, "upstream": upstream_config})

    with TestClient(create_app(cfg, upstream)) as client:
        models = client.get("/api/admin/upstream-configuration/models", headers=_admin_headers())
        connectivity = client.post(
            "/api/admin/upstream-configuration/test",
            headers=_admin_headers(),
            json={"model": "openai/gpt-test"},
        )

    assert models.status_code == 200
    assert models.json()["target_endpoint"] == "https://openrouter.ai/api/v1/models"
    assert models.json()["models"] == ["openai/gpt-test"]
    assert connectivity.status_code == 200
    assert connectivity.json()["ok"] is True
    assert connectivity.json()["all_ok"] is True
    assert [item["target_endpoint"] for item in connectivity.json()["results"]] == [
        "https://openrouter.ai/api/v1/chat/completions",
        "https://openrouter.ai/api/v1/responses",
        "https://openrouter.ai/api/v1/messages",
    ]
    assert captured == [
        ("GET", "https://openrouter.ai/api/v1/models"),
        ("POST", "https://openrouter.ai/api/v1/chat/completions"),
        ("POST", "https://openrouter.ai/api/v1/responses"),
        ("POST", "https://openrouter.ai/api/v1/messages"),
    ]


def test_webui_upstream_model_list_rejects_non_json_success_response(tmp_path) -> None:
    class NonJsonModelListUpstream(AdminFakeUpstream):
        async def request_json(self, method, path, payload=None):
            return 200, {"content-type": "text/html; charset=utf-8"}, {
                "error": {"message": "Upstream returned non-JSON response"}
            }

    with TestClient(create_app(_config(tmp_path), NonJsonModelListUpstream())) as client:
        response = client.get(
            "/api/admin/upstream-configuration/models",
            headers=_admin_headers(),
        )

    assert response.status_code == 200
    result = response.json()
    assert result["ok"] is False
    assert result["models"] == []
    assert result["error"] == {
        "type": "UpstreamResponseFormatError",
        "code": "APG_UPSTREAM_NON_JSON",
        "message": "The upstream model-list endpoint returned a non-JSON response.",
    }


def test_default_upstream_store_survives_app_restart(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("APG_LAUNCHER_CONFIG_PATH", raising=False)
    launcher_path = tmp_path / "launcher.json"
    cfg = _config(tmp_path)

    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        initial = client.get("/api/admin/upstream-configuration", headers=_admin_headers())
        assert initial.status_code == 200
        assert initial.json()["persistent"] is True
        assert initial.json()["active_profile_id"] == "runtime_default"
        assert initial.json()["profiles"][0]["persisted"] is False

        saved = client.put(
            "/api/admin/upstream-configuration",
            headers=_admin_headers(),
            json={
                "profile_id": "runtime_default",
                "name": "本地持久配置",
                "protocol": ANTHROPIC_MESSAGES,
                "protocols": list(DEFAULT_UPSTREAM_PROTOCOLS),
                "base_url": "https://persisted.example/anthropic",
                "endpoint_overrides": {},
                "api_key": "",
            },
        )
        assert saved.status_code == 200
        saved_body = saved.json()
        assert saved_body["profiles"][0]["persisted"] is True
        assert saved_body["active_profile_id"] != "runtime_default"
        assert "provider-key" not in saved.text

    assert launcher_path.exists()
    assert os.stat(launcher_path).st_mode & 0o777 == 0o600

    with TestClient(create_app(cfg, AdminFakeUpstream())) as restarted_client:
        restored = restarted_client.get(
            "/api/admin/upstream-configuration",
            headers=_admin_headers(),
        )
        assert restored.status_code == 200
        restored_body = restored.json()
        assert restored_body["configured"] is True
        assert restored_body["base_url"] == "https://persisted.example/anthropic"
        assert restored_body["protocol"] == ANTHROPIC_MESSAGES
        assert restored_body["profiles"] == [
            {
                "id": saved_body["active_profile_id"],
                "name": "本地持久配置",
                "protocol": ANTHROPIC_MESSAGES,
                "protocols": list(DEFAULT_UPSTREAM_PROTOCOLS),
                "base_url": "https://persisted.example/anthropic",
                "endpoint_overrides": {},
                "has_api_key": True,
                "active": True,
                "persisted": True,
            }
        ]
        assert "provider-key" not in restored.text


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
        preset = client.get(
            "/api/admin/detector-configurations/builtin.comprehensive",
            headers=_admin_headers(),
        ).json()
        assert next(module for module in preset["modules"] if module["id"] == "entropy")["enabled"] is False
        toggled = client.put(
            "/api/admin/detector-configurations/builtin.comprehensive/modules/entropy/enabled",
            headers=_admin_headers(),
            json={"enabled": True},
        )
        assert toggled.status_code == 200
        assert next(module for module in toggled.json()["modules"] if module["id"] == "entropy")["enabled"] is True
        invalid_toggle = client.put(
            "/api/admin/detector-configurations/builtin.comprehensive/modules/entropy/enabled",
            headers=_admin_headers(),
            json={"enabled": "yes"},
        )
        assert invalid_toggle.status_code == 400
        reset_toggle = client.put(
            "/api/admin/detector-configurations/builtin.comprehensive/modules/entropy/enabled",
            headers=_admin_headers(),
            json={"enabled": False},
        )
        assert reset_toggle.status_code == 200

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
                "core_guard_enabled": False,
                "flow_timeout_ms": configuration["flow_timeout_ms"],
                "content_tags": configuration["content_tags"],
                "modules": configuration["modules"],
            },
        )
        assert saved.status_code == 200
        configuration = saved.json()
        assert configuration["core_guard_enabled"] is True
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
    audit_text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "toggle_preset_detector_module" in audit_text

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


def test_admin_exposes_safe_upstream_stream_failure_details(tmp_path) -> None:
    cfg = _config(tmp_path)
    request_id = "req_0123456789ab"
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        client.app.state.admin_service.audit.log(
            {
                "request_id": request_id,
                "session_id": "sess_upstream_failure",
                "endpoint": "/v1/responses",
                "phase": "response_stream_complete",
                "stream": True,
                "termination": "failed",
                "upstream_error_event": "response.failed",
                "upstream_error_type": "server_error",
                "upstream_error_code": "concurrency_limit_exceeded",
                "upstream_trace_headers": {"x-request-id": "up_req_123"},
            }
        )

        summary = client.get(
            "/api/admin/audit/requests?activity=error",
            headers=_admin_headers(),
        ).json()["requests"][0]
        assert summary["request_id"] == request_id
        assert summary["status"] == "error"

        detail = client.get(
            f"/api/admin/audit/requests/{request_id}",
            headers=_admin_headers(),
        ).json()
        assert detail["termination"] == "failed"
        assert detail["upstream_error_event"] == "response.failed"
        assert detail["upstream_error_type"] == "server_error"
        assert detail["upstream_error_code"] == "concurrency_limit_exceeded"
        assert detail["upstream_trace_headers"] == {"x-request-id": "up_req_123"}


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
    monkeypatch.setenv("APG_ADMIN_ENABLED", "false")
    monkeypatch.setenv("APG_SIGNING_SECRET", "configured-signing-secret")
    monkeypatch.setenv("APG_DATABASE_PATH", str(tmp_path / "state.sqlite3"))
    monkeypatch.setenv("APG_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    cfg = load_config()
    assert cfg.admin_enabled is False


def test_admin_can_be_disabled(tmp_path) -> None:
    cfg = _config(tmp_path)
    cfg = GatewayConfig(**{**cfg.__dict__, "admin_enabled": False})
    with TestClient(create_app(cfg, AdminFakeUpstream())) as client:
        assert client.get("/ui/").status_code == 404
        assert client.get("/api/admin/overview", headers=_admin_headers()).status_code == 404
