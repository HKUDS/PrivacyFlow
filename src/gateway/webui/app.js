"use strict";

const API = "/api/admin";
const PAGE_META = {
  overview: ["LOCAL CONTROL PLANE", "概览", "最近 24 小时的网关活动"],
  audit: ["SAFE AUDIT TRAIL", "审计记录", "上行替换与本地还原"],
  protected: ["LOCAL MAPPING REGISTRY", "受保护值", "本地映射生命周期与撤销"],
  detectors: ["DETECTION PIPELINE", "检测器配置", "按检测内容组织的本地模块流水线"],
};
const UPSTREAM_PROTOCOL_LABELS = {
  openai_chat_completions: "OpenAI Chat Completions",
  openai_responses: "OpenAI Responses",
  anthropic_messages: "Anthropic Messages",
};
const state = {
  view: location.hash.replace("#", "") || "overview",
  loaded: new Set(),
  connection: null,
  upstream: null,
  privacyControl: null,
  upstreamEditing: false,
  upstreamEditingProfileId: "",
  upstreamSelectedProfileId: "",
  audit: null,
  auditDirection: "replacement",
  auditLoadVersion: 0,
  auditDetail: null,
  auditDetailRequestId: "",
  auditShowRaw: false,
  protected: null,
  protectedShowRaw: false,
  protectedLoadVersion: 0,
  detectorCatalog: null,
  detectorConfiguration: null,
  detectorDraft: null,
  editingModuleIndex: null,
  moduleDraft: null,
  moduleDraftSourceName: "",
  moduleDrag: null,
  agentGuide: "",
  confirmAction: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const DYNAMIC_ICONS = new Set(["arrow-right", "ban", "brain-circuit", "check-circle-2", "copy", "eye", "eye-off", "folder-tree", "gauge", "grip-vertical", "pencil", "plus", "power", "regex-reference", "search", "server-cog", "trash-2"]);

document.addEventListener("DOMContentLoaded", init);

function init() {
  renderIcons();
  bindNavigation();
  bindActions();
  syncVisibilityButtons();
  showView(PAGE_META[state.view] ? state.view : "overview", false);
  connect();
  window.addEventListener("apg:localechange", () => {
    syncVisibilityButtons();
    if ($("#agent-guide-modal")?.open && state.agentGuide) openAgentGuide(state.agentGuide);
    showView(state.view, false);
    state.loaded.clear();
    loadView(state.view, true);
  });
}

function iconMarkup(name) {
  if (!DYNAMIC_ICONS.has(name)) throw new Error(`Unsupported dynamic icon: ${name}`);
  if (name === "regex-reference") {
    return `<svg class="lucide detector-regex-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M7 3C4.4 5.2 3 8.3 3 12s1.4 6.8 4 9"></path><path d="M17 3c2.6 2.2 4 5.3 4 9s-1.4 6.8-4 9"></path><circle cx="9" cy="13" r="1.15" fill="currentColor" stroke="none"></circle><path d="M14 7v6M11.4 8.5l5.2 3M16.6 8.5l-5.2 3"></path></svg>`;
  }
  return `<i data-lucide="${name}"></i>`;
}

function renderIcons(root = document) {
  if (!window.lucide?.createIcons || !window.lucide?.icons) throw new Error("Lucide icon runtime is unavailable");
  window.lucide.createIcons({
    icons: window.lucide.icons,
    attrs: {"aria-hidden": "true", focusable: "false", "stroke-width": "2"},
    root,
  });
}

function setIconButton(button, name, label) {
  button.innerHTML = iconMarkup(name);
  button.setAttribute("aria-label", label);
  button.title = label;
  renderIcons(button);
}

function bindNavigation() {
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-view]");
    if (trigger) showView(trigger.dataset.view);
    if (event.target.closest("[data-close-modal]")) event.target.closest("dialog")?.close();
  });
  window.addEventListener("hashchange", () => {
    const next = location.hash.replace("#", "");
    if (PAGE_META[next]) showView(next, false);
  });
}

function bindActions() {
  $("#refresh-button").addEventListener("click", () => loadView(state.view, true));
  $("#privacy-control-enabled").addEventListener("change", updatePrivacyControl);
  $$('[data-copy-connection]').forEach((button) => button.addEventListener("click", () => copyConnectionValue(button.dataset.copyConnection)));
  $$("[data-copy-agent-setup]").forEach((button) => button.addEventListener("click", () => copyAgentSetup(button.dataset.copyAgentSetup)));
  $$("[data-agent-guide]").forEach((button) => button.addEventListener("click", () => openAgentGuide(button.dataset.agentGuide)));
  $("#agent-guide-modal").addEventListener("close", () => { state.agentGuide = ""; });
  $("#toggle-agent-key").addEventListener("click", toggleAgentKeyVisibility);
  $("#generate-agent-key").addEventListener("click", () => {
    confirmAction(
      "生成新的 API Key",
      "当前 API Key 将立即失效，请更新所有 Agent 配置。",
      regenerateAgentApiKey,
    );
  });
  $("#upstream-key-form").addEventListener("submit", saveUpstreamApiKey);
  $("#upstream-profile-select").addEventListener("change", (event) => {
    state.upstreamSelectedProfileId = event.target.value;
    renderUpstreamConfiguration();
  });
  $("#activate-upstream-profile").addEventListener("click", activateSelectedUpstreamProfile);
  $("#new-upstream-profile").addEventListener("click", () => {
    state.upstreamEditing = true;
    state.upstreamEditingProfileId = "";
    renderUpstreamConfiguration();
    $("#upstream-profile-name").focus();
  });
  $("#delete-upstream-profile").addEventListener("click", () => {
    const profile = selectedUpstreamProfile();
    if (profile) confirmAction("删除上游配置", `将删除“${profile.name}”。已保存的密钥也会从本机配置中移除。`, deleteSelectedUpstreamProfile);
  });
  $("#edit-upstream-key").addEventListener("click", () => {
    state.upstreamEditing = true;
    state.upstreamEditingProfileId = state.upstreamSelectedProfileId || state.upstream?.active_profile_id || "";
    renderUpstreamConfiguration();
    setTimeout(() => (state.upstream?.base_url ? $("#upstream-api-key") : $("#upstream-base-url-input")).focus(), 30);
  });
  $("#cancel-upstream-key").addEventListener("click", () => {
    state.upstreamEditing = false;
    state.upstreamEditingProfileId = "";
    $("#upstream-api-key").value = "";
    $("#upstream-key-error").textContent = "";
    renderUpstreamConfiguration();
  });
  $("#audit-query").addEventListener("input", debounce(() => loadAudit().catch(handleError), 280));
  for (const id of ["audit-risk", "audit-endpoint"]) $("#" + id).addEventListener("change", () => loadAudit().catch(handleError));
  $$('[data-audit-direction]').forEach((button) => button.addEventListener("click", () => setAuditDirection(button.dataset.auditDirection)));
  $("#audit-show-raw").addEventListener("click", handleRawVisibilityChange);
  $("#detail-modal").addEventListener("close", () => clearAuditDetail());
  $("#protected-kind").addEventListener("change", () => loadProtected().catch(handleError));
  $("#protected-show-raw").addEventListener("click", handleProtectedRawVisibilityChange);
  $("#purge-expired").addEventListener("click", () => confirmAction("清理过期记录", "将所有已过期映射转为不可恢复状态。", purgeExpired));
  $("#mapping-retention-enabled").addEventListener("change", syncMappingRetentionControls);
  $("#mapping-retention-duration").addEventListener("input", syncMappingRetentionControls);
  $("#mapping-retention-unit").addEventListener("change", syncMappingRetentionControls);
  $("#save-mapping-retention").addEventListener("click", () => saveMappingRetention().catch(handleError));
  $("#configuration-select").addEventListener("change", (event) => selectDetectorConfiguration(event.target.value));
  $("#new-configuration").addEventListener("click", openConfigurationCreator);
  $("#duplicate-configuration").addEventListener("click", duplicateDetectorConfiguration);
  $("#activate-configuration").addEventListener("click", activateDetectorConfiguration);
  $("#save-configuration").addEventListener("click", saveDetectorConfiguration);
  $("#delete-configuration").addEventListener("click", deleteDetectorConfiguration);
  $("#add-module").addEventListener("click", () => openModuleEditor(null));
  $("#configuration-form").addEventListener("submit", createDetectorConfiguration);
  $("#module-form").addEventListener("submit", applyModuleDraft);
  $("#module-type").addEventListener("change", (event) => {
    state.moduleDraft.type = event.target.value;
    state.moduleDraft.config = defaultModuleConfig(event.target.value);
    renderModuleSpecificFields();
  });
  for (const id of ["configuration-name", "configuration-description", "configuration-timeout"]) {
    $("#" + id).addEventListener("input", updateConfigurationFields);
  }
  $("#run-detection").addEventListener("click", runDetection);
  $("#confirm-action").addEventListener("click", async () => {
    const action = state.confirmAction;
    $("#confirm-modal").close();
    if (action) {
      try { await action(); }
      catch (error) { handleError(error); }
    }
  });
}

async function connect() {
  try {
    await loadOverview();
    setConnected(true);
    $("#app-shell").setAttribute("aria-busy", "false");
    if (state.view !== "overview") await loadView(state.view);
  } catch (error) {
    setConnected(false);
    handleError(error);
  }
}

function setConnected(connected) {
  $("#connection-dot").classList.toggle("is-online", connected);
  $("#connection-label").textContent = connected ? "本地网关已连接" : "连接已断开";
}

function showView(view, updateHash = true) {
  state.view = view;
  if (updateHash && location.hash !== "#" + view) history.pushState(null, "", "#" + view);
  $$(".view").forEach((element) => element.classList.toggle("is-active", element.id === "view-" + view));
  $$(".nav-item").forEach((element) => element.classList.toggle("is-active", element.dataset.view === view));
  const [eyebrow, title, subtitle] = PAGE_META[view];
  $("#page-eyebrow").textContent = eyebrow;
  $("#page-title").textContent = title;
  $("#page-subtitle").textContent = subtitle;
  if (state.connection) loadView(view);
}

async function loadView(view, force = false) {
  const loaders = {overview: loadOverview, audit: loadAudit, protected: loadProtected, detectors: loadDetectors};
  if (!force && state.loaded.has(view)) return;
  $("#refresh-button").classList.add("is-loading");
  try { await loaders[view](); state.loaded.add(view); }
  catch (error) { handleError(error); }
  finally { $("#refresh-button").classList.remove("is-loading"); }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("Content-Type", "application/json");
  const response = await fetch(API + path, {...options, headers, cache: "no-store"});
  let body = null;
  try { body = await response.json(); } catch (_) { body = {}; }
  if (!response.ok) {
    const error = new Error(typeof body.detail === "string" ? body.detail : "请求失败");
    error.status = response.status;
    throw error;
  }
  return body;
}

async function loadOverview() {
  const [data, connection, upstream, privacyControl] = await Promise.all([
    api("/overview"),
    api("/connection"),
    api("/upstream-configuration"),
    api("/privacy-control"),
  ]);
  state.connection = connection;
  state.upstream = upstream;
  state.privacyControl = privacyControl;
  renderConnection();
  renderUpstreamConfiguration();
  renderPrivacyControl();
  const metrics = [
    ["请求", data.metrics.requests_24h, "最近 24 小时", "accent-blue"],
    ["拦截", data.metrics.interceptions_24h, "已替换或折叠", "accent-coral"],
    ["本地还原", data.metrics.materializations_24h, "仅结构化工具参数", "accent-green"],
    ["活跃受保护值", data.metrics.active_protected_values, "本地保存", "accent-amber"],
  ];
  $("#overview-metrics").innerHTML = metrics.map(([label, value, foot, accent]) => `<article class="metric-card ${accent}"><span class="metric-label">${escapeHtml(label)}</span><strong>${formatNumber(value)}</strong><span class="metric-foot">${escapeHtml(foot)}</span></article>`).join("");
  renderTrend(data.trend);
  renderRisk(data.risk);
  renderEventRows($("#overview-events"), data.recent, true);
  const system = data.system;
  $("#system-strip").innerHTML = [
    ["工作区", system.workspace], ["上游", system.upstream], ["检测配置", system.detector_configuration],
    ["PII", system.pii_mode], ["严格模式", system.strict_mode ? "开启" : "关闭"], ["管理面板", system.local_only ? "仅本机" : "远程绑定"],
  ].map(([label, value]) => `<span class="system-item">${escapeHtml(label)}<strong>${escapeHtml(value)}</strong></span>`).join("");
  state.loaded.add("overview");
}

function renderPrivacyControl() {
  const control = state.privacyControl;
  if (!control) return;
  const available = Boolean(control.available);
  const effective = Boolean(control.effective);
  const input = $("#privacy-control-enabled");
  const container = $("#privacy-control");
  input.checked = effective;
  input.disabled = !available;
  container.classList.toggle("is-enabled", effective);
  container.classList.toggle("is-bypass", available && !effective);
  container.classList.toggle("is-unavailable", !available);
  $("#privacy-control-status").textContent = !available ? "不可用" : effective ? "保护已开启" : "旁路模式";
  $("#privacy-control-description").textContent = !available
    ? control.unavailable_reason === "no_detector_configuration"
      ? "没有可用的检测配置，APG 全局保护暂时无法启用。"
      : "请先选择并启用可用的上游配置。"
    : "一键开启或关闭 APG 保护。";
  $("#privacy-control-configuration").textContent = control.active_detector_configuration_name
    ? `当前检测配置：${control.active_detector_configuration_name}`
    : "未选择检测配置";
}

async function refreshPrivacyControl() {
  state.privacyControl = await api("/privacy-control");
  renderPrivacyControl();
}

async function updatePrivacyControl(event) {
  const input = event.currentTarget;
  input.disabled = true;
  try {
    state.privacyControl = await api("/privacy-control", {
      method: "PUT",
      body: JSON.stringify({enabled: input.checked}),
    });
    renderPrivacyControl();
    toast(state.privacyControl.effective ? "APG 全局保护已开启" : "APG 已切换为旁路模式");
  } catch (error) {
    await refreshPrivacyControl().catch(() => {});
    handleError(error);
  }
}

function renderUpstreamConfiguration() {
  if (!state.upstream) return;
  const configured = Boolean(state.upstream.configured);
  const editing = !configured || state.upstreamEditing;
  const profiles = state.upstream.profiles || [];
  if (!profiles.some((profile) => profile.id === state.upstreamSelectedProfileId)) {
    state.upstreamSelectedProfileId = state.upstream.active_profile_id || profiles[0]?.id || "";
  }
  if (!configured && !state.upstreamEditingProfileId && state.upstream.active_profile_id) {
    state.upstreamEditingProfileId = state.upstream.active_profile_id;
  }
  const selected = selectedUpstreamProfile();
  const setup = $("#upstream-setup");
  setup.classList.remove("is-hidden");
  setup.classList.toggle("needs-setup", !configured);
  setup.classList.toggle("is-editing", editing);
  $("#upstream-status").textContent = configured ? "已配置" : "需要配置";
  $("#upstream-status").classList.toggle("is-active", configured);
  $("#upstream-description").textContent = configured
    ? "配置已在本机保存，密钥不会回显。"
    : "填写 Base URL 和 API Key。";
  $("#upstream-base-url").textContent = state.upstream.base_url || "待填写";
  $("#upstream-protocol-value").textContent = UPSTREAM_PROTOCOL_LABELS[state.upstream.protocol] || "待选择";
  $("#upstream-profile-select").innerHTML = profiles.length
    ? profiles.map((profile) => `<option value="${escapeHtml(profile.id)}"${profile.id === state.upstreamSelectedProfileId ? " selected" : ""}>${escapeHtml(uiText(`${profile.name}${profile.active ? "（当前）" : ""}`))}</option>`).join("")
    : '<option value="">暂无配置</option>';
  $("#activate-upstream-profile").disabled = !selected || selected.active;
  $("#delete-upstream-profile").disabled = !selected || !selected.persisted;
  const editingProfile = state.upstreamEditingProfileId
    ? profiles.find((profile) => profile.id === state.upstreamEditingProfileId)
    : null;
  const showingDefaults = editing && editingProfile && !editingProfile.persisted;
  const nameInput = $("#upstream-profile-name");
  const protocolInput = $("#upstream-protocol");
  const baseUrlInput = $("#upstream-base-url-input");
  nameInput.value = editing && !showingDefaults ? (editingProfile?.name || "") : "";
  nameInput.placeholder = showingDefaults ? (editingProfile.name || "例如：Anthropic 生产环境") : "例如：Anthropic 生产环境";
  protocolInput.value = editing && !showingDefaults ? (editingProfile?.protocol || "") : "";
  baseUrlInput.value = editing && !showingDefaults ? (editingProfile?.base_url || "") : "";
  baseUrlInput.placeholder = showingDefaults ? (editingProfile.base_url || "https://api.example.com/v1") : "https://api.example.com/v1";
  $("#upstream-key-form").classList.toggle("is-hidden", !editing);
  $("#edit-upstream-key").classList.toggle("is-hidden", !configured || editing);
  $("#cancel-upstream-key").classList.toggle("is-hidden", !configured);
}

async function saveUpstreamApiKey(event) {
  event.preventDefault();
  const baseUrlInput = $("#upstream-base-url-input");
  const name = $("#upstream-profile-name").value.trim();
  const protocol = $("#upstream-protocol").value;
  const input = $("#upstream-api-key");
  const baseUrl = baseUrlInput.value.trim().replace(/\/+$/, "");
  const apiKey = input.value.trim();
  if (!name) {
    $("#upstream-key-error").textContent = "请输入配置名称。";
    $("#upstream-profile-name").focus();
    return;
  }
  if (!Object.hasOwn(UPSTREAM_PROTOCOL_LABELS, protocol)) {
    $("#upstream-key-error").textContent = "请选择上游 API 格式。";
    $("#upstream-protocol").focus();
    return;
  }
  let parsedBaseUrl = null;
  try { parsedBaseUrl = new URL(baseUrl); } catch (_) {}
  if (!parsedBaseUrl || !["http:", "https:"].includes(parsedBaseUrl.protocol) || parsedBaseUrl.username || parsedBaseUrl.password || parsedBaseUrl.search || parsedBaseUrl.hash) {
    $("#upstream-key-error").textContent = "请输入不含凭据、查询参数或片段的完整 HTTP(S) Base URL。";
    baseUrlInput.focus();
    return;
  }
  const editingProfile = (state.upstream?.profiles || []).find((profile) => profile.id === state.upstreamEditingProfileId);
  if (!apiKey && !editingProfile?.has_api_key) {
    $("#upstream-key-error").textContent = "请输入上游 API Key。";
    return;
  }
  const button = $("#save-upstream-key");
  button.disabled = true;
  $("#upstream-key-error").textContent = "";
  try {
    state.upstream = await api("/upstream-configuration", {
      method: "PUT",
      body: JSON.stringify({profile_id: state.upstreamEditingProfileId, name, protocol, base_url: baseUrl, api_key: apiKey}),
    });
    input.value = "";
    state.upstreamEditing = false;
    state.upstreamEditingProfileId = "";
    state.upstreamSelectedProfileId = state.upstream.active_profile_id || "";
    renderUpstreamConfiguration();
    await refreshPrivacyControl();
    toast(state.upstream.persistent ? "上游连接配置已安全保存并启用" : "上游连接配置已在当前进程中启用");
  } catch (error) {
    $("#upstream-key-error").textContent = error.message || "保存失败。";
  } finally {
    button.disabled = false;
  }
}

function selectedUpstreamProfile() {
  return (state.upstream?.profiles || []).find((profile) => profile.id === state.upstreamSelectedProfileId) || null;
}

async function activateSelectedUpstreamProfile() {
  const profile = selectedUpstreamProfile();
  if (!profile || profile.active) return;
  state.upstream = await api(`/upstream-configuration/${encodeURIComponent(profile.id)}/activate`, {method: "POST"});
  state.upstreamSelectedProfileId = state.upstream.active_profile_id || "";
  renderUpstreamConfiguration();
  await refreshPrivacyControl();
  toast(`已启用上游配置：${profile.name}`);
}

async function deleteSelectedUpstreamProfile() {
  const profile = selectedUpstreamProfile();
  if (!profile) return;
  state.upstream = await api(`/upstream-configuration/${encodeURIComponent(profile.id)}`, {method: "DELETE"});
  state.upstreamSelectedProfileId = state.upstream.active_profile_id || state.upstream.profiles?.[0]?.id || "";
  state.upstreamEditing = !state.upstream.profiles?.length;
  state.upstreamEditingProfileId = "";
  renderUpstreamConfiguration();
  await refreshPrivacyControl();
  toast(`已删除上游配置：${profile.name}`);
}

function renderConnection() {
  if (!state.connection) return;
  $("#agent-openai-base-url").value = location.origin + (state.connection.protocols.openai?.base_path || "");
  $("#agent-anthropic-base-url").value = location.origin + (state.connection.protocols.anthropic?.base_path || "");
  $("#agent-api-key").value = state.connection.api_key || "";
  $("#agent-api-key").placeholder = state.connection.api_key ? "" : "未配置本地 API Key";
  $$('[data-copy-connection]').forEach((button) => {
    const targets = {
      "api-key": $("#agent-api-key"),
      "openai-base-url": $("#agent-openai-base-url"),
      "anthropic-base-url": $("#agent-anthropic-base-url"),
    };
    const target = targets[button.dataset.copyConnection];
    button.disabled = !target.value;
  });
  $$("[data-copy-agent-setup]").forEach((button) => {
    button.disabled = !state.connection.api_key || !state.connection.protocols[button.dataset.agentProtocol];
  });
}

function toggleAgentKeyVisibility() {
  const input = $("#agent-api-key");
  const revealed = input.type === "password";
  input.type = revealed ? "text" : "password";
  setVisibilityButton($("#toggle-agent-key"), revealed, "显示 API Key", "隐藏 API Key");
}

async function regenerateAgentApiKey() {
  state.connection = await api("/connection/api-key", {method: "POST"});
  renderConnection();
  $("#agent-api-key").type = "text";
  syncVisibilityButtons();
  toast("API Key 已重新生成");
}

function setVisibilityButton(button, revealed, showLabel, hideLabel) {
  if (!button) return;
  const actionLabel = revealed ? hideLabel : showLabel;
  button.innerHTML = iconMarkup(revealed ? "eye-off" : "eye");
  button.classList.toggle("is-active", revealed);
  button.setAttribute("aria-pressed", String(revealed));
  button.setAttribute("aria-label", actionLabel);
  button.title = actionLabel;
  renderIcons(button);
}

function syncVisibilityButtons() {
  setVisibilityButton($("#toggle-agent-key"), $("#agent-api-key").type === "text", "显示 API Key", "隐藏 API Key");
  setVisibilityButton($("#audit-show-raw"), state.auditShowRaw, "显示敏感原文", "隐藏敏感原文");
  setVisibilityButton($("#protected-show-raw"), state.protectedShowRaw, "显示受保护值原文", "隐藏受保护值原文");
}

async function copyConnectionValue(kind) {
  const inputs = {
    "api-key": $("#agent-api-key"),
    "openai-base-url": $("#agent-openai-base-url"),
    "anthropic-base-url": $("#agent-anthropic-base-url"),
  };
  const input = inputs[kind];
  if (!input.value) return;
  await copyText(input.value);
  toast(kind === "api-key" ? "API Key 已复制" : "Base URL 已复制");
}

async function copyAgentSetup(kind) {
  const setup = agentSetupText(kind);
  if (!setup) return;
  await copyText(setup);
  const labels = {
    claude: "Claude Code 环境变量已复制",
    opencode: "OpenCode 配置已复制",
    "codex-config": "Codex 配置已复制",
    "codex-key": "Codex 密钥变量已复制",
  };
  toast(labels[kind] || "接入配置已复制");
}

function agentSetupText(kind) {
  if (!state.connection?.api_key) return "";
  const key = state.connection.api_key;
  const openaiBaseUrl = location.origin + (state.connection.protocols?.openai?.base_path || "");
  const anthropicBaseUrl = location.origin + (state.connection.protocols?.anthropic?.base_path || "");
  if (kind === "claude" && state.connection.protocols?.anthropic) {
    return [
      `export ANTHROPIC_BASE_URL=${shellQuote(anthropicBaseUrl)}`,
      `export ANTHROPIC_API_KEY=${shellQuote(key)}`,
      `export ANTHROPIC_AUTH_TOKEN=${shellQuote(key)}`,
      "export ANTHROPIC_MODEL=deepseek-v4-pro[1m]",
      "export ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-v4-pro[1m]",
      "export ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-v4-pro[1m]",
      "export ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-v4-flash",
      "export CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash",
      "export CLAUDE_CODE_EFFORT_LEVEL=max",
    ].join("\n");
  }
  if (kind === "opencode" && state.connection.protocols?.openai) {
    return JSON.stringify({
      $schema: "https://opencode.ai/config.json",
      model: "apg/deepseek-v4-flash",
      provider: {
        apg: {
          npm: "@ai-sdk/openai-compatible",
          name: "APG",
          options: {baseURL: openaiBaseUrl, apiKey: key},
          models: {
            "deepseek-v4-flash": {
              name: "DeepSeek through APG",
              tool_call: true,
            },
          },
        },
      },
    }, null, 2);
  }
  if (kind === "codex-config" && state.connection.protocols?.openai) {
    return [
      'model = "deepseek-v4-pro[1m]"',
      'model_provider = "apg"',
      "",
      "[model_providers.apg]",
      'name = "APG"',
      `base_url = ${JSON.stringify(openaiBaseUrl)}`,
      'env_key = "APG_API_KEY"',
      'wire_api = "responses"',
    ].join("\n");
  }
  if (kind === "codex-key" && state.connection.protocols?.openai) {
    return `export APG_API_KEY=${shellQuote(key)}`;
  }
  return "";
}

function openAgentGuide(kind) {
  const guides = {
    claude: {
      name: "Claude Code",
      summary: "通过 APG 的 Anthropic Messages 接口运行 Claude Code。环境变量只影响当前终端会话。",
      steps: [
        ["准备 APG", "确认上游模型配置和 APG 总开关均已启用。"],
        ["复制环境变量", "点击 Claude Code 卡片上的复制按钮，将生成的全部环境变量粘贴到准备运行 Claude Code 的同一个终端。"],
        ["启动 Claude Code", "在该终端进入项目目录，然后启动 Claude Code。", "cd /path/to/project\nclaude"],
        ["确认连接", "发送一条测试消息；请求应出现在 APG 的审计记录中。"],
      ],
      note: "关闭终端后这些环境变量会失效；如需长期使用，可将它们保存到受信任的本机 Shell 配置中。",
    },
    opencode: {
      name: "OpenCode",
      summary: "通过 APG 的 OpenAI Chat Completions 接口运行 OpenCode。配置可以按用户全局保存，也可以只用于单个项目。",
      steps: [
        ["准备 APG", "确认上游模型配置和 APG 总开关均已启用。"],
        ["复制配置", "点击 OpenCode 卡片上的复制按钮，复制完整 JSON 配置。"],
        ["写入配置文件", "合并到全局配置 ~/.config/opencode/opencode.json，或项目根目录的 opencode.json；不要覆盖文件中已有的其他设置。"],
        ["启动并选择模型", "在项目目录启动 OpenCode，并使用配置中的 APG 模型。", "cd /path/to/project\nopencode"],
        ["确认连接", "发送一条测试消息；请求应出现在 APG 的审计记录中。"],
      ],
      note: "复制的配置包含当前本地 API Key，请不要提交到 Git 或粘贴到不受信任的位置。",
    },
    codex: {
      name: "Codex",
      summary: "通过 APG 的 OpenAI Responses 接口运行 Codex。Codex 配置与 API Key 分开保存。",
      steps: [
        ["准备 APG", "确认上游模型配置和 APG 总开关均已启用。"],
        ["复制 Codex 配置", "点击 Codex 卡片上的复制按钮，将 TOML 内容合并到 ~/.codex/config.toml。"],
        ["设置本地 API Key", "点击钥匙按钮复制密钥变量，然后粘贴到准备运行 Codex 的终端。"],
        ["启动 Codex", "在同一个终端进入项目目录，然后启动 Codex。", "cd /path/to/project\ncodex"],
        ["确认连接", "发送一条测试消息；请求应出现在 APG 的审计记录中。"],
      ],
      note: "密钥环境变量只影响当前终端会话。Codex 通过 env_key 读取它，密钥本身不会写入 config.toml。",
    },
  };
  const guide = guides[kind];
  if (!guide) return;
  const text = (value) => escapeHtml(uiText(value));
  state.agentGuide = kind;
  $("#agent-guide-title").textContent = uiText(`${guide.name} 详细使用方法`);
  $("#agent-guide-body").innerHTML = `
    <p class="agent-guide-summary">${text(guide.summary)}</p>
    <ol class="agent-guide-steps">
      ${guide.steps.map(([title, description, command], index) => `
        <li>
          <span class="agent-guide-step-number">${index + 1}</span>
          <div class="agent-guide-step-content">
            <strong>${text(title)}</strong>
            <p>${text(description)}</p>
            ${command ? `<pre class="agent-guide-command">${escapeHtml(command)}</pre>` : ""}
          </div>
        </li>
      `).join("")}
    </ol>
    <p class="agent-guide-note">${text(guide.note)}</p>`;
  if (!$("#agent-guide-modal").open) $("#agent-guide-modal").showModal();
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
  } catch (_) {
    const input = document.createElement("textarea");
    input.value = value;
    input.setAttribute("readonly", "");
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.appendChild(input);
    input.select();
    document.execCommand("copy");
    input.remove();
  }
}

function renderTrend(trend) {
  const max = Math.max(1, ...trend.map((item) => item.count));
  $("#trend-chart").innerHTML = trend.map((item) => {
    const date = new Date(item.day + "T00:00:00");
    const label = new Intl.DateTimeFormat(displayLocale(), {weekday: "short"}).format(date);
    const heightClass = item.count ? Math.max(1, Math.ceil(item.count / max * 10)) : 0;
    return `<div class="bar-column"><strong>${formatNumber(item.count)}</strong><div class="bar bar-h-${heightClass}"></div><span>${escapeHtml(label)}</span></div>`;
  }).join("");
}

function renderRisk(risk) {
  const labels = {critical: "严重", high: "高", medium: "中", low: "低"};
  const max = Math.max(1, ...Object.values(risk));
  $("#risk-breakdown").innerHTML = Object.entries(labels).map(([key, label]) => {
    const widthClass = risk[key] ? Math.max(1, Math.ceil(risk[key] / max * 10)) : 0;
    return `<div class="risk-row"><span>${label}</span><div class="risk-track"><div class="risk-fill ${key} risk-w-${widthClass}"></div></div><b>${formatNumber(risk[key] || 0)}</b></div>`;
  }).join("");
}

async function loadAudit() {
  const direction = state.auditDirection;
  const includeRaw = state.auditShowRaw;
  const loadVersion = ++state.auditLoadVersion;
  const params = new URLSearchParams({limit: "250"});
  params.set("direction", direction);
  if (includeRaw) params.set("include_raw", "true");
  for (const [key, id] of [["query","audit-query"],["risk","audit-risk"],["endpoint","audit-endpoint"]]) {
    const value = $("#" + id).value;
    if (value) params.set(key, value);
  }
  const data = await api("/audit/operations?" + params);
  if (loadVersion !== state.auditLoadVersion || direction !== state.auditDirection || includeRaw !== state.auditShowRaw) return;
  state.audit = data;
  populateSelect($("#audit-endpoint"), data.filters.endpoints, "全部端点");
  renderAuditOperationRows($("#audit-events"), data.operations, direction);
  const label = direction === "replacement" ? "替换" : "还原";
  const occurrenceNote = data.occurrence_count !== data.count ? ` · ${formatNumber(data.occurrence_count)} 次出现` : "";
  $("#audit-count").textContent = `${formatNumber(data.count)} 条${label}记录${occurrenceNote}`;
  $("#audit-window-note").textContent = data.truncated ? `当前显示最近 ${formatNumber(data.operations.length)} 条` : "";
  $("#audit-map-heading").textContent = direction === "replacement" ? "替换内容" : "还原内容";
  $("#audit-result-heading").textContent = direction === "replacement" ? "检测与动作" : "工具与结果";
  $("#audit-empty").classList.toggle("is-hidden", data.count !== 0);
  $(".audit-table-wrap").classList.toggle("is-hidden", data.count === 0);
  state.loaded.add("audit");
}

function setAuditDirection(direction) {
  if (!["replacement", "materialization"].includes(direction) || state.auditDirection === direction) return;
  state.auditDirection = direction;
  state.audit = null;
  state.auditLoadVersion += 1;
  $("#audit-endpoint").value = "";
  $$('[data-audit-direction]').forEach((button) => {
    const selected = button.dataset.auditDirection === direction;
    button.classList.toggle("is-active", selected);
    button.setAttribute("aria-selected", String(selected));
  });
  $("#audit-events").replaceChildren();
  loadAudit().catch(handleError);
}

function renderAuditOperationRows(target, operations, direction) {
  if (!operations.length) {
    target.innerHTML = `<tr><td colspan="6" class="muted">暂无${direction === "replacement" ? "替换" : "还原"}记录</td></tr>`;
    return;
  }
  target.innerHTML = operations.map((operation) => {
    const original = operation.original === null
      ? `<span class="operation-value-cleared">原文已清除</span>`
      : `<code class="operation-value ${operation.original === "***" ? "is-masked" : ""}">${escapeHtml(operation.original)}</code>`;
    const representation = `<code class="operation-value representation">${escapeHtml(operation.representation)}</code>`;
    const mapping = direction === "replacement"
      ? `${original}<span class="operation-arrow" aria-label="替换为">${iconMarkup("arrow-right")}</span>${representation}`
      : `${representation}<span class="operation-arrow" aria-label="还原为">${iconMarkup("arrow-right")}</span>${original}`;
    const failed = operation.direction === "materialization_failed";
    const handling = direction === "replacement"
      ? `<strong>${escapeHtml(operation.action || "替换")}</strong>${operation.detector ? `<span class="muted">${escapeHtml(operation.detector)}</span>` : ""}`
      : `<strong>${escapeHtml(operation.tool_name || "本地工具")}</strong><span class="muted">${escapeHtml(operation.sink || "-")}</span><span class="badge ${failed ? "red" : "green"}">${escapeHtml(failed ? "未还原" : "已还原")}</span><code class="audit-result-code">${escapeHtml(operation.result_code || "-")}</code>`;
    const labels = {
      time: uiText("时间"),
      mapping: uiText(direction === "replacement" ? "替换内容" : "还原内容"),
      type: uiText("类型"),
      handling: uiText(direction === "replacement" ? "检测与动作" : "工具与结果"),
      count: uiText("次数"),
      context: uiText("上下文"),
    };
    return `<tr class="audit-operation-row ${failed ? "has-failure" : ""}"><td data-label="${escapeHtml(labels.time)}">${formatDateTime(operation.timestamp)}</td><td class="audit-map-cell" data-label="${escapeHtml(labels.mapping)}"><div class="operation-map audit-list-map">${mapping}</div><div class="operation-metadata"><span class="mapping-id">${escapeHtml(operation.protected_value_id)}</span>${operation.value_state !== "active" ? `<span class="operation-state-inline">${escapeHtml(valueStateLabel(operation.value_state))}</span>` : ""}</div></td><td class="audit-type" data-label="${escapeHtml(labels.type)}"><strong>${escapeHtml(operation.subtype || operation.kind || "-")}</strong><span class="badge ${escapeHtml(operation.risk || "low")}">${escapeHtml(operation.risk || "low")}</span></td><td class="audit-handling" data-label="${escapeHtml(labels.handling)}">${handling}</td><td data-label="${escapeHtml(labels.count)}"><strong>${formatNumber(operation.occurrence_count)}</strong></td><td class="audit-context" data-label="${escapeHtml(labels.context)}"><code>${escapeHtml(operation.endpoint || "-")}</code><span>${escapeHtml(operation.session || "-")}</span><code>${escapeHtml(operation.request_id)}</code></td></tr>`;
  }).join("");
  renderIcons(target);
}

function renderAuditRequestRows(target, requests) {
  if (!requests.length) {
    target.innerHTML = `<tr><td colspan="7" class="muted">暂无匹配请求</td></tr>`;
    return;
  }
  target.innerHTML = requests.map((request) => {
    const replacement = formatOperationCount(request.replacement_count, request.replacement_unique_count);
    const materialization = formatOperationCount(request.materialization_count, request.materialization_unique_count);
    const failure = request.materialization_failed_count ? `<span class="operation-failure">${formatNumber(request.materialization_failed_count)} 未还原</span>` : "";
    return `<tr><td>${formatDateTime(request.timestamp)}</td><td>${replacement}</td><td>${materialization}${failure}</td><td><span class="badge ${statusClass(request.status)}">${escapeHtml(auditStatusLabel(request.status))}</span></td><td class="mono">${escapeHtml(request.endpoint || "-")}</td><td>${escapeHtml(request.session || "-")}</td><td><button class="row-action icon-row-button" type="button" data-audit-request-id="${escapeHtml(request.request_id)}" aria-label="查看请求详情" title="查看请求详情">${iconMarkup("search")}</button></td></tr>`;
  }).join("");
  renderIcons(target);
  $$('[data-audit-request-id]', target).forEach((button) => button.addEventListener("click", () => openAuditRequestDetail(button.dataset.auditRequestId).catch(handleError)));
}

function formatOperationCount(count, uniqueCount) {
  if (!count) return `<span class="muted">无</span>`;
  const unique = Number(uniqueCount || 0);
  return `<strong class="operation-count">${formatNumber(count)} 次</strong>${unique ? `<span class="muted">${formatNumber(unique)} 项</span>` : ""}`;
}

async function openAuditRequestDetail(requestId) {
  const includeRaw = state.auditShowRaw;
  state.auditDetailRequestId = requestId;
  $("#modal-kicker").textContent = "AGENT REQUEST";
  $("#modal-title").textContent = requestId;
  $("#modal-body").innerHTML = `<div class="detail-loading">正在读取安全审计详情…</div>`;
  if (!$("#detail-modal").open) $("#detail-modal").showModal();
  const detail = await api(`/audit/requests/${encodeURIComponent(requestId)}?include_raw=${includeRaw}`);
  if (!$("#detail-modal").open || state.auditDetailRequestId !== requestId || state.auditShowRaw !== includeRaw) return;
  state.auditDetail = detail;
  renderAuditRequestDetail(detail);
}

function renderAuditRequestDetail(detail) {
  const status = detail.termination || (detail.status_code && detail.status_code >= 400 ? "error" : "completed");
  const fields = [
    ["时间", formatDateTime(detail.timestamp)], ["端点", detail.endpoint || "-"], ["请求", detail.request_id],
    ["会话", detail.session || "-"], ["状态", auditStatusLabel(status)], ["原文", detail.raw_values_included ? "临时显示" : "已隐藏"],
  ];
  let content = `<dl class="detail-grid">${fields.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}</dl>`;
  if (detail.legacy_summary_only) {
    content += `<div class="audit-legacy-note"><strong>无逐项详情</strong><span>该请求来自旧版安全审计，只保留了汇总记录。</span></div>`;
  } else {
    content += renderOperationSection("上行替换", "UPSTREAM REPLACEMENTS", detail.replacements, "replacement");
    content += renderOperationSection("本地还原", "LOCAL MATERIALIZATIONS", detail.materializations, "materialization");
  }
  if (detail.materialization_failures.length || Object.keys(detail.failure_reasons || {}).length || detail.parse_errors) {
    content += renderAuditFailureSection(detail);
  }
  if (detail.details_truncated) {
    content += `<div class="audit-truncated-note">另有 ${formatNumber(detail.omitted_count)} 项操作仅计入总数。</div>`;
  }
  $("#modal-body").innerHTML = content;
  renderIcons($("#modal-body"));
}

function renderOperationSection(title, kicker, operations, direction) {
  const rows = operations.length
    ? operations.map((operation) => renderAuditOperation(operation, direction)).join("")
    : `<div class="audit-operation-empty">本次请求没有${escapeHtml(title)}。</div>`;
  return `<section class="audit-operation-section"><div class="audit-operation-heading"><div><p class="section-kicker">${escapeHtml(kicker)}</p><h3>${escapeHtml(title)}</h3></div><span>${formatNumber(operations.length)} 项</span></div><div class="audit-operation-list">${rows}</div></section>`;
}

function renderAuditOperation(operation, direction) {
  const original = operation.original === null
    ? `<span class="operation-value-cleared">原文已清除</span>`
    : `<code class="operation-value ${operation.original === "***" ? "is-masked" : ""}">${escapeHtml(operation.original)}</code>`;
  const representation = `<code class="operation-value representation">${escapeHtml(operation.representation)}</code>`;
  const mapping = direction === "replacement"
    ? `${original}<span class="operation-arrow" aria-label="替换为">${iconMarkup("arrow-right")}</span>${representation}`
    : `${representation}<span class="operation-arrow" aria-label="还原为">${iconMarkup("arrow-right")}</span>${original}`;
  const metadata = [
    operation.protected_value_id,
    operation.subtype || operation.kind,
    operation.risk,
    operation.detector,
    operation.tool_name ? `工具 ${operation.tool_name}` : null,
    operation.sink,
    operation.result_code,
    `${formatNumber(operation.occurrence_count)} 次`,
  ].filter(Boolean);
  return `<article class="audit-operation"><div class="operation-map">${mapping}</div><div class="operation-metadata">${metadata.map((item, index) => `<span class="${index === 0 ? "mapping-id" : ""}">${escapeHtml(item)}</span>`).join("")}</div>${operation.value_state !== "active" ? `<span class="operation-state">${escapeHtml(valueStateLabel(operation.value_state))}</span>` : ""}</article>`;
}

function renderAuditFailureSection(detail) {
  const failures = detail.materialization_failures.map((operation) => renderAuditOperation(operation, "materialization"));
  const reasons = Object.entries(detail.failure_reasons || {}).map(([code, count]) => `<div class="failure-reason"><code>${escapeHtml(code)}</code><strong>${formatNumber(count)} 次</strong></div>`);
  if (detail.parse_errors) reasons.push(`<div class="failure-reason"><code>STREAM_PARSE_ERROR</code><strong>${formatNumber(detail.parse_errors)} 次</strong></div>`);
  return `<section class="audit-operation-section failure-section"><div class="audit-operation-heading"><div><p class="section-kicker">NOT MATERIALIZED</p><h3>未还原与协议错误</h3></div></div><div class="audit-operation-list">${failures.join("")}${reasons.join("")}</div></section>`;
}

function handleRawVisibilityChange() {
  if (!state.auditShowRaw) {
    confirmAction("显示敏感原文", "原文只从当前仍有效的本地映射临时读取。请确认屏幕与浏览器环境可信。", async () => {
      state.auditShowRaw = true;
      state.audit = null;
      state.auditLoadVersion += 1;
      setVisibilityButton($("#audit-show-raw"), true, "显示敏感原文", "隐藏敏感原文");
      $("#audit-events").replaceChildren();
      await loadAudit();
      const requestId = state.auditDetailRequestId;
      if (requestId) await openAuditRequestDetail(requestId);
    });
    return;
  }
  disableRawVisibility().catch(handleError);
}

async function disableRawVisibility() {
  const requestId = state.auditDetailRequestId;
  state.auditShowRaw = false;
  state.audit = null;
  state.auditLoadVersion += 1;
  setVisibilityButton($("#audit-show-raw"), false, "显示敏感原文", "隐藏敏感原文");
  $("#audit-events").replaceChildren();
  clearAuditDetail(true, false);
  await loadAudit();
  if (requestId && $("#detail-modal").open) await openAuditRequestDetail(requestId);
}

function resetRawVisibility() {
  state.auditShowRaw = false;
  state.audit = null;
  state.auditLoadVersion += 1;
  state.auditDetail = null;
  state.auditDetailRequestId = "";
  state.protectedShowRaw = false;
  state.protectedLoadVersion += 1;
  state.protected = null;
  setVisibilityButton($("#audit-show-raw"), false, "显示敏感原文", "隐藏敏感原文");
  setVisibilityButton($("#protected-show-raw"), false, "显示受保护值原文", "隐藏受保护值原文");
  const modal = $("#detail-modal");
  if (modal?.open) modal.close();
  const body = $("#modal-body");
  if (body) body.replaceChildren();
  const events = $("#audit-events");
  if (events) events.replaceChildren();
  const protectedValues = $("#protected-values");
  if (protectedValues) protectedValues.replaceChildren();
}

function clearAuditDetail(clearBody = true, clearRequest = true) {
  state.auditDetail = null;
  if (clearRequest) state.auditDetailRequestId = "";
  if (clearBody) $("#modal-body").replaceChildren();
}

function renderEventRows(target, events, compact) {
  if (!events.length) {
    target.innerHTML = `<tr><td colspan="7" class="muted">暂无记录</td></tr>`;
    return;
  }
  target.innerHTML = events.map((event) => {
    const primary = event.detections?.[0] || {};
    const risk = highestRisk(event.detections || []);
    const type = primary.subtype || primary.type || event.action || event.phase || "event";
    const action = primary.action || event.action || event.termination || "recorded";
    const status = event.parse_errors ? "error" : event.termination || (event.status ? String(event.status) : "safe");
    if (compact) return `<tr><td>${formatTime(event.timestamp)}</td><td><span class="badge ${risk}">${escapeHtml(type)}</span></td><td>${escapeHtml(action)}</td><td class="mono">${escapeHtml(event.endpoint || "-")}</td><td><span class="badge ${statusClass(status)}">${escapeHtml(status)}</span></td></tr>`;
    return `<tr><td>${formatDateTime(event.timestamp)}</td><td>${escapeHtml(event.phase)}</td><td><span class="badge ${risk}">${escapeHtml(type)}</span>${event.detection_count > 1 ? `<span class="muted"> +${event.detection_count - 1}</span>` : ""}</td><td>${escapeHtml(action)}</td><td class="mono">${escapeHtml(event.endpoint || "-")}</td><td>${escapeHtml(event.session || "-")}</td><td><button class="row-action icon-row-button" type="button" data-event-id="${escapeHtml(event.id)}" aria-label="查看事件详情" title="查看事件详情">${iconMarkup("search")}</button></td></tr>`;
  }).join("");
  if (!compact) renderIcons(target);
  if (!compact) $$('[data-event-id]', target).forEach((button) => button.addEventListener("click", () => openEventDetail(events.find((event) => event.id === button.dataset.eventId))));
}

function openEventDetail(event) {
  $("#modal-kicker").textContent = "AUDIT EVENT";
  $("#modal-title").textContent = event.id;
  const fields = [["时间", formatDateTime(event.timestamp)],["阶段", event.phase],["端点", event.endpoint || "-"],["请求", event.request_id || "-"],["会话", event.session],["状态", event.termination || event.status || "recorded"]];
  $("#modal-body").innerHTML = `<dl class="detail-grid">${fields.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}</dl><div class="detail-detections"><p class="section-kicker">SAFE DETECTIONS</p>${event.detections.length ? `<div class="finding-list">${event.detections.map((item) => `<div class="finding-row"><span>${escapeHtml(item.subtype || item.type)}</span><strong>${escapeHtml(item.action || item.result_code || "recorded")}</strong></div>`).join("")}</div>` : `<span class="muted">该事件没有检测项。</span>`}</div>`;
  $("#detail-modal").showModal();
}

async function loadProtected() {
  const kind = $("#protected-kind").value;
  const includeRaw = state.protectedShowRaw;
  const loadVersion = ++state.protectedLoadVersion;
  const params = new URLSearchParams();
  if (kind) params.set("kind", kind);
  if (includeRaw) params.set("include_raw", "true");
  const data = await api("/protected-values" + (params.size ? "?" + params : ""));
  if (loadVersion !== state.protectedLoadVersion || includeRaw !== state.protectedShowRaw || kind !== $("#protected-kind").value) return;
  state.protected = data;
  renderMappingRetention(data.retention_policy);
  const summaries = [["当前清单",data.counts.total],["活跃",data.counts.active],["Secret",data.kinds.secret || 0],["PII / Path",(data.kinds.pii || 0) + (data.kinds.path || 0)]];
  $("#protected-summary").innerHTML = summaries.map(([label, value]) => `<div class="summary-cell"><span>${escapeHtml(label)}</span><strong>${formatNumber(value)}</strong></div>`).join("");
  const target = $("#protected-values");
  target.innerHTML = data.records.length ? data.records.map((record) => {
    const original = record.original === null
      ? `<span class="protected-original-cleared">原文已清除</span>`
      : `<code class="protected-original ${record.original === "***" ? "is-masked" : ""}">${escapeHtml(record.original)}</code>`;
    const labels = ["标识", "原文", "分类", "作用域", "状态", "最后使用", "到期时间", "操作"].map(uiText);
    return `<tr><td data-label="${escapeHtml(labels[0])}"><span class="protected-cell-stack"><strong>${escapeHtml(record.label)}</strong><span class="muted mono">${escapeHtml(record.id.slice(-6))}</span></span></td><td class="protected-original-cell" data-label="${escapeHtml(labels[1])}">${original}</td><td data-label="${escapeHtml(labels[2])}"><span class="protected-cell-stack">${escapeHtml(record.subtype)}<span class="muted">${escapeHtml(record.kind)}</span></span></td><td data-label="${escapeHtml(labels[3])}"><span class="protected-cell-stack">${escapeHtml(record.scope)}<span class="muted">${escapeHtml(record.session)}</span></span></td><td data-label="${escapeHtml(labels[4])}"><span class="badge ${record.display_state}">${stateLabel(record.display_state)}</span></td><td data-label="${escapeHtml(labels[5])}">${formatRelative(record.last_seen_at)}</td><td data-label="${escapeHtml(labels[6])}">${record.auto_expires ? formatRelative(record.expires_at) : "不自动过期"}</td><td data-label="${escapeHtml(labels[7])}">${record.display_state === "active" ? `<button class="row-action danger icon-row-button" type="button" data-revoke="${escapeHtml(record.id)}" aria-label="撤销受保护值 ${escapeHtml(record.label)}" title="撤销受保护值">${iconMarkup("ban")}</button>` : ""}</td></tr>`;
  }).join("") : `<tr><td colspan="8" class="muted">没有受保护值记录</td></tr>`;
  renderIcons(target);
  $$('[data-revoke]', target).forEach((button) => button.addEventListener("click", () => {
    const record = data.records.find((item) => item.id === button.dataset.revoke);
    confirmAction("撤销受保护值", `${record.label} 将立即失效，之后的占位符无法还原。`, () => revokeProtected(record.id));
  }));
  state.loaded.add("protected");
}

function handleProtectedRawVisibilityChange() {
  if (!state.protectedShowRaw) {
    confirmAction("显示受保护值原文", "原文只会从当前仍有效的本地映射临时读取。请确认屏幕与浏览器环境可信。", async () => {
      state.protectedShowRaw = true;
      state.protected = null;
      state.protectedLoadVersion += 1;
      setVisibilityButton($("#protected-show-raw"), true, "显示受保护值原文", "隐藏受保护值原文");
      $("#protected-values").replaceChildren();
      await loadProtected();
    });
    return;
  }
  disableProtectedRawVisibility().catch(handleError);
}

async function disableProtectedRawVisibility() {
  state.protectedShowRaw = false;
  state.protected = null;
  state.protectedLoadVersion += 1;
  setVisibilityButton($("#protected-show-raw"), false, "显示受保护值原文", "隐藏受保护值原文");
  $("#protected-values").replaceChildren();
  await loadProtected();
}

function renderMappingRetention(policy) {
  const [duration, unit] = retentionDurationParts(policy.idle_ttl_seconds);
  $("#mapping-retention-enabled").checked = Boolean(policy.enabled);
  $("#mapping-retention-duration").value = String(duration);
  $("#mapping-retention-unit").value = String(unit);
  syncMappingRetentionControls();
}

function syncMappingRetentionControls() {
  const enabled = $("#mapping-retention-enabled").checked;
  const duration = Number($("#mapping-retention-duration").value || 0);
  const unit = Number($("#mapping-retention-unit").value || 60);
  $("#mapping-retention-duration").disabled = !enabled;
  $("#mapping-retention-unit").disabled = !enabled;
  $("#retention-enabled-label").textContent = enabled ? "开启" : "关闭";
  $("#retention-status").textContent = enabled && duration > 0 ? `空闲 ${formatRetentionDuration(duration * unit)}后清除` : "永久保留";
  $("#retention-status").className = `badge ${enabled ? "amber" : "neutral"}`;
}

async function saveMappingRetention() {
  const policy = state.protected?.retention_policy;
  if (!policy) return;
  const enabled = $("#mapping-retention-enabled").checked;
  const duration = Number($("#mapping-retention-duration").value);
  const unit = Number($("#mapping-retention-unit").value);
  if (!Number.isInteger(duration) || duration < 1) return toast("请输入有效的自动清除时长", true);
  const idleTtlSeconds = duration * unit;
  if (idleTtlSeconds < 60 || idleTtlSeconds > 365 * 86_400) return toast("自动清除时长须在 1 分钟到 365 天之间", true);
  await api("/protected-values/retention", {
    method: "PUT",
    body: JSON.stringify({enabled, idle_ttl_seconds: idleTtlSeconds, revision: policy.revision}),
  });
  toast(enabled ? `已启用：空闲 ${formatRetentionDuration(idleTtlSeconds)}后清除` : "已关闭自动清除");
  await loadProtected();
}

function retentionDurationParts(seconds) {
  for (const unit of [86400, 3600, 60]) {
    if (seconds % unit === 0) return [seconds / unit, unit];
  }
  return [Math.max(1, Math.ceil(seconds / 60)), 60];
}

function formatRetentionDuration(seconds) {
  const [duration, unit] = retentionDurationParts(seconds);
  return `${formatNumber(duration)} ${unit === 86400 ? "天" : unit === 3600 ? "小时" : "分钟"}`;
}

async function revokeProtected(id) {
  await api(`/protected-values/${encodeURIComponent(id)}/revoke`, {method: "POST"});
  toast("受保护值已撤销");
  state.loaded.delete("overview");
  await loadProtected();
}

async function purgeExpired() {
  const result = await api("/protected-values/purge-expired", {method: "POST"});
  toast(`已清理 ${result.affected_count} 条过期记录`);
  await loadProtected();
}

async function loadDetectors() {
  const selected = state.detectorConfiguration?.id;
  state.detectorCatalog = await api("/detector-configurations");
  renderConfigurationOptions();
  const available = [...state.detectorCatalog.templates, ...state.detectorCatalog.configurations];
  const configurationId = available.some((item) => item.id === selected) ? selected : state.detectorCatalog.active_configuration_id;
  await loadDetectorConfiguration(configurationId);
  state.loaded.add("detectors");
}

function renderConfigurationOptions() {
  const select = $("#configuration-select");
  const options = (items) => items.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(uiText(item.name))}${item.is_active ? ` · ${escapeHtml(uiText("当前启用"))}` : ""}</option>`).join("");
  select.innerHTML = `<optgroup label="${escapeHtml(uiText("内置与部署模板"))}">${options(state.detectorCatalog.templates)}</optgroup><optgroup label="${escapeHtml(uiText("用户配置"))}">${options(state.detectorCatalog.configurations)}</optgroup>`;
  if (state.detectorConfiguration) select.value = state.detectorConfiguration.id;
}

async function loadDetectorConfiguration(configurationId) {
  const data = await api(`/detector-configurations/${encodeURIComponent(configurationId)}`);
  state.detectorConfiguration = data;
  state.detectorDraft = structuredClone(data);
  $("#configuration-select").value = data.id;
  renderDetectorConfiguration();
}

function selectDetectorConfiguration(configurationId) {
  if (!configurationId || configurationId === state.detectorConfiguration?.id) return;
  if (detectorConfigurationDirty()) {
    $("#configuration-select").value = state.detectorConfiguration.id;
    return confirmAction("放弃未保存更改", "切换配置将丢弃当前草稿。", () => loadDetectorConfiguration(configurationId));
  }
  loadDetectorConfiguration(configurationId).catch(handleError);
}

function renderDetectorConfiguration() {
  const configuration = state.detectorDraft;
  if (!configuration) return;
  const readonly = configuration.readonly;
  $("#configuration-name").value = uiText(configuration.name);
  $("#configuration-description").value = uiText(configuration.description || "");
  $("#configuration-timeout").value = configuration.flow_timeout_ms ?? "";
  for (const id of ["configuration-name", "configuration-description", "configuration-timeout"]) $("#" + id).disabled = readonly;
  $("#configuration-status").innerHTML = `${configuration.is_active ? '<span class="badge green">当前启用</span>' : ""}${configuration.readonly ? '<span class="configuration-readonly-note">默认预设不可编辑，请复制或新建自定义配置。模块开关仍可直接调整。</span>' : ""}`;
  $("#activate-configuration").disabled = configuration.is_active || detectorConfigurationDirty();
  setIconButton($("#activate-configuration"), configuration.is_active ? "check-circle-2" : "power", configuration.is_active ? "当前检测器配置" : "启用检测器配置");
  setIconButton($("#duplicate-configuration"), "copy", readonly ? "复制并编辑检测器配置" : "复制检测器配置");
  $("#save-configuration").disabled = readonly || !detectorConfigurationDirty();
  $("#delete-configuration").disabled = readonly || configuration.is_active;
  $("#add-module").disabled = readonly;
  renderDetectorModules();
  $("#detection-output").innerHTML = `<span class="muted">等待测试</span>`;
  $("#detection-diagnostics").innerHTML = "";
}

function renderDetectorModules() {
  const readonly = state.detectorDraft.readonly;
  const modules = state.detectorDraft.modules || [];
  const target = $("#detector-modules");
  if (!modules.length) {
    target.innerHTML = `<div class="empty-pipeline"><strong>配置中还没有检测模块</strong><span>新增模块后，它们会按这里的顺序依次执行。</span></div>`;
    return;
  }
  target.innerHTML = modules.map((module, index) => {
    const type = moduleTypeLabel(module.type);
    const typeIcon = moduleTypeIcon(module.type);
    const unavailable = module.type === "local_model" && module.enabled && module.runtime_available === false;
    const status = !module.enabled ? "disabled" : unavailable ? "unavailable" : module.editable === false ? "managed" : "activated";
    const statusClass = status === "activated" ? "green" : status === "unavailable" ? "red" : "neutral";
    const editable = !readonly && module.editable !== false;
    const dragControl = editable ? `<button class="module-drag-handle" type="button" title="拖动排序" aria-label="拖动排序 ${escapeHtml(module.name)}" aria-keyshortcuts="Alt+ArrowUp Alt+ArrowDown" aria-grabbed="false" data-module-drag="${index}">${iconMarkup("grip-vertical")}</button>` : `<span class="module-drag-spacer" aria-hidden="true"></span>`;
    const controls = editable ? `<div class="module-actions"><button type="button" title="编辑模块" aria-label="编辑 ${escapeHtml(module.name)}" data-module-edit="${index}">${iconMarkup("pencil")}</button><button type="button" title="复制模块" aria-label="复制 ${escapeHtml(module.name)}" data-module-copy="${index}">${iconMarkup("copy")}</button><button type="button" class="danger" title="删除模块" aria-label="删除 ${escapeHtml(module.name)}" data-module-delete="${index}">${iconMarkup("trash-2")}</button></div>` : "";
    return `<div class="module-row" data-module-row="${index}">${dragControl}<span class="module-order">${index + 1}</span><div class="module-name"><span class="module-symbol module-symbol-${escapeHtml(module.type)}" aria-hidden="true" title="${escapeHtml(type)}">${iconMarkup(typeIcon)}</span><div><strong>${escapeHtml(module.name)}</strong><span>${escapeHtml(type)}</span></div></div><span class="badge ${statusClass}">${escapeHtml(moduleStatusLabel(status))}</span>${controls}<label class="toggle"><input type="checkbox" data-module-toggle="${index}" ${module.enabled ? "checked" : ""} aria-label="启用 ${escapeHtml(module.name)}"><span></span></label></div>`;
  }).join("");
  renderIcons(target);
  $$('[data-module-toggle]', target).forEach((input) => input.addEventListener("change", () => updateModuleEnabled(Number(input.dataset.moduleToggle), input.checked)));
  $$('[data-module-drag]', target).forEach((button) => {
    button.addEventListener("pointerdown", beginModuleDrag);
    button.addEventListener("keydown", handleModuleDragKeydown);
  });
  $$('[data-module-edit]', target).forEach((button) => button.addEventListener("click", () => openModuleEditor(Number(button.dataset.moduleEdit))));
  $$('[data-module-copy]', target).forEach((button) => button.addEventListener("click", () => duplicateModule(Number(button.dataset.moduleCopy))));
  $$('[data-module-delete]', target).forEach((button) => button.addEventListener("click", () => removeModule(Number(button.dataset.moduleDelete))));
}

function updateConfigurationFields(event) {
  if (!state.detectorDraft || state.detectorDraft.readonly) return;
  if (event.target.id === "configuration-name") state.detectorDraft.name = event.target.value;
  else if (event.target.id === "configuration-description") state.detectorDraft.description = event.target.value;
  else if (event.target.id === "configuration-timeout") state.detectorDraft.flow_timeout_ms = event.target.value ? Number(event.target.value) : null;
  renderDetectorSaveState();
}

function renderDetectorSaveState() {
  $("#save-configuration").disabled = state.detectorDraft.readonly || !detectorConfigurationDirty();
  $("#activate-configuration").disabled = state.detectorDraft.is_active || detectorConfigurationDirty();
}

function detectorConfigurationPayload(configuration) {
  return {
    revision: configuration.revision,
    name: configuration.name,
    description: configuration.description || "",
    flow_timeout_ms: configuration.flow_timeout_ms,
    content_tags: configuration.content_tags || [],
    modules: configuration.modules,
  };
}

function detectorConfigurationDirty() {
  if (!state.detectorConfiguration || !state.detectorDraft || state.detectorDraft.readonly) return false;
  return JSON.stringify(detectorConfigurationPayload(state.detectorConfiguration)) !== JSON.stringify(detectorConfigurationPayload(state.detectorDraft));
}

async function saveDetectorConfiguration() {
  if (!detectorConfigurationDirty()) return;
  try {
    const data = await api(`/detector-configurations/${encodeURIComponent(state.detectorDraft.id)}`, {method: "PUT", body: JSON.stringify(detectorConfigurationPayload(state.detectorDraft))});
    state.detectorConfiguration = data;
    state.detectorDraft = structuredClone(data);
    await refreshDetectorCatalog(data.id);
    renderDetectorConfiguration();
    toast("检测器配置已保存并校验");
  } catch (error) { handleError(error); }
}

async function activateDetectorConfiguration() {
  if (detectorConfigurationDirty()) return toast("请先保存当前草稿", true);
  try {
    const data = await api(`/detector-configurations/${encodeURIComponent(state.detectorDraft.id)}/activate`, {method: "POST"});
    await refreshDetectorCatalog(data.id);
    await loadDetectorConfiguration(data.id);
    state.loaded.delete("overview");
    toast("检测器配置已启用");
  } catch (error) { handleError(error); }
}

function deleteDetectorConfiguration() {
  const configuration = state.detectorDraft;
  if (configuration.readonly || configuration.is_active) return;
  confirmAction("删除检测器配置", `${configuration.name} 将被永久删除。`, async () => {
    await api(`/detector-configurations/${encodeURIComponent(configuration.id)}`, {method: "DELETE"});
    await refreshDetectorCatalog(state.detectorCatalog.active_configuration_id);
    await loadDetectorConfiguration(state.detectorCatalog.active_configuration_id);
    toast("检测器配置已删除");
  });
}

function openConfigurationCreator() {
  $("#configuration-form").reset();
  $("#configuration-error").textContent = "";
  const all = [...state.detectorCatalog.templates, ...state.detectorCatalog.configurations];
  $("#configuration-source").innerHTML = `<option value="">${escapeHtml(uiText("空白配置"))}</option>${all.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(uiText(item.name))}</option>`).join("")}`;
  $("#configuration-source").value = state.detectorConfiguration?.id || "builtin.comprehensive";
  $("#configuration-form [name=name]").value = uiText("新检测配置");
  $("#configuration-modal").showModal();
}

async function createDetectorConfiguration(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  $("#configuration-error").textContent = "";
  try {
    const data = await api("/detector-configurations", {method: "POST", body: JSON.stringify({name: form.get("name"), source_id: form.get("source_id")})});
    $("#configuration-modal").close();
    await refreshDetectorCatalog(data.id);
    await loadDetectorConfiguration(data.id);
    toast("检测器配置已创建");
  } catch (error) { $("#configuration-error").textContent = error.message; }
}

async function duplicateDetectorConfiguration() {
  try {
    const data = await api("/detector-configurations", {method: "POST", body: JSON.stringify({source_id: state.detectorDraft.id})});
    await refreshDetectorCatalog(data.id);
    await loadDetectorConfiguration(data.id);
    toast("已创建可编辑副本");
  } catch (error) { handleError(error); }
}

async function refreshDetectorCatalog(selectedId) {
  state.detectorCatalog = await api("/detector-configurations");
  renderConfigurationOptions();
  if (selectedId) $("#configuration-select").value = selectedId;
}

async function updateModuleEnabled(index, enabled) {
  if (state.detectorDraft.readonly) {
    const configurationId = state.detectorDraft.id;
    const moduleId = state.detectorDraft.modules[index].id;
    try {
      const data = await api(`/detector-configurations/${encodeURIComponent(configurationId)}/modules/${encodeURIComponent(moduleId)}/enabled`, {
        method: "PUT",
        body: JSON.stringify({enabled}),
      });
      state.detectorConfiguration = data;
      state.detectorDraft = structuredClone(data);
      state.loaded.delete("overview");
      renderDetectorConfiguration();
      toast(enabled ? "检测模块已启用" : "检测模块已停用");
    } catch (error) {
      await loadDetectorConfiguration(configurationId);
      handleError(error);
    }
    return;
  }
  state.detectorDraft.modules[index].enabled = enabled;
  renderDetectorConfiguration();
}

function moveModule(index, direction) {
  const target = index + direction;
  if (target < 0 || target >= state.detectorDraft.modules.length) return false;
  const modules = state.detectorDraft.modules;
  [modules[index], modules[target]] = [modules[target], modules[index]];
  renderDetectorConfiguration();
  return true;
}

function beginModuleDrag(event) {
  if (event.pointerType === "mouse" && event.button !== 0) return;
  const handle = event.currentTarget;
  state.moduleDrag = {
    handle,
    pointerId: event.pointerId,
    sourceIndex: Number(handle.dataset.moduleDrag),
    targetIndex: null,
    placement: null,
    startX: event.clientX,
    startY: event.clientY,
    active: false,
  };
  handle.setPointerCapture?.(event.pointerId);
  handle.addEventListener("pointermove", updateModuleDrag);
  handle.addEventListener("pointerup", finishModuleDrag);
  handle.addEventListener("pointercancel", cancelModuleDrag);
}

function updateModuleDrag(event) {
  const drag = state.moduleDrag;
  if (!drag || drag.pointerId !== event.pointerId) return;
  if (!drag.active && Math.hypot(event.clientX - drag.startX, event.clientY - drag.startY) < 5) return;
  drag.active = true;
  event.preventDefault();
  drag.handle.setAttribute("aria-grabbed", "true");
  drag.handle.closest(".module-row")?.classList.add("is-dragging");
  document.body.classList.add("is-module-dragging");
  clearModuleDropTarget();
  const row = document.elementFromPoint(event.clientX, event.clientY)?.closest("[data-module-row]");
  if (!row || !$("#detector-modules").contains(row)) {
    drag.targetIndex = null;
    drag.placement = null;
    return;
  }
  const targetIndex = Number(row.dataset.moduleRow);
  if (targetIndex === drag.sourceIndex) {
    drag.targetIndex = null;
    drag.placement = null;
    return;
  }
  const bounds = row.getBoundingClientRect();
  drag.targetIndex = targetIndex;
  drag.placement = event.clientY < bounds.top + bounds.height / 2 ? "before" : "after";
  row.classList.add(drag.placement === "before" ? "is-drop-before" : "is-drop-after");
}

function finishModuleDrag(event, cancelled = false) {
  const drag = state.moduleDrag;
  if (!drag || drag.pointerId !== event.pointerId) return;
  drag.handle.removeEventListener("pointermove", updateModuleDrag);
  drag.handle.removeEventListener("pointerup", finishModuleDrag);
  drag.handle.removeEventListener("pointercancel", cancelModuleDrag);
  if (drag.handle.hasPointerCapture?.(event.pointerId)) drag.handle.releasePointerCapture(event.pointerId);
  drag.handle.setAttribute("aria-grabbed", "false");
  drag.handle.closest(".module-row")?.classList.remove("is-dragging");
  document.body.classList.remove("is-module-dragging");
  clearModuleDropTarget();
  state.moduleDrag = null;
  if (!cancelled && drag.active && drag.targetIndex !== null) {
    reorderModule(drag.sourceIndex, drag.targetIndex, drag.placement);
  }
}

function cancelModuleDrag(event) {
  finishModuleDrag(event, true);
}

function clearModuleDropTarget() {
  $$(".module-row.is-drop-before, .module-row.is-drop-after", $("#detector-modules")).forEach((row) => {
    row.classList.remove("is-drop-before", "is-drop-after");
  });
}

function reorderModule(sourceIndex, targetIndex, placement) {
  const modules = state.detectorDraft.modules;
  let insertionIndex = targetIndex + (placement === "after" ? 1 : 0);
  const [module] = modules.splice(sourceIndex, 1);
  if (sourceIndex < insertionIndex) insertionIndex -= 1;
  modules.splice(insertionIndex, 0, module);
  renderDetectorConfiguration();
  requestAnimationFrame(() => $(`[data-module-drag="${insertionIndex}"]`)?.focus());
}

function handleModuleDragKeydown(event) {
  if (!event.altKey || !["ArrowUp", "ArrowDown"].includes(event.key)) return;
  event.preventDefault();
  const index = Number(event.currentTarget.dataset.moduleDrag);
  const direction = event.key === "ArrowUp" ? -1 : 1;
  const target = index + direction;
  if (moveModule(index, direction)) requestAnimationFrame(() => $(`[data-module-drag="${target}"]`)?.focus());
}

function duplicateModule(index) {
  const module = structuredClone(state.detectorDraft.modules[index]);
  module.id = randomId("mod");
  module.name += " 副本";
  module.editable = true;
  state.detectorDraft.modules.splice(index + 1, 0, module);
  renderDetectorConfiguration();
}

function removeModule(index) {
  const module = state.detectorDraft.modules[index];
  confirmAction("删除检测模块", `${module.name} 将从配置草稿中移除。`, () => {
    state.detectorDraft.modules.splice(index, 1);
    renderDetectorConfiguration();
  });
}

function openModuleEditor(index) {
  const editing = index !== null;
  state.editingModuleIndex = index;
  state.moduleDraft = index === null ? {
    id: randomId("mod"), name: "新检测模块", type: "regex", enabled: true,
    timeout_ms: null, failure_mode: "open", editable: true, config: defaultModuleConfig("regex"),
  } : structuredClone(state.detectorDraft.modules[index]);
  state.moduleDraftSourceName = state.moduleDraft.name;
  $("#module-form").reset();
  $("#module-error").textContent = "";
  $("#module-modal-title").textContent = index === null ? "新增检测模块" : "编辑检测模块";
  $("#module-form [name=name]").value = uiText(state.moduleDraft.name);
  $("#module-type").value = state.moduleDraft.type;
  $("#module-type").disabled = editing;
  $("#module-type-field").hidden = editing;
  $("#module-name-field").classList.toggle("full-row", editing);
  $("#module-form [name=timeout_ms]").value = state.moduleDraft.timeout_ms ?? "";
  $("#module-form [name=failure_mode]").value = state.moduleDraft.failure_mode || "open";
  renderModuleSpecificFields();
  $("#module-modal").showModal();
}

function defaultModuleConfig(type) {
  if (type === "regex") return {rules: []};
  if (type === "entropy") return {min_length: 20, min_entropy: 3.5, risk: "medium"};
  if (type === "path") return {detect_unix_home: true, detect_macos_private: true, detect_shell_config: true, detect_windows_user: true, exclude_patterns: [], path_risk: "medium"};
  return {adapter: "transformers_token_classification", model_name: "iiiorg/piiranha-v1-detect-personal-information", threshold: 0.75, device: "cpu", aggregation_strategy: "simple", labels: ["email", "phone_number", "user_name"]};
}

function renderModuleSpecificFields() {
  const module = state.moduleDraft;
  const target = $("#module-specific-fields");
  if (module.type === "regex") {
    target.innerHTML = `<div class="specific-heading"><div><p class="section-kicker">REGEX RULES</p><strong>${module.config.rules.length} 条规则</strong></div><button class="secondary-button icon-action-button" type="button" id="add-regex-rule" aria-label="添加正则规则" title="添加正则规则">${iconMarkup("plus")}</button></div><div class="rule-editor-list">${module.config.rules.map(renderRegexRule).join("")}</div>`;
    renderIcons(target);
    $("#add-regex-rule").addEventListener("click", () => {
      syncModuleSpecificFields();
      state.moduleDraft.config.rules.push({id: `custom.rule_${randomHex(8)}`, pattern: "", type: "MACHINE_SECRET", subtype: "custom_secret", risk: "high", flags: [], validators: [], require_validators: [], reject_validators: [], preview_keep: 0, enabled: true, metadata: {source: "webui"}});
      renderModuleSpecificFields();
    });
    $$('[data-remove-rule]', target).forEach((button) => button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      syncModuleSpecificFields();
      state.moduleDraft.config.rules.splice(Number(button.dataset.removeRule), 1);
      renderModuleSpecificFields();
    }));
  } else if (module.type === "entropy") {
    const config = module.config;
    target.innerHTML = `<div class="form-grid specific-grid"><label><span>最小 Token 长度</span><input id="entropy-min-length" type="number" min="8" max="512" value="${config.min_length}"></label><label><span>熵阈值</span><input id="entropy-threshold" type="number" min="0" max="8" step="0.1" value="${config.min_entropy}"></label>${riskField("entropy", "模块", config.risk || "medium")}</div>`;
  } else if (module.type === "path") {
    const config = module.config;
    target.innerHTML = `<div class="check-grid"><label><input id="path-unix" type="checkbox" ${config.detect_unix_home ? "checked" : ""}> Unix / macOS Home</label><label><input id="path-private" type="checkbox" ${config.detect_macos_private ? "checked" : ""}> macOS /private</label><label><input id="path-shell" type="checkbox" ${config.detect_shell_config ? "checked" : ""}> Shell 配置目录</label><label><input id="path-windows" type="checkbox" ${config.detect_windows_user ? "checked" : ""}> Windows User 路径</label></div><div class="form-grid specific-grid"><label class="full-row"><span>排除模式（逗号分隔 glob）</span><input id="path-excludes" value="${escapeHtml(config.exclude_patterns.join(", "))}"></label>${riskField("path", "模块", config.path_risk)}</div>`;
  } else {
    const config = module.config;
    target.innerHTML = `<div class="form-grid specific-grid"><label><span>运行方式</span><select id="model-adapter"><option value="transformers_token_classification" ${config.adapter === "transformers_token_classification" ? "selected" : ""}>Transformers Token Classification</option><option value="gliner" ${config.adapter === "gliner" ? "selected" : ""}>GLiNER</option></select></label><label><span>模型分数阈值</span><input id="model-threshold" type="number" min="0" max="1" step="0.01" value="${config.threshold}"></label><label class="full-row"><span>Hugging Face 模型地址或本地路径</span><input id="model-name" value="${escapeHtml(config.model_name)}"></label><label><span>设备</span><select id="model-device"><option value="cpu">CPU</option><option value="mps">Apple MPS</option><option value="cuda">CUDA</option><option value="cuda:0">CUDA:0</option></select></label>${config.adapter === "gliner" ? `<label class="full-row"><span>实体标签（逗号分隔）</span><input id="model-labels" value="${escapeHtml(config.labels.join(", "))}"></label>` : `<label><span>聚合方式</span><select id="model-aggregation"><option value="simple">Simple</option><option value="first">First</option><option value="average">Average</option><option value="max">Max</option></select></label>`}<div class="model-policy-note full-row">模型按需延迟加载；是否允许下载由部署策略决定。</div></div>`;
    $("#model-device").value = config.device;
    if ($("#model-aggregation")) $("#model-aggregation").value = config.aggregation_strategy;
    $("#model-adapter").addEventListener("change", (event) => { syncModuleSpecificFields(); state.moduleDraft.config.adapter = event.target.value; renderModuleSpecificFields(); });
  }
}

function renderRegexRule(rule, index) {
  const name = String(rule.metadata?.display_name || rule.id);
  return `<details class="rule-editor" data-rule-card="${index}" ${rule.pattern ? "" : "open"}><summary class="rule-editor-heading"><strong>${escapeHtml(name)}</strong><label class="inline-check"><input data-rule-field="enabled" type="checkbox" ${rule.enabled !== false ? "checked" : ""}>启用</label><button class="row-action danger icon-row-button" type="button" data-remove-rule="${index}" aria-label="删除正则规则 ${escapeHtml(name)}" title="删除正则规则">${iconMarkup("trash-2")}</button></summary><div class="form-grid"><label><span>规则名称</span><input data-rule-field="name" value="${escapeHtml(name)}"></label><label class="full-row"><span>正则表达式</span><textarea data-rule-field="pattern" rows="3">${escapeHtml(rule.pattern)}</textarea></label><label><span>数据类型</span><select data-rule-field="type">${selectOptions(["MACHINE_SECRET", "PII", "LOCAL_CONTEXT", "CREDENTIAL_FILE", "UNKNOWN_SECRET_CANDIDATE"], rule.type)}</select></label><label><span>风险等级（仅用于审计）</span><select data-rule-field="risk">${selectOptions(["critical", "high", "medium", "low"], rule.risk)}</select></label><details class="rule-advanced full-row"><summary>高级选项（选填）</summary><div class="form-grid"><label><span>Flags（逗号分隔）</span><input data-rule-field="flags" value="${escapeHtml((rule.flags || []).join(", "))}"></label><label><span>Validators（选填）</span><input data-rule-field="validators" value="${escapeHtml((rule.validators || []).join(", "))}"></label><label><span>必须通过的 Validators（选填）</span><input data-rule-field="require_validators" value="${escapeHtml((rule.require_validators || []).join(", "))}"></label><label><span>拒绝的 Validators（选填）</span><input data-rule-field="reject_validators" value="${escapeHtml((rule.reject_validators || []).join(", "))}"></label></div></details></div></details>`;
}

function riskField(prefix, label, risk) {
  return `<label><span>${label}风险等级（仅用于审计）</span><select id="${prefix}-risk">${selectOptions(["critical", "high", "medium", "low"], risk)}</select></label>`;
}

function syncModuleSpecificFields() {
  const module = state.moduleDraft;
  if (module.type === "regex") {
    module.config.rules = $$('[data-rule-card]').map((card) => {
      const field = (name) => card.querySelector(`[data-rule-field="${name}"]`);
      const previous = module.config.rules[Number(card.dataset.ruleCard)] || {};
      const displayName = field("name").value.trim() || previous.id;
      return {...previous, metadata: {...(previous.metadata || {}), display_name: displayName}, pattern: field("pattern").value, type: field("type").value, risk: field("risk").value, flags: commaList(field("flags").value), validators: commaList(field("validators").value), require_validators: commaList(field("require_validators").value), reject_validators: commaList(field("reject_validators").value), enabled: field("enabled").checked};
    });
  } else if (module.type === "entropy") {
    module.config = {...module.config, min_length: Number($("#entropy-min-length").value), min_entropy: Number($("#entropy-threshold").value), risk: $("#entropy-risk").value};
  } else if (module.type === "path") {
    module.config = {...module.config, detect_unix_home: $("#path-unix").checked, detect_macos_private: $("#path-private").checked, detect_shell_config: $("#path-shell").checked, detect_windows_user: $("#path-windows").checked, exclude_patterns: commaList($("#path-excludes").value), path_risk: $("#path-risk").value};
  } else {
    module.config = {...module.config, adapter: $("#model-adapter").value, model_name: $("#model-name").value.trim(), threshold: Number($("#model-threshold").value), device: $("#model-device").value, aggregation_strategy: $("#model-aggregation")?.value || module.config.aggregation_strategy, labels: $("#model-labels") ? commaList($("#model-labels").value) : module.config.labels};
  }
}

function applyModuleDraft(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  $("#module-error").textContent = "";
  try {
    syncModuleSpecificFields();
    const submittedName = String(form.get("name") || "").trim();
    state.moduleDraft.name = submittedName === uiText(state.moduleDraftSourceName)
      ? state.moduleDraftSourceName
      : submittedName;
    state.moduleDraft.timeout_ms = form.get("timeout_ms") ? Number(form.get("timeout_ms")) : null;
    state.moduleDraft.failure_mode = form.get("failure_mode") || "open";
    if (!state.moduleDraft.name) throw new Error("请输入模块名称");
    if (state.editingModuleIndex === null) state.detectorDraft.modules.push(state.moduleDraft);
    else state.detectorDraft.modules[state.editingModuleIndex] = state.moduleDraft;
    $("#module-modal").close();
    renderDetectorConfiguration();
  } catch (error) { $("#module-error").textContent = error.message; }
}

function renderDetectionDiagnostics(diagnostics) {
  $("#detection-diagnostics").innerHTML = diagnostics.length ? `<div class="diagnostic-heading"><p class="section-kicker">EXECUTION TRACE</p><span>${diagnostics.length} 个步骤</span></div>${diagnostics.map((item, index) => `<div class="diagnostic-row"><span class="diagnostic-order">${index + 1}</span><strong>${escapeHtml(item.id === "apg_core" ? uiText("APG 内置安全防线") : item.id)}</strong><span>${escapeHtml(item.type)}</span><span>${item.findings} 命中</span><span>${Number(item.elapsed_ms).toFixed(2)} ms</span><b class="badge ${item.status === "ok" ? "green" : ["disabled", "unavailable"].includes(item.status) ? "neutral" : "red"}">${escapeHtml(item.status)}</b></div>`).join("")}` : "";
}

function moduleTypeLabel(type) {
  return ({regex: "正则检测", entropy: "熵值检测", path: "路径检测", local_model: "本地小模型", deployment: "部署模块"})[type] || type;
}

function moduleTypeIcon(type) {
  return ({regex: "regex-reference", entropy: "gauge", path: "folder-tree", local_model: "brain-circuit", deployment: "server-cog"})[type] || "search";
}

function selectOptions(values, selected) {
  return values.map((value) => `<option value="${escapeHtml(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(value)}</option>`).join("");
}

function commaList(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function randomHex(length) {
  const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(length / 2)));
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("").slice(0, length);
}

function randomId(prefix) {
  return `${prefix}_${randomHex(12)}`;
}

async function runDetection() {
  const text = $("#detection-input").value;
  if (!text.trim()) return toast("请输入测试文本", true);
  if (detectorConfigurationDirty()) return toast("请先保存配置草稿再试跑", true);
  const output = $("#detection-output");
  output.innerHTML = `<span class="muted">正在检测…</span>`;
  $("#detection-diagnostics").innerHTML = "";
  try {
    const data = await api(`/detector-configurations/${encodeURIComponent(state.detectorDraft.id)}/test`, {method: "POST", body: JSON.stringify({text})});
    renderHighlightedDetection(output, text, data.findings);
    renderDetectionDiagnostics(data.diagnostics);
  } catch (error) { output.innerHTML = `<span class="form-error">${escapeHtml(error.message)}</span>`; handleError(error); }
}

function renderHighlightedDetection(output, text, findings) {
  output.replaceChildren();
  if (!findings.length) {
    const empty = document.createElement("span");
    empty.className = "muted";
    empty.textContent = "未发现敏感内容";
    output.append(empty);
    return;
  }

  const characters = Array.from(text);
  const groups = mergeFindingRanges(characters.length, findings);
  const summary = document.createElement("div");
  summary.className = "highlight-summary";
  const summaryText = document.createElement("strong");
  summaryText.textContent = `发现 ${groups.length} 处敏感内容`;
  const localOnly = document.createElement("span");
  localOnly.textContent = "本地检测 · 未上传云端";
  summary.append(summaryText, localOnly);

  const source = document.createElement("pre");
  source.className = "highlighted-source";
  let cursor = 0;
  groups.forEach((group, index) => {
    if (group.start > cursor) source.append(document.createTextNode(characters.slice(cursor, group.start).join("")));
    const mark = document.createElement("mark");
    mark.className = `text-highlight risk-${group.risk}`;
    mark.title = group.findings.map((finding) => `${finding.subtype} · ${finding.risk} · ${finding.detectors.join(" + ")}`).join("\n");
    mark.append(document.createTextNode(characters.slice(group.start, group.end).join("")));
    const marker = document.createElement("sup");
    marker.className = "highlight-index";
    marker.textContent = String(index + 1);
    mark.append(marker);
    source.append(mark);
    cursor = group.end;
  });
  if (cursor < characters.length) source.append(document.createTextNode(characters.slice(cursor).join("")));

  const legend = document.createElement("div");
  legend.className = "highlight-legend";
  groups.forEach((group, index) => {
    const row = document.createElement("div");
    row.className = "highlight-detail";
    const number = document.createElement("span");
    number.className = `detail-index risk-${group.risk}`;
    number.textContent = String(index + 1);
    const content = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = unique(group.findings.map((finding) => finding.subtype)).join(" + ");
    const detectors = document.createElement("span");
    detectors.textContent = unique(group.findings.flatMap((finding) => finding.detectors)).join(" + ");
    content.append(title, detectors);
    const risk = document.createElement("b");
    risk.textContent = group.risk;
    row.append(number, content, risk);
    legend.append(row);
  });

  output.append(summary, source, legend);
}

function mergeFindingRanges(textLength, findings) {
  const riskOrder = {critical: 4, high: 3, medium: 2, low: 1};
  const ranges = findings
    .map((finding) => ({
      start: Math.max(0, Math.min(textLength, Number(finding.original_start))),
      end: Math.max(0, Math.min(textLength, Number(finding.original_end))),
      findings: [finding],
      risk: finding.risk || "low",
    }))
    .filter((range) => Number.isFinite(range.start) && Number.isFinite(range.end) && range.end > range.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const merged = [];
  ranges.forEach((range) => {
    const previous = merged[merged.length - 1];
    if (previous && range.start < previous.end) {
      previous.end = Math.max(previous.end, range.end);
      previous.findings.push(...range.findings);
      if ((riskOrder[range.risk] || 0) > (riskOrder[previous.risk] || 0)) previous.risk = range.risk;
    } else {
      merged.push(range);
    }
  });
  return merged;
}

function unique(values) {
  return [...new Set(values)];
}

function confirmAction(title, message, action) {
  $("#confirm-title").textContent = title;
  $("#confirm-message").textContent = message;
  state.confirmAction = action;
  $("#confirm-modal").showModal();
}

function populateSelect(select, options, placeholder) {
  const current = select.value;
  select.innerHTML = `<option value="">${escapeHtml(placeholder)}</option>` + options.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
  if (options.includes(current)) select.value = current;
}

function highestRisk(detections) {
  const order = {critical: 4, high: 3, medium: 2, low: 1};
  return detections.reduce((best, item) => (order[item.risk] || 0) > (order[best] || 0) ? item.risk : best, "low");
}

function statusClass(status) {
  if (["completed", "safe", "200", "201"].includes(status)) return "green";
  if (status.includes("error") || status === "revoked") return "red";
  return "neutral";
}

function auditStatusLabel(value) {
  return ({completed: "已完成", in_progress: "进行中", recorded: "已记录", error: "异常", protocol_error: "协议错误", client_disconnected: "连接中断"})[value] || value || "已记录";
}

function valueStateLabel(value) {
  return ({active: "映射有效", expired: "原文已过期清除", revoked: "原文已撤销清除", unavailable: "原文不可用"})[value] || value;
}

function stateLabel(value) { return ({active: "活跃", expired: "已过期", revoked: "已撤销"})[value] || value; }
function moduleStatusLabel(value) {
  if (displayLocale() === "en-US") return value;
  return ({activated: "已启用", disabled: "已停用", managed: "内置", unavailable: "不可用"})[value] || value;
}
function uiText(value) { return window.APG_I18N?.translate(String(value ?? "")) ?? String(value ?? ""); }
function displayLocale() { return window.APG_I18N?.locale === "en" ? "en-US" : "zh-CN"; }
function formatNumber(value) { return new Intl.NumberFormat(displayLocale()).format(Number(value || 0)); }
function formatTime(timestamp) { return timestamp ? new Intl.DateTimeFormat(displayLocale(), {hour: "2-digit", minute: "2-digit"}).format(new Date(timestamp * 1000)) : "-"; }
function formatDateTime(timestamp) { return timestamp ? new Intl.DateTimeFormat(displayLocale(), {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"}).format(new Date(timestamp * 1000)) : "-"; }
function formatRelative(timestamp) {
  if (!timestamp) return "-";
  const seconds = timestamp - Date.now() / 1000;
  const abs = Math.abs(seconds);
  const [amount, unit] = abs < 60 ? [Math.round(seconds), "second"] : abs < 3600 ? [Math.round(seconds / 60), "minute"] : abs < 86400 ? [Math.round(seconds / 3600), "hour"] : [Math.round(seconds / 86400), "day"];
  return new Intl.RelativeTimeFormat(displayLocale(), {numeric: "auto"}).format(amount, unit);
}

function toast(message, error = false) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.toggle("is-error", error);
  element.classList.add("is-visible");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove("is-visible"), 2800);
}

function handleError(error) {
  toast(error.message || "请求失败", true);
}

function debounce(fn, wait) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), wait); };
}
