"use strict";

const API = "/api/admin";
const PAGE_META = {
  overview: ["LOCAL CONTROL PLANE", "隐私运行概览", "最近 24 小时的网关活动"],
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
  confirmAction: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const DYNAMIC_ICONS = new Set(["arrow-right", "ban", "brain-circuit", "check-circle-2", "chevron-down", "chevron-up", "copy", "eye", "eye-off", "folder-tree", "gauge", "pencil", "plus", "power", "regex-reference", "search", "server-cog", "trash-2"]);

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
  $$('[data-copy-connection]').forEach((button) => button.addEventListener("click", () => copyConnectionValue(button.dataset.copyConnection)));
  $("#copy-claude-command").addEventListener("click", copyClaudeCodeCommand);
  $("#toggle-agent-key").addEventListener("click", toggleAgentKeyVisibility);
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
  $("#configuration-core-guard").addEventListener("change", updateCoreGuard);
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
  const [data, connection, upstream] = await Promise.all([
    api("/overview"),
    api("/connection"),
    api("/upstream-configuration"),
  ]);
  state.connection = connection;
  state.upstream = upstream;
  renderConnection();
  renderUpstreamConfiguration();
  const metrics = [
    ["请求", data.metrics.requests_24h, "最近 24 小时", "accent-blue"],
    ["拦截", data.metrics.interceptions_24h, "敏感内容已替换或折叠", "accent-coral"],
    ["本地还原", data.metrics.materializations_24h, "仅结构化工具参数", "accent-green"],
    ["活跃受保护值", data.metrics.active_protected_values, "保存在本地映射库", "accent-amber"],
  ];
  $("#overview-metrics").innerHTML = metrics.map(([label, value, foot, accent]) => `<article class="metric-card ${accent}"><span class="metric-label">${escapeHtml(label)}</span><strong>${formatNumber(value)}</strong><span class="metric-foot">${escapeHtml(foot)}</span></article>`).join("");
  renderTrend(data.trend);
  renderRisk(data.risk);
  renderEventRows($("#overview-events"), data.recent, true);
  const system = data.system;
  $("#system-strip").innerHTML = [
    ["Workspace", system.workspace], ["Upstream", system.upstream], ["检测配置", system.detector_configuration],
    ["PII", system.pii_mode], ["Strict", system.strict_mode ? "On" : "Off"], ["管理面板", system.local_only ? "仅本机" : "远程绑定"],
  ].map(([label, value]) => `<span class="system-item">${escapeHtml(label)}<strong>${escapeHtml(value)}</strong></span>`).join("");
  state.loaded.add("overview");
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
  $("#upstream-status").textContent = configured ? "已配置" : "需要配置";
  $("#upstream-status").classList.toggle("is-active", configured);
  $("#upstream-description").textContent = configured
    ? "上游连接配置已生效。APG 不会通过管理接口回显已保存的密钥。"
    : "输入模型服务商的 Base URL 和 API Key 后即可开始使用 Agent。配置只保存在本机。";
  $("#upstream-base-url").textContent = state.upstream.base_url || "待填写";
  $("#upstream-protocol-value").textContent = UPSTREAM_PROTOCOL_LABELS[state.upstream.protocol] || "待选择";
  $("#upstream-profile-select").innerHTML = profiles.length
    ? profiles.map((profile) => `<option value="${escapeHtml(profile.id)}"${profile.id === state.upstreamSelectedProfileId ? " selected" : ""}>${escapeHtml(profile.name)}${profile.active ? "（当前）" : ""}</option>`).join("")
    : '<option value="">暂无配置</option>';
  $("#activate-upstream-profile").disabled = !selected || selected.active;
  $("#delete-upstream-profile").disabled = !selected;
  const editingProfile = state.upstreamEditingProfileId
    ? profiles.find((profile) => profile.id === state.upstreamEditingProfileId)
    : null;
  $("#upstream-profile-name").value = editing ? (editingProfile?.name || "") : "";
  $("#upstream-protocol").value = editing ? (editingProfile?.protocol || "") : "";
  $("#upstream-base-url-input").value = editing ? (editingProfile?.base_url || "") : "";
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
  $("#copy-claude-command").disabled = !state.connection.api_key || !state.connection.protocols.anthropic;
}

function toggleAgentKeyVisibility() {
  const input = $("#agent-api-key");
  const revealed = input.type === "password";
  input.type = revealed ? "text" : "password";
  setVisibilityButton($("#toggle-agent-key"), revealed, "显示 API Key", "隐藏 API Key");
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

async function copyClaudeCodeCommand() {
  if (!state.connection?.api_key || !state.connection.protocols?.anthropic) return;
  const baseUrl = location.origin + (state.connection.protocols.anthropic.base_path || "");
  const key = state.connection.api_key;
  const command = [
    `export ANTHROPIC_BASE_URL=${shellQuote(baseUrl)}`,
    `export ANTHROPIC_AUTH_TOKEN=${shellQuote(key)}`,
    "export ANTHROPIC_MODEL=deepseek-v4-pro[1m]",
    "export ANTHROPIC_DEFAULT_OPUS_MODEL=deepseek-v4-pro[1m]",
    "export ANTHROPIC_DEFAULT_SONNET_MODEL=deepseek-v4-pro[1m]",
    "export ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-v4-flash",
    "export CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash",
    "export CLAUDE_CODE_EFFORT_LEVEL=max",
  ].join("\n");
  await copyText(command);
  toast("Claude Code 接入命令已复制");
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
    return `<tr class="audit-operation-row ${failed ? "has-failure" : ""}"><td data-label="时间">${formatDateTime(operation.timestamp)}</td><td class="audit-map-cell" data-label="${direction === "replacement" ? "替换内容" : "还原内容"}"><div class="operation-map audit-list-map">${mapping}</div><div class="operation-metadata"><span class="mapping-id">${escapeHtml(operation.protected_value_id)}</span>${operation.value_state !== "active" ? `<span class="operation-state-inline">${escapeHtml(valueStateLabel(operation.value_state))}</span>` : ""}</div></td><td data-label="类型"><strong>${escapeHtml(operation.subtype || operation.kind || "-")}</strong><span class="badge ${escapeHtml(operation.risk || "low")}">${escapeHtml(operation.risk || "low")}</span></td><td class="audit-handling" data-label="${direction === "replacement" ? "检测与动作" : "工具与结果"}">${handling}</td><td data-label="出现"><strong>${formatNumber(operation.occurrence_count)}</strong></td><td class="audit-context" data-label="上下文"><code>${escapeHtml(operation.endpoint || "-")}</code><span>${escapeHtml(operation.session || "-")}</span><code>${escapeHtml(operation.request_id)}</code></td></tr>`;
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
    return `<tr><td><strong>${escapeHtml(record.label)}</strong><span class="muted mono"> ${escapeHtml(record.id.slice(-6))}</span></td><td class="protected-original-cell">${original}</td><td>${escapeHtml(record.subtype)}<br><span class="muted">${escapeHtml(record.kind)}</span></td><td>${escapeHtml(record.scope)}<br><span class="muted">${escapeHtml(record.session)}</span></td><td><span class="badge ${record.display_state}">${stateLabel(record.display_state)}</span></td><td>${formatRelative(record.last_seen_at)}</td><td>${record.auto_expires ? formatRelative(record.expires_at) : "不自动过期"}</td><td>${record.display_state === "active" ? `<button class="row-action danger icon-row-button" type="button" data-revoke="${escapeHtml(record.id)}" aria-label="撤销受保护值 ${escapeHtml(record.label)}" title="撤销受保护值">${iconMarkup("ban")}</button>` : ""}</td></tr>`;
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
  const options = (items) => items.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}${item.is_active ? " · 当前" : ""}</option>`).join("");
  select.innerHTML = `<optgroup label="内置与部署模板">${options(state.detectorCatalog.templates)}</optgroup><optgroup label="用户配置">${options(state.detectorCatalog.configurations)}</optgroup>`;
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
  $("#configuration-name").value = configuration.name;
  $("#configuration-description").value = configuration.description || "";
  $("#configuration-timeout").value = configuration.flow_timeout_ms ?? "";
  $("#configuration-core-guard").checked = configuration.core_guard_enabled;
  for (const id of ["configuration-name", "configuration-description", "configuration-timeout", "configuration-core-guard"]) $("#" + id).disabled = readonly;
  $("#configuration-tags").innerHTML = (configuration.content_tags || []).map((tag) => `<span class="badge neutral">${escapeHtml(tag)}</span>`).join("");
  $("#configuration-status").innerHTML = `${configuration.is_active ? '<span class="badge green">当前启用</span>' : ""}${configuration.readonly ? '<span class="badge neutral">只读模板</span>' : `<span class="muted">Revision ${configuration.revision}</span>`}`;
  $("#core-guard-warning").classList.toggle("is-hidden", configuration.core_guard_enabled);
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
    const rules = module.type === "regex" ? module.config.rules.length : null;
    const unavailable = module.type === "local_model" && module.enabled && module.runtime_available === false;
    const status = !module.enabled ? "disabled" : unavailable ? "unavailable" : module.editable === false ? "managed" : "ready";
    const statusClass = status === "ready" ? "green" : status === "unavailable" ? "red" : "neutral";
    const controls = readonly || module.editable === false ? "" : `<div class="module-actions"><button type="button" title="上移模块" aria-label="上移 ${escapeHtml(module.name)}" data-module-up="${index}" ${index === 0 ? "disabled" : ""}>${iconMarkup("chevron-up")}</button><button type="button" title="下移模块" aria-label="下移 ${escapeHtml(module.name)}" data-module-down="${index}" ${index === modules.length - 1 ? "disabled" : ""}>${iconMarkup("chevron-down")}</button><button type="button" title="编辑模块" aria-label="编辑 ${escapeHtml(module.name)}" data-module-edit="${index}">${iconMarkup("pencil")}</button><button type="button" title="复制模块" aria-label="复制 ${escapeHtml(module.name)}" data-module-copy="${index}">${iconMarkup("copy")}</button><button type="button" class="danger" title="删除模块" aria-label="删除 ${escapeHtml(module.name)}" data-module-delete="${index}">${iconMarkup("trash-2")}</button></div>`;
    return `<div class="module-row"><span class="module-order">${index + 1}</span><div class="module-name"><span class="module-symbol module-symbol-${escapeHtml(module.type)}" aria-hidden="true" title="${escapeHtml(type)}">${iconMarkup(typeIcon)}</span><div><strong>${escapeHtml(module.name)}</strong><span>${escapeHtml(type)} · ${escapeHtml(module.id)}</span></div></div><span class="badge ${statusClass}">${status}</span><span class="module-meta">${rules === null ? escapeHtml(module.failure_mode) : `${rules} 条规则`}</span>${controls}<label class="toggle"><input type="checkbox" data-module-toggle="${index}" ${module.enabled ? "checked" : ""} ${readonly || module.editable === false ? "disabled" : ""} aria-label="启用 ${escapeHtml(module.name)}"><span></span></label></div>`;
  }).join("");
  renderIcons(target);
  $$('[data-module-toggle]', target).forEach((input) => input.addEventListener("change", () => updateModuleEnabled(Number(input.dataset.moduleToggle), input.checked)));
  $$('[data-module-up]', target).forEach((button) => button.addEventListener("click", () => moveModule(Number(button.dataset.moduleUp), -1)));
  $$('[data-module-down]', target).forEach((button) => button.addEventListener("click", () => moveModule(Number(button.dataset.moduleDown), 1)));
  $$('[data-module-edit]', target).forEach((button) => button.addEventListener("click", () => openModuleEditor(Number(button.dataset.moduleEdit))));
  $$('[data-module-copy]', target).forEach((button) => button.addEventListener("click", () => duplicateModule(Number(button.dataset.moduleCopy))));
  $$('[data-module-delete]', target).forEach((button) => button.addEventListener("click", () => removeModule(Number(button.dataset.moduleDelete))));
}

function updateConfigurationFields() {
  if (!state.detectorDraft || state.detectorDraft.readonly) return;
  state.detectorDraft.name = $("#configuration-name").value;
  state.detectorDraft.description = $("#configuration-description").value;
  state.detectorDraft.flow_timeout_ms = $("#configuration-timeout").value ? Number($("#configuration-timeout").value) : null;
  renderDetectorSaveState();
}

function updateCoreGuard(event) {
  if (state.detectorDraft.readonly) return;
  if (!event.target.checked) {
    event.target.checked = true;
    return confirmAction("关闭 APG 核心保护", "这会关闭 APG 标记、已知会话 Secret 和流式边界折叠。占位符签名与 session 校验仍保持开启。", () => {
      state.detectorDraft.core_guard_enabled = false;
      renderDetectorConfiguration();
    });
  }
  state.detectorDraft.core_guard_enabled = true;
  renderDetectorConfiguration();
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
    core_guard_enabled: configuration.core_guard_enabled,
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
  $("#configuration-source").innerHTML = `<option value="">空白配置</option>${all.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}</option>`).join("")}`;
  $("#configuration-source").value = state.detectorConfiguration?.id || "builtin.comprehensive";
  $("#configuration-form [name=name]").value = "新检测配置";
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

function updateModuleEnabled(index, enabled) {
  state.detectorDraft.modules[index].enabled = enabled;
  renderDetectorConfiguration();
}

function moveModule(index, direction) {
  const target = index + direction;
  if (target < 0 || target >= state.detectorDraft.modules.length) return;
  const modules = state.detectorDraft.modules;
  [modules[index], modules[target]] = [modules[target], modules[index]];
  renderDetectorConfiguration();
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
  state.editingModuleIndex = index;
  state.moduleDraft = index === null ? {
    id: randomId("mod"), name: "新检测模块", type: "regex", enabled: true,
    timeout_ms: null, failure_mode: "open", editable: true, config: defaultModuleConfig("regex"),
  } : structuredClone(state.detectorDraft.modules[index]);
  $("#module-form").reset();
  $("#module-error").textContent = "";
  $("#module-modal-title").textContent = index === null ? "新增检测模块" : "编辑检测模块";
  $("#module-form [name=name]").value = state.moduleDraft.name;
  $("#module-type").value = state.moduleDraft.type;
  $("#module-type").disabled = index !== null;
  $("#module-form [name=timeout_ms]").value = state.moduleDraft.timeout_ms ?? "";
  $("#module-form [name=failure_mode]").value = state.moduleDraft.failure_mode || "open";
  renderModuleSpecificFields();
  $("#module-modal").showModal();
}

function defaultModuleConfig(type) {
  if (type === "regex") return {rules: []};
  if (type === "entropy") return {min_length: 20, min_entropy: 3.5, context_window: 80, sensitive_words: ["api_key", "token", "secret", "password", "credential"], false_positive_hints: ["fake", "example", "dummy", "sample"], sensitive_risk: "high", contextless_risk: "medium", sensitive_action: "redact", contextless_action: "warn"};
  if (type === "path") return {detect_unix_home: true, detect_macos_private: true, detect_shell_config: true, detect_windows_user: true, credential_names: [".env", "id_rsa", "id_ed25519", "credentials.json", "kubeconfig"], exclude_patterns: [], path_risk: "medium", credential_risk: "high", path_action: "warn", credential_action: "redact"};
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
      state.moduleDraft.config.rules.push({id: `custom.rule_${randomHex(8)}`, pattern: "", type: "MACHINE_SECRET", subtype: "custom_secret", confidence: 0.9, risk: "high", suggested_action: "redact", flags: [], validators: [], require_validators: [], reject_validators: [], preview_keep: 0, enabled: true, metadata: {source: "webui"}});
      renderModuleSpecificFields();
    });
    $$('[data-remove-rule]', target).forEach((button) => button.addEventListener("click", () => {
      syncModuleSpecificFields();
      state.moduleDraft.config.rules.splice(Number(button.dataset.removeRule), 1);
      renderModuleSpecificFields();
    }));
  } else if (module.type === "entropy") {
    const config = module.config;
    target.innerHTML = `<div class="form-grid specific-grid"><label><span>最小 Token 长度</span><input id="entropy-min-length" type="number" min="8" max="512" value="${config.min_length}"></label><label><span>熵阈值</span><input id="entropy-threshold" type="number" min="0" max="8" step="0.1" value="${config.min_entropy}"></label><label><span>上下文窗口</span><input id="entropy-window" type="number" min="0" max="1024" value="${config.context_window}"></label><label class="full-row"><span>敏感上下文词（逗号分隔）</span><input id="entropy-words" value="${escapeHtml(config.sensitive_words.join(", "))}"></label><label class="full-row"><span>误报提示词（逗号分隔）</span><input id="entropy-hints" value="${escapeHtml(config.false_positive_hints.join(", "))}"></label>${riskActionFields("entropy-sensitive", "敏感上下文", config.sensitive_risk, config.sensitive_action)}${riskActionFields("entropy-contextless", "无上下文", config.contextless_risk, config.contextless_action)}</div>`;
  } else if (module.type === "path") {
    const config = module.config;
    target.innerHTML = `<div class="check-grid"><label><input id="path-unix" type="checkbox" ${config.detect_unix_home ? "checked" : ""}> Unix / macOS Home</label><label><input id="path-private" type="checkbox" ${config.detect_macos_private ? "checked" : ""}> macOS /private</label><label><input id="path-shell" type="checkbox" ${config.detect_shell_config ? "checked" : ""}> Shell 配置目录</label><label><input id="path-windows" type="checkbox" ${config.detect_windows_user ? "checked" : ""}> Windows User 路径</label></div><div class="form-grid specific-grid"><label class="full-row"><span>凭据文件名（逗号分隔）</span><input id="path-credentials" value="${escapeHtml(config.credential_names.join(", "))}"></label><label class="full-row"><span>排除模式（逗号分隔 glob）</span><input id="path-excludes" value="${escapeHtml(config.exclude_patterns.join(", "))}"></label>${riskActionFields("path-normal", "普通路径", config.path_risk, config.path_action)}${riskActionFields("path-credential", "凭据文件", config.credential_risk, config.credential_action)}</div>`;
  } else {
    const config = module.config;
    target.innerHTML = `<div class="form-grid specific-grid"><label><span>运行方式</span><select id="model-adapter"><option value="transformers_token_classification" ${config.adapter === "transformers_token_classification" ? "selected" : ""}>Transformers Token Classification</option><option value="gliner" ${config.adapter === "gliner" ? "selected" : ""}>GLiNER</option></select></label><label><span>置信度阈值</span><input id="model-threshold" type="number" min="0" max="1" step="0.01" value="${config.threshold}"></label><label class="full-row"><span>Hugging Face 模型地址或本地路径</span><input id="model-name" value="${escapeHtml(config.model_name)}"></label><label><span>设备</span><select id="model-device"><option value="cpu">CPU</option><option value="mps">Apple MPS</option><option value="cuda">CUDA</option><option value="cuda:0">CUDA:0</option></select></label>${config.adapter === "gliner" ? `<label class="full-row"><span>实体标签（逗号分隔）</span><input id="model-labels" value="${escapeHtml(config.labels.join(", "))}"></label>` : `<label><span>聚合方式</span><select id="model-aggregation"><option value="simple">Simple</option><option value="first">First</option><option value="average">Average</option><option value="max">Max</option></select></label>`}<div class="model-policy-note full-row">模型按需延迟加载；是否允许下载由部署策略决定。</div></div>`;
    $("#model-device").value = config.device;
    if ($("#model-aggregation")) $("#model-aggregation").value = config.aggregation_strategy;
    $("#model-adapter").addEventListener("change", (event) => { syncModuleSpecificFields(); state.moduleDraft.config.adapter = event.target.value; renderModuleSpecificFields(); });
  }
}

function renderRegexRule(rule, index) {
  return `<section class="rule-editor" data-rule-card="${index}"><div class="rule-editor-heading"><strong>${escapeHtml(rule.id)}</strong><label class="inline-check"><input data-rule-field="enabled" type="checkbox" ${rule.enabled !== false ? "checked" : ""}>启用</label><button class="row-action danger icon-row-button" type="button" data-remove-rule="${index}" aria-label="删除正则规则 ${escapeHtml(rule.id)}" title="删除正则规则">${iconMarkup("trash-2")}</button></div><div class="form-grid"><label><span>规则 ID</span><input data-rule-field="id" value="${escapeHtml(rule.id)}"></label><label><span>Subtype</span><input data-rule-field="subtype" value="${escapeHtml(rule.subtype)}"></label><label class="full-row"><span>正则表达式</span><textarea data-rule-field="pattern" rows="3">${escapeHtml(rule.pattern)}</textarea></label><label><span>数据类型</span><select data-rule-field="type">${selectOptions(["MACHINE_SECRET", "PII", "LOCAL_CONTEXT", "CREDENTIAL_FILE", "UNKNOWN_SECRET_CANDIDATE"], rule.type)}</select></label><label><span>置信度</span><input data-rule-field="confidence" type="number" min="0" max="1" step="0.01" value="${rule.confidence}"></label><label><span>风险</span><select data-rule-field="risk">${selectOptions(["critical", "high", "medium", "low"], rule.risk)}</select></label><label><span>动作</span><select data-rule-field="suggested_action">${selectOptions(["redact", "block", "pseudonymize", "warn", "alias"], rule.suggested_action)}</select></label><label><span>Flags（逗号分隔）</span><input data-rule-field="flags" value="${escapeHtml((rule.flags || []).join(", "))}"></label><label><span>Validators</span><input data-rule-field="validators" value="${escapeHtml((rule.validators || []).join(", "))}"></label><label><span>必须通过的 Validators</span><input data-rule-field="require_validators" value="${escapeHtml((rule.require_validators || []).join(", "))}"></label><label><span>拒绝的 Validators</span><input data-rule-field="reject_validators" value="${escapeHtml((rule.reject_validators || []).join(", "))}"></label></div></section>`;
}

function riskActionFields(prefix, label, risk, action) {
  return `<label><span>${label}风险</span><select id="${prefix}-risk">${selectOptions(["critical", "high", "medium", "low"], risk)}</select></label><label><span>${label}动作</span><select id="${prefix}-action">${selectOptions(["redact", "block", "pseudonymize", "warn", "alias"], action)}</select></label>`;
}

function syncModuleSpecificFields() {
  const module = state.moduleDraft;
  if (module.type === "regex") {
    module.config.rules = $$('[data-rule-card]').map((card) => {
      const field = (name) => card.querySelector(`[data-rule-field="${name}"]`);
      const previous = module.config.rules[Number(card.dataset.ruleCard)] || {};
      return {...previous, id: field("id").value.trim(), subtype: field("subtype").value.trim(), pattern: field("pattern").value, type: field("type").value, confidence: Number(field("confidence").value), risk: field("risk").value, suggested_action: field("suggested_action").value, flags: commaList(field("flags").value), validators: commaList(field("validators").value), require_validators: commaList(field("require_validators").value), reject_validators: commaList(field("reject_validators").value), enabled: field("enabled").checked};
    });
  } else if (module.type === "entropy") {
    module.config = {...module.config, min_length: Number($("#entropy-min-length").value), min_entropy: Number($("#entropy-threshold").value), context_window: Number($("#entropy-window").value), sensitive_words: commaList($("#entropy-words").value), false_positive_hints: commaList($("#entropy-hints").value), sensitive_risk: $("#entropy-sensitive-risk").value, sensitive_action: $("#entropy-sensitive-action").value, contextless_risk: $("#entropy-contextless-risk").value, contextless_action: $("#entropy-contextless-action").value};
  } else if (module.type === "path") {
    module.config = {...module.config, detect_unix_home: $("#path-unix").checked, detect_macos_private: $("#path-private").checked, detect_shell_config: $("#path-shell").checked, detect_windows_user: $("#path-windows").checked, credential_names: commaList($("#path-credentials").value), exclude_patterns: commaList($("#path-excludes").value), path_risk: $("#path-normal-risk").value, path_action: $("#path-normal-action").value, credential_risk: $("#path-credential-risk").value, credential_action: $("#path-credential-action").value};
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
    state.moduleDraft.name = String(form.get("name") || "").trim();
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
  $("#detection-diagnostics").innerHTML = diagnostics.length ? `<div class="diagnostic-heading"><p class="section-kicker">EXECUTION TRACE</p><span>${diagnostics.length} 个步骤</span></div>${diagnostics.map((item, index) => `<div class="diagnostic-row"><span class="diagnostic-order">${index + 1}</span><strong>${escapeHtml(item.id === "apg_core" ? "APG 核心保护" : item.id)}</strong><span>${escapeHtml(item.type)}</span><span>${item.findings} 命中</span><span>${Number(item.elapsed_ms).toFixed(2)} ms</span><b class="badge ${item.status === "ok" ? "green" : ["disabled", "unavailable"].includes(item.status) ? "neutral" : "red"}">${escapeHtml(item.status)}</b></div>`).join("")}` : "";
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
    const confidence = document.createElement("b");
    confidence.textContent = `${Math.round(Math.max(...group.findings.map((finding) => finding.confidence)) * 100)}%`;
    row.append(number, content, confidence);
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
