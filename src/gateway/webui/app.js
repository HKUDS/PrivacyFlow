"use strict";

const API = "/api/admin";
const PAGE_META = {
  overview: ["LOCAL CONTROL PLANE", "概览", "最近 24 小时的网关活动"],
  audit: ["SAFE AUDIT TRAIL", "审计记录", "上行替换与本地还原"],
  protected: ["LOCAL MAPPING REGISTRY", "受保护值", "本地映射生命周期与撤销"],
  detectors: ["DETECTION PIPELINE", "检测器配置", "按检测内容组织的本地模块流水线"],
  "local-models": ["LOCAL MODEL RUNTIME", "本地模型管理", "添加模型后由 APG 自动准备、下载并验证"],
  "agent-connectors": ["LOCAL AGENT CONFIGURATION", "Agent 快速接入", "一键接入 APG，并可完整恢复原配置"],
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
  detectionTooltip: null,
  detectionTooltipMark: null,
  detectionTooltipPinned: false,
  localModels: null,
  capabilities: [],
  buildId: "",
  localModelJobTimer: null,
  localModelTarget: "",
  agentConnectors: null,
  connectorTarget: null,
  connectorRestoreTarget: null,
  connectorMigrationTarget: null,
  connectorMigrationModel: "",
  confirmAction: null,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const DYNAMIC_ICONS = new Set(["arrow-right", "ban", "brain-circuit", "check-circle-2", "circle-x", "copy", "download", "eye", "eye-off", "folder-tree", "gauge", "grip-vertical", "hard-drive", "package-check", "pencil", "plug-zap", "plus", "power", "regex-reference", "rotate-cw", "search", "server-cog", "trash-2", "triangle-alert", "undo-2", "wrench"]);

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
  document.addEventListener("click", (event) => {
    if (state.detectionTooltip && !event.target.closest(".text-highlight")) closeDetectionTooltip();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDetectionTooltip();
  });
  window.addEventListener("resize", closeDetectionTooltip);
  window.addEventListener("scroll", closeDetectionTooltip, true);
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
    if (trigger) {
      state.localModelTarget = trigger.dataset.localModelTarget || "";
      showView(trigger.dataset.view);
      if (state.localModelTarget) requestAnimationFrame(focusLocalModelTarget);
    }
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
  $$('[data-copy-connection]').forEach((button) => button.addEventListener("click", () => copyConnectionValue(button.dataset.copyConnection, button)));
  $("#toggle-agent-key").addEventListener("click", toggleAgentKeyVisibility);
  $("#generate-agent-key").addEventListener("click", () => {
    confirmAction(
      "生成新的 API Key",
      "当前 API Key 将立即失效，请更新所有 Agent 配置。",
      regenerateAgentApiKey,
    );
  });
  $("#upstream-key-form").addEventListener("submit", saveUpstreamApiKey);
  $("#fetch-upstream-models").addEventListener("click", fetchUpstreamModels);
  $("#test-upstream-connection").addEventListener("click", testUpstreamConnection);
  $("#upstream-test-model-select").addEventListener("change", selectUpstreamTestModel);
  $("#show-upstream-model-list").addEventListener("click", showUpstreamModelList);
  $("#upstream-profile-select").addEventListener("change", (event) => switchUpstreamProfile(event.target.value));
  $("#new-upstream-profile").addEventListener("click", () => {
    state.upstreamEditing = true;
    state.upstreamEditingProfileId = "";
    resetUpstreamTestResult();
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
    resetUpstreamTestResult();
    renderUpstreamConfiguration();
    setTimeout(() => (state.upstream?.base_url ? $("#upstream-api-key") : $("#upstream-base-url-input")).focus(), 30);
  });
  $("#cancel-upstream-key").addEventListener("click", () => {
    state.upstreamEditing = false;
    state.upstreamEditingProfileId = "";
    $("#upstream-api-key").value = "";
    $("#upstream-key-error").textContent = "";
    resetUpstreamTestResult();
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
  $("#save-configuration").addEventListener("click", saveDetectorConfiguration);
  $("#delete-configuration").addEventListener("click", deleteDetectorConfiguration);
  $("#add-module").addEventListener("click", () => openModuleEditor(null));
  $("#configuration-form").addEventListener("submit", createDetectorConfiguration);
  $("#module-form").addEventListener("submit", applyModuleDraft);
  $("#module-type").addEventListener("change", async (event) => {
    state.moduleDraft.type = event.target.value;
    state.moduleDraft.config = defaultModuleConfig(event.target.value);
    if (event.target.value === "local_model") {
      $("#module-error").textContent = "";
      try {
        await refreshLocalModelCatalog();
      } catch (error) {
        state.localModels = {models: []};
        $("#module-error").textContent = error.message;
      }
    }
    renderModuleSpecificFields();
  });
  for (const id of ["configuration-name", "configuration-description", "configuration-timeout"]) {
    $("#" + id).addEventListener("input", updateConfigurationFields);
  }
  $("#run-detection").addEventListener("click", runDetection);
  $("#manual-model-form").addEventListener("submit", addManualLocalModel);
  $("#prepare-all-models").addEventListener("click", () => prepareLocalModels([], ["inspect", "runtime", "download", "verify"]));
  $("#local-model-list").addEventListener("click", handleLocalModelAction);
  $("#connector-list").addEventListener("click", handleConnectorAction);
  $("#connector-form").addEventListener("submit", connectAgent);
  $("#connector-model-select").addEventListener("change", syncConnectorModelInput);
  $("#connector-restore-form").addEventListener("submit", confirmConnectorRestore);
  $("#connector-migrate-form").addEventListener("submit", confirmConnectorMigration);
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
  const activeNavigation = $(`.nav-item[data-view="${view}"]`);
  if (activeNavigation && matchMedia("(max-width: 760px)").matches) {
    activeNavigation.scrollIntoView({block: "nearest", inline: "center", behavior: "smooth"});
  }
  const [eyebrow, title, subtitle] = PAGE_META[view];
  $("#page-eyebrow").textContent = eyebrow;
  $("#page-title").textContent = title;
  $("#page-subtitle").textContent = subtitle;
  if (state.connection) loadView(view);
}

async function loadView(view, force = false) {
  const loaders = {overview: loadOverview, audit: loadAudit, protected: loadProtected, detectors: loadDetectors, "local-models": loadLocalModels, "agent-connectors": loadAgentConnectors};
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
    const detail = body.detail;
    const error = new Error(typeof detail === "string" ? detail : detail?.message || "请求失败");
    error.status = response.status;
    error.code = detail?.code;
    error.paths = Array.isArray(detail?.paths) ? detail.paths : [];
    error.requiresConfirmation = detail?.requires_confirmation === true;
    throw error;
  }
  return body;
}

async function loadAgentConnectors() {
  if (!state.capabilities.includes("agent_connectors_v1")) {
    state.agentConnectors = {unsupported: true, connectors: []};
  } else {
    state.agentConnectors = await api("/agent-connectors");
  }
  renderAgentConnectors();
}

function renderAgentConnectors() {
  const list = $("#connector-list");
  if (state.agentConnectors?.unsupported) {
    list.innerHTML = `<div class="connector-empty"><strong>${escapeHtml(uiText("APG 需要重启或更新"))}</strong><span>${escapeHtml(uiText("当前后端不支持 Agent 快速接入。"))}</span></div>`;
    return;
  }
  const connectors = state.agentConnectors?.connectors || [];
  if (!connectors.length) {
    list.innerHTML = `<div class="connector-empty">${escapeHtml(uiText("没有可用的 Agent Connector"))}</div>`;
    return;
  }
  list.innerHTML = connectors.map((connector) => {
    const status = connectorStatus(connector.status);
    const connected = Boolean(connector.connected);
    const disabled = connector.status === "not_installed";
    const actionLabel = connected ? uiText("恢复原配置") : uiText("快速接入");
    const actionIcon = connected ? "undo-2" : "plug-zap";
    const path = (connector.paths || []).join(" · ");
    return `<article class="connector-row ${connector.status === "configuration_changed" ? "has-warning" : ""}">
      <div class="connector-identity">${connectorIconMarkup(connector.id)}<div><strong>${escapeHtml(connector.name)}</strong><span class="mono">${escapeHtml(path)}</span></div></div>
      <div class="connector-details"><span>${escapeHtml(uiText("所需协议"))}</span><strong>${escapeHtml(protocolLabel(connector.protocol))}</strong>${connector.model ? `<small>${escapeHtml(uiText("默认模型"))}: ${escapeHtml(connector.model)}</small>` : ""}${connector.executable ? `<small class="mono">${escapeHtml(connector.executable)}</small>` : connector.detection === "not_found_on_apg_path" ? `<small>${escapeHtml(uiText("命令未出现在 APG 的 PATH 中"))}</small>` : ""}</div>
      <span class="badge ${status.className}">${escapeHtml(status.label)}</span>
      <button class="${connected ? "secondary-button" : "primary-button"} labeled-icon-button" type="button" data-connector-action="${connected ? "restore" : "connect"}" data-connector-id="${escapeHtml(connector.id)}" ${disabled ? "disabled" : ""}>${iconMarkup(actionIcon)}<span>${escapeHtml(actionLabel)}</span></button>
    </article>`;
  }).join("");
  renderIcons(list);
}

function connectorStatus(status) {
  return ({
    not_installed: {label: uiText("未安装"), className: "neutral"},
    ready: {label: uiText("可接入"), className: "blue"},
    connected: {label: uiText("已连接"), className: "green"},
    configuration_changed: {label: uiText("配置已变更"), className: "amber"},
    attention_required: {label: uiText("需要处理"), className: "red"},
  })[status] || {label: uiText("需要处理"), className: "red"};
}

function connectorIconMarkup(connectorId) {
  const icon = ({
    codex: "agent-codex.svg",
    "claude-code": "agent-claude-code.svg",
    "deepseek-harness": "agent-deepseek-harness.svg",
    nanobot: "agent-nanobot.svg",
  })[connectorId];
  if (!icon) return "";
  return `<span class="connector-agent-mark connector-agent-mark-${escapeHtml(connectorId)}" aria-hidden="true"><img src="/ui/assets/${icon}" alt=""></span>`;
}

function protocolLabel(protocol) {
  return UPSTREAM_PROTOCOL_LABELS[protocol] || protocol;
}

async function handleConnectorAction(event) {
  const button = event.target.closest("[data-connector-action]");
  if (!button) return;
  const connector = (state.agentConnectors?.connectors || []).find((item) => item.id === button.dataset.connectorId);
  if (!connector) return;
  button.disabled = true;
  try {
    if (button.dataset.connectorAction === "connect") await openConnectorDialog(connector);
    else await restoreAgent(connector, false);
  } finally {
    if (button.isConnected) button.disabled = false;
  }
}

async function openConnectorDialog(connector) {
  state.connectorTarget = connector;
  $("#connector-agent-name").textContent = connector.name;
  $("#connector-protocol").textContent = protocolLabel(connector.protocol);
  $("#connector-error").textContent = "";
  $("#connector-model-note").textContent = uiText("正在获取上游模型列表…");
  const select = $("#connector-model-select");
  select.innerHTML = `<option value="">${escapeHtml(uiText("正在加载…"))}</option>`;
  select.disabled = true;
  $("#connector-manual-model").value = "";
  $("#connector-manual-model-field").classList.add("is-hidden");
  $("#connector-submit").disabled = true;
  $("#connector-modal").showModal();
  try {
    const result = await api("/upstream-configuration/models", {headers: {"X-APG-Model-Catalog": "rich"}});
    const models = result.ok && Array.isArray(result.models) ? result.models : [];
    const options = result.ok && Array.isArray(result.model_options) && result.model_options.length
      ? result.model_options
      : models.map((id) => ({id, display_name: id, owned_by: ""}));
    if (models.length) {
      select.innerHTML = `<option value="">${escapeHtml(uiText("选择默认模型"))}</option>${renderConnectorModelOptions(options)}`;
      $("#connector-model-note").textContent = `${uiText("已获取")} ${models.length} ${uiText("个模型")}`;
    } else {
      if (connector.id === "deepseek-harness") {
        select.innerHTML = `<option value="">${escapeHtml(uiText("没有可用模型"))}</option>`;
        $("#connector-model-note").textContent = uiText("DeepSeek Harness 需要完整的上游模型目录，当前无法接入。");
        $("#connector-submit").disabled = true;
      } else {
        select.innerHTML = `<option value="__manual__">${escapeHtml(uiText("手动输入模型 ID"))}</option>`;
        $("#connector-model-note").textContent = uiText("上游未返回模型，请手动输入模型 ID。");
      }
    }
  } catch (error) {
    if (connector.id === "deepseek-harness") {
      select.innerHTML = `<option value="">${escapeHtml(uiText("模型目录不可用"))}</option>`;
      $("#connector-model-note").textContent = uiText("DeepSeek Harness 需要完整的上游模型目录，当前无法接入。");
      $("#connector-submit").disabled = true;
    } else {
      select.innerHTML = `<option value="__manual__">${escapeHtml(uiText("手动输入模型 ID"))}</option>`;
      $("#connector-model-note").textContent = uiText("无法获取模型列表，请手动输入模型 ID。");
    }
  } finally {
    select.disabled = false;
    if (connector.id !== "deepseek-harness" || select.value) $("#connector-submit").disabled = false;
    syncConnectorModelInput();
    select.focus();
  }
}

function renderConnectorModelOptions(options) {
  const groups = new Map();
  for (const option of options) {
    const id = String(option?.id || "").trim();
    if (!id) continue;
    const group = String(option?.owned_by || "").trim() || uiText("上游模型");
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(option);
  }
  const render = (option) => {
    const id = String(option.id || "");
    const display = String(option.display_name || id);
    const label = display === id ? id : `${display} · ${id}`;
    return `<option value="${escapeHtml(id)}">${escapeHtml(label)}</option>`;
  };
  if (groups.size <= 1) return [...groups.values()].flat().map(render).join("");
  return [...groups.entries()].map(([group, items]) => `<optgroup label="${escapeHtml(group)}">${items.map(render).join("")}</optgroup>`).join("");
}

function syncConnectorModelInput() {
  const manual = $("#connector-model-select").value === "__manual__";
  $("#connector-manual-model-field").classList.toggle("is-hidden", !manual);
  if (manual) $("#connector-manual-model").focus();
}

async function connectAgent(event) {
  event.preventDefault();
  const connector = state.connectorTarget;
  if (!connector) return;
  const selected = $("#connector-model-select").value;
  const model = (selected === "__manual__" ? $("#connector-manual-model").value : selected).trim();
  if (!model) {
    $("#connector-error").textContent = uiText("请选择或输入模型 ID。");
    return;
  }
  const submit = $("#connector-submit");
  submit.disabled = true;
  $("#connector-error").textContent = "";
  $("#connector-model-note").textContent = uiText("正在验证协议并更新配置…");
  try {
    await api(`/agent-connectors/${encodeURIComponent(connector.id)}/connect`, {method: "POST", body: JSON.stringify({model})});
    $("#connector-modal").close();
    await loadAgentConnectors();
    toast(`${connector.name} ${uiText("已接入 APG")}`);
  } catch (error) {
    if (error.status === 409 && error.code === "CONNECTOR_CONFIG_CONFLICT") {
      state.connectorMigrationTarget = connector;
      state.connectorMigrationModel = model;
      $("#connector-modal").close();
      $("#connector-migrate-agent-name").textContent = connector.name;
      $("#connector-migrate-error").textContent = "";
      $("#connector-migrate-paths").innerHTML = (error.paths || []).map((path) => `<li class="mono">${escapeHtml(path)}</li>`).join("");
      $("#connector-migrate-modal").showModal();
      $("#connector-migrate-submit").focus();
      return;
    }
    $("#connector-error").textContent = connectorErrorMessage(error);
  } finally {
    submit.disabled = false;
  }
}

async function confirmConnectorMigration(event) {
  event.preventDefault();
  const connector = state.connectorMigrationTarget;
  const model = state.connectorMigrationModel;
  if (!connector || !model) return;
  const submit = $("#connector-migrate-submit");
  submit.disabled = true;
  $("#connector-migrate-error").textContent = "";
  try {
    await api(`/agent-connectors/${encodeURIComponent(connector.id)}/connect`, {
      method: "POST",
      body: JSON.stringify({model, confirm_existing_config: true}),
    });
    $("#connector-migrate-modal").close();
    state.connectorMigrationTarget = null;
    state.connectorMigrationModel = "";
    await loadAgentConnectors();
    toast(`${connector.name} ${uiText("已接入 APG")}`);
  } catch (error) {
    $("#connector-migrate-error").textContent = connectorErrorMessage(error);
  } finally {
    submit.disabled = false;
  }
}

async function restoreAgent(connector, confirmExternalChanges) {
  try {
    await api(`/agent-connectors/${encodeURIComponent(connector.id)}/restore`, {
      method: "POST", body: JSON.stringify({confirm_external_changes: confirmExternalChanges}),
    });
    $("#connector-restore-modal").close();
    await loadAgentConnectors();
    toast(`${connector.name} ${uiText("已恢复原配置")}`);
  } catch (error) {
    if (error.status === 409 && error.code === "CONNECTOR_EXTERNAL_CHANGES" && !confirmExternalChanges) {
      state.connectorRestoreTarget = connector;
      $("#connector-restore-error").textContent = "";
      $("#connector-restore-paths").innerHTML = (error.paths || []).map((path) => `<li class="mono">${escapeHtml(path)}</li>`).join("");
      $("#connector-restore-modal").showModal();
      $("#connector-restore-submit").focus();
      return;
    }
    if (confirmExternalChanges) throw error;
    handleError(error);
  }
}

async function confirmConnectorRestore(event) {
  event.preventDefault();
  if (!state.connectorRestoreTarget) return;
  const submit = $("#connector-restore-submit");
  submit.disabled = true;
  try {
    await restoreAgent(state.connectorRestoreTarget, true);
  } catch (error) {
    $("#connector-restore-error").textContent = error.message;
  } finally {
    submit.disabled = false;
  }
}

async function loadLocalModels() {
  await refreshLocalModelCatalog();
  renderLocalModels();
  if (state.localModels.active_job) watchLocalModelJob(state.localModels.active_job);
}

async function refreshLocalModelCatalog() {
  if (!state.capabilities.includes("local_models_v2")) {
    state.localModels = {unsupported: true, setup_allowed: false, models: []};
    return;
  }
  try {
    state.localModels = await api("/local-models");
  } catch (error) {
    if (error.status === 404) {
      state.localModels = {unsupported: true, setup_allowed: false, models: []};
      return;
    }
    throw error;
  }
}

function availableLocalModels() {
  return (state.localModels?.models || []).filter((model) =>
    model.status === "ready"
    && ["transformers_token_classification", "gliner"].includes(model.resolved_adapter)
    && Boolean(model.resolved_device)
  );
}

function renderLocalModels() {
  const data = state.localModels;
  if (!data) return;
  const unsupported = Boolean(data.unsupported);
  const allowed = Boolean(data.setup_allowed);
  const notice = $("#local-model-setup-notice");
  notice.classList.toggle("is-hidden", allowed && !unsupported);
  notice.innerHTML = allowed && !unsupported ? "" : unsupported
    ? `${iconMarkup("rotate-cw")}<div><strong>${escapeHtml(uiText("APG 需要重启或更新"))}</strong><span>${escapeHtml(uiText("当前后端不支持新版本地模型管理，请重启 APG 或更新到相同版本。"))}</span></div>`
    : `${iconMarkup("ban")}<div><strong>${escapeHtml(uiText("本地模型设置已停用"))}</strong><span>${escapeHtml(uiText("安装和下载只允许从绑定到 loopback 的 APG 服务本机执行。"))}</span></div>`;
  if (!allowed || unsupported) renderIcons(notice);
  for (const id of ["local-model-entry", "local-model-list-title", "local-runtime-details"]) {
    const element = document.getElementById(id);
    if (element) element.closest("section")?.classList.toggle("is-hidden", unsupported);
  }
  $("#local-model-entry").classList.toggle("is-hidden", unsupported);
  $(".local-model-list-section").classList.toggle("is-hidden", unsupported);
  $("#local-runtime-details").classList.toggle("is-hidden", unsupported);
  if (unsupported) return;

  const environment = data.environment || {};
  const packages = environment.packages || {};
  const runtimeItems = [
    [uiText("受管 Runtime"), environment.runtime_ready ? environment.runtime_version : uiText("未准备"), environment.runtime_ready ? uiText("可用") : uiText("按需创建"), environment.runtime_ready],
    ["PyTorch", packages.torch?.version || uiText("未安装"), packages.torch?.installed ? uiText("已安装") : uiText("缺少依赖"), packages.torch?.installed],
    ["Transformers", packages.transformers?.version || uiText("未安装"), packages.transformers?.installed ? uiText("已安装") : uiText("缺少依赖"), packages.transformers?.installed],
    ["GLiNER", packages.gliner?.version || uiText("未安装"), packages.gliner?.installed ? uiText("已安装") : uiText("缺少依赖"), packages.gliner?.installed],
    [uiText("模型缓存"), formatBytes(environment.disk_free), uiText("可用空间"), Number(environment.disk_free) > 0],
  ];
  $("#local-runtime-grid").innerHTML = runtimeItems.map(([label, value, note, ready]) => `
    <article class="local-runtime-card ${ready ? "is-ready" : ""}">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
      <small>${escapeHtml(note)}</small>
    </article>
  `).join("");
  $("#local-device-grid").innerHTML = (data.devices || []).map((device) => `
    <article class="local-device-card ${device.available ? "is-ready" : ""}">
      <span class="local-device-icon">${iconMarkup(device.id === "cpu" ? "server-cog" : device.id === "mps" ? "brain-circuit" : "hard-drive")}</span>
      <div><strong>${escapeHtml(device.label)}</strong><small>${escapeHtml(device.available ? uiText("可用") : localDeviceReason(device.reason))}</small></div>
      <span class="badge ${device.available ? "green" : "neutral"}">${escapeHtml(uiText(device.available ? "可用" : "不可用"))}</span>
    </article>
  `).join("");
  renderIcons($("#local-device-grid"));

  const models = data.models || [];
  $("#local-model-empty").classList.toggle("is-hidden", models.length > 0);
  $("#local-model-list").innerHTML = models.map(renderLocalModelCard).join("");
  renderIcons($("#local-model-list"));
  focusLocalModelTarget();
  const pending = models.filter((model) => !model.orphaned && model.status !== "ready");
  $("#prepare-all-models").classList.toggle("is-hidden", pending.length < 2);
  $("#prepare-all-models").disabled = !allowed || Boolean(data.active_job);
  $$("input, select, button", $("#manual-model-form")).forEach((element) => { element.disabled = !allowed; });
  renderLocalModelJob(data.active_job);
}

function renderLocalModelCard(model) {
  const status = localModelStatus(model.status);
  const references = model.references || [];
  const referenceText = references.length
    ? unique(references.map((reference) => reference.configuration_name)).map((name) => uiText(name)).join(uiText("、"))
    : model.orphaned ? uiText("未关联配置") : uiText("手动添加");
  const error = model.last_error?.message ? `<p class="local-model-error">${escapeHtml(localModelErrorMessage(model.last_error.code, model.last_error.message))}</p>` : "";
  const disabled = !state.localModels.setup_allowed;
  const cacheDisabled = disabled || !model.cache_managed || model.active_in_use;
  const displaySize = model.cache_size || model.expected_size;
  const sizeLabel = model.cache_size ? uiText("实际大小") : uiText("预计大小");
  const primaryAction = localModelPrimaryAction(model, disabled);
  const runtimeFault = ["RUNTIME_MISSING", "RUNTIME_CREATE_FAILED", "RUNTIME_UPDATE_FAILED", "COMMAND_FAILED"].includes(model.last_error?.code);
  return `
    <article class="local-model-card" id="local-model-${escapeHtml(model.id)}">
      <div class="local-model-card-heading">
        <span class="local-model-card-icon" aria-hidden="true">${iconMarkup("brain-circuit")}</span>
        <div>
          <strong>${escapeHtml(model.display_name)}</strong>
          <span class="mono">${escapeHtml(model.source)}</span>
        </div>
        <span class="badge ${status.className}">${escapeHtml(status.label)}</span>
      </div>
      <div class="local-model-facts">
        <span><small>${escapeHtml(sizeLabel)}</small><strong>${escapeHtml(displaySize ? formatBytes(displaySize) : uiText("未知"))}</strong></span>
        <span><small>${escapeHtml(uiText("实际设备"))}</small><strong>${escapeHtml((model.resolved_device || uiText("尚未选择")).toUpperCase())}</strong></span>
        <span class="local-model-reference"><small>${escapeHtml(uiText("使用位置"))}</small><strong>${escapeHtml(referenceText)}</strong></span>
      </div>
      ${error}
      <details class="local-model-advanced">
        <summary>${escapeHtml(uiText("高级详情"))}</summary>
        <div class="local-model-advanced-grid">
          <span><small>Repository ID</small><strong class="mono">${escapeHtml(model.source)}</strong></span>
          <span><small>Adapter</small><strong>${escapeHtml(model.resolved_adapter || uiText("尚未识别"))}</strong></span>
          <span><small>${escapeHtml(uiText("提交版本"))}</small><strong class="mono">${escapeHtml(model.resolved_revision ? model.resolved_revision.slice(0, 12) : "-")}</strong></span>
          <span><small>${escapeHtml(uiText("许可证"))}</small><strong>${escapeHtml(model.license || "-")}</strong></span>
          <span class="wide"><small>${escapeHtml(uiText("缓存位置"))}</small><strong class="mono">${escapeHtml(model.cache_location || uiText("尚未下载"))}</strong></span>
        </div>
        <div class="local-model-preferences">
          <label><span>${escapeHtml(uiText("模型类型"))}</span><select data-model-adapter="${escapeHtml(model.id)}"><option value="auto" ${model.adapter_preference === "auto" ? "selected" : ""}>${escapeHtml(uiText("自动识别"))}</option><option value="transformers_token_classification" ${model.adapter_preference === "transformers_token_classification" ? "selected" : ""}>Transformers Token Classification</option><option value="gliner" ${model.adapter_preference === "gliner" ? "selected" : ""}>GLiNER</option></select></label>
          <label><span>${escapeHtml(uiText("计算设备"))}</span><select data-model-device="${escapeHtml(model.id)}"><option value="auto" ${model.device_preference === "auto" ? "selected" : ""}>${escapeHtml(uiText("自动选择"))}</option><option value="cpu" ${model.device_preference === "cpu" ? "selected" : ""}>CPU</option><option value="mps" ${model.device_preference === "mps" ? "selected" : ""}>Apple MPS</option><option value="cuda" ${model.device_preference === "cuda" ? "selected" : ""}>NVIDIA CUDA</option></select></label>
          <button class="secondary-button" type="button" data-local-model-action="save-preferences" data-model-id="${escapeHtml(model.id)}" ${disabled ? "disabled" : ""}>${escapeHtml(uiText("保存设置"))}</button>
        </div>
      </details>
      <div class="local-model-actions">
        ${primaryAction}
        ${runtimeFault ? `<button class="secondary-button labeled-icon-button" type="button" data-local-model-action="runtime" data-model-id="${escapeHtml(model.id)}" ${disabled ? "disabled" : ""}>${iconMarkup("wrench")}<span>${escapeHtml(uiText("修复运行环境"))}</span></button>` : ""}
        ${model.status === "ready" && model.source_type !== "local" ? `<button class="secondary-button icon-action-button" type="button" data-local-model-action="download" data-model-id="${escapeHtml(model.id)}" aria-label="${escapeHtml(uiText("重新下载模型"))}" title="${escapeHtml(uiText("重新下载模型"))}" ${disabled ? "disabled" : ""}>${iconMarkup("download")}</button>` : ""}
        ${model.status === "ready" || model.last_error?.code === "MODEL_VERIFICATION_FAILED" ? `<button class="secondary-button icon-action-button" type="button" data-local-model-action="verify" data-model-id="${escapeHtml(model.id)}" aria-label="${escapeHtml(uiText("重新验证模型"))}" title="${escapeHtml(uiText("重新验证模型"))}" ${disabled ? "disabled" : ""}>${iconMarkup("rotate-cw")}</button>` : ""}
        ${model.cache_managed ? `<button class="secondary-button danger-text icon-action-button" type="button" data-local-model-action="cache" data-model-id="${escapeHtml(model.id)}" aria-label="${escapeHtml(uiText("清理模型缓存"))}" title="${escapeHtml(uiText(model.active_in_use ? "当前启用配置正在使用该模型" : "清理模型缓存"))}" ${cacheDisabled ? "disabled" : ""}>${iconMarkup("trash-2")}</button>` : ""}
        ${model.manual ? `<button class="secondary-button danger-text icon-action-button" type="button" data-local-model-action="delete" data-model-id="${escapeHtml(model.id)}" aria-label="${escapeHtml(uiText("移除手动模型"))}" title="${escapeHtml(uiText("移除手动模型"))}" ${disabled ? "disabled" : ""}>${iconMarkup("ban")}</button>` : ""}
      </div>
    </article>
  `;
}

function localModelPrimaryAction(model, disabled) {
  if (model.status === "ready") return "";
  if (model.status === "needs_input") {
    return `<button class="primary-button labeled-icon-button" type="button" data-local-model-action="open-settings" data-model-id="${escapeHtml(model.id)}" ${disabled ? "disabled" : ""}>${iconMarkup("wrench")}<span>${escapeHtml(uiText("选择模型类型"))}</span></button>`;
  }
  const label = model.status === "failed" ? uiText("重试") : uiText("准备");
  return `<button class="primary-button labeled-icon-button" type="button" data-local-model-action="prepare" data-model-id="${escapeHtml(model.id)}" ${disabled ? "disabled" : ""}>${iconMarkup("package-check")}<span>${escapeHtml(label)}</span></button>`;
}

function localModelStatus(value) {
  return ({
    not_prepared: {label: uiText("未准备"), className: "neutral"},
    inspecting: {label: uiText("检查中"), className: "blue"},
    preparing_runtime: {label: uiText("准备运行环境"), className: "blue"},
    downloading: {label: uiText("下载中"), className: "blue"},
    verifying: {label: uiText("验证中"), className: "blue"},
    ready: {label: uiText("可用"), className: "green"},
    needs_input: {label: uiText("需要选择模型类型"), className: "amber"},
    failed: {label: uiText("失败"), className: "red"},
  })[value] || {label: uiText(value || "未准备"), className: "neutral"};
}

function focusLocalModelTarget() {
  if (!state.localModelTarget) return;
  const target = document.getElementById(`local-model-${state.localModelTarget}`);
  if (!target) return;
  state.localModelTarget = "";
  target.scrollIntoView({behavior: "smooth", block: "center"});
}

function localDeviceReason(value) {
  return ({
    mps_not_supported: uiText("当前设备不支持 Apple MPS"),
    cuda_not_detected: uiText("未检测到 CUDA"),
    device_probe_failed: uiText("设备检测失败"),
  })[value] || uiText("当前不可用");
}

function localModelErrorMessage(code, fallback) {
  const message = ({
    LOCAL_MODEL_SETUP_LOCAL_ONLY: "安装和下载只能从 APG 服务本机执行。",
    INVALID_MODEL_SOURCE: "请输入有效的 Hugging Face 仓库 ID 或本地模型目录。",
    INVALID_SOURCE_TYPE: "请选择有效的模型来源。",
    INVALID_ADAPTER: "请选择受支持的模型运行方式。",
    INVALID_DEVICE: "请选择受支持的计算设备。",
    MODEL_TYPE_REQUIRED: "无法可靠识别模型类型，请在高级设置中明确选择。",
    MODEL_TYPE_INCOMPATIBLE: "选择的模型类型与模型元数据不匹配。",
    MODEL_INSPECTION_FAILED: "无法读取 Hugging Face 模型元数据，请检查地址与网络。",
    MODEL_CONFIG_MISSING: "模型目录缺少 config.json。",
    MODEL_CONFIG_INVALID: "模型目录中的 config.json 无效。",
    MODEL_WEIGHTS_MISSING: "模型目录中没有可用的权重文件。",
    REMOTE_CODE_UNSUPPORTED: "该模型需要执行远程自定义代码，APG 不支持。",
    DEVICE_UNAVAILABLE: "明确选择的计算设备当前不可用。",
    RUNTIME_MISSING: "模型运行环境尚未准备。",
    RUNTIME_CREATE_FAILED: "无法创建受管模型运行环境。",
    RUNTIME_UPDATE_FAILED: "更新受管模型运行环境失败，原有 Runtime 未受影响。",
    MODEL_VERIFICATION_FAILED: "模型加载或最小推理验证失败。",
    MODEL_NOT_READY: "模型尚未准备完成。",
    LOCAL_MODEL_MISSING: "指定的本地模型目录不存在。",
    LOCAL_PATH_NOT_MANAGED: "APG 不会删除用户自己的本地模型目录。",
    MODEL_IN_ACTIVE_USE: "当前启用配置正在使用该模型，不能清理缓存。",
    MODEL_NOT_DOWNLOADED: "请先下载或定位模型，再执行验证。",
    DEPENDENCIES_MISSING: "请先安装该模型所需的运行依赖。",
    DISK_SPACE_LOW: "模型缓存至少需要 512 MiB 可用磁盘空间。",
    CUDA_NOT_DETECTED: "未检测到可用的 NVIDIA CUDA 驱动。",
    CUDA_VERSION_UNSUPPORTED: "当前 CUDA 驱动不在 APG 自动安装支持范围内。",
    CUDA_UNSUPPORTED_PLATFORM: "macOS 不支持 NVIDIA CUDA，请选择 CPU 或 Apple MPS。",
    JOB_IN_PROGRESS: "已有本地模型任务正在运行，请等待它完成。",
    NO_MODELS: "当前没有可准备的本地模型。",
    COMMAND_TIMEOUT: "本地模型操作超时。",
    COMMAND_START_FAILED: "无法启动本地模型操作。",
    COMMAND_FAILED: "依赖安装、模型下载或验证失败。",
    DOWNLOAD_RESULT_INVALID: "模型下载结果无效。",
    DOWNLOAD_PATH_INVALID: "下载结果不在 APG 管理的模型缓存中。",
  })[code] || fallback || "本地模型操作失败";
  return uiText(message);
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${new Intl.NumberFormat(displayLocale(), {maximumFractionDigits: index ? 1 : 0}).format(bytes / (1024 ** index))} ${units[index]}`;
}

async function addManualLocalModel(event) {
  event.preventDefault();
  const button = $("button[type=submit]", event.currentTarget);
  button.disabled = true;
  $("#manual-model-error").textContent = "";
  try {
    const result = await api("/local-models", {
      method: "POST",
      body: JSON.stringify({
        source_type: "auto",
        source: $("#manual-model-source").value.trim(),
        adapter: $("#manual-model-adapter").value,
        device: $("#manual-model-device").value,
        prepare: true,
      }),
    });
    $("#manual-model-source").value = "";
    await loadLocalModels();
    if (result.job) {
      state.localModels.active_job = result.job;
      renderLocalModelJob(result.job);
      watchLocalModelJob(result.job);
    }
    toast(uiText("模型已添加，正在准备"));
  } catch (error) {
    $("#manual-model-error").textContent = error.status === 404
      ? uiText("APG 需要重启或更新")
      : localModelErrorMessage(error.code, error.message);
  } finally {
    button.disabled = !state.localModels?.setup_allowed;
  }
}

async function handleLocalModelAction(event) {
  const button = event.target.closest("[data-local-model-action]");
  if (!button) return;
  const modelId = button.dataset.modelId;
  const action = button.dataset.localModelAction;
  if (action === "prepare") return prepareLocalModels([modelId], ["inspect", "runtime", "download", "verify"]);
  if (action === "runtime") return prepareLocalModels([modelId], ["runtime"], true);
  if (action === "download") return prepareLocalModels([modelId], ["download"], true);
  if (action === "verify") return prepareLocalModels([modelId], ["verify"]);
  if (action === "open-settings") {
    const card = button.closest(".local-model-card");
    const details = $(".local-model-advanced", card);
    details.open = true;
    $(`[data-model-adapter="${CSS.escape(modelId)}"]`, card)?.focus();
    return;
  }
  if (action === "save-preferences") return saveLocalModelPreferences(modelId, button.closest(".local-model-card"));
  if (action === "cache") {
    return confirmAction("清理模型缓存", "将删除 APG 管理的模型文件，但不会删除检测器配置。", () => deleteLocalModelCache(modelId));
  }
  if (action === "delete") {
    return confirmAction("移除手动模型", "该模型将从管理清单中移除，已下载的共享缓存不会自动删除。", () => deleteManualLocalModel(modelId));
  }
}

async function saveLocalModelPreferences(modelId, card) {
  const model = (state.localModels.models || []).find((item) => item.id === modelId);
  if (!model) return;
  const adapter = $(`[data-model-adapter="${CSS.escape(modelId)}"]`, card).value;
  const device = $(`[data-model-device="${CSS.escape(modelId)}"]`, card).value;
  try {
    await api("/local-models", {
      method: "POST",
      body: JSON.stringify({
        source_type: model.source_type,
        source: model.source,
        adapter,
        device,
      }),
    });
    await loadLocalModels();
    toast(uiText("模型设置已保存"));
  } catch (error) {
    toast(localModelErrorMessage(error.code, error.message), true);
  }
}

async function prepareLocalModels(modelIds, stages, force = false) {
  try {
    const job = await api("/local-models/prepare", {
      method: "POST",
      body: JSON.stringify({model_ids: modelIds, stages, force}),
    });
    state.localModels.active_job = job;
    renderLocalModelJob(job);
    watchLocalModelJob(job);
  } catch (error) {
    toast(localModelErrorMessage(error.code, error.message), true);
  }
}

async function deleteLocalModelCache(modelId) {
  await api(`/local-models/${encodeURIComponent(modelId)}/cache`, {method: "DELETE"});
  await loadLocalModels();
  toast("模型缓存已清理");
}

async function deleteManualLocalModel(modelId) {
  await api(`/local-models/${encodeURIComponent(modelId)}`, {method: "DELETE"});
  await loadLocalModels();
  toast("手动模型已移除");
}

function watchLocalModelJob(job) {
  clearTimeout(state.localModelJobTimer);
  if (!job || !["queued", "running"].includes(job.status)) return;
  state.localModelJobTimer = setTimeout(async () => {
    try {
      const next = await api(`/local-model-jobs/${encodeURIComponent(job.id)}`);
      state.localModels.active_job = next;
      renderLocalModelJob(next);
      if (["queued", "running"].includes(next.status)) watchLocalModelJob(next);
      else {
        await loadLocalModels();
        toast(next.status === "succeeded" ? "本地模型准备完成" : localModelErrorMessage(next.error_code, next.message || "本地模型准备失败"), next.status !== "succeeded");
      }
    } catch (error) {
      handleError(error);
    }
  }, 900);
}

function renderLocalModelJob(job) {
  const target = $("#local-model-job");
  target.classList.toggle("is-hidden", !job);
  if (!job) {
    target.innerHTML = "";
    return;
  }
  const stages = {
    queued: uiText("等待开始"),
    inspect: uiText("检查模型"),
    runtime: uiText("准备运行环境"),
    download: uiText("下载模型"),
    verify: uiText("验证模型"),
    completed: uiText("准备完成"),
    needs_input: uiText("需要用户选择"),
    failed: uiText("准备失败"),
  };
  const downloaded = Number(job.bytes_downloaded || 0);
  const total = Number(job.total_bytes || 0);
  const transfer = downloaded
    ? `${formatBytes(downloaded)}${total ? ` / ${formatBytes(total)}` : ""}${job.speed_bps ? ` · ${formatBytes(job.speed_bps)}/s` : ""}`
    : "";
  target.innerHTML = `
    <div><strong>${escapeHtml(stages[job.stage] || job.stage)}</strong><span>${escapeHtml(job.message || transfer || `${job.progress || 0}%`)}</span></div>
    <progress max="100" value="${Number(job.progress || 0)}">${Number(job.progress || 0)}%</progress>
  `;
}

async function loadOverview() {
  const [data, connection, upstream, privacyControl] = await Promise.all([
    api("/overview"),
    api("/connection"),
    api("/upstream-configuration"),
    api("/privacy-control"),
  ]);
  state.connection = connection;
  state.capabilities = Array.isArray(data.capabilities) ? data.capabilities : [];
  state.buildId = data.build_id || "";
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
  $("#upstream-profile-select").innerHTML = profiles.length
    ? profiles.map((profile) => `<option value="${escapeHtml(profile.id)}"${profile.id === state.upstreamSelectedProfileId ? " selected" : ""}>${escapeHtml(uiText(`${profile.name}${profile.active ? "（当前）" : ""}`))}</option>`).join("")
    : '<option value="">暂无配置</option>';
  $("#delete-upstream-profile").disabled = !selected || !selected.persisted;
  $("#fetch-upstream-models").disabled = !selected?.active;
  $("#test-upstream-connection").disabled = !selected?.active;
  if (selected && !selected.active) {
    resetUpstreamTestResult("请先启用所选配置后再测试。");
  }
  const editingProfile = state.upstreamEditingProfileId
    ? profiles.find((profile) => profile.id === state.upstreamEditingProfileId)
    : null;
  const showingDefaults = editing && editingProfile && !editingProfile.persisted;
  const nameInput = $("#upstream-profile-name");
  const baseUrlInput = $("#upstream-base-url-input");
  nameInput.value = editing && !showingDefaults ? (editingProfile?.name || "") : "";
  nameInput.placeholder = showingDefaults ? (editingProfile.name || "例如：Anthropic 生产环境") : "例如：Anthropic 生产环境";
  baseUrlInput.value = editing && !showingDefaults ? (editingProfile?.base_url || "") : "";
  baseUrlInput.placeholder = showingDefaults ? (editingProfile.base_url || "https://api.example.com/v1") : "https://api.example.com/v1";
  const endpointOverrides = editing && !showingDefaults ? (editingProfile?.endpoint_overrides || {}) : {};
  $("#upstream-endpoint-openai-chat-completions").value = endpointOverrides.openai_chat_completions || "";
  $("#upstream-endpoint-openai-responses").value = endpointOverrides.openai_responses || "";
  $("#upstream-endpoint-anthropic-messages").value = endpointOverrides.anthropic_messages || "";
  $("#upstream-models-url").value = editing && !showingDefaults ? (editingProfile?.models_url || "") : "";
  $("#upstream-user-agent").value = editing && !showingDefaults ? (editingProfile?.user_agent || "") : "";
  $("#upstream-key-form").classList.toggle("is-hidden", !editing);
  $("#upstream-connectivity-test").classList.toggle("is-hidden", !configured || editing);
  $("#edit-upstream-key").classList.toggle("is-hidden", !configured || editing);
  $("#cancel-upstream-key").classList.toggle("is-hidden", !configured);
}

async function saveUpstreamApiKey(event) {
  event.preventDefault();
  const baseUrlInput = $("#upstream-base-url-input");
  const name = $("#upstream-profile-name").value.trim();
  const input = $("#upstream-api-key");
  const baseUrl = baseUrlInput.value.trim().replace(/\/+$/, "");
  const apiKey = input.value.trim();
  if (!name) {
    $("#upstream-key-error").textContent = "请输入配置名称。";
    $("#upstream-profile-name").focus();
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
    const endpointOverrides = {
      openai_chat_completions: $("#upstream-endpoint-openai-chat-completions").value.trim(),
      openai_responses: $("#upstream-endpoint-openai-responses").value.trim(),
      anthropic_messages: $("#upstream-endpoint-anthropic-messages").value.trim(),
    };
    const modelsUrl = $("#upstream-models-url").value.trim();
    const userAgent = $("#upstream-user-agent").value.trim();
    state.upstream = await api("/upstream-configuration", {
      method: "PUT",
      body: JSON.stringify({
        profile_id: state.upstreamEditingProfileId,
        name,
        base_url: baseUrl,
        api_key: apiKey,
        endpoint_overrides: endpointOverrides,
        provider_type: "custom",
        models_url: modelsUrl,
        user_agent: userAgent,
      }),
    });
    input.value = "";
    state.upstreamEditing = false;
    state.upstreamEditingProfileId = "";
    state.upstreamSelectedProfileId = state.upstream.active_profile_id || "";
    resetUpstreamTestResult();
    renderUpstreamConfiguration();
    await refreshPrivacyControl();
    toast(state.upstream.persistent ? "上游连接配置已安全保存并启用" : "上游连接配置已在当前进程中启用");
  } catch (error) {
    $("#upstream-key-error").textContent = error.message || "保存失败。";
  } finally {
    button.disabled = false;
  }
}

async function fetchUpstreamModels() {
  const selected = selectedUpstreamProfile();
  if (!selected?.active) {
    resetUpstreamTestResult("请先启用所选配置后再测试。", "is-error");
    return;
  }
  const fetchButton = $("#fetch-upstream-models");
  const testButton = $("#test-upstream-connection");
  const resultNode = $("#upstream-test-result");
  const profileId = selected.id;
  fetchButton.disabled = true;
  testButton.disabled = true;
  resultNode.className = "upstream-test-result is-running";
  resultNode.textContent = uiText("正在从当前上游获取模型列表…");
  try {
    const result = await api("/upstream-configuration/models");
    if (selectedUpstreamProfile()?.id !== profileId) return;
    const options = Array.isArray(result.models) ? result.models : [];
    setUpstreamModelOptions(options);
    const trace = Object.entries(result.upstream_trace_headers || {}).map(([key, value]) => `${key}: ${value}`).join(" · ");
    const target = `${uiText("实际端点")} ${result.target_endpoint}`;
    if (result.ok && options.length) {
      resultNode.className = "upstream-test-result is-success";
      const truncated = result.truncated ? ` · ${uiText("仅显示前 500 个模型")}` : "";
      resultNode.textContent = `${uiText("已获取")} ${options.length} ${uiText("个模型，点击下拉列表选择")} · ${result.latency_ms} ms · ${target}${truncated}${trace ? ` · ${trace}` : ""}`;
      $("#upstream-test-model-select").focus();
    } else if (result.ok) {
      resultNode.className = "upstream-test-result";
      resultNode.textContent = `${uiText("上游未返回可用模型，请手动输入模型名称")} · ${result.latency_ms} ms · ${target}${trace ? ` · ${trace}` : ""}`;
    } else {
      const error = result.error || {};
      const status = result.status_code ? `HTTP ${result.status_code}` : uiText("未收到 HTTP 响应");
      const reason = [error.code, error.type, error.message].filter(Boolean).join(" · ");
      resultNode.className = "upstream-test-result is-error";
      resultNode.textContent = `${uiText("获取模型列表失败")} · ${status} · ${result.latency_ms} ms · ${target}${reason ? ` · ${reason}` : ""}${trace ? ` · ${trace}` : ""}`;
    }
  } catch (error) {
    resultNode.className = "upstream-test-result is-error";
    resultNode.textContent = error.message || uiText("获取模型列表失败");
  } finally {
    const active = Boolean(selectedUpstreamProfile()?.active);
    fetchButton.disabled = !active;
    testButton.disabled = !active;
  }
}

async function testUpstreamConnection() {
  const selected = selectedUpstreamProfile();
  if (!selected?.active) {
    resetUpstreamTestResult("请先启用所选配置后再测试。", "is-error");
    return;
  }
  const modelControl = activeUpstreamModelControl();
  const model = modelControl.value.trim();
  const button = $("#test-upstream-connection");
  const resultNode = $("#upstream-test-result");
  if (!model) {
    resultNode.className = "upstream-test-result is-error";
    resultNode.textContent = uiText("请输入测试模型。此字段仅用于本次测试，不会保存。");
    modelControl.focus();
    return;
  }
  button.disabled = true;
  resultNode.className = "upstream-test-result is-running";
  resultNode.textContent = uiText("正在自动测试三种 API 格式…");
  try {
    const test = await api("/upstream-configuration/test", {
      method: "POST",
      body: JSON.stringify({model}),
    });
    renderUpstreamProtocolResults(test.results || []);
  } catch (error) {
    resultNode.className = "upstream-test-result is-error";
    resultNode.textContent = error.message || uiText("测试失败。");
  } finally {
    button.disabled = false;
  }
}

function renderUpstreamProtocolResults(results) {
  const resultNode = $("#upstream-test-result");
  resultNode.className = "upstream-test-result upstream-protocol-results";
  resultNode.innerHTML = results.map((result) => {
    const error = result.error || {};
    const status = result.status_code ? `HTTP ${result.status_code}` : uiText("未收到 HTTP 响应");
    const target = `${uiText("实际端点")} ${result.target_endpoint || "—"}`;
    const trace = Object.entries(result.upstream_trace_headers || {}).map(([key, value]) => `${key}: ${value}`).join(" · ");
    const mismatch = error.code === "APG_UPSTREAM_PROTOCOL_MISMATCH"
      ? uiText("HTTP 成功，但响应结构不符合该 API 格式。")
      : "";
    const reason = mismatch || [error.code, error.type, error.message].filter(Boolean).join(" · ");
    return `<div class="upstream-protocol-result ${result.ok ? "is-success" : "is-error"}">
      <div class="upstream-protocol-result-heading">
        <span>${iconMarkup(result.ok ? "check-circle-2" : "circle-x")}<strong>${escapeHtml(UPSTREAM_PROTOCOL_LABELS[result.protocol] || result.protocol)}</strong></span>
        <em>${escapeHtml(uiText(result.ok ? "可用" : "不可用"))}</em>
      </div>
      <small>${escapeHtml(`${status} · ${result.latency_ms} ms · ${target}${trace ? ` · ${trace}` : ""}`)}</small>
      ${reason ? `<small class="upstream-protocol-result-error">${escapeHtml(reason)}</small>` : ""}
    </div>`;
  }).join("");
  renderIcons(resultNode);
}

function resetUpstreamTestResult(message = "", className = "") {
  const resultNode = $("#upstream-test-result");
  resultNode.className = `upstream-test-result${className ? ` ${className}` : ""}`;
  resultNode.textContent = message ? uiText(message) : "";
  setUpstreamModelOptions([]);
}

function setUpstreamModelOptions(models) {
  const picker = $("#upstream-model-picker");
  const input = $("#upstream-test-model");
  const select = $("#upstream-test-model-select");
  const selectShell = $("#upstream-model-select-shell");
  const listToggle = $("#show-upstream-model-list");
  const current = input.value.trim();
  picker.dataset.hasModels = String(models.length > 0);
  select.innerHTML = models.length
    ? `<option value="" disabled>${escapeHtml(uiText("请选择测试模型"))}</option><option value="__manual__">${escapeHtml(uiText("手动输入模型名称…"))}</option>${models.map((model) => `<option value="${escapeHtml(model)}">${escapeHtml(model)}</option>`).join("")}`
    : "";
  if (!models.length) {
    input.hidden = false;
    selectShell.hidden = true;
    listToggle.hidden = true;
    return;
  }
  select.value = models.includes(current) ? current : "";
  input.hidden = true;
  selectShell.hidden = false;
  listToggle.hidden = true;
}

function selectUpstreamTestModel(event) {
  const select = event.currentTarget;
  if (select.value === "__manual__") {
    const input = $("#upstream-test-model");
    input.hidden = false;
    $("#upstream-model-select-shell").hidden = true;
    $("#show-upstream-model-list").hidden = false;
    input.focus();
    return;
  }
  if (select.value) $("#upstream-test-model").value = select.value;
}

function showUpstreamModelList() {
  const input = $("#upstream-test-model");
  const select = $("#upstream-test-model-select");
  const available = [...select.options].map((option) => option.value);
  select.value = available.includes(input.value.trim()) ? input.value.trim() : "";
  input.hidden = true;
  $("#upstream-model-select-shell").hidden = false;
  $("#show-upstream-model-list").hidden = true;
  select.focus();
}

function activeUpstreamModelControl() {
  return $("#upstream-model-select-shell").hidden ? $("#upstream-test-model") : $("#upstream-test-model-select");
}

function selectedUpstreamProfile() {
  return (state.upstream?.profiles || []).find((profile) => profile.id === state.upstreamSelectedProfileId) || null;
}

async function activateSelectedUpstreamProfile() {
  const profile = selectedUpstreamProfile();
  if (!profile || profile.active) return;
  const select = $("#upstream-profile-select");
  select.disabled = true;
  try {
    state.upstream = await api(`/upstream-configuration/${encodeURIComponent(profile.id)}/activate`, {method: "POST"});
    state.upstreamSelectedProfileId = state.upstream.active_profile_id || "";
    resetUpstreamTestResult();
    renderUpstreamConfiguration();
    await refreshPrivacyControl();
    toast(`${uiText("已切换上游配置")}：${profile.name}`);
  } catch (error) {
    state.upstreamSelectedProfileId = state.upstream?.active_profile_id || "";
    renderUpstreamConfiguration();
    handleError(error);
  } finally {
    select.disabled = false;
  }
}

function switchUpstreamProfile(profileId) {
  state.upstreamSelectedProfileId = profileId;
  resetUpstreamTestResult();
  renderUpstreamConfiguration();
  activateSelectedUpstreamProfile();
}

async function deleteSelectedUpstreamProfile() {
  const profile = selectedUpstreamProfile();
  if (!profile) return;
  state.upstream = await api(`/upstream-configuration/${encodeURIComponent(profile.id)}`, {method: "DELETE"});
  state.upstreamSelectedProfileId = state.upstream.active_profile_id || state.upstream.profiles?.[0]?.id || "";
  state.upstreamEditing = !state.upstream.profiles?.length;
  state.upstreamEditingProfileId = "";
  resetUpstreamTestResult();
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

async function copyConnectionValue(kind, button) {
  const inputs = {
    "api-key": $("#agent-api-key"),
    "openai-base-url": $("#agent-openai-base-url"),
    "anthropic-base-url": $("#agent-anthropic-base-url"),
  };
  const input = inputs[kind];
  if (!input.value) return;
  await copyText(input.value);
  flashCopied(button);
  toast(kind === "api-key" ? "API Key 已复制" : "Base URL 已复制");
}

function flashCopied(button) {
  if (!button) return;
  clearTimeout(flashCopied.timers.get(button));
  button.classList.add("is-copied");
  button.innerHTML = iconMarkup("check-circle-2");
  renderIcons(button);
  flashCopied.timers.set(button, setTimeout(() => {
    button.classList.remove("is-copied");
    button.innerHTML = iconMarkup("copy");
    renderIcons(button);
  }, 1400));
}
flashCopied.timers = new WeakMap();

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
  const labels = Object.fromEntries(["critical", "high", "medium", "low"].map((key) => [key, riskLabel(key)]));
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
    return `<tr class="audit-operation-row ${failed ? "has-failure" : ""}"><td data-label="${escapeHtml(labels.time)}">${formatDateTime(operation.timestamp)}</td><td class="audit-map-cell" data-label="${escapeHtml(labels.mapping)}"><div class="operation-map audit-list-map">${mapping}</div><div class="operation-metadata"><span class="mapping-id">${escapeHtml(operation.protected_value_id)}</span>${operation.value_state !== "active" ? `<span class="operation-state-inline">${escapeHtml(valueStateLabel(operation.value_state))}</span>` : ""}</div></td><td class="audit-type" data-label="${escapeHtml(labels.type)}"><strong>${escapeHtml(operation.subtype || operation.kind || "-")}</strong><span class="badge ${escapeHtml(operation.risk || "low")}">${escapeHtml(riskLabel(operation.risk || "low"))}</span></td><td class="audit-handling" data-label="${escapeHtml(labels.handling)}">${handling}</td><td data-label="${escapeHtml(labels.count)}"><strong>${formatNumber(operation.occurrence_count)}</strong></td><td class="audit-context" data-label="${escapeHtml(labels.context)}"><code>${escapeHtml(operation.endpoint || "-")}</code><span>${escapeHtml(operation.session || "-")}</span><code>${escapeHtml(operation.request_id)}</code></td></tr>`;
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
  const upstreamTrace = Object.entries(detail.upstream_trace_headers || {})
    .map(([key, value]) => `${key}: ${value}`)
    .join(" · ");
  const fields = [
    ["时间", formatDateTime(detail.timestamp)], ["端点", detail.endpoint || "-"], ["请求", detail.request_id],
    ["会话", detail.session || "-"], ["状态", auditStatusLabel(status)], ["原文", detail.raw_values_included ? "临时显示" : "已隐藏"],
  ];
  if (detail.upstream_error_code || detail.upstream_error_type) {
    fields.push(["上游错误", detail.upstream_error_code || detail.upstream_error_type]);
  }
  if (detail.upstream_error_event) fields.push(["上游事件", detail.upstream_error_event]);
  if (upstreamTrace) fields.push(["上游请求标识", upstreamTrace]);
  let content = `<dl class="detail-grid">${fields.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>`).join("")}</dl>`;
  content += renderOperationSection("上行替换", "UPSTREAM REPLACEMENTS", detail.replacements, "replacement");
  content += renderOperationSection("本地还原", "LOCAL MATERIALIZATIONS", detail.materializations, "materialization");
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
    riskLabel(operation.risk),
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
  const upstreamTrace = Object.entries(event.upstream_trace_headers || {}).map(([key, value]) => `${key}: ${value}`).join(" · ");
  const fields = [["时间", formatDateTime(event.timestamp)],["阶段", event.phase],["端点", event.endpoint || "-"],["请求", event.request_id || "-"],["会话", event.session],["状态", event.termination || event.status || "recorded"]];
  if (event.upstream_error_code || event.upstream_error_type) fields.push(["上游错误", event.upstream_error_code || event.upstream_error_type]);
  if (event.upstream_error_event) fields.push(["上游事件", event.upstream_error_event]);
  if (upstreamTrace) fields.push(["上游请求标识", upstreamTrace]);
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
    return confirmAction(uiText("放弃未保存更改"), uiText("切换配置将丢弃当前草稿并立即启用所选配置。"), () => activateDetectorConfiguration(configurationId));
  }
  activateDetectorConfiguration(configurationId);
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
  setIconButton($("#duplicate-configuration"), "copy", readonly ? "复制并编辑检测器配置" : "复制检测器配置");
  $("#save-configuration").disabled = readonly || !detectorConfigurationDirty();
  $("#delete-configuration").disabled = readonly;
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
    const statusMarkup = status === "unavailable"
      ? `<button class="badge ${statusClass} module-status-link" type="button" data-view="local-models" data-local-model-target="${escapeHtml(module.local_model_id || "")}" title="打开本地模型管理">${escapeHtml(moduleStatusLabel(status))}</button>`
      : `<span class="badge ${statusClass}">${escapeHtml(moduleStatusLabel(status))}</span>`;
    const editable = !readonly && module.editable !== false;
    const dragControl = editable ? `<button class="module-drag-handle" type="button" title="拖动排序" aria-label="拖动排序 ${escapeHtml(module.name)}" aria-keyshortcuts="Alt+ArrowUp Alt+ArrowDown" aria-grabbed="false" data-module-drag="${index}">${iconMarkup("grip-vertical")}</button>` : `<span class="module-drag-spacer" aria-hidden="true"></span>`;
    const controls = editable ? `<div class="module-actions"><button type="button" title="编辑模块" aria-label="编辑 ${escapeHtml(module.name)}" data-module-edit="${index}">${iconMarkup("pencil")}</button><button type="button" title="复制模块" aria-label="复制 ${escapeHtml(module.name)}" data-module-copy="${index}">${iconMarkup("copy")}</button><button type="button" class="danger" title="删除模块" aria-label="删除 ${escapeHtml(module.name)}" data-module-delete="${index}">${iconMarkup("trash-2")}</button></div>` : "";
    return `<div class="module-row" data-module-row="${index}">${dragControl}<span class="module-order">${index + 1}</span><div class="module-name"><span class="module-symbol module-symbol-${escapeHtml(module.type)}" aria-hidden="true" title="${escapeHtml(type)}">${iconMarkup(typeIcon)}</span><div><strong>${escapeHtml(module.name)}</strong><span>${escapeHtml(type)}</span></div></div>${statusMarkup}${controls}<label class="toggle"><input type="checkbox" data-module-toggle="${index}" ${module.enabled ? "checked" : ""} aria-label="启用 ${escapeHtml(module.name)}"><span></span></label></div>`;
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

async function activateDetectorConfiguration(configurationId) {
  const previousId = state.detectorConfiguration?.id || state.detectorCatalog?.active_configuration_id || "";
  const select = $("#configuration-select");
  select.disabled = true;
  try {
    const data = await api(`/detector-configurations/${encodeURIComponent(configurationId)}/activate`, {method: "POST"});
    await refreshDetectorCatalog(data.id);
    await loadDetectorConfiguration(data.id);
    state.loaded.delete("overview");
    toast(`${uiText("已切换检测器配置")}：${uiText(data.name)}`);
  } catch (error) {
    if (previousId) select.value = previousId;
    handleError(error);
  } finally {
    select.disabled = false;
  }
}

function deleteDetectorConfiguration() {
  const configuration = state.detectorDraft;
  if (configuration.readonly) return;
  confirmAction("删除检测器配置", `${configuration.name} 将被永久删除。`, async () => {
    if (configuration.is_active) {
      const fallback = state.detectorCatalog.templates?.find((item) => item.id !== configuration.id);
      if (!fallback) throw new Error(uiText("没有可用于接替的默认检测器配置。"));
      await api(`/detector-configurations/${encodeURIComponent(fallback.id)}/activate`, {method: "POST"});
    }
    const catalog = await api(`/detector-configurations/${encodeURIComponent(configuration.id)}`, {method: "DELETE"});
    state.detectorCatalog = catalog;
    renderConfigurationOptions();
    await loadDetectorConfiguration(catalog.active_configuration_id);
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
    await activateDetectorConfiguration(data.id);
    toast(uiText("检测器配置已创建并启用"));
  } catch (error) { $("#configuration-error").textContent = error.message; }
}

async function duplicateDetectorConfiguration() {
  try {
    const data = await api("/detector-configurations", {method: "POST", body: JSON.stringify({source_id: state.detectorDraft.id})});
    await activateDetectorConfiguration(data.id);
    toast(uiText("已创建并启用可编辑副本"));
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

async function openModuleEditor(index) {
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
  if (state.moduleDraft.type === "local_model") {
    try {
      await refreshLocalModelCatalog();
    } catch (error) {
      state.localModels = {models: []};
      $("#module-error").textContent = error.message;
    }
  }
  renderModuleSpecificFields();
  $("#module-modal").showModal();
}

function defaultModuleConfig(type) {
  if (type === "regex") return {rules: []};
  if (type === "entropy") return {min_length: 20, min_entropy: 3.5, risk: "medium"};
  if (type === "path") return {detect_unix_home: true, detect_macos_private: true, detect_shell_config: true, detect_windows_user: true, exclude_patterns: [], path_risk: "medium"};
  return {adapter: "transformers_token_classification", model_name: "", threshold: 0.75, device: "cpu", aggregation_strategy: "simple", labels: ["email", "phone_number", "user_name"]};
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
    const models = availableLocalModels();
    const selected = models.find((model) => model.source === config.model_name);
    const unavailable = Boolean(config.model_name) && !selected;
    const placeholder = unavailable
      ? `当前配置的模型不可用：${config.model_name}`
      : models.length ? "请选择可用模型" : "没有可用模型";
    const options = models.map((model) => {
      const device = String(model.resolved_device || "").toUpperCase();
      const label = `${model.display_name || model.source}${device ? ` · ${device}` : ""}`;
      return `<option value="${escapeHtml(model.id)}" ${model.id === selected?.id ? "selected" : ""}>${escapeHtml(label)}</option>`;
    }).join("");
    target.innerHTML = `<div class="form-grid specific-grid"><label class="full-row"><span>使用的本地模型</span><select id="model-selection" required ${models.length ? "" : "disabled"}><option value="" ${selected ? "" : "selected"} disabled>${escapeHtml(placeholder)}</option>${options}</select></label><label><span>模型分数阈值</span><input id="model-threshold" type="number" min="0" max="1" step="0.01" value="${config.threshold}"></label>${config.adapter === "gliner" ? `<label class="full-row"><span>实体标签（逗号分隔）</span><input id="model-labels" value="${escapeHtml(config.labels.join(", "))}"></label>` : `<label><span>聚合方式</span><select id="model-aggregation"><option value="simple">Simple</option><option value="first">First</option><option value="average">Average</option><option value="max">Max</option></select></label>`}<div class="model-policy-note full-row"><span>${escapeHtml(models.length ? "只能选择已在本地模型管理中准备并验证成功的模型。" : "请先在本地模型管理中完成模型准备，然后返回选择。")}</span><button class="secondary-button" type="button" data-view="local-models" data-close-modal>${escapeHtml("前往本地模型管理")}</button></div></div>`;
    if ($("#model-aggregation")) $("#model-aggregation").value = config.aggregation_strategy;
    $("#model-selection").addEventListener("change", (event) => {
      const model = models.find((item) => item.id === event.target.value);
      if (!model) return;
      state.moduleDraft.config = {
        ...state.moduleDraft.config,
        model_name: model.source,
        adapter: model.resolved_adapter,
        device: model.resolved_device,
      };
      renderModuleSpecificFields();
    });
  }
}

function renderRegexRule(rule, index) {
  const name = uiText(String(rule.metadata?.display_name || rule.id));
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
    const model = availableLocalModels().find((item) => item.id === $("#model-selection").value);
    if (!model) throw new Error("请先准备并选择一个可用的本地模型");
    module.config = {...module.config, adapter: model.resolved_adapter, model_name: model.source, threshold: Number($("#model-threshold").value), device: model.resolved_device, aggregation_strategy: $("#model-aggregation")?.value || module.config.aggregation_strategy, labels: $("#model-labels") ? commaList($("#model-labels").value) : module.config.labels};
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
  const visibleDiagnostics = diagnostics.filter((item) => item.id !== "apg_core");
  $("#detection-diagnostics").innerHTML = visibleDiagnostics.length ? `<div class="diagnostic-heading"><p class="section-kicker">EXECUTION TRACE</p><span>${visibleDiagnostics.length} 个步骤</span></div>${visibleDiagnostics.map((item, index) => `<div class="diagnostic-row"><span class="diagnostic-order">${index + 1}</span><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(item.type)}</span><span>${item.findings} 命中</span><span>${Number(item.elapsed_ms).toFixed(2)} ms</span><b class="badge ${item.status === "ok" ? "green" : ["disabled", "unavailable"].includes(item.status) ? "neutral" : "red"}">${escapeHtml(item.status)}</b></div>`).join("")}` : "";
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
  closeDetectionTooltip();
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
  localOnly.textContent = "本地检测 · 悬停或点击高亮查看模块";
  summary.append(summaryText, localOnly);

  const source = document.createElement("pre");
  source.className = "highlighted-source";
  let cursor = 0;
  groups.forEach((group, index) => {
    if (group.start > cursor) source.append(document.createTextNode(characters.slice(cursor, group.start).join("")));
    const mark = document.createElement("mark");
    mark.className = `text-highlight risk-${group.risk}`;
    const moduleNames = findingGroupModuleNames(group);
    mark.tabIndex = 0;
    mark.setAttribute("role", "button");
    mark.setAttribute("aria-expanded", "false");
    mark.setAttribute("aria-label", `检测模块：${moduleNames.join("、")}`);
    mark.append(document.createTextNode(characters.slice(group.start, group.end).join("")));
    const marker = document.createElement("sup");
    marker.className = "highlight-index";
    marker.textContent = String(index + 1);
    mark.append(marker);
    mark.addEventListener("pointerenter", () => {
      if (!state.detectionTooltipPinned) showDetectionTooltip(mark, group, false);
    });
    mark.addEventListener("pointerleave", () => {
      if (!state.detectionTooltipPinned) closeDetectionTooltip();
    });
    mark.addEventListener("focus", () => {
      if (!state.detectionTooltipPinned) showDetectionTooltip(mark, group, false);
    });
    mark.addEventListener("blur", () => {
      if (!state.detectionTooltipPinned) closeDetectionTooltip();
    });
    mark.addEventListener("click", (event) => {
      event.stopPropagation();
      if (state.detectionTooltipMark === mark && state.detectionTooltipPinned) closeDetectionTooltip();
      else showDetectionTooltip(mark, group, true);
    });
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
    title.textContent = unique(group.findings.map((finding) => findingSubtypeLabel(finding.subtype))).join(" + ");
    const detectors = document.createElement("span");
    detectors.textContent = findingGroupModuleNames(group).join(" + ");
    content.append(title, detectors);
    const risk = document.createElement("b");
    risk.textContent = riskLabel(group.risk);
    row.append(number, content, risk);
    legend.append(row);
  });

  output.append(summary, source, legend);
}

function findingGroupModuleNames(group) {
  return unique(group.findings.flatMap(findingModuleNames));
}

function findingModuleNames(finding) {
  const modules = state.detectorDraft?.modules || [];
  const ruleId = String(finding.metadata?.rule_id || "");
  const names = [];
  for (const detector of finding.detectors || []) {
    if (detector === "rules.apg_markers" || ruleId.startsWith("apg.")) {
      names.push(uiText("APG 内置安全防线"));
      continue;
    }
    const matched = modules.filter((module) => {
      if (detector === `rules.${module.id}` || detector === `models.${module.id}`) return true;
      if (module.type === "regex" && ruleId) {
        return (module.config?.rules || []).some((rule) => rule.id === ruleId);
      }
      if (module.type === "path" && detector === "paths") return true;
      if (module.type === "entropy" && detector === "heuristic.entropy_context") return true;
      return false;
    });
    if (matched.length) names.push(...matched.map((module) => uiText(module.name)));
    else names.push(detector);
  }
  return unique(names);
}

function showDetectionTooltip(mark, group, pinned) {
  closeDetectionTooltip();
  const tooltip = document.createElement("div");
  tooltip.className = "detection-tooltip";
  tooltip.id = "detection-highlight-tooltip";
  tooltip.setAttribute("role", "tooltip");
  const label = document.createElement("span");
  label.textContent = uiText("检测模块");
  const modules = document.createElement("strong");
  modules.textContent = findingGroupModuleNames(group).join(" + ");
  const details = document.createElement("small");
  details.textContent = `${unique(group.findings.map((finding) => findingSubtypeLabel(finding.subtype))).join(" + ")} · ${group.risk}`;
  tooltip.append(label, modules, details);
  document.body.append(tooltip);

  const markBounds = mark.getBoundingClientRect();
  const tooltipBounds = tooltip.getBoundingClientRect();
  const margin = 12;
  const centered = markBounds.left + markBounds.width / 2 - tooltipBounds.width / 2;
  const left = Math.max(margin, Math.min(window.innerWidth - tooltipBounds.width - margin, centered));
  let top = markBounds.bottom + 8;
  if (top + tooltipBounds.height > window.innerHeight - margin) top = markBounds.top - tooltipBounds.height - 8;
  tooltip.style.left = `${left}px`;
  tooltip.style.top = `${Math.max(margin, top)}px`;

  mark.setAttribute("aria-expanded", "true");
  mark.setAttribute("aria-describedby", tooltip.id);
  state.detectionTooltip = tooltip;
  state.detectionTooltipMark = mark;
  state.detectionTooltipPinned = pinned;
}

function closeDetectionTooltip() {
  if (state.detectionTooltipMark) {
    state.detectionTooltipMark.setAttribute("aria-expanded", "false");
    state.detectionTooltipMark.removeAttribute("aria-describedby");
  }
  state.detectionTooltip?.remove();
  state.detectionTooltip = null;
  state.detectionTooltipMark = null;
  state.detectionTooltipPinned = false;
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

function findingSubtypeLabel(value) {
  const labels = {
    api_key: "API 密钥",
    access_url_token: "访问链接令牌",
    credential_username: "登录账号",
    credential_password: "登录密码",
    local_path: "本地路径",
    email: "电子邮箱",
    phone: "电话号码",
    private_key: "私钥",
    bearer_token: "Bearer Token",
    database_url: "数据库连接",
    high_entropy_token: "高熵 Token",
  };
  return uiText(labels[value] || value);
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
  if (["failed", "upstream_disconnected", "client_disconnected"].includes(status) || status.includes("error") || status === "revoked") return "red";
  return "neutral";
}

function auditStatusLabel(value) {
  return ({completed: "已完成", in_progress: "进行中", recorded: "已记录", error: "异常", failed: "上游失败", protocol_error: "协议错误", client_disconnected: "客户端连接中断", upstream_disconnected: "上游连接中断"})[value] || value || "已记录";
}

function valueStateLabel(value) {
  return ({active: "映射有效", expired: "原文已过期清除", revoked: "原文已撤销清除", unavailable: "原文不可用"})[value] || value;
}

function stateLabel(value) { return ({active: "活跃", expired: "已过期", revoked: "已撤销"})[value] || value; }
function riskLabel(value) { return ({critical: "严重", high: "高", medium: "中", low: "低"})[value] || value; }
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
  toast(localModelErrorMessage(error.code, error.message || "请求失败"), true);
}

function connectorErrorMessage(error) {
  const message = ({
    CONNECTOR_CONFIG_CONFLICT: "检测到已有 Agent 配置。确认迁移后，APG 会先保存完整快照再替换；取消则不改动。",
    CONNECTOR_CONCURRENT_CHANGE: "配置在接入前发生了变化，请重新打开快速接入并确认迁移。",
    CONNECTOR_EXTERNAL_CHANGES: "接入后的配置已被外部修改，请先恢复原配置。",
    CONNECTOR_PROTOCOL_PROBE_FAILED: "所选模型未通过该 Agent 所需的协议测试。",
  })[error.code];
  return uiText(message || error.message || "接入失败。");
}

function debounce(fn, wait) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), wait); };
}
