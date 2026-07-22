"use strict";

const API = "/api/admin";
const PAGE_META = {
  overview: ["LOCAL CONTROL PLANE", "隐私运行概览", "最近 24 小时的网关活动"],
  audit: ["SAFE AUDIT TRAIL", "审计记录", "拦截、折叠与本地还原事件"],
  protected: ["LOCAL MAPPING REGISTRY", "受保护值", "本地映射生命周期与撤销"],
  detectors: ["DETECTION PIPELINE", "检测器配置", "按检测内容组织的本地模块流水线"],
};

const state = {
  key: sessionStorage.getItem("apg_admin_key") || "",
  view: location.hash.replace("#", "") || "overview",
  loaded: new Set(),
  audit: null,
  protected: null,
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

document.addEventListener("DOMContentLoaded", init);

function init() {
  bindNavigation();
  bindActions();
  showView(PAGE_META[state.view] ? state.view : "overview", false);
  if (state.key) connect();
  else showLogin();
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
  $("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    state.key = $("#admin-key").value.trim();
    $("#login-error").textContent = "";
    await connect(true);
  });
  $("#logout-button").addEventListener("click", logout);
  $("#refresh-button").addEventListener("click", () => loadView(state.view, true));
  $("#audit-query").addEventListener("input", debounce(() => loadAudit().catch(handleError), 280));
  for (const id of ["audit-phase", "audit-risk", "audit-endpoint"]) $("#" + id).addEventListener("change", () => loadAudit().catch(handleError));
  $("#protected-kind").addEventListener("change", () => loadProtected().catch(handleError));
  $("#purge-expired").addEventListener("click", () => confirmAction("清理过期记录", "将所有已过期映射转为不可恢复状态。", purgeExpired));
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

async function connect(fromForm = false) {
  if (!state.key) return showLogin();
  try {
    await loadOverview();
    sessionStorage.setItem("apg_admin_key", state.key);
    $("#login-overlay").classList.add("is-hidden");
    setConnected(true);
    $("#app-shell").setAttribute("aria-busy", "false");
    if (state.view !== "overview") await loadView(state.view);
  } catch (error) {
    setConnected(false);
    if (fromForm || error.status === 401) $("#login-error").textContent = "无法验证管理员密钥。";
    showLogin();
  }
}

function showLogin() {
  $("#login-overlay").classList.remove("is-hidden");
  setTimeout(() => $("#admin-key").focus(), 30);
}

function logout() {
  state.key = "";
  state.loaded.clear();
  sessionStorage.removeItem("apg_admin_key");
  $("#admin-key").value = "";
  showLogin();
  setConnected(false);
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
  if (state.key) loadView(view);
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
  headers.set("Authorization", "Bearer " + state.key);
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
  const data = await api("/overview");
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

function renderTrend(trend) {
  const max = Math.max(1, ...trend.map((item) => item.count));
  $("#trend-chart").innerHTML = trend.map((item) => {
    const date = new Date(item.day + "T00:00:00");
    const label = new Intl.DateTimeFormat("zh-CN", {weekday: "short"}).format(date);
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
  const params = new URLSearchParams({limit: "250"});
  for (const [key, id] of [["query","audit-query"],["phase","audit-phase"],["risk","audit-risk"],["endpoint","audit-endpoint"]]) {
    const value = $("#" + id).value;
    if (value) params.set(key, value);
  }
  const data = await api("/audit?" + params);
  state.audit = data;
  populateSelect($("#audit-phase"), data.filters.phases, "全部阶段");
  populateSelect($("#audit-endpoint"), data.filters.endpoints, "全部端点");
  renderEventRows($("#audit-events"), data.events, false);
  $("#audit-count").textContent = `${data.count} 条记录`;
  $("#audit-window-note").textContent = data.truncated ? "仅检索最近 10,000 条审计事件" : "";
  $("#audit-empty").classList.toggle("is-hidden", data.count !== 0);
  $(".audit-table-wrap").classList.toggle("is-hidden", data.count === 0);
  state.loaded.add("audit");
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
    return `<tr><td>${formatDateTime(event.timestamp)}</td><td>${escapeHtml(event.phase)}</td><td><span class="badge ${risk}">${escapeHtml(type)}</span>${event.detection_count > 1 ? `<span class="muted"> +${event.detection_count - 1}</span>` : ""}</td><td>${escapeHtml(action)}</td><td class="mono">${escapeHtml(event.endpoint || "-")}</td><td>${escapeHtml(event.session || "-")}</td><td><button class="row-action" type="button" data-event-id="${escapeHtml(event.id)}">详情</button></td></tr>`;
  }).join("");
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
  const data = await api("/protected-values" + (kind ? "?kind=" + encodeURIComponent(kind) : ""));
  state.protected = data;
  const summaries = [["当前清单",data.counts.total],["活跃",data.counts.active],["Secret",data.kinds.secret || 0],["PII / Path",(data.kinds.pii || 0) + (data.kinds.path || 0)]];
  $("#protected-summary").innerHTML = summaries.map(([label, value]) => `<div class="summary-cell"><span>${escapeHtml(label)}</span><strong>${formatNumber(value)}</strong></div>`).join("");
  const target = $("#protected-values");
  target.innerHTML = data.records.length ? data.records.map((record) => `<tr><td><strong>${escapeHtml(record.label)}</strong><span class="muted mono"> ${escapeHtml(record.id.slice(-6))}</span></td><td>${escapeHtml(record.subtype)}<br><span class="muted">${escapeHtml(record.kind)}</span></td><td>${escapeHtml(record.scope)}<br><span class="muted">${escapeHtml(record.session)}</span></td><td><span class="badge ${record.display_state}">${stateLabel(record.display_state)}</span></td><td>${formatRelative(record.last_seen_at)}</td><td>${formatRelative(record.expires_at)}</td><td>${record.display_state === "active" ? `<button class="row-action danger" type="button" data-revoke="${escapeHtml(record.id)}">撤销</button>` : ""}</td></tr>`).join("") : `<tr><td colspan="7" class="muted">没有受保护值记录</td></tr>`;
  $$('[data-revoke]', target).forEach((button) => button.addEventListener("click", () => {
    const record = data.records.find((item) => item.id === button.dataset.revoke);
    confirmAction("撤销受保护值", `${record.label} 将立即失效，之后的占位符无法还原。`, () => revokeProtected(record.id));
  }));
  state.loaded.add("protected");
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
  $("#activate-configuration").textContent = configuration.is_active ? "当前配置" : "启用配置";
  $("#duplicate-configuration").textContent = readonly ? "复制并编辑" : "复制";
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
    const rules = module.type === "regex" ? module.config.rules.length : null;
    const unavailable = module.type === "local_model" && module.enabled && module.runtime_available === false;
    const status = !module.enabled ? "disabled" : unavailable ? "unavailable" : module.editable === false ? "managed" : "ready";
    const statusClass = status === "ready" ? "green" : status === "unavailable" ? "red" : "neutral";
    const controls = readonly || module.editable === false ? "" : `<div class="module-actions"><button type="button" title="上移" aria-label="上移 ${escapeHtml(module.name)}" data-module-up="${index}" ${index === 0 ? "disabled" : ""}>↑</button><button type="button" title="下移" aria-label="下移 ${escapeHtml(module.name)}" data-module-down="${index}" ${index === modules.length - 1 ? "disabled" : ""}>↓</button><button type="button" data-module-edit="${index}">编辑</button><button type="button" data-module-copy="${index}">复制</button><button type="button" class="danger" data-module-delete="${index}">删除</button></div>`;
    return `<div class="module-row"><span class="module-order">${index + 1}</span><div class="module-name"><span class="module-symbol">${escapeHtml(type.slice(0, 2))}</span><div><strong>${escapeHtml(module.name)}</strong><span>${escapeHtml(type)} · ${escapeHtml(module.id)}</span></div></div><span class="badge ${statusClass}">${status}</span><span class="module-meta">${rules === null ? escapeHtml(module.failure_mode) : `${rules} 条规则`}</span>${controls}<label class="toggle"><input type="checkbox" data-module-toggle="${index}" ${module.enabled ? "checked" : ""} ${readonly || module.editable === false ? "disabled" : ""} aria-label="启用 ${escapeHtml(module.name)}"><span></span></label></div>`;
  }).join("");
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
    target.innerHTML = `<div class="specific-heading"><div><p class="section-kicker">REGEX RULES</p><strong>${module.config.rules.length} 条规则</strong></div><button class="secondary-button" type="button" id="add-regex-rule">＋ 添加规则</button></div><div class="rule-editor-list">${module.config.rules.map(renderRegexRule).join("")}</div>`;
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
  return `<section class="rule-editor" data-rule-card="${index}"><div class="rule-editor-heading"><strong>${escapeHtml(rule.id)}</strong><label class="inline-check"><input data-rule-field="enabled" type="checkbox" ${rule.enabled !== false ? "checked" : ""}>启用</label><button class="row-action danger" type="button" data-remove-rule="${index}">删除</button></div><div class="form-grid"><label><span>规则 ID</span><input data-rule-field="id" value="${escapeHtml(rule.id)}"></label><label><span>Subtype</span><input data-rule-field="subtype" value="${escapeHtml(rule.subtype)}"></label><label class="full-row"><span>正则表达式</span><textarea data-rule-field="pattern" rows="3">${escapeHtml(rule.pattern)}</textarea></label><label><span>数据类型</span><select data-rule-field="type">${selectOptions(["MACHINE_SECRET", "PII", "LOCAL_CONTEXT", "CREDENTIAL_FILE", "UNKNOWN_SECRET_CANDIDATE"], rule.type)}</select></label><label><span>置信度</span><input data-rule-field="confidence" type="number" min="0" max="1" step="0.01" value="${rule.confidence}"></label><label><span>风险</span><select data-rule-field="risk">${selectOptions(["critical", "high", "medium", "low"], rule.risk)}</select></label><label><span>动作</span><select data-rule-field="suggested_action">${selectOptions(["redact", "block", "pseudonymize", "warn", "alias"], rule.suggested_action)}</select></label><label><span>Flags（逗号分隔）</span><input data-rule-field="flags" value="${escapeHtml((rule.flags || []).join(", "))}"></label><label><span>Validators</span><input data-rule-field="validators" value="${escapeHtml((rule.validators || []).join(", "))}"></label><label><span>必须通过的 Validators</span><input data-rule-field="require_validators" value="${escapeHtml((rule.require_validators || []).join(", "))}"></label><label><span>拒绝的 Validators</span><input data-rule-field="reject_validators" value="${escapeHtml((rule.reject_validators || []).join(", "))}"></label></div></section>`;
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

function stateLabel(value) { return ({active: "活跃", expired: "已过期", revoked: "已撤销"})[value] || value; }
function formatNumber(value) { return new Intl.NumberFormat("zh-CN").format(Number(value || 0)); }
function formatTime(timestamp) { return timestamp ? new Intl.DateTimeFormat("zh-CN", {hour: "2-digit", minute: "2-digit"}).format(new Date(timestamp * 1000)) : "-"; }
function formatDateTime(timestamp) { return timestamp ? new Intl.DateTimeFormat("zh-CN", {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit"}).format(new Date(timestamp * 1000)) : "-"; }
function formatRelative(timestamp) {
  if (!timestamp) return "-";
  const seconds = timestamp - Date.now() / 1000;
  const abs = Math.abs(seconds);
  const [amount, unit] = abs < 60 ? [Math.round(seconds), "second"] : abs < 3600 ? [Math.round(seconds / 60), "minute"] : abs < 86400 ? [Math.round(seconds / 3600), "hour"] : [Math.round(seconds / 86400), "day"];
  return new Intl.RelativeTimeFormat("zh-CN", {numeric: "auto"}).format(amount, unit);
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
  if (error.status === 401) { logout(); return; }
  toast(error.message || "请求失败", true);
}

function debounce(fn, wait) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), wait); };
}
