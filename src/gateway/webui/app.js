"use strict";

const API = "/api/admin";
const PAGE_META = {
  overview: ["LOCAL CONTROL PLANE", "隐私运行概览", "最近 24 小时的网关活动"],
  audit: ["SAFE AUDIT TRAIL", "审计记录", "拦截、折叠与本地还原事件"],
  protected: ["LOCAL MAPPING REGISTRY", "受保护值", "本地映射生命周期与撤销"],
  detectors: ["DETECTION PIPELINE", "检测器", "预设、模块与项目规则"],
};

const state = {
  key: sessionStorage.getItem("apg_admin_key") || "",
  view: location.hash.replace("#", "") || "overview",
  loaded: new Set(),
  audit: null,
  protected: null,
  detectors: null,
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
  $("#add-rule-button").addEventListener("click", () => {
    $("#rule-form").reset();
    $("#rule-error").textContent = "";
    updateRuleMode();
    $("#rule-modal").showModal();
  });
  $("#rule-mode").addEventListener("change", updateRuleMode);
  $("#rule-form").addEventListener("submit", saveRule);
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
    ["Workspace", system.workspace], ["Upstream", system.upstream], ["Preset", system.preset],
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
  const data = await api("/detectors");
  state.detectors = data;
  renderDetectors(data);
  state.loaded.add("detectors");
}

function renderDetectors(data) {
  $("#preset-control").innerHTML = data.presets.map((preset) => `<button type="button" class="segment ${preset.id === data.preset ? "is-active" : ""}" data-preset="${escapeHtml(preset.id)}">${escapeHtml(preset.label)}</button>`).join("");
  $$('[data-preset]', $("#preset-control")).forEach((button) => button.addEventListener("click", () => setPreset(button.dataset.preset)));
  $("#flow-timeout").textContent = data.flow_timeout_ms ? `Flow timeout ${data.flow_timeout_ms} ms` : "No flow timeout";
  $("#detector-modules").innerHTML = data.modules.map((module) => `<div class="module-row"><div class="module-name"><span class="module-symbol">${escapeHtml(module.category.slice(0, 3))}</span><div><strong>${escapeHtml(module.id)}</strong><span>${escapeHtml(module.description)}</span></div></div><span class="badge ${module.status === "ready" ? "green" : module.status === "error" ? "red" : "neutral"}">${escapeHtml(module.status)}</span><span class="module-meta">${module.rule_count ? `${module.rule_count} rules` : escapeHtml(module.type)}</span><label class="toggle"><input type="checkbox" data-module="${escapeHtml(module.id)}" ${module.enabled ? "checked" : ""} aria-label="启用 ${escapeHtml(module.id)}"><span></span></label></div>`).join("");
  $$('[data-module]', $("#detector-modules")).forEach((input) => input.addEventListener("change", () => toggleModule(input.dataset.module, input.checked, input)));
  const target = $("#custom-rules");
  target.innerHTML = data.custom_rules.length ? data.custom_rules.map((rule) => `<tr><td><strong>${escapeHtml(rule.id)}</strong><br><span class="muted">${escapeHtml(rule.subtype)}</span></td><td>${escapeHtml(rule.type)}</td><td><span class="badge ${escapeHtml(rule.risk)}">${escapeHtml(rule.risk)}</span></td><td>${escapeHtml(rule.suggested_action)}</td><td class="mono">${escapeHtml(rule.pattern)}</td><td><button class="row-action danger" type="button" data-delete-rule="${escapeHtml(rule.id)}">删除</button></td></tr>`).join("") : `<tr><td colspan="6" class="muted">尚未通过 WebUI 添加项目规则</td></tr>`;
  $$('[data-delete-rule]', target).forEach((button) => button.addEventListener("click", () => confirmAction("删除检测规则", `${button.dataset.deleteRule} 将从运行流程中移除。`, () => deleteRule(button.dataset.deleteRule))));
  $("#detection-output").innerHTML = `<span class="muted">等待测试</span>`;
}

async function setPreset(preset) {
  try {
    const data = await api("/detectors/preset", {method: "PUT", body: JSON.stringify({preset})});
    state.detectors = data; renderDetectors(data); toast("检测预设已更新");
  } catch (error) { handleError(error); }
}

async function toggleModule(moduleId, enabled, input) {
  input.disabled = true;
  try {
    const data = await api(`/detectors/modules/${encodeURIComponent(moduleId)}`, {method: "PATCH", body: JSON.stringify({enabled})});
    state.detectors = data; renderDetectors(data); toast(`${moduleId} 已${enabled ? "启用" : "停用"}`);
  } catch (error) { input.checked = !enabled; handleError(error); }
}

function updateRuleMode() {
  const prefix = $("#rule-mode").value === "prefix";
  $("#prefix-field").classList.toggle("is-hidden", !prefix);
  $("#min-length-field").classList.toggle("is-hidden", !prefix);
  $("#pattern-field").classList.toggle("is-hidden", prefix);
}

async function saveRule(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const payload = Object.fromEntries(form.entries());
  payload.min_length = Number(payload.min_length || 12);
  $("#rule-error").textContent = "";
  try {
    const data = await api("/detectors/rules", {method: "POST", body: JSON.stringify(payload)});
    state.detectors = data; renderDetectors(data); $("#rule-modal").close(); toast("自定义规则已启用");
  } catch (error) { $("#rule-error").textContent = error.message; }
}

async function deleteRule(ruleId) {
  const data = await api(`/detectors/rules/${encodeURIComponent(ruleId)}`, {method: "DELETE"});
  state.detectors = data; renderDetectors(data); toast("自定义规则已删除");
}

async function runDetection() {
  const text = $("#detection-input").value;
  if (!text.trim()) return toast("请输入测试文本", true);
  const output = $("#detection-output");
  output.innerHTML = `<span class="muted">正在检测…</span>`;
  try {
    const data = await api("/detectors/test", {method: "POST", body: JSON.stringify({text})});
    renderHighlightedDetection(output, text, data.findings);
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
