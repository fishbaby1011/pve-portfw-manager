"use strict";

const CONFIG = {};
const APPLY_STEPS = [
  { label: "validate rules", detail: "Check protocol, ports, subnet, duplicates and protected external ports" },
  { label: "generate nft", detail: "Host renders only table ip pve_portfw from validated JSON" },
  { label: "nft syntax check", detail: "Check the atomic replacement transaction with nft -c -f" },
  { label: "backup current table", detail: "Persist host rollback snapshot and audit entry" },
  { label: "apply pve_portfw", detail: "Atomically replace only the project table" },
  { label: "rollback armed", detail: "Host watchdog restores the previous confirmed snapshot after 120 seconds" },
];
const PHASES = {
  unsaved: "未儲存 · Unsaved",
  saved_pending_apply: "已儲存，等待套用",
  pending_confirmation: "已套用，等待確認",
  applying: "套用結果待確認",
  confirmed: "已確認 · Confirmed",
  apply_failed: "套用失敗 · Failed",
  recovery_failed: "回滾 / 恢復失敗",
  rolled_back: "已回滾 · Rolled Back",
  never_applied: "尚未套用",
  unknown: "Host 狀態未知",
};
const state = {
  view: "dashboard", rules: [], savedRules: [], activeRules: null, rulesRevision: null,
  status: null, statusAt: 0, preflight: null, diagnostics: null, editingId: null,
  csrf: null, busy: false, error: "", applyLog: [], validatedDraft: null,
  nftText: "", nftSafetyChecks: [], filters: { keyword: "", status: "all", proto: "all" },
};
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
const clone = (value) => JSON.parse(JSON.stringify(value));
const escaped = (value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
const icon = (name) => '<i data-lucide="' + name + '" aria-hidden="true"></i>';
const draftStamp = () => JSON.stringify({ rules: state.rules, settings: CONFIG });
const dirty = () => JSON.stringify(state.rules) !== JSON.stringify(state.savedRules);
const connected = () => state.status?.helperConnected && Date.now() - state.statusAt < 20000;
const phase = () => dirty() ? "unsaved" : (connected() ? state.status?.phase || "unknown" : "unknown");
let statusSequence = 0;

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  await initialize();
  setInterval(() => { if (!state.busy && !document.hidden) refreshStatus(); }, 5000);
  setInterval(() => { renderBanner(); renderDashboard(); renderWorkflow(); refreshIcons(); }, 1000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshStatus(); });
});

function bindEvents() {
  $$(".nav-item").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-action]");
    if (!button || button.disabled) return;
    const action = button.dataset.action;
    $("#rules-menu").open = false;
    const actions = {
      "go-rules": () => { setView("rules"); openRuleDrawer(); },
      "go-diagnostics": () => setView("diagnostics"),
      "add-rule": openRuleDrawer, "close-drawer": () => closeDrawer("rule-drawer"),
      "close-import": () => closeDrawer("import-drawer"), "close-review": () => closeDrawer("review-drawer"),
      "toggle-theme": toggleTheme, "clear-filters": clearFilters, "review": openReview,
      "export-json": exportJson, "import-json": openImportDrawer, "disable-all": disableAll,
      "copy-rules-json": () => copyText(JSON.stringify(state.rules, null, 2), "rules.json copied"),
      "copy-nft": () => copyText(state.nftText, "generated.nft 已複製"),
      "copy-apply-plan": copyApplyPlan,
      "reload-rules": async () => {
        if (dirty() && !window.confirm("放棄目前未儲存草稿並重新載入 rules.json？")) return;
        state.rules = await apiJson("/api/rules"); state.savedRules = clone(state.rules);
        state.error = ""; state.validatedDraft = null; await refreshStatus();
      },
      "save": () => runBusy(saveRules), "dry-run": () => runBusy(dryRun),
      "apply": () => runBusy(applyRules), "confirm": () => runBusy(confirmApply),
      "rollback": () => runBusy(rollbackNow),
      "refresh": () => runBusy(async () => { await refreshStatus(); await loadPreflight(); }),
      "preflight": () => runBusy(loadPreflight), "refresh-diagnostics": () => runBusy(loadDiagnostics),
    };
    try { await actions[action]?.(); } catch (error) { reportError(error); }
  });
  $("#rule-form").addEventListener("submit", saveRuleFromForm);
  $("#rule-form").addEventListener("input", renderMapping);
  $("#import-form").addEventListener("submit", importJson);
  ["rule-drawer", "import-drawer", "review-drawer"].forEach((id) => {
    $("#" + id).addEventListener("click", (event) => { if (event.target.id === id && !state.busy) closeDrawer(id); });
  });
  document.addEventListener("keydown", (event) => {
    const drawer = $(".drawer.open");
    if (!drawer) return;
    if (event.key === "Escape" && !state.busy) closeDrawer(drawer.id);
    if (event.key === "Tab") {
      const focusables = $$('button:not(:disabled), input:not(:disabled), select, textarea, summary, [tabindex="0"]', drawer)
        .filter((element) => element.getClientRects().length);
      const first = focusables[0], last = focusables[focusables.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }
  });
  document.addEventListener("click", (event) => {
    if (!event.target.closest(".action-menu")) $("#rules-menu").open = false;
  });
  [["filter-keyword", "keyword", "input"], ["filter-status", "status", "change"], ["filter-proto", "proto", "change"]].forEach(([id, key, event]) => {
    $("#" + id).addEventListener(event, (e) => { state.filters[key] = e.target.value; renderRules(); refreshIcons(); });
  });
  window.addEventListener("beforeunload", (event) => { if (dirty()) { event.preventDefault(); event.returnValue = ""; } });
}

async function initialize() {
  try {
    const session = await apiJson("/api/session");
    state.csrf = session.csrfToken;
    Object.assign(CONFIG, await apiJson("/api/config"));
    $("#preview-banner").hidden = !CONFIG.previewMode;
    CONFIG.protectedPortRanges = parsePortRanges(CONFIG.protectedPorts);
    state.rules = await apiJson("/api/rules");
    state.savedRules = clone(state.rules);
    await refreshStatus();
    await Promise.allSettled([loadPreflight(), updatePreview()]);
  } catch (error) { reportError(error); }
  render();
}

async function refreshStatus() {
  const sequence = ++statusSequence;
  try {
    const result = await apiJson("/api/apply-status");
    if (sequence !== statusSequence) return;
    const localDirty = dirty();
    state.status = result;
    state.statusAt = Date.now();
    state.activeRules = result.activeRules;
    const revisionChanged = state.rulesRevision && result.rulesRevision !== state.rulesRevision;
    if (localDirty && revisionChanged) {
      state.error = "已儲存規則在另一個操作中改變；目前草稿保留，請重新載入後再編輯。";
    } else if (result.savedRules) {
      state.savedRules = clone(result.savedRules);
      if (!localDirty) state.rules = clone(result.savedRules);
      state.rulesRevision = result.rulesRevision;
    }
    if (result.lastApplyLog?.length && !state.applyLog.length) state.applyLog = result.lastApplyLog.map((label) => ({ label, status: "recorded" }));
    render();
  } catch (error) {
    if (error.status !== 409) {
      state.error = "Host 狀態更新失敗：" + error.message;
      state.statusAt = 0;
      render();
    }
  }
}

async function loadPreflight() {
  state.preflight = await apiJson("/api/preflight");
  render();
}

async function loadDiagnostics() {
  $("#diagnostic-list").innerHTML = '<div class="empty-state">診斷檢查中…</div>';
  state.diagnostics = await apiJson("/api/diagnostics");
  renderDiagnostics.signature = null;
  renderDiagnostics();
  refreshIcons();
}

function setView(view) {
  state.view = view;
  $$(".nav-item").forEach((button) => {
    const active = button.dataset.view === view;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  $$(".view").forEach((section) => section.classList.toggle("active", section.id === "view-" + view));
  $("#current-view").textContent = { dashboard: "總覽", rules: "轉發規則", diagnostics: "診斷檢查", nft: "nft 預覽" }[view];
  if (view === "diagnostics" && state.diagnostics === null) loadDiagnostics().catch(reportError);
  if (view === "nft") updatePreview().catch(reportError);
  render();
}

function render() {
  renderTheme();
  renderDashboard();
  renderRules();
  renderWorkflow();
  renderBanner();
  renderReview();
  renderPreflight();
  renderDiagnostics();
  renderLog();
  refreshIcons();
  const error = state.error || state.status?.lastError;
  $("#connection-error").hidden = !error;
  $("#connection-error").textContent = error || "";
  $$('[data-action="save"]').forEach((button) => button.disabled = state.busy || !dirty());
  $$('[data-action="review"]').forEach((button) => button.disabled = state.busy);
  $$('[data-action="rollback"]').forEach((button) => button.disabled = state.busy || !connected() || !(state.status?.rollbackArmed || state.status?.lastConfirmedAt));
  $$('[data-action="confirm"]').forEach((button) => button.disabled = state.busy || !connected() || !state.status?.rollbackArmed || remaining() <= 0);
  $$('[data-action="add-rule"], [data-action="go-rules"], [data-action="import-json"], [data-action="disable-all"]').forEach((button) => button.disabled = state.busy);
}

function renderTheme() {
  const dark = document.documentElement.dataset.theme === "dark";
  $("#theme-toggle").innerHTML = icon(dark ? "sun" : "moon");
  $("#theme-toggle").title = dark ? "切換淺色模式" : "切換深色模式";
  $("#theme-toggle").setAttribute("aria-label", $("#theme-toggle").title);
}

function toggleTheme() {
  document.documentElement.dataset.theme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  try { localStorage.setItem("pve-portfw-theme", document.documentElement.dataset.theme); } catch { /* Optional preference. */ }
  renderTheme();
  refreshIcons();
}

function formatDate(value) {
  if (!value) return "尚未記錄";
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  return Number.isNaN(date.getTime()) ? "未知" : date.toLocaleString("zh-TW", { hour12: false });
}

function pendingChanges() {
  return state.activeRules === null ? null : changes(state.rules, state.activeRules).length;
}

function renderDashboard() {
  const live = connected();
  const verified = live && state.status?.tableVerified;
  $("#connection-pill").className = "connection-pill " + (live ? "ok" : "unknown");
  $("#connection-label").textContent = live ? "Host 已連線" : "Host 未驗證";
  $("#metric-helper").textContent = live ? "已連線" : "未驗證";
  $("#metric-helper-detail").textContent = live ? "Restricted SSH · protocol v2" : "請檢查 SSH 與 Host Helper";
  $("#metric-active").textContent = verified ? state.status.activeRuleCount : "—";
  $("#metric-active-detail").textContent = verified ? "Host table 與快照一致" : "未把草稿當成生效規則";
  const pending = pendingChanges();
  $("#metric-pending").textContent = pending === null || !live ? "—" : pending;
  $("#metric-pending-detail").textContent = dirty() ? "有尚未儲存的草稿" : "草稿與 Host 快照的差異";
  $("#metric-rollback").textContent = !live ? "未知" : state.status.rollbackArmed ? remaining() + "s" : "未啟動";
  $("#metric-rollback-detail").textContent = state.status?.rollbackArmed ? "Host watchdog 等待確認" : "下次套用時啟動保護";
  $("#table-status").textContent = verified ? "Host table 已驗證" : live && state.status?.tablePresent === false ? "Host table 不存在" : "尚未驗證生效狀態";
  $("#metric-apply").textContent = formatDate(state.status?.lastAppliedAt);
  $("#last-confirmed").textContent = formatDate(state.status?.lastConfirmedAt);
  const enabled = state.rules.filter((rule) => rule.enabled).length;
  $("#metric-total").textContent = state.rules.length + " / " + enabled + " / " + (state.rules.length - enabled);
  $("#metric-protocols").textContent = state.rules.filter((rule) => rule.proto === "tcp").length + " / " + state.rules.filter((rule) => rule.proto === "udp").length;
  $("#nav-rule-count").textContent = state.rules.length;
  const values = { "public-ip": CONFIG.publicIp, "external-interface": CONFIG.externalInterface, "internal-interface": CONFIG.internalInterface,
    "internal-subnet": CONFIG.internalSubnet, gateway: CONFIG.gateway, "panel-listen": CONFIG.webListen, "protected-ports": CONFIG.protectedPorts };
  Object.entries(values).forEach(([key, value]) => $$('[data-config="' + key + '"]').forEach((element) => element.textContent = value || "—"));
  const attention = [];
  if (!live) attention.push({ title: "Host 狀態未取得", text: state.status?.hostError || "尚無可驗證的 Host 回應。", status: "error" });
  if (live && !verified) attention.push({ title: "轉發 table 尚未驗證", text: state.status.tablePresent === false ? "Host 上沒有 pve_portfw table；已儲存的規則不一定已生效。" : "Host table 與記錄可能不一致，請檢查診斷。", status: "warn" });
  if (live && !state.status.recoveryEnabled) attention.push({ title: "開機恢復尚未啟用", text: "Host 重開機可能遺失 nft 規則。確認套用後可手動啟用恢復服務。", status: "warn" });
  if (state.preflight && !state.preflight.ready) attention.push({ title: "環境檢查未通過", text: "請先修正下方錯誤項目。", status: "error" });
  if (dirty()) attention.push({ title: "草稿尚未儲存", text: "目前的編輯尚未寫入 rules.json。", status: "warn" });
  if (live && state.status.rollbackArmed) attention.push({ title: "套用等待確認", text: "請從外網確認服務，再決定確認套用或立即回滾。", status: "warn" });
  $("#attention-list").innerHTML = attention.length ? attention.map((item) => '<div class="attention-row ' + item.status + '">' + icon(item.status === "error" ? "circle-alert" : "triangle-alert") + '<div><strong>' + escaped(item.title) + '</strong><span>' + escaped(item.text) + '</span></div></div>').join("") : '<div class="attention-row ok">' + icon("circle-check") + '<div><strong>目前沒有待處理警示</strong><span>外網連線仍需獨立驗證。</span></div></div>';
}

function renderWorkflow() {
  const current = phase();
  $("#workflow-phase").textContent = PHASES[current] || current;
  $("#workflow-phase").className = "phase-badge " + (current === "confirmed" ? "ok" : current.includes("failed") ? "error" : "warn");
  $("#workflow-detail").textContent = dirty() ? "草稿變更尚未寫入 rules.json" :
    state.status?.rollbackArmed ? "Host 120 秒確認視窗進行中" :
    current === "saved_pending_apply" ? "儲存完成；Host 尚未套用這些變更" :
    current === "confirmed" ? "已確認的快照；流量可達性需另行測試" :
    current === "rolled_back" ? "Host 已回滾；後續草稿編輯會保留" : state.status?.lastApplyResult || "尚未取得 Host 狀態";
}

function remaining() {
  return Math.max(0, (state.status?.remainingSeconds || 0) - Math.floor((Date.now() - state.statusAt) / 1000));
}

function renderBanner() {
  const armed = state.status?.rollbackArmed;
  $("#apply-banner").hidden = !armed;
  if (!armed) return;
  const seconds = remaining();
  $("#rollback-countdown").textContent = connected() ? seconds + "s" : "未知";
  $("#apply-banner-text").textContent = !connected() ? "Host 連線中斷，等待重新驗證回滾狀態。" :
    seconds > 0 ? "請確認外網服務；逾時由 Host 還原上一個已確認快照。" : "確認期限已過，等待 Host 回滾結果。";
  $("#confirm-button").disabled = state.busy || !connected() || seconds <= 0;
}

function renderRules() {
  const signature = JSON.stringify([state.rules, state.filters, CONFIG.publicIp, state.busy]);
  if (renderRules.signature === signature) return;
  renderRules.signature = signature;
  const keyword = state.filters.keyword.trim().toLowerCase();
  const filtered = state.rules.filter((rule) => (!keyword || Object.values(rule).join(" ").toLowerCase().includes(keyword)) &&
    (state.filters.status === "all" || rule.enabled === (state.filters.status === "enabled")) &&
    (state.filters.proto === "all" || rule.proto === state.filters.proto));
  $("#filter-count").textContent = filtered.length + " / " + state.rules.length + " 條";
  $("#rules-body").innerHTML = filtered.map((rule) => {
    const id = escaped(rule.id), name = escaped(rule.name);
    return '<tr><td class="enable-cell"><button class="switch-button ' + (rule.enabled ? "is-on" : "") + '" type="button" role="switch" aria-checked="' + rule.enabled + '" aria-label="' + (rule.enabled ? "停用 " : "啟用 ") + name + '" title="' + (rule.enabled ? "停用規則" : "啟用規則") + '" data-toggle="' + id + '" ' + (state.busy ? "disabled" : "") + '><span></span></button></td>' +
      '<td class="name-cell"><strong>' + name + '</strong><small>' + id + '</small></td><td class="proto-cell"><span class="proto-badge ' + rule.proto + '">' + rule.proto.toUpperCase() + '</span></td>' +
      '<td class="external-cell" data-label="External"><span class="endpoint">' + escaped(CONFIG.publicIp) + ':<b>' + rule.external_port + '</b></span></td>' +
      '<td class="internal-cell" data-label="Internal"><span class="endpoint">' + escaped(rule.dest_ip) + ':<b>' + rule.dest_port + '</b></span></td>' +
      '<td class="note-cell"><span>' + escaped(rule.note || "—") + '</span></td><td class="actions-cell"><div class="row-actions">' +
      '<button class="icon-button" type="button" data-edit="' + id + '" title="編輯" aria-label="編輯 ' + name + '">' + icon("pencil") + '</button>' +
      '<button class="icon-button" type="button" data-duplicate="' + id + '" title="複製規則" aria-label="複製 ' + name + '">' + icon("copy-plus") + '</button>' +
      '<button class="icon-button" type="button" data-delete="' + id + '" title="刪除" aria-label="刪除 ' + name + '">' + icon("trash-2") + '</button></div></td></tr>';
  }).join("") || '<tr><td colspan="7" class="empty-state">' + (state.rules.length ? "沒有符合篩選的規則" : "尚無規則") + '</td></tr>';
  $$("[data-toggle]").forEach((button) => button.addEventListener("click", () => {
    if (state.busy) return;
    const rule = state.rules.find((item) => item.id === button.dataset.toggle);
    rule.enabled = !rule.enabled;
    draftChanged();
  }));
  $$("[data-edit]").forEach((button) => button.addEventListener("click", () => { if (!state.busy) openRuleDrawer(button.dataset.edit); }));
  $$("[data-duplicate]").forEach((button) => button.addEventListener("click", () => { if (!state.busy) duplicateRule(button.dataset.duplicate); }));
  $$("[data-delete]").forEach((button) => button.addEventListener("click", () => {
    if (!state.busy && window.confirm("刪除此規則的草稿？")) {
      state.rules = state.rules.filter((rule) => rule.id !== button.dataset.delete);
      draftChanged();
    }
  }));
}

function draftChanged() {
  state.validatedDraft = null;
  state.error = "";
  render();
  if (state.view === "nft") updatePreview().catch(reportError);
}

function clearFilters() {
  state.filters = { keyword: "", status: "all", proto: "all" };
  $("#filter-keyword").value = "";
  $("#filter-status").value = "all";
  $("#filter-proto").value = "all";
  renderRules(); refreshIcons();
}

function showDrawer(id) {
  state.returnFocus = document.activeElement;
  $("#" + id).classList.add("open");
  $("#" + id).setAttribute("aria-hidden", "false");
  $(".app-shell").inert = true;
  document.body.classList.add("dialog-open");
  $("input, button", $("#" + id))?.focus();
  refreshIcons();
}

function closeDrawer(id) {
  $("#" + id).classList.remove("open");
  $("#" + id).setAttribute("aria-hidden", "true");
  $(".app-shell").inert = false;
  document.body.classList.remove("dialog-open");
  state.returnFocus?.focus();
}

function openRuleDrawer(id = null) {
  if (state.busy) return;
  state.editingId = typeof id === "string" ? id : null;
  const form = $("#rule-form");
  form.reset();
  const rule = state.rules.find((item) => item.id === state.editingId);
  $("#drawer-title").textContent = rule ? "編輯規則" : "新增規則";
  if (rule) Object.entries(rule).forEach(([key, value]) => {
    if (key === "enabled") form.elements[key].checked = value;
    else if (form.elements[key]) form.elements[key].value = value;
  });
  form.elements.id.readOnly = !!rule;
  $("#validation-box").hidden = true;
  form.elements.dest_ip.placeholder = firstUsableIp(CONFIG.internalSubnet);
  renderMapping();
  showDrawer("rule-drawer");
  form.elements.name.focus();
}

function renderMapping() {
  const form = $("#rule-form");
  $("#rule-mapping").textContent = (CONFIG.publicIp || "External") + ":" + (form.elements.external_port.value || "Port") +
    " → " + (form.elements.dest_ip.value || "Internal IP") + ":" + (form.elements.dest_port.value || "Port");
}

function saveRuleFromForm(event) {
  event.preventDefault();
  if (state.busy) return;
  const form = event.currentTarget;
  const rule = { id: form.elements.id.value.trim() || uniqueId(form.elements.name.value),
    name: form.elements.name.value.trim(), enabled: form.elements.enabled.checked, proto: form.elements.proto.value,
    external_port: Number(form.elements.external_port.value), dest_ip: form.elements.dest_ip.value.trim(),
    dest_port: Number(form.elements.dest_port.value), note: form.elements.note.value.trim() };
  const proposed = state.editingId ? state.rules.map((item) => item.id === state.editingId ? rule : item) : [...state.rules, rule];
  const errors = validateRules(proposed);
  if (errors.length) { showErrors("validation-box", errors); return; }
  state.rules = proposed;
  closeDrawer("rule-drawer");
  draftChanged();
  toast("草稿已更新，尚未套用");
}

function uniqueId(value) {
  const base = String(value).toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "rule-" + crypto.randomUUID().slice(0, 8);
  let id = base, count = 2;
  while (state.rules.some((rule) => rule.id === id)) id = base + "-" + count++;
  return id;
}

function duplicateRule(id) {
  const original = state.rules.find((rule) => rule.id === id);
  for (let offset = 1; offset < 65536; offset++) {
    const port = ((original.external_port + offset - 1) % 65535) + 1;
    if (!forbiddenPort(port) && !state.rules.some((rule) => rule.proto === original.proto && rule.external_port === port)) {
      state.rules.push({ ...original, id: uniqueId(original.id + "-copy"), name: (original.name + " Copy").slice(0, 120), external_port: port });
      draftChanged(); toast("已建立規則副本"); return;
    }
  }
  toast("沒有可用的 External Port");
}

function disableAll() {
  if (!window.confirm("將所有草稿規則停用？Host 規則需套用後才會改變。")) return;
  state.rules = state.rules.map((rule) => ({ ...rule, enabled: false }));
  draftChanged();
}

async function saveRules() {
  const errors = validateRules(state.rules);
  if (errors.length) throw new Error(errors.join("; "));
  const saved = await apiJson("/api/rules", { method: "PUT", headers: { "If-Match": state.rulesRevision || "" }, body: JSON.stringify(state.rules) });
  state.rules = saved; state.savedRules = clone(saved);
  await refreshStatus();
  toast("rules.json 已儲存，尚未套用 Host");
}

function changes(current, baseline) {
  const before = new Map(baseline.map((rule) => [rule.id, rule]));
  const after = new Map(current.map((rule) => [rule.id, rule]));
  return [...new Set([...before.keys(), ...after.keys()])].flatMap((id) => {
    const old = before.get(id), next = after.get(id);
    if (JSON.stringify(old) === JSON.stringify(next)) return [];
    return [{ id, old, next, type: !old ? "added" : !next ? "removed" : old.enabled && !next.enabled ? "disabled" : "modified" }];
  });
}

function renderChangeSummary(element) {
  const baseline = state.activeRules ?? state.savedRules;
  const diff = changes(state.rules, baseline);
  const counts = ["added", "modified", "disabled", "removed"].map((type) => '<span><b>' + diff.filter((item) => item.type === type).length + '</b>' + ({ added: "新增", modified: "修改", disabled: "停用", removed: "刪除" }[type]) + '</span>').join("");
  element.innerHTML = '<div class="change-counts">' + counts + '</div><div class="baseline-note">' + (state.activeRules === null ? "Host 尚未驗證；此摘要以已儲存草稿為比較基準。" : "比較基準：Host 實際驗證的規則快照") + '</div>' +
    diff.map((item) => '<div class="change-row"><span class="change-kind">' + ({ added: "+", modified: "~", disabled: "停用", removed: "−" }[item.type]) + '</span><div><strong>' + escaped((item.next || item.old).name) + '</strong><span>' +
      escaped((item.old ? item.old.dest_ip + ":" + item.old.dest_port + " / " + item.old.proto + ":" + item.old.external_port : "—") +
      " → " + (item.next ? item.next.dest_ip + ":" + item.next.dest_port + " / " + item.next.proto + ":" + item.next.external_port : "—")) + '</span></div></div>').join("") +
    '<div class="protected-summary">' + icon("shield-check") + '受保護 External Port：' + escaped(CONFIG.protectedPorts) + '</div>';
}

async function openReview() {
  $("#review-error").hidden = true;
  renderChangeSummary($("#review-summary"));
  showDrawer("review-drawer");
  renderReview();
  await loadPreflight();
}

function renderReview() {
  const valid = state.validatedDraft === draftStamp();
  $("#review-validation").textContent = valid ? "Dry Run 通過 · 尚未套用" : "尚未執行此草稿的 Dry Run";
  $("#review-host").textContent = state.preflight?.ready && connected() ? "Host 環境檢查通過" : "Host 環境需要確認";
  $("#dry-run-button").disabled = state.busy || !connected() || !state.preflight?.ready || !!state.status?.rollbackArmed;
  $("#apply-button").disabled = state.busy || !valid || !connected() || !state.preflight?.ready || !!state.status?.rollbackArmed;
}

async function dryRun() {
  $("#review-error").hidden = true;
  await saveRules();
  const response = await apiJson("/api/dry-run", { method: "POST", body: JSON.stringify({ revision: state.rulesRevision }) });
  if (!response.ok) throw new Error(response.stderr || "Dry Run failed");
  state.validatedDraft = draftStamp();
  state.applyLog = response.log.map((label) => ({ label, status: "done" }));
  await updatePreview();
  render();
  toast("Dry Run 通過；外網連線尚未測試");
}

async function applyRules() {
  if (state.validatedDraft !== draftStamp()) throw new Error("草稿已改變，請重新執行 Dry Run。");
  $("#review-error").hidden = true;
  state.applyLog = [{ label: "send restricted host apply", status: "running" }];
  renderLog();
  const response = await apiJson("/api/apply", { method: "POST", body: JSON.stringify({ revision: state.rulesRevision }) });
  state.applyLog = response.log.map((label) => ({ label, status: "done" }));
  state.validatedDraft = null;
  closeDrawer("review-drawer");
  $("#apply-log-section").open = true;
  await refreshStatus();
  toast("已套用 Host，請從外網確認後按確認套用");
}

async function confirmApply() {
  const result = await apiJson("/api/confirm", { method: "POST" });
  if (result.phase !== "confirmed") throw new Error("Host 尚未確認套用。");
  await refreshStatus();
  toast("已確認待套用快照，Host 回滾保護解除");
}

async function rollbackNow() {
  if (!window.confirm("立即回滾至 Host 保存的上一個已確認狀態？後續草稿編輯會保留。")) return;
  const result = await apiJson("/api/rollback", { method: "POST" });
  state.applyLog = result.log.map((label) => ({ label, status: "done" }));
  state.validatedDraft = null;
  await refreshStatus();
  await updatePreview();
  toast("Host 回滾完成並已驗證");
}

async function updatePreview() {
  const stamp = draftStamp();
  const response = await apiJson("/api/preview", { method: "POST", body: JSON.stringify(state.rules) });
  if (draftStamp() !== stamp) return;
  state.nftText = response.nft;
  state.nftSafetyChecks = response.safetyChecks;
  $("#nft-code").textContent = state.nftText;
  $("#preview-source").textContent = dirty() ? "尚未儲存的草稿" : "已儲存草稿 · 不代表生效";
  renderChangeSummary($("#nft-change-summary"));
  $("#nft-safety-checks").innerHTML = response.safetyChecks.map((item) => '<div class="safety-check ' + (item.ok ? "ok" : "error") + '">' + icon(item.ok ? "check" : "x") + '<span>' + escaped(item.label) + '</span><b>' + (item.ok ? "PASS" : "FAIL") + '</b></div>').join("");
  refreshIcons();
}

function renderLog() {
  $("#apply-log").innerHTML = state.applyLog.map((item) => '<div class="log-row ' + item.status + '">' + icon(item.status === "error" ? "circle-x" : item.status === "running" ? "loader-circle" : "check") + '<span>' + escaped(item.label) + '</span><small>' + escaped(item.status) + '</small></div>').join("") || '<div class="empty-state">尚無操作紀錄</div>';
}

const DIAG_LABELS = { ok: "正常 · Healthy", warn: "注意 · Warning", error: "錯誤 · Error", unknown: "未測試 · Unknown" };
function diagnosticRow(item) {
  return '<article class="diagnostic-row"><div class="diagnostic-heading"><div>' + icon(item.status === "ok" ? "circle-check" : item.status === "error" ? "circle-x" : item.status === "warn" ? "triangle-alert" : "circle-help") +
    '<strong>' + escaped(item.label) + '</strong></div><span class="diag-badge ' + item.status + '">' + escaped(DIAG_LABELS[item.status] || "未知") + '</span></div>' +
    '<p>' + escaped(item.detail || "尚無檢查結果") + '</p>' +
    (item.status !== "ok" && item.cause ? '<p class="muted">可能原因：' + escaped(item.cause) + '</p>' : "") +
    (item.suggestion ? '<p class="suggestion">' + escaped(item.suggestion) + '</p>' : "") +
    '<details class="raw-details"><summary>技術資訊 · ' + escaped(item.scope || "host") + '</summary><pre>' +
    escaped([item.command?.join(" "), item.stdout, item.stderr].filter(Boolean).join("\n") || "No command output") + '</pre></details></article>';
}

function renderPreflight() {
  if (!state.preflight) return;
  const signature = JSON.stringify(state.preflight);
  if (renderPreflight.signature === signature) return;
  renderPreflight.signature = signature;
  $("#preflight-summary").textContent = state.preflight.ready ? "通過" : "需要設定";
  $("#preflight-summary").className = state.preflight.ready ? "ok-text" : "danger-text";
  $("#preflight-list").innerHTML = state.preflight.checks.map(diagnosticRow).join("");
  if (state.preflight.ready && state.status?.tableVerified && !state.setupShown) { $("#setup-section").open = false; state.setupShown = true; }
}

function renderDiagnostics() {
  if (state.diagnostics === null) return;
  const signature = JSON.stringify(state.diagnostics);
  if (renderDiagnostics.signature === signature) return;
  renderDiagnostics.signature = signature;
  $("#diagnostic-list").innerHTML = state.diagnostics.map(diagnosticRow).join("");
  $("#diagnostic-summary").innerHTML = Object.keys(DIAG_LABELS).map((status) => '<span class="diag-badge ' + status + '">' + escaped(DIAG_LABELS[status]) + ' ' + state.diagnostics.filter((item) => item.status === status).length + '</span>').join("");
}

function openImportDrawer() {
  $("#import-json").value = "";
  $("#import-validation").hidden = true;
  showDrawer("import-drawer");
  $("#import-json").focus();
}

function importJson(event) {
  event.preventDefault();
  try {
    const parsed = JSON.parse($("#import-json").value);
    const rules = Array.isArray(parsed) ? parsed : parsed?.rules;
    if (!Array.isArray(rules)) throw new Error('匯入內容必須是 array 或 { "rules": [...] }。');
    const normalized = rules.map((rule) => ({ ...rule, enabled: rule.enabled === undefined ? true : rule.enabled, note: rule.note === undefined ? "" : rule.note }));
    const errors = validateRules(normalized);
    if (errors.length) throw new Error(errors.join("; "));
    state.rules = normalized;
    closeDrawer("import-drawer");
    draftChanged();
    toast("JSON 已匯入草稿，尚未儲存或套用");
  } catch (error) { showErrors("import-validation", [error.message, "現有規則未被覆蓋。"]); }
}

function exportJson() {
  const blob = new Blob([JSON.stringify(state.rules, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob), link = $("#download-link");
  link.href = url; link.download = "rules.json"; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast("目前草稿 JSON 已匯出");
}

function copyApplyPlan() {
  copyText(["Apply changes the PVE Host project table only. Confirm within 120 seconds.", "", ...APPLY_STEPS.flatMap((step, index) => [(index + 1) + ". " + step.label, "   " + step.detail, ""])].join("\n"), "Apply Plan copied");
}

function copyText(text, message) {
  if (!navigator.clipboard) { toast("複製失敗，請確認瀏覽器權限或使用 HTTPS / localhost"); return; }
  navigator.clipboard.writeText(text).then(() => toast(message)).catch(() => toast("複製失敗，請確認瀏覽器權限或使用 HTTPS / localhost"));
}

function validateRules(rules) {
  const errors = [], ids = new Set(), ports = new Set();
  if (!Array.isArray(rules) || rules.length > 500) return ["規則必須是 array，最多 500 條。"];
  for (const rule of rules) {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) { errors.push("每條規則必須是 object。"); continue; }
    const label = rule.name || rule.id || "規則";
    if (Object.keys(rule).some((key) => !["id", "name", "enabled", "proto", "external_port", "dest_ip", "dest_port", "note"].includes(key))) errors.push(label + "：包含未知欄位。");
    if (typeof rule.id !== "string" || !/^[a-zA-Z0-9_-]{1,80}$/.test(rule.id)) errors.push(label + "：ID 只能使用英數、dash、underscore，最多 80 字元。");
    if (typeof rule.name !== "string" || !rule.name.trim() || rule.name.length > 120) errors.push(label + "：名稱必填，最多 120 字元。");
    if (typeof rule.note !== "string" || rule.note.length > 1000) errors.push(label + "：備註最多 1000 字元。");
    if (typeof rule.enabled !== "boolean") errors.push(label + "：enabled 必須為 boolean。");
    if (!["tcp", "udp"].includes(rule.proto)) errors.push(label + "：協定必須為 tcp / udp。");
    for (const key of ["external_port", "dest_port"]) if (!Number.isInteger(rule[key]) || rule[key] < 1 || rule[key] > 65535) errors.push(label + "：" + key + " 必須為 1–65535 的整數。");
    if (!internalIp(rule.dest_ip) || rule.dest_ip === CONFIG.gateway) errors.push(label + "：Internal IP 必須是 " + CONFIG.internalSubnet + " 的 VM/CT 位址，不能是 Host gateway。");
    if (forbiddenPort(rule.external_port)) errors.push(label + "：External Port " + rule.external_port + " 是受保護 Port。");
    const key = rule.proto + ":" + rule.external_port;
    if (ids.has(rule.id)) errors.push(label + "：ID 重複。");
    if (ports.has(key)) errors.push(label + "：External Port + 協定與其他規則衝突。");
    ids.add(rule.id); ports.add(key);
  }
  return errors;
}

function parsePortRanges(value) {
  return String(value || "").split(",").flatMap((part) => {
    const match = /^\s*(\d+)(?:\s*-\s*(\d+))?\s*$/.exec(part);
    return match ? [[Number(match[1]), Number(match[2] || match[1])]] : [];
  });
}
function forbiddenPort(port) { return (CONFIG.protectedPortRanges || []).some(([start, end]) => start <= port && port <= end); }
function ipv4(value) {
  const parts = String(value).split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d*)$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((acc, part) => (acc * 256 + Number(part)) >>> 0, 0);
}
function subnetRange() {
  const [base, prefix] = String(CONFIG.internalSubnet).split("/"), ip = ipv4(base), bits = Number(prefix);
  if (ip === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { network: (ip & mask) >>> 0, broadcast: ((ip & mask) | (~mask >>> 0)) >>> 0 };
}
function internalIp(value) { const ip = ipv4(value), range = subnetRange(); return ip !== null && range && ip > range.network && ip < range.broadcast; }
function firstUsableIp() {
  const range = subnetRange(); if (!range) return "";
  const value = Math.min(range.network + 100, range.broadcast - 1);
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
}

async function apiJson(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (options.method && options.method !== "GET") headers["X-CSRF-Token"] = state.csrf || "";
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const text = await response.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { throw new Error("API 回傳非 JSON（HTTP " + response.status + "），請檢查 Panel journal。"); }
  if (!response.ok) {
    const detail = Array.isArray(data?.detail) ? data.detail.map((item) => typeof item === "string" ? item : item.msg).join("; ") : data?.detail || data?.stderr || data?.error;
    const error = new Error(detail || "HTTP " + response.status);
    error.status = response.status; error.data = data;
    throw error;
  }
  const etag = response.headers.get("etag");
  if (etag && (path === "/api/rules" || path === "/api/rules/import")) state.rulesRevision = etag.replaceAll('"', "");
  return data;
}

async function runBusy(task) {
  if (state.busy) return;
  ++statusSequence;
  state.busy = true; state.error = ""; render();
  try { await task(); }
  catch (error) {
    state.validatedDraft = null;
    state.applyLog.push({ label: error.message, status: "error" });
    reportError(error);
    await refreshStatus();
  } finally { state.busy = false; render(); }
}

function reportError(error) {
  state.error = error.message;
  if ($("#review-drawer").classList.contains("open")) showErrors("review-error", [error.message]);
  toast(error.message); render();
}
function showErrors(id, errors) { const box = $("#" + id); box.hidden = false; box.innerHTML = '<ul>' + errors.map((error) => '<li>' + escaped(error) + '</li>').join("") + '</ul>'; }
function toast(message) {
  $("#toast").textContent = message; $("#toast").hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => $("#toast").hidden = true, 5000);
}
function refreshIcons() { if (window.lucide) lucide.createIcons(); }
