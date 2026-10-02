"use strict";

/* NEXUS Web Control Surface — local-only UI over the existing control plane.
   No arbitrary execution: submission sends one natural-language request. */

const VIEW_ORDER = [
  "dashboard", "tasks", "browser", "workspace",
  "email", "calendar", "applications", "security", "activity",
];

const SERVICE_COMMANDS = ["START", "STOP", "PAUSE", "RESUME", "RESTART", "SHUTDOWN"];
const APPROVED = "APPROVED";
const REJECTED = "REJECTED";

const state = {
  activeTask: null,
  polling: null,
  busy: false,
};

function qs(sel, root) { return (root || document).querySelector(sel); }
function qsa(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/* ------------------------------ API ------------------------------ */

async function api(path, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(path, Object.assign({ signal: controller.signal }, options || {}));
    let payload = null;
    try { payload = await response.json(); } catch (_e) { payload = null; }
    if (!response.ok) {
      const reason = payload && payload.reason ? payload.reason : "The local NEXUS surface did not respond.";
      throw new Error(reason);
    }
    if (payload && payload.accepted === false) {
      throw new Error(payload.reason || "The request was not accepted.");
    }
    return payload || {};
  } finally {
    clearTimeout(timer);
  }
}

function apiGet(path) { return api(path); }
function apiPost(path, body) {
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
}

/* ------------------------------ Toasts ------------------------------ */

function toast(message, kind) {
  const region = qs("#toast-region");
  const node = el("div", "toast" + (kind ? " " + kind : ""), message);
  region.appendChild(node);
  setTimeout(() => node.remove(), 4200);
}

/* ------------------------------ Router ------------------------------ */

function currentView() {
  const raw = location.hash.replace(/^#\//, "").split("?")[0];
  return VIEW_ORDER.indexOf(raw) >= 0 ? raw : "dashboard";
}

function activate(viewName) {
  VIEW_ORDER.forEach((name) => {
    const section = qs("#view-" + name);
    if (section) section.classList.toggle("active-view", name === viewName);
  });
  qsa(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === viewName);
  });
  refreshView(viewName);
}

/* ------------------------------ Connection ------------------------------ */

function setConnection(text, kind) {
  const indicator = qs("#connection-indicator");
  indicator.classList.remove("online", "offline", "busy");
  if (kind) indicator.classList.add(kind);
  qs("#connection-text").textContent = text;
}

function friendly(value) { return value || "—"; }
function badgeClass(value) {
  if (/WAITING_APPROVAL|PAUSED/.test(value)) return "warn";
  if (/FAILED|BLOCKED|REJECTED|ERROR|UNAVAILABLE|STOPPED|SHUTDOWN/.test(value)) return "danger";
  if (/COMPLETED|SUCCESS|READ_ONLY|HEALTHY|RUNNING|NORMAL|AUTHENTICATED|CAPABILITY/.test(value)) return "ok";
  return "";
}

function statusBadge(value) {
  const badge = el("span", "status-badge");
  const className = "status-" + String(value || "NONE").toUpperCase().replace(/[\s/]/g, "_");
  badge.className = "status-badge " + className;
  badge.textContent = value || "NONE";
  return badge;
}

/* ------------------------------ Helpers ------------------------------ */

function formatTime(value) {
  if (!value) return "—";
  const text = String(value).replace("T", " ").slice(0, 19);
  return text;
}

function emptyState(container, text) {
  container.textContent = "";
  container.appendChild(el("div", "empty-text", text));
}

function loading(container, text) {
  const wrap = el("div", "loading");
  wrap.appendChild(el("span", "spinner"));
  wrap.appendChild(document.createTextNode(text || "Loading…"));
  container.textContent = "";
  container.appendChild(wrap);
}

function renderField(heading, value, opts) {
  const field = el("div", "detail-field" + ((opts && opts.full) ? " full" : ""));
  field.appendChild(el("span", "field-label", heading));
  const holder = el("span", "field-value");
  holder.textContent = value === undefined || value === null || value === "" ? "Not available" : String(value);
  if (opts && opts.pre) { holder.classList.add("pre-wrap"); }
  field.appendChild(holder);
  return field;
}

function renderJsonObject(container, value) {
  container.textContent = "";
  try {
    const pane = el("pre", "pre-wrap");
    pane.textContent = JSON.stringify(value, null, 2);
    container.appendChild(pane);
  } catch (_e) {
    container.appendChild(el("span", "empty-text", "Not available"));
  }
}

function renderResultPanel(value) {
  const panel = el("div", "result-panel");
  panel.appendChild(el("span", "field-label", "Result"));
  const pre = el("pre", "pre-wrap");
  pre.textContent = value;
  panel.appendChild(pre);
  return panel;
}

/* ------------------------------ Dashboard ------------------------------ */

async function refreshView(viewName) {
  setConnection("REFRESHING", "busy");
  try {
    if (viewName === "dashboard") await loadDashboard();
    else if (viewName === "tasks") await loadTasks();
    else if (viewName === "browser") await loadSectionProviders("browser", "#browser-providers");
    else if (viewName === "workspace") await loadWorkspace();
    else if (viewName === "email") await loadSectionProviders("email", "#email-providers");
    else if (viewName === "calendar") await loadSectionProviders("calendar", "#calendar-providers");
    else if (viewName === "applications") {
      await loadSectionProviders("job_search", "#job-search-providers");
      await loadSectionProviders("application", "#application-providers");
    }
    else if (viewName === "security") await loadSecurity();
    else if (viewName === "activity") await loadActivity();
    setConnection("CONNECTED · LOCAL", "online");
  } catch (error) {
    setConnection("OFFLINE", "offline");
    toast(error.message || "Could not reach the local NEXUS surface.", "error");
  }
}

async function loadDashboard() {
  const status = await apiGet("/api/status");
  const health = await apiGet("/api/health");
  const approvals = await apiGet("/api/approvals");
  const activity = await apiGet("/api/activity");
  renderHealthStrip(status, health);
  renderDashboardMetrics(status, health);
  renderCurrentTask(status);
  renderApprovalsList(approvals, qs("#dashboard-approvals"));
  qs("#pending-approvals-tag").textContent = String(approvals.count || 0);
  renderActivity(qs("#dashboard-activity"), activity.audit || [], 8);
  renderSecuritySummary(status);
  updateApprovalBadge(approvals);
}

function renderHealthStrip(status, health) {
  const s = status.status || {};
  const stateName = String((s.lifecycle && s.lifecycle.state) || health.state || "UNAVAILABLE").toUpperCase();
  const serviceChip = qs("#chip-service");
  serviceChip.textContent = stateName;
  serviceChip.className = badgeClass(stateName) || "";
  const h = qs("#chip-health");
  h.textContent = health.health || "UNAVAILABLE";
  h.className = badgeClass(h.textContent) || "";
  const r = qs("#chip-resources");
  r.textContent = (s.resource && s.resource.status) || "UNAVAILABLE";
  r.className = badgeClass(r.textContent) || "";
  const a = qs("#chip-approvals");
  a.textContent = String(health.pending_approvals || s.approvals && s.approvals.pending_count || 0);
  const rec = qs("#chip-recovery");
  rec.textContent = String((s.recovery && s.recovery.recovery_failures) || 0);
}

function renderDashboardMetrics(status, health) {
  const s = status.status || {};
  const counts = s.task_counts || {};
  const metrics = [
    ["Service", stateNameFor(s), s.lifecycle && s.lifecycle.state || "UNAVAILABLE"],
    ["Active tasks", countOpen(counts), "Running · waiting · verifying"],
    ["Approvals", s.approvals && s.approvals.pending_count || 0, "Awaiting human decision"],
    ["Security", (s.security && s.security.health) || "UNAVAILABLE", "Monitor posture"],
    ["Recovery", String(s.recovery && s.recovery.recovery_failures || 0), "Recovery failures"],
    ["Providers", String((s.providers && s.providers.length) || 0), "Adapter catalog"],
  ];
  const grid = qs("#dashboard-metrics");
  grid.textContent = "";
  metrics.forEach(([label, value, sub]) => {
    const article = el("article", "metric");
    article.appendChild(el("span", null, label));
    const strong = el("strong", null, String(value));
    strong.className = typeof value === "string" ? badgeClass(value) : "";
    article.appendChild(strong);
    article.appendChild(el("small", null, sub));
    grid.appendChild(article);
  });
}

function stateNameFor(s) {
  return String((s.lifecycle && s.lifecycle.state) || "UNAVAILABLE").toUpperCase();
}

function countOpen(counts) {
  return Number(counts.RUNNING || 0) + Number(counts.WAITING_APPROVAL || 0) + Number(counts.VERIFYING || 0);
}

function renderCurrentTask(status) {
  const s = status.status || {};
  const active = s.active_task;
  const panel = qs("#current-task-panel");
  const tag = qs("#current-task-tag");
  panel.textContent = "";
  tag.textContent = "NONE";
  tag.className = "tag neutral";
  if (!active) {
    panel.appendChild(el("div", "empty-text", "No active task."));
    return;
  }
  tag.textContent = active.status || "RUNNING";
  tag.className = "tag " + badgeClass(tag.textContent) || "tag";
  panel.appendChild(renderField("Task", active.task_id, { full: true }));
  panel.appendChild(renderField("Request", active.objective));
  panel.appendChild(renderField("Status", active.status));
  panel.appendChild(renderField("Stage", active.current_stage));
  const sub = active.current_sub_goal ? active.current_sub_goal : active.current_subgoal_id;
  panel.appendChild(renderField("Sub-goal", sub));
  panel.appendChild(renderField("Outcome", active.final_outcome));
  if (s.active_checkpoint) {
    panel.appendChild(renderField("Checkpoint", s.active_checkpoint.checkpoint_id));
    panel.appendChild(renderField("Approval", s.active_checkpoint.approval_status));
  }
}

function renderSecuritySummary(status) {
  const s = status.status || {};
  const sec = s.security || {};
  const tag = qs("#security-tag");
  tag.textContent = sec.health || "UNAVAILABLE";
  tag.className = "tag " + badgeClass(tag.textContent) || "tag";
  const box = qs("#security-summary");
  box.textContent = "";
  const rows = [
    ["Security", sec.health],
    ["Runtime containment", sec.runtime_containment],
    ["Audit", sec.audit_status],
    ["Ledger", sec.task_ledger_status],
    ["Recovery", sec.recovery_status],
  ];
  rows.forEach(([label, value]) => box.appendChild(renderField(label, value)));
}

function updateApprovalBadge(approvals) {
  const badge = qs("#approval-summary");
  const count = Number(approvals.count || 0);
  badge.textContent = "Approvals · " + count;
  badge.classList.toggle("warn", count > 0);
}

/* ------------------------------ Approvals ------------------------------ */

function renderApprovalsList(approvals, container) {
  container.textContent = "";
  const items = approvals.items || [];
  if (!items.length) {
    container.appendChild(el("div", "empty-text", "No approvals awaiting a decision."));
    return;
  }
  items.forEach((item) => {
    const card = el("article", "approval-card");
    const head = el("div", "approval-head");
    head.appendChild(el("h3", null, item.action_type || "Action"));
    head.appendChild(statusBadge(item.status));
    card.appendChild(head);

    const grid = el("div", "approval-grid");
    grid.appendChild(renderField("Approval", item.approval_id));
    grid.appendChild(renderField("Task", item.task_id));
    grid.appendChild(renderField("Target", item.target));
    grid.appendChild(renderField("Risk", item.risk_level));
    grid.appendChild(renderField("Tool", item.tool_name));
    grid.appendChild(renderField("Expires", formatTime(item.expires_at)));
    card.appendChild(grid);

    if (item.reason) {
      card.appendChild(renderField("Reason", item.reason, { full: true }));
    }

    const actions = el("div", "approval-actions");
    const approve = el("button", "button primary", "Approve");
    approve.type = "button";
    approve.addEventListener("click", () => decideApproval(item, APPROVED));
    const reject = el("button", "button danger", "Reject");
    reject.type = "button";
    reject.addEventListener("click", () => decideApproval(item, REJECTED));
    actions.appendChild(reject);
    actions.appendChild(approve);
    card.appendChild(actions);
    container.appendChild(card);
  });
}

async function decideApproval(item, decision) {
  const buttonGroup = qsa(".approval-actions");
  try {
    const path = "/api/approvals/" + encodeURIComponent(item.approval_id) + "/" + decision.toLowerCase();
    const result = await apiPost(path, {});
    toast("Approval " + decision.toLowerCase() + " · " + item.approval_id, decision === "APPROVED" ? "ok" : "warn");
  } catch (error) {
    toast(error.message || "Approval decision failed.", "error");
  }
  refreshView(currentView());
}

/* ------------------------------ Tasks ------------------------------ */

let detailTaskId = null;

async function loadTasks() {
  const filter = qs("#task-filter").value;
  const path = filter ? "/api/tasks?status=" + encodeURIComponent(filter) : "/api/tasks";
  const payload = await apiGet(path);
  const container = qs("#task-list");
  container.textContent = "";
  const items = payload.items || [];
  if (!items.length) {
    container.appendChild(el("div", "empty-text", "No tasks match."));
  }
  items.forEach((task) => {
    const row = el("div", "task-item");
    row.appendChild(el("span", "task-id", task.task_id));
    const obj = el("span", "task-objective", task.objective || "—");
    row.appendChild(obj);
    const stage = el("span", "task-stage", task.current_stage || task.current_sub_goal || "—");
    row.appendChild(stage);
    row.appendChild(statusBadge(task.status));
    row.addEventListener("click", () => showTaskDetail(task.task_id));
    container.appendChild(row);
  });
  updateApprovalBadge(await apiGet("/api/approvals"));
}

async function showTaskDetail(taskId) {
  detailTaskId = taskId;
  let payload;
  try {
    payload = await apiGet("/api/tasks/" + encodeURIComponent(taskId));
  } catch (error) {
    toast(error.message || "Could not inspect the task.", "error");
    return;
  }
  const detail = qs("#task-detail");
  detail.hidden = false;
  detail.textContent = "";
  const head = el("div", "card-head");
  const title = el("h2", null, taskId);
  head.appendChild(title);
  head.appendChild(statusBadge(payload.task && payload.task.status || "NONE"));
  detail.appendChild(head);

  const t = payload.task || {};
  if (t.task_answer || String(t.status || "").toUpperCase() === "COMPLETED") {
    detail.appendChild(renderResultPanel(t.task_answer || "No result was produced for this task."));
  }

  const grid = el("div", "detail-grid");
  grid.appendChild(renderField("Request", t.objective, { full: true }));
  grid.appendChild(renderField("Status", t.status));
  grid.appendChild(renderField("Stage", t.current_stage));
  grid.appendChild(renderField("Sub-goal", t.current_sub_goal || t.current_subgoal_id));
  grid.appendChild(renderField("Priority", t.priority));
  grid.appendChild(renderField("Deadline", t.deadline));
  grid.appendChild(renderField("Risk", t.status_reason && t.status_reason.split("|").pop().trim() || "Not available"));
  grid.appendChild(renderField("Outcome", t.final_outcome));
  row(grid, "Progress", t.plan_version && t.plan_revisions !== undefined ? "Plan v" + t.plan_version + " · revisions " + t.plan_revisions : "Not available");
  grid.appendChild(renderField("Verification", t.verification_status && "Recorded" || "Not available"));
  grid.appendChild(renderField("Created", formatTime(t.created_at)));
  grid.appendChild(renderField("Updated", formatTime(t.updated_at)));
  grid.appendChild(renderField("Resume reason", t.resume_reason, { full: true }));
  grid.appendChild(renderField("Status reason", t.status_reason, { full: true }));
  if (payload.checkpoint) {
    grid.appendChild(renderField("Checkpoint", payload.checkpoint.checkpoint_id));
    grid.appendChild(renderField("Action type", payload.checkpoint.action_type));
    grid.appendChild(renderField("Action target", payload.checkpoint.action_target));
    grid.appendChild(renderField("Approval status", payload.checkpoint.approval_status));
  }

  detail.appendChild(grid);

  if (t.goal_plan && t.goal_plan.length) {
    detail.appendChild(renderField("Goal plan", JSON.stringify(t.goal_plan), { full: true, pre: true }));
  }
  if (t.completion_evidence && t.completion_evidence.length) {
    detail.appendChild(renderField("Completion evidence", JSON.stringify(t.completion_evidence.slice(-5), null, 2), { full: true, pre: true }));
  }
  if (t.verification_history && t.verification_history.length) {
    detail.appendChild(renderField("Verification history", JSON.stringify(t.verification_history.slice(-3), null, 2), { full: true, pre: true }));
  }
  if (t.evidence_refs && t.evidence_refs.length) {
    detail.appendChild(renderField("Evidence references", t.evidence_refs.join(", "), { full: true }));
  }
  detail.appendChild(renderField("Audit reference", taskId, { full: true }));
}

function row(grid, label, value) {
  grid.appendChild(renderField(label, value));
}

async function submitTask(textareaId, statusId) {
  const input = qs(textareaId);
  const status = qs(statusId);
  const text = input.value.trim();
  if (!text) { toast("Enter a task request first.", "warn"); return; }
  status.textContent = "Sending request to the local NEXUS pipeline…";
  try {
    const result = await apiPost("/api/tasks", { request: text });
    status.textContent = "Task created · " + result.task_id;
    input.value = "";
    toast("Task " + result.task_id + " created.", "ok");
    if (result.task_id) {
      detailTaskId = result.task_id;
      maybeSchedulePolling();
      setTimeout(() => showTaskDetail(result.task_id), 600);
    }
    loadTasks();
  } catch (error) {
    status.textContent = "";
    toast(error.message || "Task could not be submitted.", "error");
  }
}

/* ------------------------------ Sections ------------------------------ */

async function loadSectionProviders(applicationId, targetSelector) {
  const payload = await apiGet("/api/sections/" + encodeURIComponent(applicationId));
  const container = qs(targetSelector);
  container.textContent = "";
  const providers = payload.providers || [];
  if (!providers.length) {
    container.appendChild(el("div", "empty-text", "No providers are registered for this application."));
    return;
  }
  providers.forEach((provider) => {
    const row = el("div", "provider-row");
    const nameCell = el("div", null);
    nameCell.appendChild(el("div", "provider-name", provider.display_name || provider.provider_id));
    nameCell.appendChild(el("div", "provider-kind", provider.provider_id + " · " + provider.kind + (provider.fixture_or_mock ? " · FIXTURE/MOCK" : "")));
    row.appendChild(nameCell);
    row.appendChild(statusBadge(provider.status));
    const capabilities = el("div", "tag", String((provider.capabilities || []).length) + " caps");
    row.appendChild(capabilities);
    container.appendChild(row);
  });
}

async function loadWorkspace() {
  const root = qs("#workspace-panels");
  loading(root, "Loading workspace state…");
  let workspace;
  let git;
  try {
    workspace = (await apiGet("/api/workspace")).workspace || {};
  } catch (_e) { workspace = {}; }
  try {
    git = (await apiGet("/api/git")).git || {};
  } catch (_e) { git = {}; }
  root.textContent = "";
  const section = el("div", "detail-grid");
  section.appendChild(renderField("Workspace root", workspace.workspace_root));
  section.appendChild(renderField("Monitor", workspace.monitor_running ? "RUNNING" : "STOPPED"));
  section.appendChild(renderField("Queued events", String(workspace.queued_workspace_events || 0)));
  root.appendChild(section);

  const gitCard = el("article", "card");
  const gitHead = el("div", "card-head");
  gitHead.appendChild(el("h2", null, "Git state"));
  gitHead.appendChild((el("span", "tag neutral", "TOOL")));
  gitCard.appendChild(gitHead);
  const gitGrid = el("div", "detail-grid");
  if (git.status === "UNAVAILABLE" || !git || Object.keys(git).length === 0) {
    gitGrid.appendChild(renderField("Status", git.status === "UNAVAILABLE" ? git.reason || "Unavailable" : "Not available", { full: true }));
  } else {
    gitGrid.appendChild(renderField("Branch", git.branch));
    gitGrid.appendChild(renderField("Repository", git.repository_exists ? "Yes" : "No"));
    gitGrid.appendChild(renderField("Uncommitted", String(git.uncommitted_changes_count !== undefined ? git.uncommitted_changes_count : "Not available")));
    gitGrid.appendChild(renderField("Recent commits", Array.isArray(git.recent_commits) ? String(git.recent_commits.length) : "Not available"));
  }
  gitCard.appendChild(gitGrid);
  root.appendChild(gitCard);

  const events = workspace.recent_workspace_events || [];
  const eventsCard = el("article", "card");
  const eventsHead = el("div", "card-head");
  eventsHead.appendChild(el("h2", null, "Recent workspace events"));
  eventsHead.appendChild((el("span", "tag", "MONITOR")));
  eventsCard.appendChild(eventsHead);
  const eventsList = el("div", "event-list");
  if (!events.length) emptyState(eventsList, "No recent workspace events.");
  else events.forEach((event) => eventsList.appendChild(renderEventRow(event)));
  eventsCard.appendChild(eventsList);
  root.appendChild(eventsCard);
}

function renderEventRow(event) {
  const row = el("div", "event-item");
  row.appendChild(el("span", "act-time", formatTime(event.last_seen_at || event.timestamp || event.created_at || event.detected_at)));
  row.appendChild(el("span", "act-type", String(event.event_type || event.type || "EVENT")));
  const detailText = event.path || event.target || event.reason || event.instruction || "";
  row.appendChild(el("span", "act-detail", detailText.length ? detailText : "—"));
  row.appendChild(el("span", "act-result", String(event.status || event.severity || event.result || "—").toUpperCase()));
  return row;
}

async function loadSecurity() {
  const payload = await apiGet("/api/security");
  const sec = payload.security || {};
  qs("#security-health").textContent = sec.health || "UNAVAILABLE";
  qs("#security-health").className = badgeClass(qs("#security-health").textContent) || "";
  qs("#security-runtime").textContent = sec.runtime_containment || "UNAVAILABLE";
  qs("#security-runtime").className = badgeClass(qs("#security-runtime").textContent) || "";
  qs("#security-audit").textContent = sec.audit_status || "UNAVAILABLE";
  qs("#security-audit").className = badgeClass(qs("#security-audit").textContent) || "";
  qs("#security-scanner").textContent = sec.scanner_status || "UNAVAILABLE";
  qs("#security-scanner").className = badgeClass(qs("#security-scanner").textContent) || "";

  const events = sec.recent_security_events || [];
  const container = qs("#security-events");
  container.textContent = "";
  if (!events.length) emptyState(container, "No recent security events.");
  else events.forEach((event) => container.appendChild(renderEventRow(event)));
}

async function loadActivity() {
  const payload = await apiGet("/api/activity");
  const audit = payload.audit || [];
  const events = payload.events || [];
  renderActivity(qs("#activity-list"), audit, 40);
  const auto = qs("#autonomous-events");
  auto.textContent = "";
  if (!events.length) emptyState(auto, "No recent autonomous events.");
  else events.forEach((event) => auto.appendChild(renderEventRow(event)));
}

function renderActivity(container, audit, limit) {
  container.textContent = "";
  const items = (audit || []).slice(0, limit);
  if (!items.length) {
    container.appendChild(el("div", "empty-text", "No recent activity."));
    return;
  }
  items.forEach((event) => {
    const row = el("div", "activity-item");
    row.appendChild(el("span", "act-time", formatTime(event.timestamp || event.created_at)));
    row.appendChild(el("span", "act-type", String(event.event_type || "EVENT")));
    const detailParts = [];
    if (event.target) detailParts.push("target=" + event.target);
    if (event.tool) detailParts.push("tool=" + event.tool);
    if (event.reason) detailParts.push(String(event.reason).slice(0, 160));
    const detail = el("span", "act-detail", detailParts.join(" · ") || "—");
    row.appendChild(detail);
    row.appendChild(el("span", "act-result", String((event.result || event.risk_level || "").toUpperCase() || "—")));
    container.appendChild(row);
  });
}

/* ------------------------------ Polling ------------------------------ */

function openWorkExists() {
  const statusStore = window.__nexus_status || {};
  const counts = (statusStore.task_counts || {});
  const open = Number(counts.RUNNING || 0) + Number(counts.WAITING_APPROVAL || 0) + Number(counts.VERIFYING || 0);
  return open > 0;
}

function maybeSchedulePolling() {
  stopPolling();
  const CHECK_MS = 4000;
  state.polling = setInterval(async () => {
    try {
      const status = await apiGet("/api/status");
      window.__nexus_status = status.status || {};
      if (detailTaskId) {
        try { await showTaskDetail(detailTaskId); } catch (_e) { /* keep polling */ }
      }
      refreshTaskBadges(status);
      if (!openWorkExists()) stopPolling();
    } catch (_e) {
      stopPolling();
    }
  }, CHECK_MS);
}

function refreshTaskBadges(status) {
  const s = status.status || {};
  const tag = qs("#current-task-tag");
  if (s.active_task) {
    tag.textContent = s.active_task.status || "RUNNING";
    tag.className = "tag " + (badgeClass(tag.textContent) || "tag");
  }
}

function stopPolling() {
  if (state.polling) {
    clearInterval(state.polling);
    state.polling = null;
  }
}

/* ------------------------------ Service controls ------------------------------ */

async function serviceCommand(command) {
  const text = command === "START" ? "Starting NEXUS service…" : "Sending " + command.toLowerCase() + "…";
  toast(text, "");
  try {
    const result = await apiPost("/api/service/" + command.toLowerCase(), {});
    toast("Service " + command.toLowerCase() + " · state " + String((result.result && result.result.state) || result.current_state || "—"), "ok");
  } catch (error) {
    toast(error.message || "Service command failed.", "error");
  }
  refreshView(currentView());
}

/* ------------------------------ Wire up ------------------------------ */

function wireButtons() {
  qs("#btn-run-task").addEventListener("click", () => submitTask("#task-input", "#composer-status"));
  qs("#btn-run-task-2").addEventListener("click", () => submitTask("#task-input-2", "#composer-status-2"));
  qs("#task-input").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) qs("#btn-run-task").click(); });
  qs("#task-input-2").addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) qs("#btn-run-task-2").click(); });
  qs("#btn-service-refresh").addEventListener("click", () => refreshView(currentView()));
  qs("#btn-service-start").addEventListener("click", () => serviceCommand("START"));
  qs("#btn-service-stop").addEventListener("click", () => serviceCommand("STOP"));
  qs("#task-filter").addEventListener("change", () => loadTasks());
  window.addEventListener("hashchange", () => activate(currentView()));
}

function ensurePageBasics() {
  const s = new Date().toISOString().slice(0, 10);
  qs("#boundary-value").textContent = "LOCAL · 127.0.0.1";
  void s;
}

async function bootstrap() {
  wireButtons();
  ensurePageBasics();
  activate(currentView());
  try {
    const status = await apiGet("/api/status");
    window.__nexus_status = status.status || {};
  } catch (_e) { /* offline state handled in views */ }
  maybeSchedulePolling();
}

document.addEventListener("DOMContentLoaded", bootstrap);