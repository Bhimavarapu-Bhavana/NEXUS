const sections = [...document.querySelectorAll('.view')];
const navItems = [...document.querySelectorAll('.nav-item')];
const text = (value, fallback = '—') => value === undefined || value === null || value === '' ? fallback : String(value);
const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };
const el = (tag, content, className) => { const node = document.createElement(tag); if (className) node.className = className; if (content !== undefined) node.textContent = content; return node; };

async function getJson(path) {
  const response = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return response.json();
}

function showSection(name) {
  sections.forEach(section => section.classList.toggle('active-view', section.id === name));
  navItems.forEach(item => item.classList.toggle('active', item.dataset.section === name));
  refreshAll();
}
navItems.forEach(item => item.addEventListener('click', () => showSection(item.dataset.section)));

async function renderStatus() {
  const data = await getJson('/api/status');
  document.getElementById('local-status').textContent = `LOCAL / ${text(data.status, 'IDLE')}`;
  document.getElementById('hero-status').textContent = text(data.status, 'IDLE');
  document.getElementById('metric-approvals').textContent = text(data.pending_approvals, '0');
  document.getElementById('metric-verification').textContent = text(data.verification);
  document.getElementById('approval-count').textContent = text(data.pending_approvals, '0');
}

async function renderSecurity() {
  const data = await getJson('/api/security');
  const status = text(data.status, 'SCANNER_UNAVAILABLE');
  document.getElementById('metric-security').textContent = status;
  document.getElementById('security-summary').replaceChildren(el('strong', status), el('span', text(data.message, 'No current scanner result is available.'), 'muted'));
  document.getElementById('security-view').replaceChildren(el('h2', status), el('p', text(data.message, 'A clean scan does not guarantee that the system is completely safe.'), 'muted'));
}

async function renderActivity() {
  const data = await getJson('/api/audit');
  const node = document.getElementById('activity'); clear(node);
  const events = data.events || [];
  events.slice(0, 6).forEach(event => {
    const row = el('div', undefined, 'activity-row');
    row.append(el('strong', text(event.event_type, 'EVENT')));
    row.append(el('small', text(event.timestamp)));
    node.append(row);
  });
  if (!events.length) node.append(el('div', 'No audit events yet.', 'empty'));
}

async function renderEvidence() {
  const data = await getJson('/api/evidence');
  const node = document.getElementById('evidence-list'); clear(node);
  const evidence = data.evidence || [];
  evidence.forEach(item => {
    const card = el('article', undefined, 'evidence-card');
    card.append(el('strong', text(item.source, 'SOURCE')));
    card.append(el('span', text(item.status, 'OBSERVED'), 'evidence-status'));
    card.append(el('small', text(item.target, 'No target')));
    card.append(el('p', text(item.summary, 'No summary')));
    node.append(card);
  });
  if (!evidence.length) node.append(el('div', 'No normalized evidence available.', 'empty'));
  document.getElementById('metric-evidence').textContent = String(evidence.length);
  renderRelations('correlations', data.correlations || [], 'No correlations available.');
  renderRelations('conflicts', data.conflicts || [], 'No conflicts detected.');
}
function renderRelations(id, values, emptyText) {
  const node = document.getElementById(id); clear(node);
  values.forEach(value => node.append(el('div', JSON.stringify(value), 'relation')));
  if (!values.length) node.append(el('div', emptyText, 'empty'));
}

async function renderApprovals() {
  const data = await getJson('/api/approvals');
  const node = document.getElementById('approvals-list'); clear(node);
  (data.approvals || []).forEach(item => {
    const card = el('article', undefined, 'approval-card');
    const details = el('div'); details.append(el('h3', text(item.action_type))); details.append(el('p', `${text(item.target)} · ${text(item.risk_level)}`));
    details.append(el('small', `task ${text(item.task_id)} · tool ${text(item.tool_name)} · expires ${text(item.expires_at)}`, 'muted'));
    const controls = el('div', undefined, 'approval-actions');
    const approve = el('button', 'Approve', 'button approve'); const reject = el('button', 'Reject', 'button reject');
    approve.addEventListener('click', () => decide(item.id, 'approve')); reject.addEventListener('click', () => decide(item.id, 'reject'));
    controls.append(approve, reject); card.append(details, controls); node.append(card);
  });
  if (!(data.approvals || []).length) node.append(el('div', 'No pending approvals.', 'empty'));
}

let currentTaskId = '';
async function submitTask() {
  const input = document.getElementById('task-input');
  const note = document.getElementById('task-submit-note');
  const body = { request: input.value };
  note.textContent = 'Submitting task through the StateGraph...';
  let response;
  try {
    response = await fetch('/api/tasks', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  } catch (error) { note.textContent = 'Submission failed: cannot reach the local agent.'; return; }
  let payload = {};
  try { payload = await response.json(); } catch (error) { note.textContent = 'Submission failed: malformed response.'; return; }
  if (!response.ok || !payload.task) { note.textContent = `Submission rejected: ${text((payload || {}).error, response.status)}`; return; }
  currentTaskId = text(payload.task.task_id, '');
  input.value = '';
  note.textContent = `Task ${currentTaskId} accepted with status ${text(payload.task.status)}.`;
  await renderTaskCurrent();
  await renderTaskHistory();
}
function taskRow(label, value) {
  const row = el('div', undefined, 'activity-row');
  row.append(el('strong', label));
  row.append(el('small', text(value)));
  return row;
}
async function renderTaskCurrent() {
  const node = document.getElementById('task-current'); if (!node) return; clear(node);
  const planNode = document.getElementById('task-plan'); if (planNode) clear(planNode);
  const secNode = document.getElementById('task-security'); if (secNode) clear(secNode);
  if (!currentTaskId) { node.append(el('div', 'No task selected yet. Submit a task above.', 'empty')); return; }
  let data;
  try { data = await getJson(`/api/tasks/${encodeURIComponent(currentTaskId)}`); }
  catch (error) { node.append(el('div', 'Task view unavailable.', 'empty')); return; }
  const task = data.task || {};
  node.append(taskRow('Task ID', task.task_id));
  node.append(taskRow('Status', task.status));
  node.append(taskRow('Stage', task.current_stage));
  node.append(taskRow('Subgoal', task.current_sub_goal));
  node.append(taskRow('Outcome', task.final_outcome));
  node.append(taskRow('Verification', task.verification_status));
  if (planNode) {
    const plan = task.goal_plan || [];
    const statuses = task.subgoal_statuses || {};
    if (!plan.length) planNode.append(el('div', 'No plan yet.', 'empty'));
    plan.forEach(item => {
      const sid = text(item.sub_goal_id);
      planNode.append(taskRow(sid, statuses[sid] || 'PLANNED'));
    });
    const completed = (task.completion_evidence || []).length;
    planNode.append(taskRow('Completed evidence items', String(completed)));
    planNode.append(taskRow('Recovery attempts', String(task.recovery_attempts || 0)));
  }
  if (secNode) {
    (data.approvals || []).forEach(item => {
      secNode.append(taskRow(`Approval ${text(item.approval_id)}`, `${text(item.status)} · ${text(item.tool_name)} · ${text(item.risk_level)}`));
    });
    (data.decisions || []).forEach(event => {
      secNode.append(taskRow(text(event.event_type), `${text(event.result)} · ${text(event.reason, '')}`));
    });
    if (!(data.approvals || []).length && !(data.decisions || []).length) secNode.append(el('div', 'No security decisions recorded yet.', 'empty'));
  }
}
async function renderTaskHistory() {
  const node = document.getElementById('task-history'); if (!node) return; clear(node);
  let data;
  try { data = await getJson('/api/tasks'); } catch (error) { node.append(el('div', 'History unavailable.', 'empty')); return; }
  (data.tasks || []).forEach(task => {
    const row = el('div', undefined, 'activity-row');
    const link = el('button', text(task.task_id), 'button secondary');
    link.addEventListener('click', () => { currentTaskId = text(task.task_id); renderTaskCurrent(); });
    row.append(link);
    row.append(el('small', `${text(task.status)} · ${text(task.final_outcome)}`));
    node.append(row);
  });
  if (!(data.tasks || []).length) node.append(el('div', 'No tasks yet.', 'empty'));
}
async function renderDna() {
  const node = document.getElementById('dna-list'); if (!node) return; clear(node);
  let data;
  try { data = await getJson('/api/dna'); } catch (error) { node.append(el('div', 'User DNA unavailable.', 'empty')); return; }
  (data.records || []).forEach(item => {
    const card = el('article', undefined, 'evidence-card');
    card.append(el('strong', `${text(item.kind)} · ${text(item.record_key)}`));
    card.append(el('span', text(item.confidence, ''), 'evidence-status'));
    card.append(el('small', `subject ${text(item.subject)} · status ${text(item.status)}`));
    node.append(card);
  });
  if (!(data.records || []).length) node.append(el('div', 'No User DNA records.', 'empty'));
}
async function decide(id, decision) { await fetch(`/api/approvals/${encodeURIComponent(id)}/${decision}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); await renderApprovals(); await renderStatus(); }

async function renderAudit() {
  const data = await getJson('/api/audit'); const node = document.getElementById('audit-list'); clear(node);
  (data.events || []).forEach(event => {
    const row = el('article', undefined, 'audit-row'); row.append(el('time', text(event.timestamp))); row.append(el('strong', text(event.event_type))); row.append(el('small', `${text(event.result)} ${text(event.reason, '')}`)); node.append(row);
  });
  if (!(data.events || []).length) node.append(el('div', 'No audit events yet.', 'empty'));
}

async function refreshAll() {
  try { await Promise.all([renderStatus(), renderSecurity(), renderActivity(), renderEvidence(), renderApprovals(), renderAudit(), renderTaskCurrent(), renderTaskHistory(), renderDna()]); }
  catch (error) { console.warn('NEXUS UI refresh failed', error); }
}
document.getElementById('refresh').addEventListener('click', refreshAll);
document.querySelectorAll('.refresh-action').forEach(button => button.addEventListener('click', refreshAll));
const runButton = document.getElementById('task-run');
if (runButton) runButton.addEventListener('click', submitTask);
const taskInput = document.getElementById('task-input');
if (taskInput) taskInput.addEventListener('keydown', event => { if (event.key === 'Enter') submitTask(); });
refreshAll();
setInterval(renderStatus, 15000);
