"""Dependency-free browser dashboard for the local API.

The script is served separately at /dashboard.js so the page's Content
Security Policy can forbid inline scripts.
"""

DASHBOARD_HTML = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SIEM Dashboard</title>
  <style>
    :root { --ink:#172033; --muted:#667085; --line:#e5e8ef; --panel:#fff; --bg:#f5f7fb; --red:#b42318; --orange:#b54708; --blue:#175cd3; --purple:#6941c6; --green:#027a48; }
    * { box-sizing:border-box } body { font:15px system-ui,sans-serif; max-width:1180px; margin:0 auto; padding:2rem 1rem; background:radial-gradient(circle at 0 0,#e9f2ff 0,transparent 32rem),var(--bg); color:var(--ink) }
    header { display:flex; align-items:center; justify-content:space-between; gap:1rem; margin-bottom:1.5rem; padding:1.35rem 1.5rem; border-radius:16px; color:white; background:linear-gradient(135deg,#172554,#175cd3 58%,#7f56d9); box-shadow:0 12px 30px #175cd333 } h1 { margin:.2rem 0; letter-spacing:-.03em } header .muted { color:#dbeafe } h2 { margin-top:2rem; letter-spacing:-.02em } h3 { margin:0 0 .8rem; font-size:.95rem }
    button,input,select { font:inherit; border:1px solid #cfd5df; border-radius:8px; padding:.58rem .75rem; background:white } button { cursor:pointer; background:var(--blue); color:white; border-color:var(--blue); transition:transform .15s,box-shadow .15s } button:hover { transform:translateY(-1px); box-shadow:0 4px 12px #175cd344 } header button { background:#ffffff1f; border-color:#ffffff66 } header input { background:#ffffffee }
    .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem } .grid.panels { grid-template-columns:repeat(2,1fr); margin-top:1rem } .card { position:relative; overflow:hidden; background:var(--panel); border:1px solid #e6eaf2; border-radius:14px; padding:1.1rem; box-shadow:0 5px 18px #1018280d } .card:after { content:""; position:absolute; left:0; right:0; bottom:0; height:3px; background:linear-gradient(90deg,var(--blue),var(--purple)) } .number { font-size:2.15rem; font-weight:750; margin-top:.35rem }
    .bar-row { display:grid; grid-template-columns:minmax(7rem,38%) 1fr 3rem; gap:.6rem; align-items:center; margin:.35rem 0; font-size:.88rem } .bar-row code { overflow:hidden; text-overflow:ellipsis; white-space:nowrap } .bar { height:.6rem; border-radius:999px; background:var(--blue); min-width:2px } .bar.critical,.bar.high { background:var(--red) } .bar.medium { background:var(--orange) } .bar.low { background:var(--green) } .bar-row .count { text-align:right; font-variant-numeric:tabular-nums }
    .toolbar { display:flex; flex-wrap:wrap; gap:.6rem; align-items:center; margin:1rem 0 } .muted { color:var(--muted) } .error { color:var(--red); min-height:1.4rem }
    .nav { display:flex; gap:.5rem; align-items:center; margin:1rem 0 } .nav button { background:#eef4ff; color:var(--blue); border-color:#c7d7fe } .nav button.active { background:var(--blue); color:white } .nav #role-label { margin-left:auto; font-size:.85rem } .view { display:none } .view.active { display:block }
    .table-wrap { overflow-x:auto; border:1px solid #e6eaf2; border-radius:12px; box-shadow:0 5px 18px #1018280d } table { width:100%; border-collapse:collapse; background:var(--panel) } th,td { text-align:left; padding:.8rem; border-bottom:1px solid var(--line); vertical-align:top } th { white-space:nowrap; color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.06em; background:#f8fafc } tr:last-child td { border-bottom:0 } tbody tr:hover { background:#f8fbff }
    .high,.critical { color:var(--red); font-weight:700 } .medium { color:var(--orange); font-weight:700 } .status { color:var(--green); font-weight:700 } dialog { border:0; border-radius:14px; padding:1.5rem; min-width:min(580px,90vw); box-shadow:0 24px 70px #10182844 } dialog::backdrop { background:#10182888; backdrop-filter:blur(3px) } pre { max-height:260px; overflow:auto; padding:1rem; border-radius:8px; background:#101828; color:#d1fadf; font-size:.8rem } .toolbar { background:#ffffffaa; padding:.45rem; border-radius:10px }
    .badge { display:inline-block; padding:.22rem .55rem; border-radius:999px; font-size:.75rem; font-weight:700; text-transform:uppercase; letter-spacing:.04em; background:#eef2ff; color:#3538cd } .badge.high,.badge.critical { background:#fef3f2; color:var(--red) } .badge.medium { background:#fffaeb; color:var(--orange) } .badge.low { background:#ecfdf3; color:var(--green) }
    .login { max-width:420px; margin:3rem auto } .login form { display:grid; gap:.75rem } .login label { display:grid; gap:.3rem; font-size:.9rem } .login details { margin-top:1rem; font-size:.9rem } .login details .toolbar { margin:.6rem 0 0; padding:0; background:none } [hidden] { display:none !important }
    @media (max-width:760px) { header { align-items:flex-start; flex-direction:column } .grid, .grid.panels { grid-template-columns:repeat(2,1fr) } }
    @media (max-width:520px) { .grid.panels { grid-template-columns:1fr } }
  </style>
</head>
<body>
  <header><div><h1>SIEM Dashboard</h1><div class="muted">Local security monitoring and incident triage</div></div><div class="toolbar"><button id="refresh">Refresh</button><button id="logout" hidden>Sign out</button></div></header>
  <section id="login-view" class="login card" hidden><h2>Sign in</h2>
    <form id="login-form"><label>Username <input id="login-user" autocomplete="username" required></label><label>Password <input id="login-password" type="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form>
    <p id="login-error" class="error" role="alert"></p>
    <details><summary>Use an API key instead</summary><div class="toolbar"><input id="api-key" type="password" placeholder="API key (kept for this tab only)" autocomplete="off"><button id="save-key">Use key</button></div></details>
  </section>
  <nav id="app-nav" class="nav" aria-label="Dashboard views"><button data-view="overview">Overview</button><button data-view="triage">Analyst triage</button><button data-view="operations">Operations</button><span id="role-label" class="muted"></span></nav>
  <div id="error" class="error" role="alert"></div>
  <section id="overview" class="view">
    <section class="grid"><div class="card"><div>API status</div><div id="status" class="number">…</div></div><div class="card"><div>Security events</div><div id="event-count" class="number">…</div></div><div class="card"><div>Open incidents</div><div id="incident-count" class="number">…</div></div><div class="card"><div>Alerts (24h)</div><div id="alert-count" class="number">…</div></div></section>
    <section class="grid panels">
      <div class="card"><h3>Alerts by severity (24h)</h3><div id="alert-severity" class="muted">…</div></div>
      <div class="card"><h3>Alerts by rule (24h)</h3><div id="alert-rules" class="muted">…</div></div>
      <div class="card"><h3>Top failed-login sources (24h)</h3><div id="top-ips" class="muted">…</div></div>
      <div class="card"><h3>Most targeted accounts (24h)</h3><div id="top-users" class="muted">…</div></div>
    </section>
  </section>
  <section id="triage" class="view"><h2>Alerts</h2>
  <div class="toolbar"><input id="search" type="search" placeholder="Search alerts"><select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><span id="updated" class="muted"></span></div>
  <div class="table-wrap"><table><thead><tr><th>Severity</th><th>Title</th><th>Reason</th><th>Rule</th><th>Created</th></tr></thead><tbody id="alerts"><tr><td colspan="5">Loading…</td></tr></tbody></table></div>
  <h2>Open incidents</h2><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Title</th><th>Status</th><th>Assignee</th><th>Updated</th></tr></thead><tbody id="incidents"><tr><td colspan="5">Loading…</td></tr></tbody></table></div></section>
  <section id="operations" class="view"><h2>Event search</h2><div class="toolbar"><input id="event-search" type="search" placeholder="Search event text, type, or source"><select id="event-severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><button id="search-events">Search</button></div>
  <div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Type</th><th>Message</th></tr></thead><tbody id="events"><tr><td colspan="5">Search for events.</td></tr></tbody></table></div></section>
  <dialog id="incident-dialog"><form method="dialog"><h2>Incident</h2><pre id="incident-detail"></pre><label>Status <select id="incident-status"><option>open</option><option>investigating</option><option>resolved</option><option>closed</option></select></label><br><label>Assignee <input id="incident-assignee"></label><p id="incident-error" class="error"></p><p><button id="save-incident" value="default">Save</button> <button>Cancel</button></p></form></dialog>
  <script src="/dashboard.js"></script>
</body></html>'''

DASHBOARD_JS = r'''"use strict";
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'}[c]));
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function storedKey() { try { return sessionStorage.getItem('siem-api-key') || ''; } catch { return ''; } }
function headers() { const key = storedKey(); return key ? {'X-API-Key': key} : {}; }
class HttpError extends Error { constructor(path, status) { super(`${path}: HTTP ${status}`); this.status = status; } }
async function request(path, options = {}) {
  const response = await fetch(path, {...options, headers: {...headers(), ...(options.headers || {})}});
  if (!response.ok) throw new HttpError(path, response.status);
  return response;
}
const postJson = (path, body) => request(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});

function showSignedIn(signedIn) {
  $('login-view').hidden = signedIn;
  $('app-nav').hidden = !signedIn;
  $('logout').hidden = !signedIn;
  $('refresh').hidden = !signedIn;
  document.querySelectorAll('.view').forEach(view => { view.hidden = !signedIn; });
  if (!signedIn) $('login-user').focus();
}
const get = async (path, options) => (await request(path, options)).json();
const text = async path => (await request(path)).text();

function bars(target, rows, {severityColors = false} = {}) {
  const max = Math.max(1, ...rows.map(row => row.count));
  $(target).className = rows.length ? '' : 'muted';
  $(target).innerHTML = rows.map(row => `<div class="bar-row"><code title="${esc(row.label)}">${esc(row.label)}</code>`
    + `<div class="bar ${severityColors ? esc(row.label) : ''}" style="width:${(row.count / max) * 100}%"></div>`
    + `<span class="count">${esc(row.count)}</span></div>`).join('') || 'Nothing in this window.';
}

function renderStats(stats) {
  const bySeverity = stats.alerts.by_severity || {};
  const severities = Object.keys(bySeverity).sort((a, b) => SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b));
  $('alert-count').textContent = Object.values(bySeverity).reduce((sum, count) => sum + count, 0);
  bars('alert-severity', severities.map(label => ({label, count: bySeverity[label]})), {severityColors: true});
  bars('alert-rules', Object.entries(stats.alerts.by_rule || {}).map(([label, count]) => ({label, count})));
  bars('top-ips', (stats.top_failed_login_ips || []).map(row => ({label: row.value, count: row.count})));
  bars('top-users', (stats.top_failed_login_users || []).map(row => ({label: row.value, count: row.count})));
}

function renderAlerts(alerts) {
  $('alerts').innerHTML = alerts.slice().reverse().map(a => `<tr><td><span class="badge ${esc(a.severity)}">${esc(a.severity || 'unknown')}</span></td><td><strong>${esc(a.title)}</strong></td><td>${esc(a.reason)}</td><td><code>${esc(a.rule_id)}</code></td><td>${esc(a.created_at)}</td></tr>`).join('')
    || '<tr><td colspan="5">No alerts found.</td></tr>';
}

function renderIncidents(items) {
  $('incidents').innerHTML = items.map(i => `<tr><td><span class="badge ${esc(i.severity)}">${esc(i.severity)}</span></td><td><button data-incident="${esc(i.incident_id)}">${esc(i.title)}</button></td><td class="status">${esc(i.status)}</td><td>${esc(i.assignee || 'Unassigned')}</td><td>${esc(i.updated_at)}</td></tr>`).join('')
    || '<tr><td colspan="5">No open incidents.</td></tr>';
  document.querySelectorAll('[data-incident]').forEach(b => b.addEventListener('click', () => openIncident(b.dataset.incident)));
}

function renderEvents(items) {
  $('events').innerHTML = items.map(e => `<tr><td>${esc(e.observed_at)}</td><td class="${esc(e.severity)}">${esc(e.severity)}</td><td>${esc(e.source)}</td><td>${esc(e.event_type)}</td><td>${esc(e.message)}</td></tr>`).join('')
    || '<tr><td colspan="5">No events found.</td></tr>';
}

async function openIncident(id) {
  const result = await get(`/incidents/${encodeURIComponent(id)}`);
  const incident = result.incident;
  $('incident-detail').textContent = JSON.stringify({...incident, audit: result.audit}, null, 2);
  $('incident-status').value = incident.status;
  $('incident-assignee').value = incident.assignee || '';
  $('incident-error').textContent = '';
  $('incident-dialog').dataset.id = id;
  $('incident-dialog').showModal();
}

async function searchEvents() {
  const result = await get(`/events?limit=100&text=${encodeURIComponent($('event-search').value)}&severity=${encodeURIComponent($('event-severity').value)}`);
  renderEvents(result.events || []);
}

function switchView(view) {
  document.querySelectorAll('.view').forEach(x => x.classList.toggle('active', x.id === view));
  document.querySelectorAll('[data-view]').forEach(x => x.classList.toggle('active', x.dataset.view === view));
  try { localStorage.setItem('siem-view', view); } catch {}
}

async function load() {
  $('error').textContent = '';
  try {
    await get('/me');
  } catch (error) {
    if (error.status === 401) { showSignedIn(false); return; }
  }
  showSignedIn(true);
  try {
    const [health, metricsText, stats, alerts, incidents, me] = await Promise.all([
      get('/health'), text('/metrics'), get('/stats?hours=24'),
      get(`/alerts?limit=100&text=${encodeURIComponent($('search').value)}&severity=${encodeURIComponent($('severity').value)}`),
      get('/incidents?status=open&limit=100'), get('/me'),
    ]);
    const metrics = {};
    for (const match of metricsText.matchAll(/^siem_([a-z_]+)\s+(\d+)$/gm)) metrics[match[1]] = Number(match[2]);
    $('role-label').textContent = `Signed in as ${me.name} (${me.role})`;
    $('status').textContent = health.status || 'ok';
    $('status').className = 'number status';
    $('event-count').textContent = metrics.security_events ?? '0';
    $('incident-count').textContent = metrics.open_incidents ?? '0';
    renderStats(stats);
    renderAlerts(alerts.alerts || []);
    renderIncidents(incidents.incidents || []);
    $('updated').textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    $('status').textContent = 'error';
    $('error').textContent = `Dashboard unavailable: ${error.message}`;
  }
}

$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('login-error').textContent = '';
  try {
    await postJson('/login', {username: $('login-user').value, password: $('login-password').value});
    $('login-password').value = '';
    load();
  } catch (error) {
    $('login-error').textContent = error.status === 429 ? 'Too many failed attempts. Try again in a few minutes.' : 'Wrong username or password.';
  }
});
$('logout').addEventListener('click', async () => {
  try { sessionStorage.removeItem('siem-api-key'); } catch {}
  $('api-key').value = '';
  try { await postJson('/logout', {}); } catch {}
  showSignedIn(false);
});
$('api-key').value = storedKey();
document.querySelectorAll('[data-view]').forEach(button => button.addEventListener('click', () => switchView(button.dataset.view)));
let savedView = 'overview';
try { savedView = localStorage.getItem('siem-view') || 'overview'; } catch {}
switchView(savedView);
$('save-key').addEventListener('click', () => { try { sessionStorage.setItem('siem-api-key', $('api-key').value); } catch {} load(); });
$('refresh').addEventListener('click', load);
$('search').addEventListener('input', load);
$('severity').addEventListener('change', load);
$('search-events').addEventListener('click', searchEvents);
$('save-incident').addEventListener('click', async event => {
  event.preventDefault();
  const id = $('incident-dialog').dataset.id;
  try {
    await get(`/incidents/${encodeURIComponent(id)}`, {method: 'PATCH', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({status: $('incident-status').value, assignee: $('incident-assignee').value})});
    $('incident-dialog').close();
    load();
  } catch (error) {
    $('incident-error').textContent = `Save failed: ${error.message}`;
  }
});
load();
setInterval(load, 30000);
'''
