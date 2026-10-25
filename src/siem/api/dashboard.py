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
    .bar-row { display:grid; grid-template-columns:minmax(7rem,38%) 1fr 3rem; gap:.6rem; align-items:center; margin:.35rem 0; font-size:.88rem } .bar-row code { overflow:hidden; text-overflow:ellipsis; white-space:nowrap } .bar { height:.6rem; border-radius:999px; background:var(--blue); min-width:2px } .bar.critical { background:#7a271a } .bar.high { background:var(--red) } .bar.medium { background:#f79009 } .bar.low { background:var(--green) } .bar-row .count { text-align:right; font-variant-numeric:tabular-nums }
    .toolbar { display:flex; flex-wrap:wrap; gap:.6rem; align-items:center; margin:1rem 0 } .muted { color:var(--muted) } .error { color:var(--red); min-height:1.4rem }
    .nav { display:flex; gap:.5rem; align-items:center; margin:1rem 0 } .nav button { background:#eef4ff; color:var(--blue); border-color:#c7d7fe } .nav button.active { background:var(--blue); color:white } .nav #role-label { margin-left:auto; font-size:.85rem } .view { display:none } .view.active { display:block }
    .table-wrap { overflow-x:auto; border:1px solid #e6eaf2; border-radius:12px; box-shadow:0 5px 18px #1018280d } table { width:100%; border-collapse:collapse; background:var(--panel) } th,td { text-align:left; padding:.8rem; border-bottom:1px solid var(--line); vertical-align:top } th { white-space:nowrap; color:var(--muted); font-size:.78rem; text-transform:uppercase; letter-spacing:.06em; background:#f8fafc } tr:last-child td { border-bottom:0 } tbody tr:hover { background:#f8fbff }
    .high,.critical { color:var(--red); font-weight:700 } .medium { color:var(--orange); font-weight:700 } .status { color:var(--green); font-weight:700 } dialog { border:0; border-radius:14px; padding:1.5rem; min-width:min(580px,90vw); box-shadow:0 24px 70px #10182844 } dialog::backdrop { background:#10182888; backdrop-filter:blur(3px) } pre { max-height:260px; overflow:auto; padding:1rem; border-radius:8px; background:#101828; color:#d1fadf; font-size:.8rem } .toolbar { background:#ffffffaa; padding:.45rem; border-radius:10px }
    .badge { display:inline-block; padding:.22rem .55rem; border-radius:999px; font-size:.75rem; font-weight:700; text-transform:uppercase; letter-spacing:.04em; background:#eef2ff; color:#3538cd } .badge.high,.badge.critical { background:#fef3f2; color:var(--red) } .badge.medium { background:#fffaeb; color:var(--orange) } .badge.low { background:#ecfdf3; color:var(--green) }
    .chart-card { margin-top:1rem } .chart-head { display:flex; flex-wrap:wrap; gap:.75rem; align-items:center; justify-content:space-between; margin-bottom:.6rem } .chart-head h3 { margin:0 } .legend { display:flex; flex-wrap:wrap; gap:.8rem; font-size:.8rem; color:var(--muted) } .legend i { display:inline-block; width:.7rem; height:.7rem; border-radius:3px; margin-right:.3rem; vertical-align:-1px }
    #timeline svg { width:100%; height:auto; display:block } #timeline .axis { fill:var(--muted); font-size:11px } #timeline .grid-line { stroke:var(--line) } .sev-critical { fill:#7a271a; background:#7a271a } .sev-high { fill:var(--red); background:var(--red) } .sev-medium { fill:#f79009; background:#f79009 } .sev-low { fill:var(--green); background:var(--green) } .sev-info { fill:#98a2b3; background:#98a2b3 } .logins-line { fill:none; stroke:var(--purple); stroke-width:2 } .logins-key { background:var(--purple) }
    .login { max-width:420px; margin:3rem auto } .login form { display:grid; gap:.75rem } .login label { display:grid; gap:.3rem; font-size:.9rem } .login details { margin-top:1rem; font-size:.9rem } .login details .toolbar { margin:.6rem 0 0; padding:0; background:none } [hidden] { display:none !important }
    .chips { display:flex; flex-wrap:wrap; gap:.4rem } .chip { display:inline-block; padding:.2rem .55rem; border-radius:999px; background:#eef4ff; color:var(--blue); font-size:.8rem; font-weight:600 } .chip.danger { background:#fef3f2; color:var(--red) }
    .result { margin:1rem 0 } .result-head { display:flex; flex-wrap:wrap; gap:.8rem; align-items:center; justify-content:space-between } .result-head h3 { margin:0; font-size:1.25rem; word-break:break-all }
    .verdict { white-space:nowrap; padding:.35rem .8rem; border-radius:999px; font-weight:800; text-transform:uppercase; letter-spacing:.05em; font-size:.85rem } .verdict.suspicious { background:#fef3f2; color:var(--red) } .verdict.potentially-suspicious { background:#fffaeb; color:var(--orange) } .verdict.no-obvious-indicators { background:#ecfdf3; color:var(--green) }
    .facts { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:.8rem; margin:1rem 0 } .facts div { background:#f8fafc; border:1px solid var(--line); border-radius:10px; padding:.6rem .75rem } .facts dt { color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.05em } .facts dd { margin:.2rem 0 0; font-weight:700; word-break:break-all }
    .caps { display:grid; gap:.45rem; margin:.4rem 0 1rem; padding:0; list-style:none } .caps li { padding:.55rem .75rem; border-left:4px solid var(--red); background:#fffbfa; border-radius:6px } .caps code { font-size:.8rem; color:var(--muted) }
    .reputation { padding:.75rem 1rem; border-radius:10px; background:#f8fafc; border:1px solid var(--line); margin:.6rem 0 } .reputation.bad { background:#fef3f2; border-color:#fecdca } .reputation.good { background:#ecfdf3; border-color:#abefc6 }
    .note { font-size:.88rem; color:var(--muted) } button:disabled { opacity:.45; cursor:not-allowed; transform:none; box-shadow:none } button.secondary { background:white; color:var(--blue) } button.danger { background:var(--red); border-color:var(--red) }
    .report-view { background:var(--panel); border:1px solid #e6eaf2; border-radius:14px; padding:1.2rem 1.5rem; box-shadow:0 5px 18px #1018280d; line-height:1.55 } .report-view h3 { margin:1.2rem 0 .4rem } .report-view h4 { margin:1rem 0 .3rem } .report-view ul { margin:.3rem 0; padding-left:1.3rem } .report-view.ai { border-left:4px solid var(--purple) }
    @media (max-width:760px) { .facts { grid-template-columns:repeat(2,minmax(0,1fr)) } }
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
  <nav id="app-nav" class="nav" aria-label="Dashboard views"><button data-view="overview">Overview</button><button data-view="triage">Analyst triage</button><button data-view="operations">Operations</button><button data-view="malware">Malware analysis</button><button data-view="intel">Threat intel</button><button data-view="reports">Reports &amp; AI</button><span id="role-label" class="muted"></span></nav>
  <div id="error" class="error" role="alert"></div>
  <section id="overview" class="view">
    <div class="toolbar"><label>Time range <select id="range"><option value="24">Last 24 hours</option><option value="168">Last 7 days</option><option value="720">Last 30 days</option></select></label></div>
    <section class="grid"><div class="card"><div>API status</div><div id="status" class="number">…</div></div><div class="card"><div>Security events</div><div id="event-count" class="number">…</div></div><div class="card"><div>Open incidents</div><div id="incident-count" class="number">…</div></div><div class="card"><div>Alerts (<span class="range-label">24h</span>)</div><div id="alert-count" class="number">…</div></div></section>
    <div class="card chart-card"><div class="chart-head"><h3>Alerts over time</h3><div class="legend"><span><i class="sev-critical"></i>critical</span><span><i class="sev-high"></i>high</span><span><i class="sev-medium"></i>medium</span><span><i class="sev-low"></i>low</span><span><i class="logins-key"></i>failed logins</span></div></div><div id="timeline" class="muted">…</div></div>
    <section class="grid panels">
      <div class="card"><h3>Alerts by severity (<span class="range-label">24h</span>)</h3><div id="alert-severity" class="muted">…</div></div>
      <div class="card"><h3>Alerts by rule (<span class="range-label">24h</span>)</h3><div id="alert-rules" class="muted">…</div></div>
      <div class="card"><h3>Top failed-login sources (<span class="range-label">24h</span>)</h3><div id="top-ips" class="muted">…</div></div>
      <div class="card"><h3>Most targeted accounts (<span class="range-label">24h</span>)</h3><div id="top-users" class="muted">…</div></div>
    </section>
  </section>
  <section id="triage" class="view"><h2>Alerts</h2>
  <div class="toolbar"><input id="search" type="search" placeholder="Search alerts"><select id="severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><button id="export-alerts">Export CSV</button><span id="updated" class="muted"></span></div>
  <div class="table-wrap"><table><thead><tr><th>Severity</th><th>Title</th><th>Reason</th><th>Rule</th><th>Created</th></tr></thead><tbody id="alerts"><tr><td colspan="5">Loading…</td></tr></tbody></table></div>
  <h2>Open incidents</h2><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Title</th><th>Status</th><th>Assignee</th><th>Updated</th></tr></thead><tbody id="incidents"><tr><td colspan="5">Loading…</td></tr></tbody></table></div></section>
  <section id="operations" class="view"><h2>Event search</h2><div class="toolbar"><input id="event-search" type="search" placeholder="Search event text, type, or source"><select id="event-severity"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><button id="search-events">Search</button><button id="export-events">Export CSV</button></div>
  <div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Type</th><th>Message</th></tr></thead><tbody id="events"><tr><td colspan="5">Search for events.</td></tr></tbody></table></div></section>
  <section id="malware" class="view"><h2>Malware analysis</h2>
    <p class="note">Static analysis only: the SIEM reads the file's bytes and never runs it. Uploaded samples are stored without execute permission.</p>
    <div class="toolbar"><input id="sample-file" type="file"><button id="analyze">Analyze file</button><span id="analyze-status" class="muted"></span></div>
    <div id="analysis-result" class="card result" hidden></div>
    <h2>Analyzed files</h2><div class="table-wrap"><table><thead><tr><th>Verdict</th><th>File</th><th>Capabilities</th><th>VirusTotal</th><th>Analyzed</th></tr></thead><tbody id="analyses"><tr><td colspan="5">No files analyzed yet.</td></tr></tbody></table></div></section>
  <section id="intel" class="view"><h2>Threat intelligence</h2>
    <p class="note">Known-bad indicators (hashes, IPs, domains, URLs). Every event is checked against them; a match raises an alert.</p>
    <form id="ioc-form" class="toolbar"><select id="ioc-kind"><option>sha256</option><option>ip</option><option>domain</option><option>url</option><option>md5</option><option>sha1</option></select><input id="ioc-value" placeholder="Indicator value" required size="40"><input id="ioc-source" placeholder="Source, e.g. abuse.ch"><label>Confidence <input id="ioc-confidence" type="number" min="0" max="100" value="80"></label><button type="submit">Add indicator</button></form>
    <div class="toolbar"><button id="ioc-scan" class="secondary">Scan all events against indicators</button><span id="ioc-status" class="muted"></span></div>
    <div class="table-wrap"><table><thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th><th>Added</th></tr></thead><tbody id="iocs"><tr><td colspan="5">No indicators yet.</td></tr></tbody></table></div></section>
  <section id="reports" class="view"><h2>Incident report</h2>
    <p class="note">The standard report is built only from recorded evidence. The AI summary sends the same bounded evidence (never the file itself) to the configured AI provider; a human must review it.</p>
    <div class="toolbar"><label>Include file <select id="report-file"><option value="">No file</option></select></label><button id="make-report">Generate report</button><button id="make-ai-report" class="secondary">AI summary</button><button id="download-report" class="secondary" hidden>Download .md</button><span id="report-status" class="muted"></span></div>
    <div id="report-output" class="report-view muted">Choose a report to generate.</div></section>
  <dialog id="incident-dialog"><form method="dialog"><h2>Incident</h2><pre id="incident-detail"></pre><label>Status <select id="incident-status"><option>open</option><option>investigating</option><option>resolved</option><option>closed</option></select></label><br><label>Assignee <input id="incident-assignee"></label><p id="incident-error" class="error"></p><p><button id="save-incident" value="default">Save</button> <button>Cancel</button></p></form></dialog>
  <script src="/dashboard.js"></script>
</body></html>'''

DASHBOARD_JS = r'''"use strict";
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'}[c]));
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function storedKey() { try { return sessionStorage.getItem('siem-api-key') || ''; } catch { return ''; } }
function headers() { const key = storedKey(); return key ? {'X-API-Key': key} : {}; }
class HttpError extends Error { constructor(path, status, detail) { super(detail || `${path}: HTTP ${status}`); this.status = status; } }
async function request(path, options = {}) {
  const response = await fetch(path, {...options, headers: {...headers(), ...(options.headers || {})}});
  if (!response.ok) {
    let detail = '';
    try { detail = (await response.json()).error || ''; } catch {}
    throw new HttpError(path, response.status, detail);
  }
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

const SVG_NS = 'http://www.w3.org/2000/svg';
function svg(tag, attributes = {}, text) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
  if (text !== undefined) node.textContent = text;
  return node;
}

function bucketLabel(iso, minutes) {
  const date = new Date(iso);
  return minutes < 1440 ? date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}) + (minutes > 60 ? ` ${date.getDate()}/${date.getMonth() + 1}` : '')
                        : date.toLocaleDateString([], {day: 'numeric', month: 'short'});
}

function renderTimeline(data) {
  const buckets = data.buckets || [];
  const target = $('timeline');
  target.textContent = '';
  const totals = buckets.map(b => Object.values(b.alerts).reduce((sum, n) => sum + n, 0));
  const maxAlerts = Math.max(1, ...totals);
  const maxLogins = Math.max(1, ...buckets.map(b => b.failed_logins));
  if (!totals.some(Boolean) && !buckets.some(b => b.failed_logins)) {
    target.className = 'muted';
    target.textContent = 'No alerts or failed logins in this window.';
    return;
  }
  target.className = '';
  const width = 1000, height = 220, left = 36, right = 40, top = 10, bottom = 26;
  const plotWidth = width - left - right, plotHeight = height - top - bottom;
  const step = plotWidth / Math.max(1, buckets.length);
  const chart = svg('svg', {viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': 'Alerts per time bucket by severity, with failed logins'});
  for (const fraction of [0, 0.5, 1]) {
    const y = top + plotHeight * (1 - fraction);
    chart.append(svg('line', {x1: left, x2: width - right, y1: y, y2: y, class: 'grid-line'}));
    chart.append(svg('text', {x: left - 6, y: y + 4, 'text-anchor': 'end', class: 'axis'}, Math.round(maxAlerts * fraction)));
  }
  chart.append(svg('text', {x: width - right + 6, y: top + 4, class: 'axis'}, maxLogins));
  const labelEvery = Math.max(1, Math.ceil(buckets.length / 8));
  const points = [];
  buckets.forEach((bucket, index) => {
    const x = left + index * step;
    let y = top + plotHeight;
    for (const severity of ['low', 'medium', 'high', 'critical']) {
      const count = bucket.alerts[severity] || 0;
      if (!count) continue;
      const barHeight = (count / maxAlerts) * plotHeight;
      y -= barHeight;
      const bar = svg('rect', {x: x + step * 0.15, y, width: Math.max(1, step * 0.7), height: barHeight, class: `sev-${severity}`});
      bar.append(svg('title', {}, `${bucketLabel(bucket.start, data.bucket_minutes)}: ${count} ${severity}`));
      chart.append(bar);
    }
    points.push(`${x + step / 2},${top + plotHeight * (1 - bucket.failed_logins / maxLogins)}`);
    if (index % labelEvery === 0) {
      chart.append(svg('text', {x: x + step / 2, y: height - 8, 'text-anchor': 'middle', class: 'axis'}, bucketLabel(bucket.start, data.bucket_minutes)));
    }
  });
  const line = svg('polyline', {points: points.join(' '), class: 'logins-line'});
  line.append(svg('title', {}, `Failed logins per bucket (right axis, max ${maxLogins})`));
  chart.append(line);
  target.append(chart);
}

async function download(path) {
  try {
    const response = await request(path);
    const name = (response.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'export.csv';
    const url = URL.createObjectURL(await response.blob());
    const link = Object.assign(document.createElement('a'), {href: url, download: name});
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    $('error').textContent = `Export failed: ${error.message}`;
  }
}

function filterQuery(textId, severityId) {
  return `text=${encodeURIComponent($(textId).value)}&severity=${encodeURIComponent($(severityId).value)}`;
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

const CAPABILITY_TEXT = {
  'kernel-driver': 'Runs as a Windows kernel driver (full control of the machine)',
  'registry-modification': 'Changes the Windows registry',
  'process-injection': 'Injects code into other running programs',
  'keylogging': 'Can record keystrokes',
  'network-download': 'Uses the network / downloads files',
  'service-persistence': 'Installs a service or autostart entry (survives reboot)',
  'process-execution': 'Launches other programs or commands',
  'privilege-escalation': 'Tries to raise its own privileges',
  'anti-debugging': 'Tries to detect analysis tools',
  'security-tampering': 'Tampers with security settings (firewall / antivirus)',
};
let role = 'viewer';
let features = {virustotal: false, ai: false};
let analyses = [];
let reportText = '';
const canWrite = () => role === 'analyst' || role === 'admin';

// High entropy is not an API capability, but it is often the reason a file looks suspicious.
function capabilityList(a) {
  const caps = Object.entries(a.capabilities || {});
  if ((a.indicators || []).includes('high-entropy')) caps.unshift(['packed', [`entropy ${a.entropy}`]]);
  return caps;
}
CAPABILITY_TEXT.packed = 'Packed or encrypted: hides its real code from analysis';
const when = iso => { const date = new Date(iso); return isNaN(date) ? iso : date.toLocaleString(); };

function size(bytes) { return bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1048576).toFixed(1)} MB`; }

function vtSummary(vt) {
  if (!vt) return '<span class="muted">not checked</span>';
  if (!vt.found) return '<span class="muted">unknown hash</span>';
  return `<span class="${vt.malicious ? 'high' : 'status'}">${esc(vt.malicious)} / ${esc(vt.total_engines)} malicious</span>`;
}

function renderAnalysis(a) {
  const box = $('analysis-result');
  box.hidden = false;
  const caps = capabilityList(a);
  const vt = a.virustotal;
  const vtBlock = vt ? (vt.found
      ? `<div class="reputation ${vt.malicious ? 'bad' : 'good'}"><strong>VirusTotal: ${esc(vt.malicious)} of ${esc(vt.total_engines)} antivirus engines flag this file as malicious</strong>${vt.suspicious ? `, ${esc(vt.suspicious)} as suspicious` : ''}.
         ${(vt.tags || []).length ? `<div class="chips">${vt.tags.slice(0, 8).map(t => `<span class="chip">${esc(t)}</span>`).join('')}</div>` : ''}
         <div><a href="${esc(vt.permalink)}" target="_blank" rel="noopener noreferrer">Open full VirusTotal report</a></div></div>`
      : '<div class="reputation">VirusTotal has never seen this hash.</div>')
    : '';
  const entropyNote = a.entropy >= 7.2 ? ' (very high: likely packed or encrypted)' : a.entropy >= 6 ? ' (high)' : ' (normal)';
  box.innerHTML = `<div class="result-head"><h3>${esc(a.filename)}</h3><span class="verdict ${esc(a.classification)}">${esc(a.classification.replace(/-/g, ' '))}</span></div>
    <dl class="facts"><div><dt>File type</dt><dd>${esc(a.magic)}</dd></div><div><dt>Size</dt><dd>${esc(size(a.size))}</dd></div>
      <div><dt>Entropy</dt><dd>${esc(a.entropy)}${esc(entropyNote)}</dd></div><div><dt>Analyst</dt><dd>${esc(a.analyst)}</dd></div></dl>
    <div><strong>SHA-256</strong> <code>${esc(a.sha256)}</code></div>
    <h4>What this file can do</h4>
    ${caps.length ? `<ul class="caps">${caps.map(([name, terms]) => `<li><strong>${esc(CAPABILITY_TEXT[name] || name)}</strong><br><code>${terms.map(esc).join(', ')}</code></li>`).join('')}</ul>`
                  : '<p class="muted">No suspicious capabilities found in the strings.</p>'}
    <div class="chips">${(a.indicators || []).map(i => `<span class="chip ${i.startsWith('capability') || i === 'high-entropy' ? 'danger' : ''}">${esc(i)}</span>`).join('')}</div>
    ${a.ioc ? `<div class="reputation bad"><strong>Threat-intel match:</strong> this hash is a known indicator from ${esc(a.ioc.source)} (${esc(a.ioc.confidence)}% confidence).</div>` : ''}
    ${vtBlock}
    ${a.quarantined ? `<div class="reputation good"><strong>Quarantined</strong> by ${esc(a.quarantined_by)}.</div>` : ''}
    <div class="toolbar">
      <button id="vt-check" ${features.virustotal && canWrite() ? '' : 'disabled'} title="${features.virustotal ? 'Look up the hash (the file is never uploaded)' : 'Set VIRUSTOTAL_API_KEY to enable'}">Check VirusTotal</button>
      <button id="quarantine" class="danger" ${role === 'admin' && !a.quarantined ? '' : 'disabled'} title="${role === 'admin' ? 'Move the sample into the quarantine vault' : 'Admin role required'}">Quarantine</button>
      <button id="report-this" class="secondary">Report on this file</button>
      <span id="action-status" class="muted">${features.virustotal ? '' : 'VirusTotal not configured.'}</span></div>
    <details><summary>Extracted strings (${esc((a.strings || []).length)})</summary><pre>${(a.strings || []).map(esc).join('\n')}</pre></details>`;
  $('vt-check').addEventListener('click', async () => {
    $('action-status').textContent = 'Asking VirusTotal…';
    try {
      const result = await (await postJson(`/analyses/${a.sha256}/virustotal`, {})).json();
      a.virustotal = result.virustotal;
      renderAnalysis(a);
      loadWorkbench();
    } catch (error) { $('action-status').textContent = error.message; }
  });
  $('quarantine').addEventListener('click', async () => {
    if (!confirm(`Quarantine ${a.filename}?`)) return;
    try {
      renderAnalysis((await (await postJson(`/analyses/${a.sha256}/quarantine`, {})).json()).analysis);
      loadWorkbench();
    } catch (error) { $('action-status').textContent = error.message; }
  });
  $('report-this').addEventListener('click', () => { $('report-file').value = a.sha256; switchView('reports'); makeReport(false); });
}

function renderAnalyses() {
  $('analyses').innerHTML = analyses.map(a => `<tr><td><span class="verdict ${esc(a.classification)}">${esc(a.classification.replace(/-/g, ' '))}</span></td>
    <td><button class="secondary" data-sha="${esc(a.sha256)}">${esc(a.filename)}</button>${a.quarantined ? ' <span class="chip">quarantined</span>' : ''}</td>
    <td><div class="chips">${capabilityList(a).map(([c]) => `<span class="chip danger">${esc(c)}</span>`).join('') || '<span class="muted">none</span>'}</div></td>
    <td>${vtSummary(a.virustotal)}</td><td>${esc(when(a.analyzed_at))}</td></tr>`).join('') || '<tr><td colspan="5">No files analyzed yet.</td></tr>';
  document.querySelectorAll('[data-sha]').forEach(b => b.addEventListener('click', () => renderAnalysis(analyses.find(a => a.sha256 === b.dataset.sha))));
  const selected = $('report-file').value;
  $('report-file').innerHTML = '<option value="">No file</option>' + analyses.map(a => `<option value="${esc(a.sha256)}">${esc(a.filename)}</option>`).join('');
  $('report-file').value = analyses.some(a => a.sha256 === selected) ? selected : '';
}

function renderIocs(items) {
  $('iocs').innerHTML = items.map(i => `<tr><td><span class="chip">${esc(i.kind)}</span></td><td><code>${esc(i.value)}</code></td><td>${esc(i.source)}</td><td>${esc(i.confidence)}%</td><td>${esc(when(i.created_at))}</td></tr>`).join('')
    || '<tr><td colspan="5">No indicators yet.</td></tr>';
}

async function loadWorkbench() {
  const [caps, list, iocs] = await Promise.all([get('/capabilities'), get('/analyses'), get('/iocs')]);
  features = caps;
  analyses = list.analyses || [];
  renderAnalyses();
  renderIocs(iocs.indicators || []);
  const writeTitle = canWrite() ? '' : 'Analyst role required';
  for (const id of ['analyze', 'ioc-scan']) { $(id).disabled = !canWrite(); $(id).title = writeTitle; }
  $('make-ai-report').disabled = !(features.ai && canWrite());
  $('make-ai-report').title = features.ai ? 'Summarize the evidence with AI' : 'Set OPENAI_API_KEY and install openai to enable';
}

function markdown(source) {
  const inline = line => esc(line).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`([^`]+)`/g, '<code>$1</code>');
  let html = '', list = false;
  for (const raw of source.split('\n')) {
    const line = raw.trimEnd();
    const bullet = line.match(/^\s*[-*] (.*)$/);
    if (bullet && !list) { html += '<ul>'; list = true; }
    if (!bullet && list) { html += '</ul>'; list = false; }
    if (bullet) html += `<li>${inline(bullet[1])}</li>`;
    else if (line.startsWith('# ')) html += `<h2>${inline(line.slice(2))}</h2>`;
    else if (line.startsWith('## ')) html += `<h3>${inline(line.slice(3))}</h3>`;
    else if (/^#{3,} /.test(line)) html += `<h4>${inline(line.replace(/^#+ /, ''))}</h4>`;
    else if (line) html += `<p>${inline(line)}</p>`;
  }
  return html + (list ? '</ul>' : '');
}

async function makeReport(ai) {
  const sha = $('report-file').value;
  $('report-status').textContent = ai ? 'AI is writing the summary… (this can take up to a minute)' : 'Generating…';
  $('download-report').hidden = true;
  try {
    const result = ai ? await (await postJson('/report/ai', {sha256: sha})).json()
                      : await get(`/report${sha ? `?sha256=${encodeURIComponent(sha)}` : ''}`);
    reportText = result.markdown;
    $('report-output').className = `report-view${ai ? ' ai' : ''}`;
    $('report-output').innerHTML = (ai ? '<p class="chip">AI-generated draft: review before acting</p>' : '') + markdown(reportText);
    $('download-report').hidden = false;
    $('report-status').textContent = '';
  } catch (error) {
    $('report-status').textContent = error.message;
  }
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
    const hours = $('range').value;
    const [health, metricsText, stats, timeline, alerts, incidents, me] = await Promise.all([
      get('/health'), text('/metrics'), get(`/stats?hours=${hours}`), get(`/stats/timeline?hours=${hours}`),
      get(`/alerts?limit=100&text=${encodeURIComponent($('search').value)}&severity=${encodeURIComponent($('severity').value)}`),
      get('/incidents?status=open&limit=100'), get('/me'),
    ]);
    const metrics = {};
    for (const match of metricsText.matchAll(/^siem_([a-z_]+)\s+(\d+)$/gm)) metrics[match[1]] = Number(match[2]);
    $('role-label').textContent = `Signed in as ${me.name} (${me.role})`;
    role = me.role;
    await loadWorkbench();
    $('status').textContent = health.status || 'ok';
    $('status').className = 'number status';
    $('event-count').textContent = metrics.security_events ?? '0';
    $('incident-count').textContent = metrics.open_incidents ?? '0';
    const label = {24: '24h', 168: '7 days', 720: '30 days'}[hours] || `${hours}h`;
    document.querySelectorAll('.range-label').forEach(node => { node.textContent = label; });
    renderStats(stats);
    renderTimeline(timeline);
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
$('range').addEventListener('change', load);
$('export-alerts').addEventListener('click', () => download(`/alerts.csv?${filterQuery('search', 'severity')}`));
$('export-events').addEventListener('click', () => download(`/events.csv?${filterQuery('event-search', 'event-severity')}`));
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
$('analyze').addEventListener('click', () => {
  const file = $('sample-file').files[0];
  if (!file) { $('analyze-status').textContent = 'Choose a file first.'; return; }
  $('analyze-status').textContent = `Analyzing ${file.name}…`;
  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const content = String(reader.result).split(',', 2)[1] || '';
      const result = await (await postJson('/analyze', {filename: file.name, content_base64: content})).json();
      $('analyze-status').textContent = result.analysis.alerts ? `Done: ${result.analysis.alerts} alert(s) raised.` : 'Done.';
      renderAnalysis(result.analysis);
      loadWorkbench();
    } catch (error) { $('analyze-status').textContent = `Analysis failed: ${error.message}`; }
  };
  reader.readAsDataURL(file);
});
$('ioc-form').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const result = await (await postJson('/iocs', {kind: $('ioc-kind').value, value: $('ioc-value').value,
      source: $('ioc-source').value, confidence: Number($('ioc-confidence').value)})).json();
    renderIocs(result.indicators || []);
    $('ioc-value').value = '';
    $('ioc-status').textContent = 'Indicator added.';
  } catch (error) { $('ioc-status').textContent = error.message; }
});
$('ioc-scan').addEventListener('click', async () => {
  $('ioc-status').textContent = 'Scanning…';
  try {
    const result = await (await postJson('/iocs/scan', {})).json();
    $('ioc-status').textContent = `Scanned ${result.events_scanned} events: ${result.new_alerts} new alert(s).`;
  } catch (error) { $('ioc-status').textContent = error.message; }
});
$('make-report').addEventListener('click', () => makeReport(false));
$('make-ai-report').addEventListener('click', () => makeReport(true));
$('download-report').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([reportText], {type: 'text/markdown'}));
  const link = Object.assign(document.createElement('a'), {href: url, download: 'siem-incident-report.md'});
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
load();
setInterval(load, 30000);
'''
