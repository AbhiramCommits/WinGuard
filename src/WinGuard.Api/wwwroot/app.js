/*
 * WinGuard analyst console.
 *
 * Vanilla JS, no framework, no build step, no CDN. Every value that comes from
 * the API is written with textContent (or setAttribute for known-safe
 * attributes) — never innerHTML — so server-controlled strings cannot inject
 * markup into the console.
 */
'use strict';

const POLL_INTERVAL_MS = 5000;
const RECENT_LIMIT = 200;

const state = {
  hosts: [],
  detections: [],
  ruleFilter: '',
  hostFilter: '',
  minSeverity: 0,
  selected: null,
  online: false,
};

/* ------------------------------------------------------------------ helpers */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function severityClass(severity) {
  if (severity >= 75) return 'sev-critical';
  if (severity >= 50) return 'sev-high';
  if (severity >= 25) return 'sev-medium';
  return 'sev-low';
}

function bucketClass(bucket) {
  switch (bucket) {
    case 'Critical': return 'chip-bad';
    case 'High': return 'chip-warn';
    case 'Medium': return 'chip-warn';
    case 'Low': return 'chip-ok';
    default: return 'chip-muted';
  }
}

function statusClass(status) {
  switch (status) {
    case 'Online': return 'badge-online';
    case 'Stale': return 'badge-stale';
    default: return 'badge-offline';
  }
}

function formatRelative(iso) {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return 'unknown';

  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function formatAbsolute(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

async function getJson(path) {
  const response = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error(`${path} -> ${response.status}`);
  return response.json();
}

function $(id) { return document.getElementById(id); }

/* ------------------------------------------------------------------- fleet */

function renderFleet() {
  const body = $('fleet-body');
  body.replaceChildren();

  const sorted = [...state.hosts].sort((a, b) => {
    if (b.highestSeverity !== a.highestSeverity) return b.highestSeverity - a.highestSeverity;
    return String(a.hostname).localeCompare(String(b.hostname));
  });

  if (sorted.length === 0) {
    const row = el('tr');
    const cell = el('td', 'empty', 'No hosts registered yet.');
    cell.colSpan = 5;
    row.appendChild(cell);
    body.appendChild(row);
  }

  for (const host of sorted) {
    const row = el('tr');
    if (state.hostFilter === host.hostId) row.className = 'selected';

    const hostCell = el('td');
    hostCell.appendChild(el('div', 'host-name', host.hostname || '(unnamed)'));
    hostCell.appendChild(el('div', 'muted', host.domain ? `${host.domain} · ${host.hostId.slice(0, 12)}…` : host.hostId));

    const statusCell = el('td');
    statusCell.appendChild(el('span', `badge ${statusClass(host.status)}`, host.status));

    const heartbeatCell = el('td', null, formatRelative(host.lastHeartbeatUtc));
    heartbeatCell.title = formatAbsolute(host.lastHeartbeatUtc);

    const countCell = el('td', 'num', host.detectionCount);

    const worstCell = el('td');
    if (host.detectionCount > 0) {
      worstCell.appendChild(el('span', `chip ${bucketClass(host.highestSeverityBucket)}`,
        `${host.highestSeverity} ${host.highestSeverityBucket}`));
    } else {
      worstCell.appendChild(el('span', 'muted', '—'));
    }

    row.append(hostCell, statusCell, heartbeatCell, countCell, worstCell);
    row.addEventListener('click', () => {
      state.hostFilter = state.hostFilter === host.hostId ? '' : host.hostId;
      $('host-filter').value = state.hostFilter;
      renderFleet();
      renderTimeline();
    });

    body.appendChild(row);
  }

  $('fleet-count').textContent = `${state.hosts.length} host${state.hosts.length === 1 ? '' : 's'}`;

  const summary = $('severity-summary');
  const worst = state.hosts.reduce((max, h) => Math.max(max, h.highestSeverity || 0), 0);
  const worstBucket = state.hosts.find(h => h.highestSeverity === worst);
  summary.className = `chip ${worst > 0 ? bucketClass(worstBucket ? worstBucket.highestSeverityBucket : 'Low') : 'chip-muted'}`;
  summary.textContent = worst > 0 ? `worst ${worst}` : 'no detections';
}

/* ---------------------------------------------------------------- timeline */

function visibleDetections() {
  return state.detections.filter(d => {
    if (state.ruleFilter && d.ruleId !== state.ruleFilter) return false;
    if (state.hostFilter && d.hostId !== state.hostFilter) return false;
    if (state.minSeverity > 0 && d.severity < state.minSeverity) return false;
    return true;
  });
}

function renderTimeline() {
  const list = $('timeline');
  list.replaceChildren();

  const detections = visibleDetections()
    .slice()
    .sort((a, b) => new Date(b.observedAtUtc) - new Date(a.observedAtUtc));

  $('timeline-count').textContent = `${detections.length} of ${state.detections.length}`;

  if (detections.length === 0) {
    list.appendChild(el('li', 'empty', 'No detections match the current filters.'));
    return;
  }

  for (const detection of detections) {
    const item = el('li');
    const button = el('button', 'detection');
    button.type = 'button';

    if (state.selected && state.selected.eventId === detection.eventId) {
      button.classList.add('selected');
    }

    button.appendChild(el('span', `severity-bar ${severityClass(detection.severity)}`));

    const main = el('div', 'detection-main');
    const title = el('div', 'detection-title');
    title.appendChild(el('span', 'rule-id', detection.ruleId));
    title.appendChild(el('span', null, detection.title || ''));
    main.appendChild(title);
    main.appendChild(el('div', 'detection-process',
      `${detection.processName || 'unknown'} · pid ${detection.pid} · ${detection.hostId.slice(0, 10)}…`));

    const score = el('div', 'detection-score');
    score.appendChild(el('span', null, detection.severity));
    score.appendChild(el('span', 'bucket', detection.severityBucket || ''));
    score.title = formatAbsolute(detection.observedAtUtc);

    button.append(main, score);
    button.addEventListener('click', () => selectDetection(detection));

    item.appendChild(button);
    list.appendChild(item);
  }
}

function renderFilters() {
  const ruleSelect = $('rule-filter');
  const currentRule = ruleSelect.value;
  const rules = [...new Set(state.detections.map(d => d.ruleId))].sort();
  ruleSelect.replaceChildren(el('option', null, 'all rules'));
  ruleSelect.firstChild.value = '';
  for (const rule of rules) {
    const option = el('option', null, rule);
    option.value = rule;
    ruleSelect.appendChild(option);
  }
  ruleSelect.value = rules.includes(currentRule) ? currentRule : '';
  state.ruleFilter = ruleSelect.value;

  const hostSelect = $('host-filter');
  const currentHost = hostSelect.value;
  hostSelect.replaceChildren(el('option', null, 'all hosts'));
  hostSelect.firstChild.value = '';
  for (const host of [...state.hosts].sort((a, b) => String(a.hostname).localeCompare(String(b.hostname)))) {
    const option = el('option', null, host.hostname || host.hostId);
    option.value = host.hostId;
    hostSelect.appendChild(option);
  }
  hostSelect.value = state.hosts.some(h => h.hostId === currentHost) ? currentHost : '';
  state.hostFilter = hostSelect.value;
}

/* --------------------------------------------------------------- drilldown */

async function selectDetection(detection) {
  state.selected = detection;
  renderTimeline();
  $('drill-close').hidden = false;

  const panel = $('drilldown');
  panel.replaceChildren(el('p', 'muted', 'Loading process detail…'));

  try {
    const detail = await getJson(
      `/api/v1/processes/${encodeURIComponent(detection.hostId)}/${detection.pid}`);
    renderDrilldown(detail, detection);
  } catch (error) {
    panel.replaceChildren(el('p', 'empty', `Could not load process detail: ${error.message}`));
  }
}

function renderDrilldown(detail, detection) {
  const panel = $('drilldown');
  panel.replaceChildren();

  const kv = el('dl', 'kv');
  const add = (key, value) => {
    kv.appendChild(el('dt', null, key));
    kv.appendChild(el('dd', null, value));
  };
  add('process', detail.processName || 'unknown');
  add('pid', detail.pid);
  add('parent pid', detail.parentPid);
  add('host', detail.hostId);
  add('image', detail.imagePath || '—');
  add('user', detail.userName || '—');
  add('protected', detail.isProtected ? 'yes' : 'no');
  add('observed', formatAbsolute(detail.observedAtUtc));
  panel.appendChild(kv);

  panel.appendChild(el('h3', null, `Modules (${detail.modules.length})`));
  if (detail.modules.length === 0) {
    panel.appendChild(el('p', 'muted', 'No module list was reported for this process.'));
  } else {
    const list = el('ul', 'module-list');
    for (const module of detail.modules) {
      const item = el('li', 'module');
      const head = el('div', 'module-head');
      head.appendChild(el('span', 'module-name', module.name || module.path || 'unnamed'));

      const status = (module.signatureStatus || 'Unknown').toLowerCase();
      head.appendChild(el('span', `sig sig-${status}`, module.signatureStatus || 'Unknown'));
      item.appendChild(head);

      item.appendChild(el('div', 'module-path', module.path || '(no backing file)'));

      if (!module.isBackedByFile) {
        item.appendChild(el('div', 'flag-warn', 'not backed by a file (manual map)'));
      }
      if (module.onDiskSha256 && module.inMemoryTextSha256
          && module.onDiskSha256 !== module.inMemoryTextSha256) {
        item.appendChild(el('div', 'flag-warn', '.text hash differs from disk (patched in memory)'));
      }

      list.appendChild(item);
    }
    panel.appendChild(list);
  }

  const flagged = detail.memoryRegions.filter(
    r => r.isExecutable && (!r.isBackedByFile || r.isWritable));
  if (flagged.length > 0) {
    panel.appendChild(el('h3', null, `Suspicious memory regions (${flagged.length})`));
    const list = el('ul', 'module-list');
    for (const region of flagged) {
      const item = el('li', 'module');
      item.appendChild(el('div', 'module-name', `${region.protection} · ${region.regionType}`));
      item.appendChild(el('div', 'module-path', `${region.baseAddress} (${region.size} bytes)`));
      list.appendChild(item);
    }
    panel.appendChild(list);
  }

  panel.appendChild(el('h3', null, `Rules fired (${detail.detections.length})`));
  const evidence = el('ul', 'evidence-list');
  const seen = new Set();
  for (const hit of detail.detections) {
    for (const [key, value] of Object.entries(hit.evidence || {})) {
      const signature = `${hit.ruleId}|${key}|${value}`;
      if (seen.has(signature)) continue;
      seen.add(signature);
      const item = el('li');
      item.appendChild(el('span', 'k', `${hit.ruleId} · ${key}`));
      item.appendChild(el('span', 'v', value));
      evidence.appendChild(item);
    }
  }
  panel.appendChild(evidence);

  panel.appendChild(el('h3', null, `Timeline (${detail.timeline.length})`));
  const mini = el('ul', 'mini-timeline');
  for (const entry of detail.timeline) {
    const item = el('li');
    item.appendChild(el('span', null, `${entry.ruleId} · ${entry.severity} ${entry.severityBucket}`));
    const when = el('span', 'muted', formatRelative(entry.observedAtUtc));
    when.title = formatAbsolute(entry.observedAtUtc);
    item.appendChild(when);
    mini.appendChild(item);
  }
  panel.appendChild(mini);

  if (detail.detections.length > 0) {
    state.selected = state.selected ? { ...state.selected, eventId: state.selected.eventId } : detection;
  }
}

/* -------------------------------------------------------------- polling */

async function refresh() {
  try {
    const [hosts, detections] = await Promise.all([
      getJson('/api/v1/hosts'),
      getJson(`/api/v1/detections/recent?limit=${RECENT_LIMIT}`),
    ]);

    state.hosts = hosts;
    state.detections = detections;
    state.online = true;

    $('connection').className = 'chip chip-ok';
    $('connection').textContent = 'live';
    $('last-refresh').textContent = `updated ${new Date().toLocaleTimeString()}`;

    renderFilters();
    renderFleet();
    renderTimeline();
  } catch (error) {
    state.online = false;
    $('connection').className = 'chip chip-bad';
    $('connection').textContent = 'reconnecting…';
    $('last-refresh').textContent = `last error: ${error.message}`;
  }
}

function wireFilters() {
  $('rule-filter').addEventListener('change', event => {
    state.ruleFilter = event.target.value;
    renderTimeline();
  });

  $('host-filter').addEventListener('change', event => {
    state.hostFilter = event.target.value;
    renderFleet();
    renderTimeline();
  });

  const severity = $('severity-filter');
  severity.addEventListener('input', event => {
    state.minSeverity = Number(event.target.value);
    $('severity-output').textContent = event.target.value;
    renderTimeline();
  });

  $('drill-close').addEventListener('click', () => {
    state.selected = null;
    $('drill-close').hidden = true;
    $('drilldown').replaceChildren(
      el('p', 'muted', 'Select a detection to inspect the process, its modules and the evidence behind each rule hit.'));
    renderTimeline();
  });
}

wireFilters();
refresh();
setInterval(refresh, POLL_INTERVAL_MS);
