import { appState } from './ui-state.js';
import { renderRowsIncrementally, virtualizeTableBody } from './virtual-table.js';
window.appState = appState;
window.renderRowsIncrementally = renderRowsIncrementally;
window.virtualizeTableBody = virtualizeTableBody;
'use strict';
// ════════════════════════════════════════════════════════════
// STATE
// ════════════════════════════════════════════════════════════
let curPid = null, curSid = null, curFilter = 'all', curPage = 1, totalPages = 1;
let allResRows = [], sortCol = null, sortDir = 1;
let scanPollTimer = null;
let activeScanStatus = 'running';
let sfCurPid = null, sfCurPage = 1, sfTotalPages = 1;
let allAlerts = [], alertsCurPage = 1, alertsTotalPages = 1;
let projectsCache = [];
let opensslRows = [];
let opensslPid = null;
let quickScanId = null;
let quickRows = [];
let quickRowsByHost = new Map();
let quickFilter = 'all';
let quickSortCol = 'hostname';
let quickSortDir = 1;
let quickRenderTimer = null;
let alertSettingsCache = null;
let genericTableObserver = null;
let pendingLogEntries = [];
let logFlushTimer = null;
let opensslRenderTimer = null;
let dashboardLoadInFlight = false;
let sseConnection = null;
let sseReconnectTimer = null;
let sseReconnectDelay = 1000;
let nucleiRowsRenderTimer = null;
let nucleiStatsRenderTimer = null;
let nucleiPendingStats = null;
const apiMemo = new Map();
const API_MEMO_TTL = 3500;


let activeNetworkRequests = 0;
let progressHideTimer = null;
function trackNetworkActivity(promise) {
  const progress = document.getElementById('appProgress');
  activeNetworkRequests += 1;
  clearTimeout(progressHideTimer);
  progress?.classList.add('is-active');
  return Promise.resolve(promise).finally(() => {
    activeNetworkRequests = Math.max(0, activeNetworkRequests - 1);
    if (!activeNetworkRequests) {
      progress?.classList.add('is-finishing');
      progressHideTimer = setTimeout(() => {
        progress?.classList.remove('is-active', 'is-finishing');
      }, 260);
    }
  });
}

function isReadRequest(opts = {}) {
  return !opts?.method || String(opts.method).toUpperCase() === 'GET';
}

function clearApiMemo(pattern = '') {
  if (!pattern) { apiMemo.clear(); return; }
  [...apiMemo.keys()].forEach(key => { if (key.includes(pattern)) apiMemo.delete(key); });
}

async function apiJSON(url, opts) {
  const req = { cache: 'no-store', ...(opts || {}) };
  const readReq = isReadRequest(req);
  const memoKey = readReq ? url : '';
  const now = performance.now();
  if (readReq && apiMemo.has(memoKey)) {
    const cached = apiMemo.get(memoKey);
    if (cached.expires > now) return cached.promise;
    apiMemo.delete(memoKey);
  } else if (!readReq) {
    clearApiMemo();
  }

  const hasBody = typeof req.body === 'string' && req.body.length > 0;
  if (hasBody) {
    req.headers = { 'Content-Type': 'application/json', ...(req.headers || {}) };
  }
  const promise = trackNetworkActivity(fetch(url, req)).then(async resp => {
    const out = await resp.json();
    if (out?.ok !== false) setLastSyncStamp();
    if (!resp.ok || out?.ok === false) apiMemo.delete(memoKey);
    return out;
  }).catch(err => {
    if (memoKey) apiMemo.delete(memoKey);
    throw err;
  });
  if (readReq) apiMemo.set(memoKey, { expires: now + API_MEMO_TTL, promise });
  return promise;
}

function setLastSyncStamp(date = new Date()) {
  const el = document.getElementById('topLastSync');
  if (!el) return;
  el.textContent = `Last sync: ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
}

function debounce(fn, wait=250) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), wait);
  };
}

function rafThrottle(fn) {
  let raf = null;
  let lastArgs = null;
  return (...args) => {
    lastArgs = args;
    if (raf) return;
    raf = requestAnimationFrame(() => {
      raf = null;
      fn(...lastArgs);
    });
  };
}


function inferCellSortValue(cell) {
  const raw = (cell?.dataset?.sortValue || cell?.textContent || '').trim();
  if (!raw) return { type: 'text', value: '' };
  const normalizedNum = raw.replace(/,/g, '');
  if (/^-?\d+(\.\d+)?$/.test(normalizedNum)) {
    return { type: 'number', value: Number(normalizedNum) };
  }
  const dateValue = Date.parse(raw);
  if (!Number.isNaN(dateValue) && /\d/.test(raw)) {
    return { type: 'date', value: dateValue };
  }
  return { type: 'text', value: raw.toLowerCase() };
}

function sortGenericResultTable(table, colIdx) {
  const tbody = table.querySelector('tbody');
  if (!tbody) return;
  const rows = Array.from(tbody.querySelectorAll('tr')).filter(tr => tr.children.length > 1);
  if (!rows.length) return;

  const prevIdx = Number(table.dataset.sortIdx || -1);
  const prevDir = Number(table.dataset.sortDir || 1);
  const dir = prevIdx === colIdx ? prevDir * -1 : 1;
  table.dataset.sortIdx = String(colIdx);
  table.dataset.sortDir = String(dir);

  const headers = Array.from(table.querySelectorAll('thead th'));
  headers.forEach((th, idx) => {
    th.classList.remove('sorted');
    const icon = th.querySelector('.sort-icon');
    if (icon) icon.textContent = idx === colIdx ? (dir > 0 ? '↑' : '↓') : '↕';
  });
  if (headers[colIdx]) headers[colIdx].classList.add('sorted');

  rows.sort((a, b) => {
    const av = inferCellSortValue(a.cells[colIdx]);
    const bv = inferCellSortValue(b.cells[colIdx]);
    if (av.type === bv.type && av.type !== 'text') return (av.value - bv.value) * dir;
    return String(av.value).localeCompare(String(bv.value), undefined, { numeric: true, sensitivity: 'base' }) * dir;
  });

  rows.forEach(r => tbody.appendChild(r));
}

function enhanceGenericSortableTables(root = document) {
  root.querySelectorAll('.table-wrap table').forEach(table => {
    if (table.dataset.sortEnhanced === '1') return;
    const headers = Array.from(table.querySelectorAll('thead th'));
    const tbody = table.querySelector('tbody');
    if (!headers.length || !tbody) return;
    if (headers.some(th => th.getAttribute('onclick'))) return;

    headers.forEach((th, idx) => {
      th.style.cursor = 'pointer';
      if (!th.querySelector('.sort-icon')) {
        th.insertAdjacentHTML('beforeend', ' <span class="sort-icon">↕</span>');
      }
      th.addEventListener('click', () => sortGenericResultTable(table, idx));
    });
    table.dataset.sortEnhanced = '1';
  });
}

function initGenericTableSorting() {
  enhanceGenericSortableTables();
  if (genericTableObserver) return;
  const debouncedEnhance = debounce(() => enhanceGenericSortableTables(), 80);
  genericTableObserver = new MutationObserver(() => debouncedEnhance());
  genericTableObserver.observe(document.body, { childList: true, subtree: true });
}

// ════════════════════════════════════════════════════════════
// THEME
// ════════════════════════════════════════════════════════════
const THEME_KEY = 'sentinel-theme';
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  localStorage.setItem(THEME_KEY, t);
  const toggle = document.getElementById('themeToggle');
  if (toggle) toggle.textContent = t === 'dark' ? '☀️' : '🌙';
  const themeSel = document.getElementById('settingsTheme');
  if (themeSel) themeSel.value = t;
}
const UI_PREFS_KEY = 'sentinel-ui-prefs';
function getUiPrefs() {
  try { return JSON.parse(localStorage.getItem(UI_PREFS_KEY) || '{}') || {}; }
  catch { return {}; }
}
function saveUiPrefs(next = {}) {
  const prefs = { density: 'standard', accent: 'violet', motion: 'full', ...getUiPrefs(), ...next };
  localStorage.setItem(UI_PREFS_KEY, JSON.stringify(prefs));
  applyUiPrefs(prefs);
}
function applyUiPrefs(prefs = getUiPrefs()) {
  const normalized = { density: 'standard', accent: 'violet', motion: 'full', ...prefs };
  document.documentElement.dataset.density = normalized.density;
  document.documentElement.dataset.accent = normalized.accent;
  document.documentElement.dataset.motion = normalized.motion;
  document.querySelectorAll('[data-density-choice]').forEach(btn => btn.classList.toggle('active', btn.dataset.densityChoice === normalized.density));
  document.querySelectorAll('[data-accent-choice]').forEach(btn => btn.classList.toggle('active', btn.dataset.accentChoice === normalized.accent));
  const motionToggle = document.getElementById('motionCalmToggle');
  if (motionToggle) motionToggle.checked = normalized.motion === 'calm';
}
document.getElementById('themeToggle')?.addEventListener('click', () => {
  setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
});
setTheme(localStorage.getItem(THEME_KEY) || 'dark');
applyUiPrefs();
setLastSyncStamp();

// ════════════════════════════════════════════════════════════
// ALERT SETTINGS
// ════════════════════════════════════════════════════════════
async function loadAlertSettings() {
  try {
    const { data } = await apiJSON('/api/alert-settings');
    alertSettingsCache = data || {};
    const s = alertSettingsCache;
    document.getElementById('set-telegram-enabled').checked = !!s.telegram_enabled;
    document.getElementById('set-telegram-token').value = s.telegram_bot_token || '';
    document.getElementById('set-telegram-chat').value = s.telegram_chat_id || '';
    document.getElementById('set-slack-enabled').checked = !!s.slack_enabled;
    document.getElementById('set-slack-webhook').value = s.slack_webhook_url || '';
    document.getElementById('set-discord-enabled').checked = !!s.discord_enabled;
    document.getElementById('set-discord-webhook').value = s.discord_webhook_url || '';
    document.getElementById('set-rule-mismatch').checked = !!s.rule_mismatch;
    document.getElementById('set-rule-expired').checked = !!s.rule_expired;
    document.getElementById('set-rule-expiring').checked = !!s.rule_expiring;
    document.getElementById('set-rule-error').checked = !!s.rule_error;
    document.getElementById('set-mismatch-scope').value = s.mismatch_scope_filter || 'all';
    document.getElementById('set-min-days').value = Number(s.minimum_days_left || 30);
  } catch {
    toast('Failed to load alert settings', 'err');
  }
}

async function saveAlertSettings() {
  const payload = {
    telegram_enabled: document.getElementById('set-telegram-enabled').checked,
    telegram_bot_token: document.getElementById('set-telegram-token').value.trim(),
    telegram_chat_id: document.getElementById('set-telegram-chat').value.trim(),
    slack_enabled: document.getElementById('set-slack-enabled').checked,
    slack_webhook_url: document.getElementById('set-slack-webhook').value.trim(),
    discord_enabled: document.getElementById('set-discord-enabled').checked,
    discord_webhook_url: document.getElementById('set-discord-webhook').value.trim(),
    rule_mismatch: document.getElementById('set-rule-mismatch').checked,
    rule_expired: document.getElementById('set-rule-expired').checked,
    rule_expiring: document.getElementById('set-rule-expiring').checked,
    rule_error: document.getElementById('set-rule-error').checked,
    mismatch_scope_filter: document.getElementById('set-mismatch-scope').value,
    minimum_days_left: Number(document.getElementById('set-min-days').value || 30),
  };
  const { ok, error } = await fetch('/api/alert-settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).then(r => r.json());
  if (!ok) {
    toast(error || 'Failed to save settings', 'err');
    return;
  }
  toast('Alert settings saved', 'ok');
}

// ════════════════════════════════════════════════════════════
// CLOCK
// ════════════════════════════════════════════════════════════
function tick() {
  const s = new Date().toUTCString().slice(0,25)+' UTC';
  document.getElementById('sideClock').textContent = s;
}
let clockTimer = setInterval(tick,1000); tick();

// ════════════════════════════════════════════════════════════
// NAVIGATION
// ════════════════════════════════════════════════════════════
const PAGE_INFRA = {
  dashboard: { title: 'Dashboard', onEnter: loadDash },
  projects: { title: 'Projects', onEnter: loadProjects },
  detail: { title: 'Project Detail' },
  alerts: { title: 'Alerts', onEnter: loadAlerts },
  subfinder: { title: 'Subfinder', onEnter: initSfPage },
  discoveries: { title: 'Discoveries', onEnter: initDiscoveriesPage },
  assets: { title: 'Assets', onEnter: initAssetsPage },
  'bounty-leads': { title: 'Bounty Leads', onEnter: initBountyLeadsPage },
  'subfinder-raw': { title: 'Subfinder Enumeration', onEnter: initSfRawPage },
  nuclei: { title: 'Nuclei CVEs', onEnter: initNucleiPage },
  openssl: { title: 'OpenSSL', onEnter: initOpenSSLPage },
  logs: { title: 'Logs', onEnter: loadLogsPage },
  settings: { title: 'Alert Routing', onEnter: loadAlertSettings },
};
const QUICK_ACTION_PAGES = ['dashboard', 'projects', 'alerts', 'subfinder', 'discoveries', 'assets', 'bounty-leads', 'subfinder-raw', 'nuclei', 'openssl', 'logs', 'settings'];
const QUICK_ACTIONS = [
  ...QUICK_ACTION_PAGES.map(page => ({
    label: PAGE_INFRA[page]?.title || page,
    description: `Open ${PAGE_INFRA[page]?.title || page}`,
    group: 'Pages',
    icon: page === 'alerts' ? '🔔' : page === 'settings' ? '📣' : page === 'logs' ? '📜' : page === 'projects' ? '📁' : page === 'dashboard' ? '⌁' : '🛰️',
    page,
  })),
  { label: 'Create project', description: 'Open the new project modal', group: 'Actions', icon: '＋', action: () => openModal('createModal'), shortcut: 'N' },
  { label: 'Refresh dashboard', description: 'Reload stats, logs, active scans, and recommendations', group: 'Actions', icon: '↻', action: () => loadDash(), shortcut: 'R' },
  { label: 'Open alert routing', description: 'Configure Slack, Discord, Telegram, and trigger rules', group: 'Actions', icon: '📣', page: 'settings' },
];

function nav(name) {
  const config = PAGE_INFRA[name] || {};
  performance.mark?.(`nav:${name}`);
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const pg = document.getElementById('page-'+name);
  if (pg) { pg.classList.add('active'); pg.setAttribute('aria-current', 'page'); }
  document.querySelectorAll('.page:not(.active)').forEach(p => p.removeAttribute('aria-current'));
  const ni = document.querySelector(`[data-page="${name}"]`);
  if (ni) ni.classList.add('active');
  document.getElementById('topTitle').textContent = config.title || name;
  document.title = `${config.title || name} · SSL Sentinel`;
  document.getElementById('mainContent')?.focus({ preventScroll: true });
  config.onEnter?.();
}

document.querySelectorAll('.nav-item[data-page]').forEach(el => {
  el.addEventListener('click', () => {
    nav(el.dataset.page);
    if (window.innerWidth <= 900) document.body.classList.remove('sidebar-open');
  });
});

const navFilterInput = document.getElementById('navFilterInput');
function filterNavItems(term = '') {
  const query = term.trim().toLowerCase();
  const items = [...document.querySelectorAll('.nav-item[data-page]')];
  items.forEach((item) => {
    const label = item.textContent.toLowerCase();
    const isMatch = !query || label.includes(query);
    item.classList.toggle('is-hidden', !isMatch);
  });
  document.querySelectorAll('.nav-section').forEach((section) => {
    let next = section.nextElementSibling;
    let hasVisibleItem = false;
    while (next && !next.classList.contains('nav-section')) {
      if (next.classList.contains('nav-item') && !next.classList.contains('is-hidden')) {
        hasVisibleItem = true;
        break;
      }
      next = next.nextElementSibling;
    }
    section.classList.toggle('is-hidden', !hasVisibleItem);
  });
}
navFilterInput?.addEventListener('input', (e) => filterNavItems(e.target.value));

const menuBtn = document.getElementById('mobileMenuBtn');
const sidebarOverlay = document.getElementById('sidebarOverlay');
menuBtn?.addEventListener('click', () => document.body.classList.toggle('sidebar-open'));
sidebarOverlay?.addEventListener('click', () => document.body.classList.remove('sidebar-open'));

const commandPalette = document.getElementById('commandPalette');
const commandInput = document.getElementById('commandInput');
const commandList = document.getElementById('commandList');
let commandMatches = [];
let commandActiveIndex = 0;
function renderCommandList(term='') {
  const q = term.trim().toLowerCase();
  commandMatches = QUICK_ACTIONS.filter(a => [a.label, a.description, a.group].join(' ').toLowerCase().includes(q));
  commandActiveIndex = Math.min(commandActiveIndex, Math.max(0, commandMatches.length - 1));
  if (!commandMatches.length) {
    commandList.innerHTML = `<div class="command-item">No matching actions.</div>`;
    return;
  }
  let lastGroup = '';
  commandList.innerHTML = commandMatches.map((item, idx) => {
    const groupLabel = item.group !== lastGroup ? `<div class="command-section-label">${esc(item.group || 'Actions')}</div>` : '';
    lastGroup = item.group;
    return `${groupLabel}<button class="command-item ${idx===commandActiveIndex?'active':''}" data-idx="${idx}" style="width:100%;border:none;background:none;text-align:left">
      <span class="command-item-icon">${esc(item.icon || '⌘')}</span>
      <span class="command-item-main"><span class="command-item-title">${esc(item.label)}</span><span class="command-item-desc">${esc(item.description || '')}</span></span>
      ${item.shortcut ? `<kbd>${esc(item.shortcut)}</kbd>` : `<span style="font-size:11px;color:var(--text-muted)">${item.page ? 'Page' : 'Run'}</span>`}
    </button>`;
  }).join('');
  commandList.querySelectorAll('.command-item[data-idx]').forEach(btn => btn.addEventListener('click', () => runQuickAction(commandMatches[Number(btn.dataset.idx)])));
}
function moveCommandSelection(delta) {
  if (!commandMatches.length) return;
  commandActiveIndex = (commandActiveIndex + delta + commandMatches.length) % commandMatches.length;
  renderCommandList(commandInput.value);
  commandList.querySelector('.command-item.active')?.scrollIntoView({ block: 'nearest' });
}
function openCommandPalette() {
  commandPalette.classList.add('open');
  commandInput.value = '';
  commandActiveIndex = 0;
  renderCommandList('');
  setTimeout(() => commandInput.focus(), 0);
}
function closeCommandPalette() { commandPalette.classList.remove('open'); }
function runQuickAction(item) {
  if (!item) return;
  if (item.page) nav(item.page);
  if (item.action) item.action();
  closeCommandPalette();
}
document.getElementById('commandBtn')?.addEventListener('click', openCommandPalette);
commandInput?.addEventListener('input', e => renderCommandList(e.target.value));
commandInput?.addEventListener('keydown', e => {
  if (e.key === 'ArrowDown') { e.preventDefault(); moveCommandSelection(1); }
  if (e.key === 'ArrowUp') { e.preventDefault(); moveCommandSelection(-1); }
  if (e.key === 'Enter') { e.preventDefault(); runQuickAction(commandMatches[commandActiveIndex]); }
  if (e.key === 'Escape') closeCommandPalette();
});
commandPalette?.addEventListener('click', e => { if (e.target === commandPalette) closeCommandPalette(); });
window.addEventListener('keydown', e => {
  const k = e.key.toLowerCase();
  if ((e.ctrlKey || e.metaKey) && k === 'k') { e.preventDefault(); openCommandPalette(); }
  if (k === 'escape' && commandPalette?.classList.contains('open')) closeCommandPalette();
});
document.addEventListener('click', (e) => {
  const densityBtn = e.target.closest('[data-density-choice]');
  if (densityBtn) saveUiPrefs({ density: densityBtn.dataset.densityChoice });
  const accentBtn = e.target.closest('[data-accent-choice]');
  if (accentBtn) saveUiPrefs({ accent: accentBtn.dataset.accentChoice });
});
document.getElementById('motionCalmToggle')?.addEventListener('change', (e) => saveUiPrefs({ motion: e.target.checked ? 'calm' : 'full' }));
document.getElementById('shortcutsFab')?.addEventListener('click', openCommandPalette);
window.addEventListener('keydown', e => {
  const k = e.key.toLowerCase();
  if (['input','textarea','select'].includes(document.activeElement?.tagName?.toLowerCase())) return;
  if (k === '?') { e.preventDefault(); openCommandPalette(); }
  if (k === 'g') { e.preventDefault(); nav('dashboard'); }
  if (k === 'p') { e.preventDefault(); nav('projects'); }
  if (k === 'a') { e.preventDefault(); nav('alerts'); }
  if (k === 'n') { e.preventDefault(); openModal('createModal'); }
});

// ════════════════════════════════════════════════════════════
// UTILS
// ════════════════════════════════════════════════════════════
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const fmt = n => (n||0).toLocaleString();

function rel(iso) {
  if (!iso) return '—';
  const d = Math.floor((Date.now()-new Date(iso))/1000);
  return d<60?`${d}s ago`:d<3600?`${Math.floor(d/60)}m ago`:d<86400?`${Math.floor(d/3600)}h ago`:`${Math.floor(d/86400)}d ago`;
}

function sbadge(r) {
  if (r.error&&!r.is_mismatch&&!r.is_expired&&!r.is_expiring&&!r.is_ok)
    return '<span class="badge badge-error">error</span>';
  if (r.is_expired) return '<span class="badge badge-expired">expired</span>';
  if (r.is_mismatch) return '<span class="badge badge-mismatch">mismatch</span>';
  if (r.is_expiring) return '<span class="badge badge-expiring">expiring</span>';
  return '<span class="badge badge-ok">valid</span>';
}

function rowStatus(r) {
  if (r.error&&!r.is_mismatch&&!r.is_expired&&!r.is_expiring&&!r.is_ok) return 'error';
  if (r.is_expired) return 'expired';
  if (r.is_mismatch) return 'mismatch';
  if (r.is_expiring) return 'expiring';
  return 'valid';
}

function daysColor(d) {
  if (d==null) return 'var(--text-muted)';
  return d<0?'var(--red)':d<=30?'var(--amber)':'var(--green)';
}

// ════════════════════════════════════════════════════════════
// TOAST
// ════════════════════════════════════════════════════════════
function toast(msg, type='') {
  const icon = type==='ok'?'✅':type==='err'?'❌':'ℹ️';
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${icon}</span><span>${esc(msg)}</span>`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ════════════════════════════════════════════════════════════
// MODAL
// ════════════════════════════════════════════════════════════
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
window.addEventListener('click', e => {
  if (e.target.classList.contains('modal-overlay')) e.target.classList.remove('open');
});

// ════════════════════════════════════════════════════════════
// SSE — Real-time updates (fixes alert counter stale bug)
// ════════════════════════════════════════════════════════════
function connectSSE() {
  if (sseConnection || document.hidden) return;
  clearTimeout(sseReconnectTimer);
  sseReconnectTimer = null;
  const es = new EventSource('/api/sse');
  sseConnection = es;

  es.addEventListener('connected', () => {
    sseReconnectDelay = 1000;
    console.log('SSE connected');
  });

  es.addEventListener('alert_update', e => {
    const d = JSON.parse(e.data);
    updateAlertBadge(d.unseen_count);
    queueAlertsRefresh();
  });

  es.addEventListener('scan_update', e => {
    const s = JSON.parse(e.data);
    // Update scan progress if we're watching this project
    if (s.project_id === curPid) {
      if (!curSid) curSid = s.id;
      document.getElementById('scan-prog-card').style.display='';
      updateScanProgress(s);
    }
    // Refresh dashboard active scans section
    if (document.getElementById('page-dashboard').classList.contains('active')) {
      refreshActiveScans();
    }
  });

  es.addEventListener('stats_update', e => {
    const s = JSON.parse(e.data);
    applyStat(s);
    updateMissionControl(s, projectsCache);
  });
  es.addEventListener('log_update', e => {
    const d = JSON.parse(e.data);
    appendLogRow(d.entry);
  });
  es.addEventListener('openssl_row', e => {
    const d = JSON.parse(e.data || '{}');
    if (!d?.row || d.project_id !== opensslPid) return;
    const idx = opensslRows.findIndex(r => r.hostname === d.row.hostname);
    if (idx >= 0) opensslRows[idx] = d.row; else opensslRows.push(d.row);
    queueOpenSSLRender();
  });
  es.addEventListener('openssl_status', e => {
    const d = JSON.parse(e.data || '{}');
    if (d.project_id !== opensslPid) return;
    const meta = document.getElementById('openssl-meta');
    meta.textContent = `Worker status: ${d.status || 'idle'} · tracked hosts: ${fmt(d.tracked_hosts || 0)}`;
  });

  es.addEventListener('project_created', () => {
    if (document.getElementById('page-projects').classList.contains('active')) loadProjects();
  });
  es.addEventListener('quick_scan_row', e => {
    const d = JSON.parse(e.data || '{}');
    if (!quickScanId || d.scan_id !== quickScanId || !d.row) return;
    const key = d.row.hostname || `${Date.now()}-${Math.random()}`;
    quickRowsByHost.set(key, d.row);
    scheduleQuickRender();
  });
  es.addEventListener('quick_scan_update', e => {
    const d = JSON.parse(e.data || '{}');
    if (!quickScanId || d.id !== quickScanId) return;
    updateQuickProgress(d);
    if (d.status === 'done') {
      document.getElementById('quick-scan-btn').disabled = false;
      toast('Quick scan complete', 'ok');
    } else if (d.status === 'error') {
      document.getElementById('quick-scan-btn').disabled = false;
      toast(d.error || 'Quick scan failed', 'err');
    }
  });
  es.addEventListener('nuclei_finding', e => {
    const d = JSON.parse(e.data || '{}');
    if (!nucleiCurrentScanId || d.id !== nucleiCurrentScanId || !d.finding) return;
    nucleiFindings.push(d.finding);
    scheduleNucleiRowsRender();
  });
  es.addEventListener('nuclei_log', e => {
    const d = JSON.parse(e.data || '{}');
    if (!nucleiCurrentScanId || d.id !== nucleiCurrentScanId || !d.entry) return;
    appendNucleiLogEntry(d.entry);
  });
  es.addEventListener('nuclei_stats', e => {
    const d = JSON.parse(e.data || '{}');
    if (!nucleiCurrentScanId || d.id !== nucleiCurrentScanId) return;
    scheduleNucleiStatsRender({ id: d.id, status: 'running', stats: d.stats || {}, progress_percent: d.progress_percent, findings_total: nucleiFindings.length });
  });
  es.addEventListener('nuclei_update', e => {
    const d = JSON.parse(e.data || '{}');
    if (!nucleiCurrentScanId || d.id !== nucleiCurrentScanId) return;
    updateNucleiLive(d);
    if (d.status === 'done') toast('Nuclei scan complete', 'ok');
    if (d.status === 'error') toast(d.error || 'Nuclei scan failed', 'err');
  });

  es.onerror = () => {
    if (sseConnection !== es) return;
    sseConnection = null;
    es.close();
    if (document.hidden) return;
    clearTimeout(sseReconnectTimer);
    const delay = sseReconnectDelay;
    sseReconnectDelay = Math.min(sseReconnectDelay * 1.6, 15000);
    sseReconnectTimer = setTimeout(connectSSE, delay);
  };
}
connectSSE();

let alertsRefreshTimer = null;
function queueAlertsRefresh() {
  if (!document.getElementById('page-alerts').classList.contains('active')) return;
  if (alertsRefreshTimer) return;
  alertsRefreshTimer = setTimeout(() => {
    alertsRefreshTimer = null;
    loadAlerts();
  }, 500);
}

// ════════════════════════════════════════════════════════════
// ALERT BADGE
// ════════════════════════════════════════════════════════════
function updateAlertBadge(n) {
  const pill = document.getElementById('alertPill');
  const badge = document.getElementById('navAlertBadge');
  const count = document.getElementById('pillCount');
  if (n > 0) {
    pill.classList.remove('hidden');
    badge.style.display = '';
    badge.textContent = n;
    count.textContent = n;
  } else {
    pill.classList.add('hidden');
    badge.style.display = 'none';
  }
}

// Poll badge every 30s as SSE fallback
async function pollBadge() {
  try {
    const { data: s } = await apiJSON('/api/stats');
    updateAlertBadge(s?.unseen_alerts || 0);
  } catch {}
}
let pollBadgeTimer = setInterval(pollBadge, 30000); pollBadge();

function humanDuration(sec){
  const s = Number(sec||0);
  const d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
  if (d>0) return `${d}d ${h}h ${m}m`;
  if (h>0) return `${h}h ${m}m`;
  return `${m}m`;
}
function humanBytes(bytes){
  const b=Number(bytes||0); if(!b) return '0 B';
  const u=['B','KB','MB','GB']; let i=0,v=b;
  while(v>=1024 && i<u.length-1){v/=1024;i++;}
  return `${v.toFixed(v>=10?0:1)} ${u[i]}`;
}

async function loadSystemOverview(){
  try{
    const { data } = await apiJSON('/api/system-overview');
    if(!data) return;
    document.getElementById('sys-uptime').textContent = humanDuration(data.uptime_seconds);
    document.getElementById('sys-running-scans').textContent = fmt(data.scans_running);
    document.getElementById('sys-enabled-projects').textContent = `${fmt(data.enabled_projects)}/${fmt(data.projects_total)}`;
    document.getElementById('sys-db-size').textContent = humanBytes(data.database?.size_bytes);
    document.getElementById('sys-discoveries').textContent = fmt(data.discoveries_total);
    document.getElementById('sys-unresolved').textContent = fmt(data.unresolved_alerts);
  }catch{}
}

// ════════════════════════════════════════════════════════════
// DASHBOARD
// ════════════════════════════════════════════════════════════
function applyStat(s) {
  if (!s) return;
  const totalDomains = s.total_domains ?? s.domains ?? s.total ?? s.projects;
  document.getElementById('s-projects').textContent = fmt(totalDomains);
  document.getElementById('s-ok').textContent = fmt(s.ok);
  document.getElementById('s-mis').textContent = fmt(s.mismatches);
  document.getElementById('s-expg').textContent = fmt(s.unseen_alerts ?? s.mismatches);
}

function calcRiskScore(stats = {}, projects = []) {
  const total = Math.max(1, Number(stats.total_domains ?? 0));
  const mismatchRate = Number(stats.mismatches ?? 0) / total;
  const errorRate = Number(stats.errors ?? 0) / total;
  const expiredRate = Number(stats.expired ?? 0) / total;
  const alertRate = Number(stats.unseen_alerts ?? 0) / total;
  const disabledProjects = projects.filter(p => !p.enabled).length;
  const disabledRate = projects.length ? disabledProjects / projects.length : 0;
  const raw = (mismatchRate * 42) + (errorRate * 20) + (expiredRate * 25) + (alertRate * 8) + (disabledRate * 5);
  return Math.max(0, Math.min(100, Math.round(raw * 100)));
}

function severityLabel(score) {
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Moderate';
  return 'Low';
}


function pctValue(value, total) {
  const t = Math.max(1, Number(total || 0));
  return Math.max(0, Math.min(100, Math.round((Number(value || 0) / t) * 100)));
}
function renderMetricRow(label, value, total, tone = 'accent') {
  const pct = pctValue(value, total);
  const color = tone === 'danger' ? 'var(--red)' : tone === 'warn' ? 'var(--amber)' : tone === 'good' ? 'var(--green)' : 'linear-gradient(90deg,var(--accent),var(--purple))';
  return `<div class="metric-row"><span>${esc(label)}</span><div class="metric-track"><div class="metric-fill" style="width:${pct}%;background:${color}"></div></div><strong>${pct}%</strong></div>`;
}
function actionChip(icon, title, desc, label, fn) {
  const id = `act-${Math.random().toString(36).slice(2)}`;
  requestAnimationFrame(() => { window[id] = fn; });
  return `<div class="action-chip"><span class="emoji">${esc(icon)}</span><span><strong>${esc(title)}</strong>${esc(desc)}</span><button type="button" onclick="${id}()">${esc(label)}</button></div>`;
}
function updateMissionControl(stats = {}, projects = [], riskIntel = null) {
  const risk = Number.isFinite(Number(riskIntel?.risk_score)) ? Number(riskIntel.risk_score) : calcRiskScore(stats, projects);
  const total = Number(stats.total_domains ?? stats.domains ?? stats.total ?? stats.hosts ?? 0);
  const ok = Number(stats.ok ?? 0);
  const mismatches = Number(stats.mismatches ?? 0);
  const expired = Number(stats.expired ?? 0);
  const expiring = Number(stats.expiring ?? 0);
  const errors = Number(stats.errors ?? 0);
  const alerts = Number(stats.unseen_alerts ?? 0);
  const scannedProjects = projects.filter(p => p.latest_scan?.finished_at || p.latest_scan?.started_at).length;
  const runningProjects = projects.filter(p => p.latest_scan?.status === 'running').length;
  const staleProjects = projects.filter(p => !p.latest_scan?.finished_at && !p.latest_scan?.started_at).length;
  const riskOrb = document.getElementById('riskOrb');
  if (riskOrb) riskOrb.style.setProperty('--risk', risk);
  const riskNumber = document.getElementById('riskNumber');
  if (riskNumber) riskNumber.textContent = risk;
  const severity = severityLabel(risk);
  const caption = document.getElementById('riskCaption');
  if (caption) caption.textContent = `${severity} signal`;
  const state = document.getElementById('missionState');
  if (state) state.textContent = runningProjects ? `${runningProjects} scan${runningProjects>1?'s':''} feeding chains` : alerts ? `${alerts} alert${alerts>1?'s':''} to validate` : 'Chain-ready';
  const narrative = document.getElementById('riskNarrative');
  if (narrative) narrative.textContent = riskIntel ? `${fmt(total)} hosts profiled · ${fmt(riskIntel.anomaly_count ?? (mismatches + expired + errors))} chainable anomaly signals · ${fmt(riskIntel.stale_projects || 0)} stale projects · posture ${riskIntel.posture || severity}.` : (total ? `${fmt(total)} hosts profiled · ${fmt(mismatches + expired + errors)} chainable anomaly signals · ${fmt(scannedProjects)}/${fmt(projects.length)} projects feeding evidence.` : 'Create or import a project to activate exploit-signal correlation.');
  updateHunterDashboard(stats, projects, { total, mismatches, expired, expiring, errors, alerts, scannedProjects, staleProjects }, riskIntel);
}

function hunterTile(label, value, copy) {
  return `<div class="hunter-tile"><div class="hunter-tile-label">${esc(label)}</div><div class="hunter-tile-value">${fmt(value)}</div><div class="hunter-tile-copy">${esc(copy)}</div></div>`;
}

function hunterSignalCount(leads, matcher) {
  return leads.filter(matcher).length;
}
function hunterConfidence(lead) {
  let c = Number(lead.score || 0);
  if (lead.http_is_active) c += 10;
  if ((lead.evidence || []).length >= 3) c += 8;
  if (lead.checked_at) c += 6;
  return Math.max(1, Math.min(99, Math.round(c)));
}
function hunterKillChain(lead) {
  const type = `${lead.lead_type || ''} ${(lead.evidence || []).join(' ')}`.toLowerCase();
  const chain = ['Scope check', lead.http_is_active ? 'Live HTTP probe' : 'HTTP probe', 'Evidence capture'];
  if (type.includes('api') || type.includes('graphql') || type.includes('swagger')) chain.splice(2, 0, 'Schema/auth review');
  if (type.includes('admin') || type.includes('login') || type.includes('dashboard')) chain.splice(2, 0, 'Access-control test');
  if (lead.is_mismatch || type.includes('tls')) chain.splice(2, 0, 'TLS tenant pivot');
  return [...new Set(chain)].slice(0, 5);
}
function renderHunterPath(lead, rank = 0) {
  const host = lead.hostname || lead.http_final_url || 'unknown-host';
  const steps = (lead.next_steps || []).slice(0, 3).map(step => `<li>${esc(step)}</li>`).join('');
  const chain = hunterKillChain(lead).map(node => `<span>${esc(node)}</span>`).join('');
  const confidence = hunterConfidence(lead);
  const sev = (lead.severity || 'low').toLowerCase();
  return `<div class="hunter-path hunter-path-${esc(sev)}">
    <div class="hunter-path-top"><span class="hunter-path-host">#${rank + 1} ${esc(host)}</span><span class="hunter-score">${fmt(lead.score || 0)} pts · ${confidence}%</span></div>
    <div class="hunter-path-type">${esc(lead.lead_type || lead.severity || 'Recon candidate')} · ${esc(lead.project_name || 'Project')}</div>
    <div class="hunter-chain">${chain}</div>
    <ul class="hunter-path-steps">${steps || '<li>Verify scope, collect screenshots, and document reproducible impact.</li>'}</ul>
  </div>`;
}

async function updateHunterDashboard(stats = {}, projects = [], context = {}, riskIntel = null) {
  const matrix = document.getElementById('hunterMatrix');
  const paths = document.getElementById('hunterPaths');
  const total = Number(context.total || stats.total_domains || stats.hosts || 0);
  const mismatches = Number(context.mismatches || 0);
  const staleProjects = Number(context.staleProjects || 0);
  let leads = [];
  try {
    const { ok, data } = await apiJSON('/api/bounty/leads?limit=25');
    leads = ok ? (data?.rows || data?.leads || []) : [];
  } catch {}
  const riskSummary = riskIntel?.bounty_summary || {};
  const high = hunterSignalCount(leads, l => (l.score || 0) >= 75);
  const apiAdmin = hunterSignalCount(leads, l => /api|graphql|swagger|admin|login|sso|dashboard/i.test(`${l.lead_type || ''} ${l.hostname || ''} ${l.http_page_title || ''}`));
  const fresh = hunterSignalCount(leads, l => l.is_latest_discovery);
  const tls = hunterSignalCount(leads, l => l.is_mismatch || l.is_expired);
  if (matrix) {
    matrix.innerHTML = [
      hunterTile('Critical paths', riskSummary.high ?? high, '75+ score chains ready for scope-safe validation and evidence capture.'),
      hunterTile('API/Admin blast radius', apiAdmin, 'Auth, API, dashboard, SSO, and documentation surfaces in top ranked leads.'),
      hunterTile('Fresh pivots', riskSummary.fresh_discoveries ?? (fresh || staleProjects), 'Newly discovered hosts plus projects that need a first scan for reliable scoring.'),
      hunterTile('TLS drift pivots', tls || (mismatches + Number(context.expired || 0)), 'Mismatch and expired-certificate leads worth tenant/takeover review.'),
      hunterTile('Mapped scope', total || Number(stats.subfinder_hosts || 0), 'Hosts tracked across projects, scan results, and discovery feeds.'),
      hunterTile('Alert pressure', Number(context.alerts || 0), 'Unseen findings to convert into validated evidence or dismissals.'),
    ].join('');
  }
  if (!paths) return;
  if (leads.length) {
    const top = leads.slice(0, 4);
    paths.innerHTML = top.map(renderHunterPath).join('') + `<div class="hunter-actions"><button class="btn btn-primary btn-sm" onclick="nav('bounty-leads')">Open full bounty lead engine</button><button class="btn btn-sm" onclick="nav('nuclei')">Validate with Nuclei</button></div>`;
  } else {
    paths.innerHTML = `<div class="hunter-empty">No ranked exploit paths yet. Run Subfinder discovery and HTTP enrichment, then this radar will surface scope-safe API, admin, staging, and TLS-misroute candidates.</div><button class="btn btn-primary btn-sm" onclick="nav('subfinder')">Launch discovery</button>`;
  }
}

async function loadDash() {
  if (dashboardLoadInFlight) return;
  dashboardLoadInFlight = true;
  try {
    const [statsResp, projectsResp, riskResp] = await Promise.all([
      apiJSON('/api/stats'),
      projectsCache.length ? Promise.resolve({ data: projectsCache }) : apiJSON('/api/projects'),
      apiJSON('/api/attack-surface/risk'),
    ]);
    const stats = statsResp.data || {};
    const projects = projectsResp.data || [];
    const riskIntel = riskResp.data || null;
    if (projects.length) projectsCache = projects;
    applyStat(stats);
    await Promise.allSettled([
      refreshActiveScans(),
      loadDashMismatches(projects),
      loadLogs(),
      loadSystemOverview(),
      Promise.resolve(updateMissionControl(stats, projects, riskIntel)),
    ]);
  } finally {
    dashboardLoadInFlight = false;
  }
}

async function loadLogs() {
  try {
    const { data } = await apiJSON('/api/logs?limit=120');
    renderLogs(data || []);
  } catch {}
}

function renderLogs(rows) {
  const el = document.getElementById('dash-logs');
  if (!rows.length) {
    el.innerHTML = '<div class="empty"><div class="empty-icon">📜</div><div class="empty-title">Waiting for logs</div></div>';
    document.getElementById('dash-log-status').textContent = 'Idle';
    return;
  }
  const active = [...rows].reverse().find(r => r.status === 'running');
  const failed = [...rows].reverse().find(r => r.status === 'failed');
  document.getElementById('dash-log-status').textContent = active ? 'Running' : failed ? 'Failed' : 'Idle';
  el.innerHTML = rows.slice(-80).reverse().map(r => `<div style="padding:4px 0;border-bottom:1px solid var(--border-subtle)">
    <span style="color:var(--text-muted)">[${new Date(r.timestamp).toLocaleTimeString()}]</span>
    <span style="color:${r.level==='ERROR'?'var(--red)':r.level==='WARNING'?'var(--amber)':'var(--text-secondary)'}">${r.level}</span>
    <span style="color:var(--purple)">(${esc(r.component)})</span>
    <span>${esc(r.message)}</span>
  </div>`).join('');
  const logsPage = document.getElementById('logs-page-body');
  if (logsPage) logsPage.innerHTML = el.innerHTML;
}

async function loadLogsPage() {
  await loadLogs();
  const logsPage = document.getElementById('logs-page-body');
  if (logsPage && !logsPage.innerHTML.trim()) {
    logsPage.innerHTML = '<div style="color:var(--text-muted)">Waiting for logs...</div>';
  }
}

function appendLogRow(entry) {
  if (!entry || !document.getElementById('page-dashboard').classList.contains('active')) return;
  pendingLogEntries.push(entry);
  if (pendingLogEntries.length > 25) pendingLogEntries = pendingLogEntries.slice(-25);
  if (logFlushTimer) return;
  logFlushTimer = setTimeout(() => {
    logFlushTimer = null;
    loadLogs();
    loadSystemOverview();
    pendingLogEntries = [];
  }, 1000);
}

async function refreshActiveScans() {
  try {
    const { data: scans } = await apiJSON('/api/active-scans');
    const el = document.getElementById('dash-active-scans');
    if (!scans?.length) {
      el.innerHTML = '<div class="empty"><div class="empty-icon">⚡</div><div class="empty-title">No scans running</div></div>';
      return;
    }
    el.innerHTML = `<div class="table-wrap"><table><thead><tr><th>Project</th><th style="min-width:220px">Progress</th><th>Checked</th></tr></thead><tbody>`+
      scans.map(s => {
        const pct = s.total>0?Math.round(s.progress/s.total*100):0;
        return `<tr><td style="font-weight:500">${esc(s.project_name)}</td>
          <td><div class="progress-wrap"><div class="progress-bar" style="width:${pct}%"></div></div>
              <div class="progress-label"><span>${fmt(s.progress)}/${fmt(s.total)}</span><span>${pct}%</span></div></td>
          <td><span class="badge badge-running">RUNNING</span></td></tr>`;
      }).join('')+`</tbody></table></div>`;
  } catch {}
}

async function loadDashMismatches(projectsOverride = null) {
  try {
    const el = document.getElementById('dash-mismatches');
    const projs = projectsOverride || (projectsCache.length ? projectsCache : ((await apiJSON('/api/projects')).data || []));
    const candidates = (projs || []).slice(0, 4).filter(p => p.latest_scan?.mismatches);
    const responses = await Promise.all(candidates.map(p =>
      apiJSON(`/api/scans/${p.latest_scan.id}/results?filter=mismatch&per_page=5&page=1`)
        .then(resp => (resp.data?.results || []).map(r => ({ ...r, pname: p.name })))
        .catch(() => [])
    ));
    const rows = responses.flat();
    if (!rows.length) {
      el.innerHTML='<div class="empty"><div class="empty-icon">✅</div><div class="empty-title">No mismatches detected</div></div>';
      return;
    }
    el.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Project</th><th>Hostname</th><th>Status</th><th>CN</th><th>Expiry</th></tr></thead><tbody>`+
      rows.map(r=>`<tr class="row-mismatch">
        <td style="color:var(--text-secondary);font-size:12px">${esc(r.pname)}</td>
        <td style="font-weight:500">${esc(r.hostname)}</td>
        <td>${sbadge(r)}</td>
        <td style="color:var(--text-secondary);font-size:12px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.cn)}</td>
        <td style="font-size:12px">${r.expiry||'—'}</td></tr>`).join('')+
      `</tbody></table></div>`;
  } catch {}
}

let dashboardRefreshTimer = setInterval(() => {
  if (document.getElementById('page-dashboard').classList.contains('active')) loadDash();
}, 60000);
let opensslRefreshTimer = setInterval(() => {
  if (document.getElementById('page-openssl').classList.contains('active') && opensslPid) loadOpenSSLRows();
}, 12000);

function renderQuickRows() {
  quickRows = Array.from(quickRowsByHost.values());
  const body = document.getElementById('quick-body');
  const rows = getQuickRowsView();
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:16px;color:var(--text-muted)">No quick scan results yet.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(r => `<tr class="${r.is_mismatch ? 'row-mismatch' : ''}">
    <td style="font-weight:500;font-family:var(--mono);font-size:12px">${esc(r.hostname || '—')}</td>
    <td>${sbadge(r)}</td>
    <td style="font-size:12px;color:var(--text-secondary);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.cn || r.error || '—')}">${esc(r.cn || r.error || '—')}</td>
    <td style="font-size:12px">${r.expiry || '—'}</td>
  </tr>`).join('');
}

function scheduleQuickRender() {
  if (quickRenderTimer) return;
  quickRenderTimer = setTimeout(() => {
    quickRenderTimer = null;
    renderQuickRows();
  }, 180);
}

function getQuickRowsView() {
  const filtered = quickRows.filter(r => {
    if (quickFilter === 'mismatch') return !!r.is_mismatch;
    if (quickFilter === 'expired') return !!r.is_expired;
    return true;
  });
  const sorted = [...filtered].sort((a, b) => {
    const av = quickSortValue(a, quickSortCol);
    const bv = quickSortValue(b, quickSortCol);
    if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * quickSortDir;
    return String(av).localeCompare(String(bv)) * quickSortDir;
  });
  return sorted;
}

function quickSortValue(row, col) {
  if (col === 'status') return rowStatus(row);
  if (col === 'cn') return row.cn || row.error || '';
  return row[col] ?? '';
}

function updateQuickSortHeader() {
  const headers = document.querySelectorAll('#quick-filter-tabs + .table-wrap thead th');
  const colMap = ['hostname', 'status', 'cn', 'expiry'];
  headers.forEach((th, idx) => {
    th.classList.remove('sorted');
    const si = th.querySelector('.sort-icon');
    if (si) si.textContent = '↕';
    if (colMap[idx] === quickSortCol) {
      th.classList.add('sorted');
      if (si) si.textContent = quickSortDir > 0 ? '↑' : '↓';
    }
  });
}

function sortQuickTable(col) {
  if (quickSortCol === col) quickSortDir *= -1; else { quickSortCol = col; quickSortDir = 1; }
  updateQuickSortHeader();
  renderQuickRows();
}

function setQuickFilter(filter, tabEl) {
  quickFilter = filter;
  document.querySelectorAll('#quick-filter-tabs .filter-tab').forEach(t => t.classList.remove('active'));
  if (tabEl) tabEl.classList.add('active');
  renderQuickRows();
}

function updateQuickProgress(s) {
  const done = s.done || 0;
  const total = s.total || 0;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  document.getElementById('quick-prog-bar').style.width = pct + '%';
  document.getElementById('quick-done').textContent = fmt(done);
  document.getElementById('quick-total').textContent = fmt(total);
  document.getElementById('quick-pct').textContent = pct + '%';
  document.getElementById('quick-ok').textContent = fmt(s.ok || 0);
  document.getElementById('quick-mis').textContent = fmt(s.mismatches || 0);
  document.getElementById('quick-exp').textContent = fmt(s.expired || 0);
  document.getElementById('quick-expg').textContent = fmt(s.expiring || 0);
  document.getElementById('quick-err').textContent = fmt(s.errors || 0);
  const meta = document.getElementById('quick-meta');
  meta.textContent = `Status: ${s.status || 'idle'}${s.finished_at ? ` · Finished: ${new Date(s.finished_at).toLocaleString()}` : ''}`;
}

function dedupeQuickHostsInput(raw) {
  const seen = new Set();
  const unique = [];
  const chunks = String(raw || '').split(/\s+/).map(v => v.trim()).filter(Boolean);
  for (const chunk of chunks) {
    let h = chunk.toLowerCase()
      .replace(/^[a-z]+:\/\//, '')
      .replace(/\/.*$/, '')
      .replace(/:\d+$/, '')
      .replace(/^\.+|\.+$/g, '');
    if (!h || seen.has(h)) continue;
    seen.add(h);
    unique.push(h);
  }
  return unique;
}

async function startQuickScan() {
  const hostInput = document.getElementById('quick-hosts');
  const hosts = hostInput.value.trim();
  if (!hosts) {
    toast('Paste at least one subdomain/hostname', 'err');
    return;
  }
  const dedupedHosts = dedupeQuickHostsInput(hosts);
  if (!dedupedHosts.length) {
    toast('Paste at least one valid subdomain/hostname', 'err');
    return;
  }
  hostInput.value = dedupedHosts.join('\n');
  const btn = document.getElementById('quick-scan-btn');
  btn.disabled = true;
  quickRows = [];
  quickRowsByHost = new Map();
  quickFilter = 'all';
  quickSortCol = 'hostname';
  quickSortDir = 1;
  document.querySelectorAll('#quick-filter-tabs .filter-tab').forEach((t, idx) => t.classList.toggle('active', idx === 0));
  updateQuickSortHeader();
  renderQuickRows();
  updateQuickProgress({ status: 'starting', total: 0, done: 0 });
  try {
    const { ok, data, error } = await fetch('/api/quick-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hosts: dedupedHosts.join('\n') })
    }).then(r => r.json());
    if (!ok) {
      btn.disabled = false;
      toast(error || 'Quick scan failed to start', 'err');
      return;
    }
    quickScanId = data.scan_id;
    updateQuickProgress({ status: 'running', total: data.total, done: 0, ok: 0, mismatches: 0, expired: 0, expiring: 0, errors: 0 });
    toast(`Quick scan started for ${fmt(data.total)} hosts`, 'ok');
  } catch {
    btn.disabled = false;
    toast('Quick scan failed to start', 'err');
  }
}


function focusQuickScan() {
  setTimeout(() => document.getElementById('quick-hosts')?.focus(), 120);
}
function insertQuickScanExample() {
  const el = document.getElementById('quick-hosts');
  if (!el) return;
  el.value = ['api.example.com', 'dev.example.com', 'https://staging.example.com/login'].join('\n');
  el.focus();
  toast('Example format inserted — replace with authorized hosts before scanning.', 'ok');
}
function clearQuickScanInput() {
  const el = document.getElementById('quick-hosts');
  if (!el) return;
  el.value = '';
  el.focus();
}

// ════════════════════════════════════════════════════════════
// PROJECTS
// ════════════════════════════════════════════════════════════
async function loadProjects() {
  try {
    const el = document.getElementById('projects-grid');
    if (el && !projectsCache.length) {
      el.innerHTML = Array.from({ length: 6 }, () => '<div class="project-card skeleton" aria-hidden="true"></div>').join('');
    }
    updateQuickSortHeader();
    if (quickScanId) {
      fetch(`/api/quick-scan/${quickScanId}`).then(r => r.json()).then(({ ok, data }) => {
        if (!ok || !data) return;
        updateQuickProgress(data);
        scheduleQuickRender();
        if (data.status !== 'running') document.getElementById('quick-scan-btn').disabled = false;
      }).catch(() => {});
    }
    const { data: projs } = await apiJSON('/api/projects');
    projectsCache = projs || [];
    if (projs?.length) hydrateTopProjectSelect(projs);
    if (!projs?.length) {
      el.innerHTML='<div class="empty" style="grid-column:1/-1"><div class="empty-icon">📁</div><div class="empty-title">No projects yet</div><p class="empty-desc">Create a project to start monitoring.</p></div>';
      return;
    }
    const projectMarkup = projs.map(p => {
      const s = p.latest_scan;
      const hasMis = s?.mismatches>0;
      const isRun = s?.status==='running';
      return `<div class="project-card ${hasMis?'has-issues':''} ${isRun?'running':''}" onclick="openProject('${p.id}')">
        <div class="proj-name">${esc(p.name)}</div>
        <div class="proj-meta">
          <span>📋 ${fmt(p.host_count)} hosts</span>
          <span>⏱ Every ${p.scan_interval_minutes}min</span>
          <span>🕐 ${s?rel(s.finished_at||s.started_at):'Never'}</span>
        </div>
        <div class="proj-badges">
          ${s?`
          <span class="badge badge-ok">✓ ${fmt(s.ok)}</span>
          ${s.mismatches>0?`<span class="badge badge-mismatch">✗ ${fmt(s.mismatches)}</span>`:''}
          ${s.expired>0?`<span class="badge badge-expired">! ${fmt(s.expired)}</span>`:''}
          ${s.expiring>0?`<span class="badge badge-expiring">⏳ ${fmt(s.expiring)}</span>`:''}
          ${isRun?`<span class="badge badge-running">RUNNING</span>`:''}
          `:`<span style="font-size:11px;color:var(--text-muted)">No scan data yet</span>`}
        </div>
        ${isRun&&s?`<div class="proj-progress" onclick="event.stopPropagation();openProject('${p.id}')">
          <div class="progress-wrap" style="margin-top:8px"><div class="progress-bar" style="width:${s.total>0?Math.round(s.done/s.total*100):0}%"></div></div>
        </div>`:''}
      </div>`;
    }).join('');
    requestAnimationFrame(() => { el.innerHTML = projectMarkup; });
  } catch { toast('Failed to load projects','err'); }
}

async function createProject() {
  const name = document.getElementById('cp-name').value.trim();
  const desc = document.getElementById('cp-desc').value.trim();
  const scan_interval = parseInt(document.getElementById('cp-scan-int').value)||60;
  const subfinder_interval = parseInt(document.getElementById('cp-sf-int').value)||30;
  if (!name) { toast('Name is required','err'); return; }
  try {
    const { data: p, ok, error } = await fetch('/api/projects',{
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name,description:desc,scan_interval,subfinder_interval})
    }).then(r=>r.json());
    if (!ok) { toast(error,'err'); return; }
    clearApiMemo();
    closeModal('createModal');
    document.getElementById('cp-name').value='';
    document.getElementById('cp-desc').value='';
    toast('Project created','ok');
    openProject(p.id);
  } catch { toast('Error creating project','err'); }
}

// ════════════════════════════════════════════════════════════
// PROJECT DETAIL
// ════════════════════════════════════════════════════════════
async function openProject(pid) {
  curPid = pid; nav('detail');
  try {
    const { data: p } = await fetch(`/api/projects/${pid}`).then(r=>r.json());
    document.getElementById('det-name').textContent = p.name;
    document.getElementById('det-meta').textContent =
      `${fmt(p.host_count)} hosts · scan every ${p.scan_interval_minutes}min · subfinder every ${p.subfinder_interval_minutes}min`;
    document.getElementById('host-count').textContent = fmt(p.host_count);
    loadHistory(pid);
    if (p.latest_scan?.status==='done') {
      curSid = p.latest_scan.id;
      showResults(p.latest_scan);
    }
    if (p.latest_scan?.status==='running') {
      curSid = p.latest_scan.id;
      activeScanStatus = 'running';
      syncScanActionButtons();
      document.getElementById('scan-prog-card').style.display='';
      startPoll();
    }
    if (['paused','stopping'].includes(p.latest_scan?.status)) {
      curSid = p.latest_scan.id;
      activeScanStatus = p.latest_scan.status;
      syncScanActionButtons();
      document.getElementById('scan-prog-card').style.display='';
      startPoll();
    }
  } catch {}
}

function renderOpenSSLRows(rows) {
  const body = document.getElementById('openssl-body');
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:16px;color:var(--text-muted)">No OpenSSL results found.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(r => `<tr>
    <td style="font-family:var(--mono);font-size:12px">${esc(r.hostname)}</td>
    <td><span class="badge ${r.status==='ok'?'badge-ok':r.status==='no_subject'?'badge-expiring':'badge-error'}">${esc(r.status || 'unknown')}</span></td>
    <td style="font-family:var(--mono);font-size:11px;max-width:700px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.subject || r.error || '—')}">${esc(r.subject || r.error || '—')}</td>
    <td style="font-size:11px;color:var(--text-muted)">${r.last_checked ? new Date(r.last_checked).toLocaleString() : '—'}</td>
  </tr>`).join('');
}

function queueOpenSSLRender() {
  if (opensslRenderTimer) return;
  opensslRenderTimer = requestAnimationFrame(() => {
    opensslRenderTimer = null;
    opensslRows.sort((a, b) => (a.hostname || '').localeCompare(b.hostname || ''));
    renderOpenSSLRows(opensslRows);
  });
}

async function initOpenSSLPage() {
  try {
    const projs = projectsCache.length ? projectsCache : ((await apiJSON('/api/projects')).data || []);
    const sel = document.getElementById('openssl-project-select');
    const curVal = sel.value;
    sel.innerHTML = '<option value="">— Choose a project —</option>' + projs.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
    if (curVal) sel.value = curVal;
    if (!sel.value && projs.length) {
      sel.value = projs[0].id;
    }
    await onOpenSSLProjectChange();
  } catch {
    toast('Failed to load OpenSSL projects', 'err');
  }
}

async function onOpenSSLProjectChange() {
  opensslPid = document.getElementById('openssl-project-select').value || null;
  await loadOpenSSLRows();
}

async function startOpenSSLContinuous() {
  if (!opensslPid) {
    toast('Please choose a project', 'err');
    return;
  }
  const btn = document.getElementById('openssl-start-btn');
  btn.disabled = true;
  try {
    const { ok, data, error } = await fetch(`/api/projects/${opensslPid}/openssl/start`, { method: 'POST' }).then(r => r.json());
    if (!ok) {
      toast(error || 'Failed to start OpenSSL continuous scan', 'err');
      return;
    }
    toast(data?.message || 'OpenSSL continuous scan started', 'ok');
    await loadOpenSSLRows();
  } catch {
    toast('Failed to start OpenSSL continuous scan', 'err');
  } finally {
    btn.disabled = false;
  }
}

async function loadOpenSSLRows() {
  const meta = document.getElementById('openssl-meta');
  if (!opensslPid) {
    opensslRows = [];
    meta.textContent = 'Choose a project to view OpenSSL results.';
    renderOpenSSLRows(opensslRows);
    return;
  }
  meta.textContent = 'Loading OpenSSL results...';
  try {
    const { ok, data, error } = await fetch(`/api/projects/${opensslPid}/openssl?limit=5000`).then(r => r.json());
    if (!ok) {
      meta.textContent = error || 'Failed to load OpenSSL results.';
      renderOpenSSLRows([]);
      return;
    }
    opensslRows = data?.rows || [];
    const worker = data?.worker || {};
    meta.textContent = `Rows: ${fmt(data?.rows_total || 0)} · Tracked hosts: ${fmt(data?.tracked_hosts || 0)} · Worker: ${worker.status || 'idle'}`;
    renderOpenSSLRows(opensslRows);
  } catch {
    meta.textContent = 'Failed to load OpenSSL results.';
  }
}

async function delProject() {
  if (!confirm('Delete this project and all its scan data?')) return;
  await fetch(`/api/projects/${curPid}`,{method:'DELETE'});
  clearApiMemo();
  toast('Project deleted','ok'); nav('projects');
}

function openEditModal() {
  fetch(`/api/projects/${curPid}`).then(r=>r.json()).then(({data:p}) => {
    document.getElementById('ep-id').value = p.id;
    document.getElementById('ep-name').value = p.name;
    document.getElementById('ep-desc').value = p.description||'';
    document.getElementById('ep-scan-int').value = p.scan_interval_minutes||60;
    document.getElementById('ep-sf-int').value = p.subfinder_interval_minutes||30;
    openModal('editModal');
  });
}

async function saveEdit() {
  const pid = document.getElementById('ep-id').value;
  const body = {
    name: document.getElementById('ep-name').value.trim(),
    description: document.getElementById('ep-desc').value.trim(),
    scan_interval_minutes: parseInt(document.getElementById('ep-scan-int').value)||60,
    subfinder_interval_minutes: parseInt(document.getElementById('ep-sf-int').value)||30,
  };
  const { ok, error } = await fetch(`/api/projects/${pid}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(r=>r.json());
  if (!ok) { toast(error,'err'); return; }
  clearApiMemo();
  closeModal('editModal');
  toast('Project updated','ok');
  openProject(pid);
}

// ════════════════════════════════════════════════════════════
// HOSTS
// ════════════════════════════════════════════════════════════
async function uploadFile(input) {
  const file = input.files[0]; if (!file) return;
  const fd = new FormData(); fd.append('file', file);
  const { data, ok, error } = await fetch(`/api/projects/${curPid}/hosts`,{method:'POST',body:fd}).then(r=>r.json());
  if (!ok) { toast(error,'err'); return; }
  clearApiMemo();
  toast(`${fmt(data.count)} hosts saved`,'ok');
  document.getElementById('host-count').textContent = fmt(data.count);
}

async function saveHosts() {
  const text = document.getElementById('paste-hosts').value.trim();
  if (!text) return;
  const { data, ok, error } = await fetch(`/api/projects/${curPid}/hosts`,{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hosts:text})
  }).then(r=>r.json());
  if (!ok) { toast(error,'err'); return; }
  clearApiMemo();
  toast(`${fmt(data.count)} hosts saved`,'ok');
  document.getElementById('host-count').textContent = fmt(data.count);
  document.getElementById('paste-hosts').value='';
}

const dz = document.getElementById('dz');
dz.addEventListener('dragover', e=>{e.preventDefault();dz.classList.add('over')});
dz.addEventListener('dragleave',()=>dz.classList.remove('over'));
dz.addEventListener('drop', e=>{
  e.preventDefault();dz.classList.remove('over');
  const f=e.dataTransfer.files[0];
  if(f){const i=document.getElementById('fi');try{const dt=new DataTransfer();dt.items.add(f);i.files=dt.files;}catch{}uploadFile(i);}
});

// ════════════════════════════════════════════════════════════
// SCAN
// ════════════════════════════════════════════════════════════
async function doScan() {
  const { ok, error } = await fetch(`/api/projects/${curPid}/scan`,{method:'POST'}).then(r=>r.json());
  if (!ok) { toast(error,'err'); return; }
  const { data: scans } = await fetch(`/api/projects/${curPid}/scans`).then(r=>r.json());
  const latest = (scans || []).find(s => ['running','paused','stopping'].includes(s.status));
  if (latest) curSid = latest.id;
  toast('Scan started!','ok');
  activeScanStatus = 'running';
  syncScanActionButtons();
  document.getElementById('scan-prog-card').style.display='';
  document.getElementById('results-card').style.display='none';
  startPoll();
}

function startPoll() {
  if (scanPollTimer) clearInterval(scanPollTimer);
  scanPollTimer = setInterval(async () => {
    try {
      const { data: scans } = await fetch(`/api/projects/${curPid}/scans`).then(r=>r.json());
      const run = (scans||[]).find(s=>['running','paused','stopping'].includes(s.status));
      const done = (scans||[]).find(s=>s.status==='done');
      const stopped = (scans||[]).find(s=>s.status==='stopped');
      const errored = (scans||[]).find(s=>s.status==='error');
      if (run) updateScanProgress(run);
      if (!run && done) {
        clearInterval(scanPollTimer);
        curSid = done.id;
        document.getElementById('scan-prog-card').style.display='none';
        showResults(done);
        loadHistory(curPid);
        pollBadge();
        toast(`Scan complete — ${fmt(done.mismatches)} mismatch(es)`, done.mismatches>0?'err':'ok');
      }
      if (!run && stopped) {
        clearInterval(scanPollTimer);
        document.getElementById('scan-prog-card').style.display='none';
        loadHistory(curPid);
        toast('Scan stopped', 'err');
      }
      if (!run && errored) {
        clearInterval(scanPollTimer);
        document.getElementById('scan-prog-card').style.display='none';
        loadHistory(curPid);
      }
    } catch {}
  }, 2500);
}

function updateScanProgress(s) {
  activeScanStatus = s.status || 'running';
  const pct = s.total>0?Math.round((s.done||s.live_progress||s.progress||0)/s.total*100):0;
  const done = s.done||s.live_progress||s.progress||0;
  document.getElementById('prog-bar').style.width = pct+'%';
  document.getElementById('prog-done').textContent = fmt(done);
  document.getElementById('prog-total').textContent = fmt(s.total);
  document.getElementById('prog-pct').textContent = pct+'%';
  const badge = document.getElementById('prog-badge');
  if (s.status === 'paused') {
    badge.className = 'badge badge-paused';
    badge.textContent = 'PAUSED';
  } else if (s.status === 'stopping') {
    badge.className = 'badge badge-stopped';
    badge.textContent = 'STOPPING';
  } else {
    badge.className = 'badge badge-running';
    badge.textContent = 'RUNNING';
  }
  syncScanActionButtons();
  document.getElementById('lv-ok').textContent = fmt(s.ok);
  document.getElementById('lv-mis').textContent = fmt(s.mismatches);
  document.getElementById('lv-exp').textContent = fmt(s.expired);
  document.getElementById('lv-expg').textContent = fmt(s.expiring);
  document.getElementById('lv-err').textContent = fmt(s.errors);
}

function syncScanActionButtons() {
  const pauseBtn = document.getElementById('scan-pause-btn');
  const stopBtn = document.getElementById('scan-stop-btn');
  if (!pauseBtn || !stopBtn) return;
  pauseBtn.disabled = activeScanStatus === 'stopping';
  stopBtn.disabled = activeScanStatus === 'stopping';
  pauseBtn.textContent = activeScanStatus === 'paused' ? '▶ Resume' : '⏸ Pause';
}

async function togglePauseScan() {
  if (!curSid) return;
  const route = activeScanStatus === 'paused' ? 'resume' : 'pause';
  const { ok, error, data } = await fetch(`/api/scans/${curSid}/${route}`, { method: 'POST' }).then(r => r.json());
  if (!ok) { toast(error || 'Unable to update scan state', 'err'); return; }
  activeScanStatus = data?.status || (route === 'pause' ? 'paused' : 'running');
  syncScanActionButtons();
  toast(activeScanStatus === 'paused' ? 'Scan paused' : 'Scan resumed', 'ok');
}

async function stopActiveScan() {
  if (!curSid) return;
  const { ok, error } = await fetch(`/api/scans/${curSid}/stop`, { method: 'POST' }).then(r => r.json());
  if (!ok) { toast(error || 'Unable to stop scan', 'err'); return; }
  activeScanStatus = 'stopping';
  syncScanActionButtons();
  toast('Stopping scan…', 'ok');
}

// ════════════════════════════════════════════════════════════
// RESULTS (paginated + sortable + searchable)
// ════════════════════════════════════════════════════════════
function showResults(scan) {
  document.getElementById('results-card').style.display='';
  document.getElementById('results-stats').innerHTML=`
    <div class="scan-stat"><div class="scan-stat-val" style="color:var(--accent)">${fmt(scan.total)}</div><div class="scan-stat-lbl">Total</div></div>
    <div class="scan-stat"><div class="scan-stat-val" style="color:var(--green)">${fmt(scan.ok)}</div><div class="scan-stat-lbl">Valid</div></div>
    <div class="scan-stat"><div class="scan-stat-val" style="color:var(--red)">${fmt(scan.mismatches)}</div><div class="scan-stat-lbl">Mismatch</div></div>
    <div class="scan-stat"><div class="scan-stat-val" style="color:var(--orange)">${fmt(scan.expired)}</div><div class="scan-stat-lbl">Expired</div></div>
    <div class="scan-stat"><div class="scan-stat-val" style="color:var(--amber)">${fmt(scan.expiring)}</div><div class="scan-stat-lbl">Expiring</div></div>
    <div class="scan-stat"><div class="scan-stat-val" style="color:var(--text-muted)">${fmt(scan.errors)}</div><div class="scan-stat-lbl">Errors</div></div>`;
  loadResults('all', document.querySelector('#result-tabs .filter-tab'));
}

async function loadResults(filter, tabEl, page) {
  curFilter=filter; curPage=page||1;
  document.querySelectorAll('#result-tabs .filter-tab').forEach(t=>t.classList.remove('active'));
  if (tabEl) tabEl.classList.add('active');
  if (!curSid) return;
  try {
    const resp = await fetch(`/api/scans/${curSid}/results?filter=${filter}&page=${curPage}&per_page=500`).then(r=>r.json());
    const d = resp.data||{};
    allResRows = d.results||[];
    totalPages = d.pages||1;
    document.getElementById('res-count').textContent = `${fmt(d.total)} results`;
    applyResTableView();
    renderResPagination(d);
  } catch {}
}

function sortTable(col) {
  if (sortCol===col) sortDir*=-1; else { sortCol=col; sortDir=1; }
  const headers = document.querySelectorAll('#results-card thead th');
  headers.forEach(th => {
    th.classList.remove('sorted');
    const si = th.querySelector('.sort-icon');
    if (si) si.textContent='↕';
  });
  const colMap = ['hostname','status','cn','expiry','days_left','tls_version','key_bits','issuer'];
  const idx = colMap.indexOf(col);
  if (idx>=0 && headers[idx]) {
    headers[idx].classList.add('sorted');
    const si = headers[idx].querySelector('.sort-icon');
    if (si) si.textContent = sortDir>0?'↑':'↓';
  }
  applyResTableView();
}

function filterResTable() {
  applyResTableView();
}

function applyResTableView() {
  const q = document.getElementById('res-search').value.toLowerCase();
  const filtered = q ? allResRows.filter(r => (r.hostname || '').toLowerCase().includes(q)) : allResRows;
  const sorted = [...filtered].sort((a, b) => {
    const av = sortValue(a, sortCol);
    const bv = sortValue(b, sortCol);
    if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * sortDir;
    return String(av).localeCompare(String(bv)) * sortDir;
  });
  renderResTable(sorted);
}

function sortValue(row, col) {
  if (!col) return row.hostname || '';
  if (col === 'status') return rowStatus(row);
  return row[col] ?? '';
}

function renderResTable(rows) {
  const body = document.getElementById('res-body');
  if (!rows.length) {
    body.innerHTML='<tr><td colspan="8" style="text-align:center;padding:32px;color:var(--text-muted)">No entries for this filter.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(r => {
    let sans=[];
    try{sans=typeof r.sans==='string'?JSON.parse(r.sans):r.sans||[];}catch{}
    const sansStr=sans.slice(0,2).join(', ')+(sans.length>2?` +${sans.length-2}`:'');
    return `<tr class="${r.is_mismatch?'row-mismatch':''}">
      <td><div style="font-weight:500;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.hostname)}">${esc(r.hostname)}</div>
          ${sansStr?`<div style="font-size:11px;color:var(--text-muted);margin-top:2px">${esc(sansStr)}</div>`:''}</td>
      <td>${sbadge(r)}</td>
      <td style="font-size:12px;color:var(--text-secondary);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.cn||r.error||'—')}</td>
      <td style="font-size:12px">${r.expiry||'—'}</td>
      <td style="font-weight:600;color:${daysColor(r.days_left)};font-variant-numeric:tabular-nums">${r.days_left??'—'}</td>
      <td><span class="badge badge-done" title="${esc(r.cipher_suite || '—')}">${esc(r.tls_version || '—')}</span></td>
      <td style="font-size:11px;color:var(--text-secondary)" title="SANs: ${esc(String(r.san_count ?? '—'))} · SHA256: ${esc(r.fingerprint_sha256 || '—')}">${esc([r.key_algorithm, r.key_bits].filter(Boolean).join(' ') || '—')}</td>
      <td style="font-size:11px;color:var(--text-muted);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.issuer||'—')}</td>
    </tr>`;
  }).join('');
}

function renderResPagination(d) {
  const el = document.getElementById('res-pagination');
  if (d.pages<=1) { el.style.display='none'; return; }
  el.style.display='flex';
  document.getElementById('pag-info').textContent=`Page ${d.page} of ${d.pages} (${fmt(d.total)} total)`;
  document.getElementById('pag-prev').disabled = d.page<=1;
  document.getElementById('pag-next').disabled = d.page>=d.pages;
}

function changePage(dir) {
  const np = curPage+dir;
  if (np<1||np>totalPages) return;
  loadResults(curFilter, null, np);
}

async function exportResultsCsv() {
  if (!curSid) return;
  window.location.href = `/api/scans/${curSid}/results/export?filter=${encodeURIComponent(curFilter || 'all')}`;
}

async function loadScanCompare() {
  if (!curSid) return;
  const box = document.getElementById('scan-compare');
  box.style.display = '';
  box.innerHTML = '<span style="color:var(--text-muted)">Loading comparison…</span>';
  try {
    const { ok, data, error } = await apiJSON(`/api/scans/${curSid}/compare`);
    if (!ok) throw new Error(error || 'Compare failed');
    const s = data.summary || {};
    const prev = data.previous_scan;
    const chips = [
      ['Added hosts', s.added_hosts, 'var(--purple)'],
      ['Removed hosts', s.removed_hosts, 'var(--text-muted)'],
      ['Status changed', s.changed_status, 'var(--amber)'],
      ['Renewed certs', s.renewed_certificates, 'var(--green)'],
    ];
    const changed = (data.changed_status || []).slice(0, 5).map(r =>
      `<div style="font-size:12px;color:var(--text-secondary);margin-top:4px"><b>${esc(r.hostname)}</b>: ${esc(r.from)} → ${esc(r.to)}</div>`
    ).join('');
    box.innerHTML = `
      <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start;flex-wrap:wrap">
        <div>
          <div style="font-weight:700;margin-bottom:4px">Scan Drift Intelligence</div>
          <div style="font-size:12px;color:var(--text-muted)">${prev ? `Compared with ${new Date(prev.created_at).toLocaleString()}` : 'No previous scan found for this project.'}</div>
        </div>
        <button class="btn btn-sm" onclick="document.getElementById('scan-compare').style.display='none'">Close</button>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:10px">${chips.map(([label,val,color]) => `<span class="badge" style="background:var(--bg-surface);color:${color};border:1px solid var(--border)">${label}: ${fmt(val || 0)}</span>`).join('')}</div>
      ${changed ? `<div style="margin-top:8px">${changed}</div>` : ''}
    `;
  } catch (e) {
    box.innerHTML = `<span style="color:var(--red)">${esc(e.message || 'Unable to compare scans')}</span>`;
  }
}

async function loadHistory(pid) {
  try {
    const { data: scans } = await fetch(`/api/projects/${pid}/scans`).then(r=>r.json());
    const el = document.getElementById('scan-history');
    if (!scans?.length) {
      el.innerHTML='<div class="empty"><div class="empty-icon">🕐</div><div class="empty-title">No scans yet</div></div>';
      return;
    }
    el.innerHTML=`<div class="table-wrap"><table><thead><tr><th>Date</th><th>Status</th><th>Total</th><th>Mismatches</th><th>Expired</th><th>Trigger</th><th></th></tr></thead><tbody>`+
      scans.map(s=>`<tr>
        <td style="font-size:12px;color:var(--text-secondary)">${s.finished_at?new Date(s.finished_at).toLocaleString():rel(s.started_at)}</td>
        <td><span class="badge ${s.status==='done'?'badge-done':s.status==='running'?'badge-running':s.status==='paused'?'badge-paused':s.status==='stopped'?'badge-stopped':'badge-error'}">${s.status}</span></td>
        <td>${fmt(s.total)}</td>
        <td style="color:${s.mismatches>0?'var(--red)':'var(--text-primary)'}">${fmt(s.mismatches)}</td>
        <td style="color:${s.expired>0?'var(--orange)':'var(--text-primary)'}">${fmt(s.expired)}</td>
        <td style="font-size:11px;color:var(--text-muted)">${s.triggered_by}</td>
        <td><button class="btn btn-sm" onclick="viewScan('${s.id}',${JSON.stringify(s).replace(/"/g,'&quot;')})">View</button></td>
      </tr>`).join('')+`</tbody></table></div>`;
  } catch {}
}

function viewScan(sid, scan) {
  curSid=sid; showResults(scan);
  document.getElementById('results-card').scrollIntoView({behavior:'smooth'});
}


// ════════════════════════════════════════════════════════════
// ASSETS
// ════════════════════════════════════════════════════════════
let assetsTimer = null;
async function initAssetsPage() {
  await ensureAssetsProjectFilter();
  await loadAssets();
}
async function ensureAssetsProjectFilter() {
  const el = document.getElementById('assets-project-filter');
  if (!el) return;
  const prev = el.value || '';
  const projs = projectsCache.length ? projectsCache : (await apiJSON('/api/projects')).data || [];
  projectsCache = projs || [];
  el.innerHTML = '<option value="">All projects</option>' + (projs || []).map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  if (prev && (projs || []).some(p => p.id === prev)) el.value = prev;
}
function debounceAssets() {
  clearTimeout(assetsTimer);
  assetsTimer = setTimeout(() => loadAssets(), 250);
}
async function loadAssets() {
  await ensureAssetsProjectFilter();
  const pid = encodeURIComponent(document.getElementById('assets-project-filter')?.value || '');
  const q = encodeURIComponent((document.getElementById('assets-search')?.value || '').trim());
  const { ok, data, error } = await apiJSON(`/api/assets?project_id=${pid}&search=${q}&per_page=250`);
  const body = document.getElementById('assets-body');
  if (!ok) { body.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:16px;color:var(--red)">${esc(error || 'Failed to load assets')}</td></tr>`; return; }
  const rows = data?.assets || [];
  document.getElementById('assets-count').textContent = `${fmt(data?.total || rows.length)} assets`;
  body.innerHTML = rows.length ? rows.map(a => `
    <tr onclick="showAssetRelationships('${esc(a.id)}')" style="cursor:pointer">
      <td><b>${esc(a.value)}</b><div style="font-size:11px;color:var(--text-muted)">${esc(a.source || '')}</div></td>
      <td><span class="badge">${esc(a.asset_type)}</span></td>
      <td>${esc(a.exposure || 'unknown')}</td>
      <td>${a.findings_count ? `<b>${fmt(a.findings_count)}</b> · ${esc(a.latest_severity || '')} ${esc(a.latest_finding || '')}` : '<span style="color:var(--text-muted)">No findings</span>'}</td>
      <td>${esc(a.project_name || a.project_id || '')}</td>
      <td>${a.last_seen ? new Date(a.last_seen).toLocaleString() : '—'}</td>
    </tr>`).join('') : '<tr><td colspan="6" style="text-align:center;padding:16px;color:var(--text-muted)">No assets found. Run scans or discovery to populate inventory.</td></tr>';
}
async function showAssetRelationships(id) {
  const { ok, data } = await apiJSON(`/api/assets/${encodeURIComponent(id)}/relationships`);
  if (!ok) return;
  const rels = data?.relationships || [];
  toast(rels.length ? `${fmt(rels.length)} relationship(s): ${rels.slice(0,3).map(r => r.relationship_type).join(', ')}` : 'No relationships recorded yet', 'ok');
}

// ════════════════════════════════════════════════════════════
// ALERTS
// ════════════════════════════════════════════════════════════
async function loadAlerts(page) {
  try {
    alertsCurPage = page || alertsCurPage || 1;
    await ensureAlertsProjectFilter();
    const q = encodeURIComponent((document.getElementById('alerts-search').value || '').trim());
    const mismatch = encodeURIComponent(document.getElementById('alerts-filter').value || 'all');
    const projectId = encodeURIComponent(document.getElementById('alerts-project-filter').value || '');
    const perPage = 200;
    const { data } = await fetch(`/api/alerts?search=${q}&mismatch_scope=${mismatch}&project_id=${projectId}&page=${alertsCurPage}&per_page=${perPage}`).then(r=>r.json());
    allAlerts = data?.alerts || [];
    alertsTotalPages = data?.pages || 1;
    renderAlerts(data || {});
  } catch {}
}

async function ensureAlertsProjectFilter() {
  const el = document.getElementById('alerts-project-filter');
  if (!el) return;
  const prev = el.value || '';
  const projs = projectsCache.length ? projectsCache : (await apiJSON('/api/projects')).data || [];
  projectsCache = projs || [];
  el.innerHTML = '<option value="">All projects</option>' +
    (projs || []).map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  if (prev && (projs || []).some(p => p.id === prev)) el.value = prev;
}

function renderAlerts(d) {
  const el = document.getElementById('alerts-body');
  if (!allAlerts.length) {
    el.innerHTML='<div class="empty"><div class="empty-icon">🔔</div><div class="empty-title">No alerts for current filters</div></div>';
  } else {
    const cls=t=>t.includes('Mismatch')?'mismatch':t.includes('Expir')?'expiring':'expired';
    el.innerHTML=allAlerts.map(a=>`
      <div class="alert-item ${a.seen?'':'unread'}" onclick="markOneSeen('${a.id}',this)">
        <div class="alert-dot" style="color:${a.seen?'var(--text-muted)':'var(--red)'}">●</div>
        <div style="flex:1;min-width:0">
          <div class="alert-host">${esc(a.hostname)}</div>
          <div class="alert-desc ${cls(a.issue_type)}">${esc(a.issue_type)} — ${esc(a.details)}</div>
          <div class="alert-meta">Project: ${esc(a.project_name)}</div>
        </div>
        <div class="alert-time">${new Date(a.created_at).toLocaleString()}</div>
      </div>`).join('');
  }
  renderAlertsPagination(d);
}

function renderAlertsPagination(d) {
  const el = document.getElementById('alerts-pagination');
  if ((d.pages || 1) <= 1) { el.style.display='none'; return; }
  el.style.display='flex';
  document.getElementById('alerts-pag-info').textContent = `Page ${d.page || 1} of ${d.pages || 1} (${fmt(d.total || 0)} total)`;
  document.getElementById('alerts-pag-prev').disabled = (d.page || 1) <= 1;
  document.getElementById('alerts-pag-next').disabled = (d.page || 1) >= (d.pages || 1);
}

function changeAlertsPage(dir) {
  const np = alertsCurPage + dir;
  if (np < 1 || np > alertsTotalPages) return;
  loadAlerts(np);
}

async function markOneSeen(id, row) {
  await fetch(`/api/alerts/${id}/read`,{method:'POST'});
  row.classList.remove('unread');
  row.querySelector('.alert-dot').style.color='var(--text-muted)';
  pollBadge();
}

async function markAllSeen() {
  await fetch('/api/alerts/seen',{method:'POST'});
  // SSE will fire and update badge immediately
  toast('All alerts marked as read','ok');
  loadAlerts();
}

async function clearAlerts() {
  if (!confirm('Clear all alerts?')) return;
  await fetch('/api/alerts/clear',{method:'POST'});
  // SSE fires alert_update with count=0 → badge resets immediately
  toast('Alerts cleared','ok');
  loadAlerts();
}

// ════════════════════════════════════════════════════════════
// SUBFINDER
// ════════════════════════════════════════════════════════════
async function initSfPage() {
  const sel = document.getElementById('sf-project-select');
  const projs = projectsCache.length ? projectsCache : (await apiJSON('/api/projects')).data || [];
  sel.innerHTML='<option value="">— Choose a project —</option>'+
    (projs||[]).map(p=>`<option value="${p.id}">${esc(p.name)}</option>`).join('');

  // Check binary
  try {
    const { data: st } = await fetch(`/api/projects/${projs?.[0]?.id||'x'}/subfinder/status`).then(r=>r.json());
    document.getElementById('sf-binary-warn').style.display = st?.binary_available?'none':'';
  } catch {}
}

async function loadSfProject() {
  const pid = document.getElementById('sf-project-select').value;
  sfCurPid = pid;
  if (!pid) { document.getElementById('sf-project-panel').style.display='none'; return; }
  document.getElementById('sf-project-panel').style.display='';
  sfCurPage=1; sfTotalPages=1;
  refreshSfPanel();
}

async function refreshSfPanel() {
  if (!sfCurPid) return;
  try {
    const [{ data: st }, { data: hostsData }, { data: rawRuns }, { data: proj }] = await Promise.all([
      apiJSON(`/api/projects/${sfCurPid}/subfinder/status`),
      apiJSON(`/api/projects/${sfCurPid}/subfinder/hosts?page=${sfCurPage}&per_page=250`),
      apiJSON(`/api/projects/${sfCurPid}/subfinder/raw-results?limit=20&preview_chars=3500`),
      apiJSON(`/api/projects/${sfCurPid}`),
    ]);

    // State
    const state = st?.state||{};
    const statusText = {running:'🔄 Running…',ssl_scanning:'🔒 SSL scanning new hosts…',done:'✅ Idle',error:'❌ Last run failed','':'🕐 Idle'}[state.status||'']||'—';
    document.getElementById('sf-status-bar').textContent = `Status: ${statusText}`;

    // Toggle
    const toggle = document.getElementById('sf-toggle');
    toggle.className = 'toggle-switch'+(proj?.subfinder_enabled?' on':'');
    document.getElementById('sf-toggle-label').onclick = () => toggleSf(sfCurPid);

    // Jobs
    const jobs = st?.jobs||[];
    document.getElementById('sf-jobs').innerHTML = jobs.length?
      `<div class="table-wrap"><table><thead><tr><th>Started</th><th>Status</th><th>New Hosts</th><th>Total Found</th></tr></thead><tbody>`+
      jobs.map(j=>`<tr>
        <td style="font-size:12px">${new Date(j.started_at).toLocaleString()}</td>
        <td><span class="badge ${j.status==='done'?'badge-done':j.status==='running'?'badge-running':'badge-error'}">${j.status}</span></td>
        <td style="color:var(--green);font-weight:600">${fmt(j.new_count)}</td>
        <td>${fmt(j.total_found)}</td></tr>`).join('')+'</tbody></table></div>':
      '<div class="empty"><div class="empty-icon">🕐</div><div class="empty-title">No jobs yet</div></div>';

    // Raw results table
    document.getElementById('sf-raw-body').innerHTML = (rawRuns||[]).length ? (rawRuns||[]).map(rr => {
      const rawList = (rr.raw_lines||[]).join('\n') || (rr.stderr_preview || rr.stderr_text || '—');
      return `<tr>
        <td style="font-family:var(--mono);font-size:12px">${esc(rr.root_domain)}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${new Date(rr.started_at).toLocaleString()}</td>
        <td style="font-weight:600">${fmt(rr.total_found||0)}</td>
        <td><span class="badge ${rr.status==='done'?'badge-done':rr.status==='running'?'badge-running':'badge-error'}">${esc(rr.status||'unknown')}</span></td>
        <td style="max-width:520px">
          <pre style="white-space:pre-wrap;overflow:auto;max-height:140px;font-size:11px;background:var(--bg-raised);padding:8px;border:1px solid var(--border);border-radius:8px">${esc(rawList)}</pre>
        </td>
      </tr>`;
    }).join('') : '<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--text-muted)">No raw subfinder runs yet.</td></tr>';

    // Stats
    document.getElementById('sf-total').textContent = fmt(hostsData?.total||0);
    const lastJob = jobs.find(j=>j.status==='done');
    document.getElementById('sf-new').textContent = lastJob ? fmt(lastJob.new_count) : '—';

    // Hosts table
    const hosts = hostsData?.hosts||[];
    sfTotalPages = hostsData?.pages||1;
    document.getElementById('sf-hosts-count').textContent = `${fmt(hostsData?.total||0)} hosts`;
    document.getElementById('sf-hosts-body').innerHTML = hosts.map(h=>`<tr>
      <td style="font-weight:500;font-family:var(--mono);font-size:12px">${esc(h.hostname)}</td>
      <td style="font-size:12px;color:var(--text-secondary)">${new Date(h.first_seen).toLocaleDateString()}</td>
      <td style="font-size:12px;color:var(--text-secondary)">${new Date(h.last_seen).toLocaleDateString()}</td>
      <td>${h.ssl_scanned?'<span class="badge badge-ok">✓ Yes</span>':'<span class="badge badge-error">Pending</span>'}</td>
    </tr>`).join('');

    // SF pagination
    const sfPag = document.getElementById('sf-pagination');
    if (hostsData?.pages>1) {
      sfPag.style.display='flex';
      document.getElementById('sf-pag-info').textContent=`Page ${sfCurPage} of ${hostsData.pages}`;
      document.getElementById('sf-pag-prev').disabled = sfCurPage<=1;
      document.getElementById('sf-pag-next').disabled = sfCurPage>=hostsData.pages;
    } else sfPag.style.display='none';

  } catch {}
}

async function runSfNow() {
  if (!sfCurPid) { toast('Please select a project before running scan','err'); return; }
  const { ok, data, error } = await fetch(`/api/projects/${sfCurPid}/subfinder/run`,{method:'POST'}).then(r=>r.json());
  if (!ok) { toast(error,'err'); return; }
  toast(data?.binary_found ? 'Subfinder started' : 'Subfinder started (binary not found — check install)','ok');
  setTimeout(refreshSfPanel, 2000);
}

async function toggleSf(pid) {
  const { ok, data } = await fetch(`/api/projects/${pid}/subfinder/toggle`,{method:'PUT'}).then(r=>r.json());
  if (!ok) return;
  const toggle = document.getElementById('sf-toggle');
  toggle.className = 'toggle-switch'+(data?.subfinder_enabled?' on':'');
  toast(`Subfinder auto-run ${data?.subfinder_enabled?'enabled':'disabled'}`,'ok');
}

function changeSfPage(dir) {
  const np = sfCurPage+dir;
  if (np<1||np>sfTotalPages) return;
  sfCurPage=np; refreshSfPanel();
}

// ════════════════════════════════════════════════════════════
// NEW DISCOVERIES
// ════════════════════════════════════════════════════════════
async function initDiscoveriesPage() {
  const sel = document.getElementById('nd-project-select');
  const projs = projectsCache.length ? projectsCache : (await apiJSON('/api/projects')).data || [];
  const prev = sel.value;
  sel.innerHTML = '<option value="">— Choose a project —</option>' +
    (projs || []).map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  if (prev) sel.value = prev;
  if (!sel.value && projs?.length) sel.value = projs[0].id;
  loadDiscoveries();
}


let enumCurrentRows = [];
let enumCurrentScan = null;

function updateEnumStats(rows, scan) {
  const uniqueSources = new Set((rows||[]).flatMap(r => String(r.source || 'mixed').split(',').map(s => s.trim()).filter(Boolean))).size;
  document.getElementById('enum-stat-total').textContent = fmt((rows||[]).length);
  document.getElementById('enum-stat-sources').textContent = fmt(uniqueSources);
  document.getElementById('enum-stat-domain').textContent = scan?.domain || '—';
}

async function updateEnumActiveHostCount(rows) {
  const el = document.getElementById('enum-stat-active');
  if (!rows?.length) { el.textContent = '0'; return; }
  el.textContent = '…';
  try {
    const url = `/api/subfinder/enumeration/scans/${enumCurrentScan?.id}/export?format=csv`;
    const res = await fetch(url);
    const csv = await res.text();
    const lines = csv.split('\n').slice(1).filter(Boolean);
    let active = 0;
    for (const line of lines) {
      if ((line.toLowerCase().includes(',true,') || line.toLowerCase().endsWith(',true'))) active += 1;
    }
    el.textContent = fmt(active);
  } catch {
    el.textContent = '—';
  }
}

function renderEnumResults() {
  const body = document.getElementById('sf-enum-results-body');
  const q = (document.getElementById('sf-enum-search').value || '').trim().toLowerCase();
  const src = document.getElementById('sf-enum-source-filter').value;
  const rows = (enumCurrentRows || []).filter(r => {
    const host = (r.hostname || '').toLowerCase();
    const source = (r.source || 'mixed');
    return (!q || host.includes(q)) && (src === 'all' || String(source).split(',').map(s => s.trim()).includes(src));
  });
  document.getElementById('sf-enum-results-count').textContent = `${fmt(rows.length)} rows`;
  body.innerHTML = rows.length ? rows.map(r => `<tr><td style="font-family:var(--mono)">${esc(r.hostname)}</td><td>${esc(r.source||'mixed')}</td><td style="font-size:12px;color:var(--text-secondary)">${new Date(r.discovered_at).toLocaleString()}</td></tr>`).join('')
    : '<tr><td colspan="3" style="text-align:center;padding:16px;color:var(--text-muted)">No results match the current filters.</td></tr>';
}

async function initSfRawPage() {
  await loadSfRawPage();
}

async function loadSfRawPage() {
  const body = document.getElementById('sf-raw-page-body');
  const { data: scans } = await apiJSON('/api/subfinder/enumeration/scans');
  body.innerHTML = (scans||[]).length ? (scans||[]).map(rr => {
    return `<tr>
      <td style="font-family:var(--mono);font-size:12px">${esc(rr.domain)}</td>
      <td style="font-size:12px;color:var(--text-secondary)">${new Date(rr.started_at).toLocaleString()}</td>
      <td style="font-weight:600">${fmt(rr.total_found||0)}</td>
      <td><span class="badge ${rr.status==='done'?'badge-done':rr.status==='running'?'badge-running':'badge-error'}">${esc(rr.status||'unknown')}</span></td>
      <td class="enum-actions-cell">
        <button class="btn btn-sm" onclick="openEnumScan('${rr.id}')">Open</button>
        <button class="btn btn-sm" onclick="exportEnumScan('${rr.id}','txt')">Export Text</button>
        <button class="btn btn-sm" onclick="exportEnumScan('${rr.id}','csv')">Export CSV</button>
        <button class="btn btn-sm" style="border-color:#ef4444;color:#ef4444" onclick="deleteEnumScan('${rr.id}')">Delete</button>
      </td>
    </tr>`;
  }).join('') : '<tr><td colspan="5" style="text-align:center;padding:18px;color:var(--text-muted)">No enumeration scans yet.</td></tr>';
}

async function exportEnumScan(scanId, format) {
  if (format === 'both') {
    window.open(`/api/subfinder/enumeration/scans/${scanId}/export?format=txt`, '_blank');
    setTimeout(() => window.open(`/api/subfinder/enumeration/scans/${scanId}/export?format=csv`, '_blank'), 250);
    return;
  }
  window.open(`/api/subfinder/enumeration/scans/${scanId}/export?format=${encodeURIComponent(format)}`, '_blank');
}

async function deleteEnumScan(scanId) {
  if (!confirm('Delete this scan and all its results?')) return;
  const { ok, error } = await apiJSON(`/api/subfinder/enumeration/scans/${scanId}`, { method:'DELETE' });
  if (!ok) return toast(error || 'Delete failed', 'err');
  toast('Enumeration scan deleted', 'ok');
  document.getElementById('sf-enum-results-body').innerHTML = '<tr><td colspan="3" style="text-align:center;padding:16px;color:var(--text-muted)">Select a scan to view results.</td></tr>';
  await loadSfRawPage();
}

async function runDomainEnumeration() {
  const domain = (document.getElementById('enum-domain-input').value||'').trim();
  if (!domain) return toast('Enter a domain', 'err');
  toast('Enumeration scan started', 'ok');
  const depthMode = document.getElementById('enum-depth-mode').value;
  const { ok, error } = await apiJSON('/api/subfinder/enumeration/run', { method:'POST', body: JSON.stringify({ domain, depth_mode: depthMode }) });
  if (!ok) return toast(error || 'Enumeration failed', 'err');
  toast('Enumeration finished', 'ok');
  await loadSfRawPage();
}

async function openEnumScan(scanId) {
  const { data } = await apiJSON(`/api/subfinder/enumeration/scans/${scanId}`);
  enumCurrentScan = data?.scan || null;
  enumCurrentRows = data?.results || [];
  const sources = [...new Set(enumCurrentRows.flatMap(r => String(r.source || 'mixed').split(',').map(s => s.trim()).filter(Boolean)))].sort();
  const filter = document.getElementById('sf-enum-source-filter');
  filter.innerHTML = '<option value="all">All sources</option>' + sources.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('');
  document.getElementById('sf-enum-search').value = '';
  updateEnumStats(enumCurrentRows, enumCurrentScan);
  renderEnumResults();
  updateEnumActiveHostCount(enumCurrentRows);
  const createBtn = document.getElementById('enum-create-project-btn');
  if (createBtn) createBtn.disabled = !enumCurrentScan || !enumCurrentRows.length;
}

async function createProjectFromEnumScan() {
  if (!enumCurrentScan?.id) return toast('Open an enumeration scan first', 'err');
  if (!(enumCurrentRows || []).length) return toast('Selected scan has no hosts', 'err');
  const defaultName = `Enum ${enumCurrentScan.domain || 'Project'}`;
  const name = prompt('Project name for this enumeration scan:', defaultName);
  if (name == null) return;
  const trimmed = (name || '').trim();
  if (!trimmed) return toast('Project name is required', 'err');
  const { ok, data, error } = await apiJSON(`/api/subfinder/enumeration/scans/${enumCurrentScan.id}/project`, {
    method: 'POST',
    body: JSON.stringify({ name: trimmed }),
  });
  if (!ok) return toast(error || 'Failed to create project', 'err');
  toast(`Project created with ${fmt(data?.host_count || 0)} hosts`, 'ok');
  await loadProjects();
  if (data?.project?.id) {
    await openProject(data.project.id);
    const scanRes = await apiJSON(`/api/projects/${data.project.id}/scan`, { method: 'POST' });
    if (scanRes?.ok) {
      toast('Initial SSL scan started', 'ok');
    } else {
      toast(scanRes?.error || 'Project created, but failed to start scan', 'err');
    }
  }
}

async function hydrateTopProjectSelect(projectsOverride = null) {
  const sel = document.getElementById('topProjectSelect');
  if (!sel) return;
  try {
    const projs = projectsOverride || (await apiJSON('/api/projects')).data || [];
    projectsCache = projs || [];
    const prev = sel.value;
    sel.innerHTML = '<option value="">All Projects</option>' +
      (projs || []).map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
    if (prev) sel.value = prev;
  } catch {}
}

document.getElementById('topProjectSelect')?.addEventListener('change', (e) => {
  if (e.target.value) openProject(e.target.value);
});

async function loadDiscoveries() {
  if (window.ndLoading) return;
  window.ndLoading = true;
  try {
    const pid = document.getElementById('nd-project-select').value;
    if (!pid) {
      document.getElementById('nd-body').innerHTML = '<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--text-muted)">Select a project to view new discoveries.</td></tr>';
      return;
    }
    const q = encodeURIComponent(document.getElementById('nd-search').value || '');
    const mode = encodeURIComponent(document.getElementById('nd-mode')?.value || 'latest');
    const { data } = await fetch(`/api/projects/${pid}/discoveries?search=${q}&page=1&per_page=200&mode=${mode}`).then(r => r.json());
    renderDiscoveriesRows(data, 'nd-count', 'nd-body');
  } finally {
    window.ndLoading = false;
  }
}

function renderDiscoveriesRows(data, countId, bodyId) {
  const rows = data?.rows || [];
  document.getElementById(countId).textContent = `${fmt(data?.total || 0)} rows`;
  if (!rows.length) {
    document.getElementById(bodyId).innerHTML = '<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--text-muted)">No discoveries found.</td></tr>';
    return;
  }
  document.getElementById(bodyId).innerHTML = rows.map(r => `<tr class="${r.is_mismatch ? 'row-mismatch' : ''}">
    <td style="font-family:var(--mono);font-size:12px;font-weight:500">${esc(r.hostname)}</td>
    <td style="font-size:12px;color:var(--text-secondary)">${new Date(r.first_seen).toLocaleString()}</td>
    <td style="font-size:12px">${r.http_status_code ?? '—'}</td>
    <td style="font-size:12px;color:var(--text-secondary)">${esc(r.http_redirect_location || r.http_final_url || '—')}</td>
    <td style="font-size:12px;color:var(--text-secondary)">${esc(r.http_page_title || '—')}</td>
    <td>${sbadge(r)}</td>
    <td style="font-size:12px;color:var(--text-secondary)">${esc(r.cn || r.error || '—')}</td>
    <td style="font-size:12px">${r.expiry || '—'}</td>
  </tr>`).join('');
}

async function initBountyLeadsPage() {
  const sel = document.getElementById('bounty-project-select');
  const projs = projectsCache.length ? projectsCache : (await apiJSON('/api/projects')).data || [];
  projectsCache = projs || [];
  const prev = sel.value;
  sel.innerHTML = '<option value="">All projects</option>' +
    (projs || []).map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  if (prev) sel.value = prev;
  await loadBountyLeads();
  await loadXbowBrief();
}


function renderXbowBrief(brief) {
  const exec = document.getElementById('xbow-exec-summary');
  if (exec) exec.textContent = brief.executive_summary || 'No ranked leads yet. Run Subfinder and HTTP enrichment first.';
  const path = document.getElementById('xbow-critical-path');
  if (path) {
    const rows = brief.critical_path || [];
    path.innerHTML = rows.length ? rows.slice(0, 5).map(r => `<div class="xbow-path"><div class="xbow-path-host">#${fmt(r.rank)} ${esc(r.hostname || '—')}</div><div class="xbow-path-meta">${fmt(r.score || 0)} pts · ${esc(r.severity || 'low')} · ${(r.why || []).slice(0,2).map(esc).join(' • ')}</div></div>`).join('') : '<div class="xbow-empty">No critical path yet. Run discovery and enrichment to seed the queue.</div>';
  }
  const hyp = document.getElementById('xbow-hypotheses');
  if (hyp) {
    const rows = brief.hypotheses || [];
    hyp.innerHTML = rows.length ? rows.slice(0, 3).map(h => `<div class="xbow-path"><div class="xbow-path-host">${esc(h.title || 'Validation playbook')}</div><ul class="xbow-list">${(h.tests || []).slice(0,3).map(t => `<li>${esc(t)}</li>`).join('')}</ul></div>`).join('') : '<div class="xbow-empty">No hypotheses yet.</div>';
  }
}

async function loadXbowBrief() {
  const pid = encodeURIComponent(document.getElementById('bounty-project-select')?.value || '');
  const q = encodeURIComponent(document.getElementById('bounty-search')?.value || '');
  const path = document.getElementById('xbow-critical-path');
  if (path) path.innerHTML = '<div class="xbow-empty">Building autonomous triage brief…</div>';
  const { ok, data, error } = await apiJSON(`/api/bounty/brief?project_id=${pid}&search=${q}&limit=25`);
  if (!ok) return toast(error || 'Unable to generate brief', 'err');
  renderXbowBrief(data || {});
}

function renderBountySummary(summary) {
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = fmt(val || 0); };
  set('bounty-stat-high', summary.high);
  set('bounty-stat-active', summary.active_http);
  set('bounty-stat-protected', summary.protected_http);
  set('bounty-stat-tls', summary.tls_anomalies);
  const exec = document.getElementById('bounty-exec-summary');
  if (exec) exec.textContent = summary.executive_summary || 'Scores are recon prioritization hints, not vulnerability claims.';
  const breakdown = document.getElementById('bounty-surface-breakdown');
  if (breakdown) {
    const chips = (summary.top_surface_types || []).map(s => `<span class="badge badge-info">${esc(s.name)} · ${fmt(s.count)}</span>`);
    breakdown.innerHTML = chips.length ? chips.join('') : '<span style="color:var(--text-muted)">Run Subfinder/HTTP enrichment to build an attack-surface breakdown.</span>';
  }
}

function bountySeverityBadge(severity) {
  const sev = String(severity || 'low').toLowerCase();
  const cls = sev === 'high' ? 'badge-mismatch' : sev === 'medium' ? 'badge-expiring' : 'badge-ok';
  return `<span class="badge ${cls}">${esc(sev)}</span>`;
}

async function loadBountyLeads() {
  const body = document.getElementById('bounty-body');
  const count = document.getElementById('bounty-count');
  if (!body) return;
  body.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--text-muted)">Ranking bounty leads...</td></tr>';
  const pid = encodeURIComponent(document.getElementById('bounty-project-select')?.value || '');
  const q = encodeURIComponent(document.getElementById('bounty-search')?.value || '');
  const [summaryResp, leadsResp] = await Promise.all([
    apiJSON(`/api/bounty/summary?project_id=${pid}&search=${q}`),
    apiJSON(`/api/bounty/leads?project_id=${pid}&search=${q}&limit=100`)
  ]);
  renderBountySummary(summaryResp?.data || {});
  const { ok, data, error } = leadsResp;
  if (!ok) {
    body.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--red)">${esc(error || 'Unable to load bounty leads')}</td></tr>`;
    return;
  }
  const rows = data?.rows || [];
  count.textContent = `${fmt(data?.total || 0)} leads`;
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--text-muted)">No leads yet. Run Subfinder and HTTP enrichment to populate prioritized bounty targets.</td></tr>';
    return;
  }
  body.innerHTML = rows.map(r => {
    const url = r.http_final_url || (r.http_scheme ? `${r.http_scheme}://${r.hostname}` : `https://${r.hostname}`);
    const evidence = (r.evidence || []).map(e => `<li>${esc(e)}</li>`).join('');
    const steps = (r.next_steps || []).slice(0, 3).map(e => `<li>${esc(e)}</li>`).join('');
    return `<tr>
      <td data-sort-value="${Number(r.score || 0)}"><div style="font-size:22px;font-weight:800">${fmt(r.score || 0)}</div>${bountySeverityBadge(r.severity)}</td>
      <td><div style="font-family:var(--mono);font-size:12px;font-weight:700">${esc(r.hostname)}</div><div style="font-size:12px;color:var(--text-secondary)">${esc(r.lead_type || 'Recon candidate')}</div></td>
      <td>${esc(r.project_name || '—')}</td>
      <td><div>${r.http_status_code ?? '—'}</div><a href="${esc(url)}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent)">${esc((r.http_page_title || r.http_final_url || 'open target').slice(0, 80))}</a></td>
      <td><ul style="margin-left:16px;color:var(--text-secondary);font-size:12px">${evidence}</ul></td>
      <td><ul style="margin-left:16px;color:var(--text-secondary);font-size:12px">${steps}</ul></td>
    </tr>`;
  }).join('');
}

function exportBountyLeads() {
  const pid = encodeURIComponent(document.getElementById('bounty-project-select')?.value || '');
  const q = encodeURIComponent(document.getElementById('bounty-search')?.value || '');
  window.location.href = `/api/bounty/leads/export?project_id=${pid}&search=${q}&limit=500`;
}

// Poll live sections with visibility-aware scheduling to keep UI responsive.
let liveRefreshTimer = null;
const LIVE_REFRESH_MS = 12000;

function scheduleLiveRefresh() {
  clearTimeout(liveRefreshTimer);
  liveRefreshTimer = setTimeout(async () => {
    if (!document.hidden) {
      if (document.getElementById('page-subfinder').classList.contains('active') && sfCurPid) {
        await refreshSfPanel();
      }
      if (document.getElementById('page-discoveries').classList.contains('active')) {
        await loadDiscoveries();
      }
    }
    scheduleLiveRefresh();
  }, LIVE_REFRESH_MS);
}

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    scheduleLiveRefresh();
    connectSSE();
  }
});



let nucleiCurrentScanId = null;
let nucleiPollTimer = null;
let nucleiFindings = [];
const NUCLEI_SCAN_KEY = 'sentinel-nuclei-current-scan';

function isNucleiActiveStatus(status) {
  return ['queued','preparing','running','paused','stopping'].includes(status);
}

function rememberNucleiScan(scan) {
  if (!scan?.id) return;
  localStorage.setItem(NUCLEI_SCAN_KEY, JSON.stringify({ id: scan.id, project_id: scan.project_id || '', ts: Date.now() }));
}

function getRememberedNucleiScan() {
  try { return JSON.parse(localStorage.getItem(NUCLEI_SCAN_KEY) || '{}') || {}; }
  catch { return {}; }
}

function renderNucleiLogEntries(entries = []) {
  const logEl = document.getElementById('nuclei-log');
  if (!logEl) return;
  if (!entries.length) {
    logEl.innerHTML = '<div class="nuclei-log-empty">Waiting for nuclei output…</div>';
    return;
  }
  logEl.innerHTML = entries.map(nucleiLogEntryHTML).join('');
  logEl.scrollTop = logEl.scrollHeight;
}

function nucleiLogEntryHTML(entry) {
  const stream = (entry.stream || 'stdout').toLowerCase();
  const label = stream === 'heartbeat' ? 'heartbeat' : stream === 'status' ? 'status' : stream === 'stats' ? 'stats' : 'output';
  const ts = entry.ts ? new Date(entry.ts).toLocaleTimeString() : new Date().toLocaleTimeString();
  return `<div class="nuclei-log-row"><span class="nuclei-log-time">${esc(ts)}</span><span class="nuclei-log-stream ${esc(label)}">${esc(label)}</span><span class="nuclei-log-line">${esc(entry.line || '')}</span></div>`;
}

function appendNucleiLogEntry(entry) {
  const logEl = document.getElementById('nuclei-log');
  if (!logEl || !entry) return;
  if (logEl.querySelector('.nuclei-log-empty')) logEl.innerHTML = '';
  logEl.insertAdjacentHTML('beforeend', nucleiLogEntryHTML(entry));
  while (logEl.children.length > 650) logEl.firstElementChild?.remove();
  logEl.scrollTop = logEl.scrollHeight;
}

async function initNucleiPage() {
  const projs = projectsCache.length ? projectsCache : ((await apiJSON('/api/projects')).data || []);
  const sel = document.getElementById('nuclei-project-select');
  const cur = sel.value;
  sel.innerHTML = '<option value="">— Choose a project —</option>' + projs.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
  if (cur) sel.value = cur;
  if (!sel.value && projs.length) sel.value = projs[0].id;
  if (!sel.dataset.nucleiBound) {
    sel.addEventListener('change', () => hydrateNucleiScanForProject(sel.value));
    sel.dataset.nucleiBound = '1';
  }
  await hydrateNucleiScanForProject(sel.value);
}

async function hydrateNucleiScanForProject(pid) {
  if (!pid) return;
  const remembered = getRememberedNucleiScan();
  if (remembered.id && (!remembered.project_id || remembered.project_id === pid)) {
    try {
      const { ok, data } = await apiJSON(`/api/nuclei/scans/${remembered.id}`);
      if (ok && data?.project_id === pid) {
        updateNucleiLive(data);
        if (isNucleiActiveStatus(data.status)) scheduleNucleiPolling();
        return;
      }
    } catch {}
  }
  await loadRecentNucleiScans(pid);
}

async function loadRecentNucleiScans(pid) {
  const history = document.getElementById('nuclei-history');
  if (history) history.innerHTML = '';
  if (!pid) return;
  try {
    const { ok, data } = await apiJSON(`/api/nuclei/scans?project_id=${encodeURIComponent(pid)}&limit=5`);
    const rows = data?.rows || [];
    if (!ok || !rows.length) return;
    const active = rows.find(r => isNucleiActiveStatus(r.status));
    updateNucleiLive(active || rows[0]);
    renderNucleiHistory(rows);
    if (active) scheduleNucleiPolling();
  } catch {}
}

function renderNucleiHistory(rows = []) {
  const history = document.getElementById('nuclei-history');
  if (!history) return;
  history.innerHTML = rows.map(r => `<div class="nuclei-history-row">
    <div>
      <div style="font-weight:700;color:var(--text-primary)">${esc(r.status || 'unknown')} · ${fmt(r.findings_total || 0)} findings · ${fmt(r.hosts_scanned || r.total || 0)} targets</div>
      <div style="font-size:11px;color:var(--text-muted)">${esc(r.project_name || '')} · ${r.started_at ? new Date(r.started_at).toLocaleString() : 'unknown start'}</div>
    </div>
    <button class="btn btn-sm" onclick="loadNucleiScanById('${esc(r.id)}')">View log</button>
  </div>`).join('');
}

async function loadNucleiScanById(id) {
  const { ok, data, error } = await apiJSON(`/api/nuclei/scans/${encodeURIComponent(id)}`);
  if (!ok) return toast(error || 'Unable to load nuclei scan', 'err');
  updateNucleiLive(data);
  if (isNucleiActiveStatus(data.status)) scheduleNucleiPolling();
}

function nucleiStatValue(stats, key, fallback = '—') {
  const value = stats?.[key];
  return value === undefined || value === null || value === '' ? fallback : fmt(value);
}

function renderNucleiStatsTerminal(scan) {
  const grid = document.getElementById('nuclei-stats-grid');
  const line = document.getElementById('nuclei-stats-line');
  if (!grid || !line) return;
  const stats = scan?.stats || {};
  const findings = scan?.findings_total ?? nucleiFindings.length ?? 0;
  const percent = scan?.progress_percent ?? stats.percent ?? 0;
  const cells = [
    ['Templates', nucleiStatValue(stats, 'templates'), ''],
    ['Targets', nucleiStatValue(stats, 'hosts', scan?.total ?? scan?.hosts_scanned ?? '—'), ''],
    ['Requests', nucleiStatValue(stats, 'requests'), ''],
    ['RPS', nucleiStatValue(stats, 'rps'), 'good'],
    ['Matched', fmt(stats.matched ?? findings), findings ? 'warn' : 'good'],
    ['Errors', nucleiStatValue(stats, 'errors', 0), Number(stats.errors || 0) ? 'bad' : 'good'],
    ['Progress', `${Math.max(0, Math.min(100, Math.round(Number(percent) || 0)))}%`, 'good'],
    ['Elapsed', `${fmt(scan?.elapsed_seconds || Math.max(0, Math.round((Date.now() - Date.parse(scan?.started_at || new Date())) / 1000)))}s`, ''],
  ];
  grid.innerHTML = cells.map(([label, value, tone]) => `<div class="nuclei-stat-cell"><div class="nuclei-stat-label">${esc(label)}</div><div class="nuclei-stat-value ${tone}">${esc(String(value))}</div></div>`).join('');
  const status = scan?.status || 'queued';
  const statsLine = stats.last_line || `nuclei -stats active · status=${status} · targets=${fmt(scan?.total || scan?.hosts_scanned || 0)} · findings=${fmt(findings)}`;
  line.textContent = statsLine;
}

function scheduleNucleiRowsRender() {
  if (nucleiRowsRenderTimer) return;
  nucleiRowsRenderTimer = requestAnimationFrame(() => {
    nucleiRowsRenderTimer = null;
    renderNucleiRows(nucleiFindings);
  });
}

function scheduleNucleiStatsRender(scan) {
  nucleiPendingStats = scan;
  if (nucleiStatsRenderTimer) return;
  nucleiStatsRenderTimer = requestAnimationFrame(() => {
    nucleiStatsRenderTimer = null;
    renderNucleiStatsTerminal(nucleiPendingStats);
  });
}

function renderNucleiRows(rows) {
  const body = document.getElementById('nuclei-body');
  if (!body) return;
  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:16px;color:var(--text-muted)">No findings.</td></tr>';
    return;
  }
  const visibleRows = rows.slice(-500);
  body.innerHTML = visibleRows.map(r => `<tr>
    <td style="font-family:var(--mono);font-size:12px">${esc(r.host || r.matched_at || '—')}</td>
    <td><span class="badge ${r.info?.severity==='critical'?'badge-expired':r.info?.severity==='high'?'badge-mismatch':'badge-expiring'}">${esc(r.info?.severity || 'unknown')}</span></td>
    <td style="font-family:var(--mono);font-size:11px">${esc(r.template_id || '—')}</td>
    <td>${esc(r.info?.name || '—')}</td>
    <td style="font-size:11px;color:var(--text-muted)">${esc(r.matched_at || '—')}</td>
  </tr>`).join('');
}

function updateNucleiLive(scan) {
  if (!scan?.id) return;
  nucleiCurrentScanId = scan.id;
  nucleiFindings = scan.findings || nucleiFindings || [];
  const live = document.getElementById('nuclei-live-card');
  const title = document.getElementById('nuclei-live-title');
  const sub = document.getElementById('nuclei-live-sub');
  const stats = document.getElementById('nuclei-live-stats');
  const meta = document.getElementById('nuclei-meta');
  const bar = document.getElementById('nuclei-progress-bar');
  const logEl = document.getElementById('nuclei-log');
  const runBtn = document.getElementById('nuclei-run-btn');
  const pauseBtn = document.getElementById('nuclei-pause-btn');
  const resumeBtn = document.getElementById('nuclei-resume-btn');
  const stopBtn = document.getElementById('nuclei-stop-btn');
  const active = isNucleiActiveStatus(scan.status);
  const elapsed = scan.elapsed_seconds || Math.max(0, Math.round((Date.now() - Date.parse(scan.started_at || new Date())) / 1000));
  const statsProgress = Number(scan.progress_percent ?? scan.stats?.percent);
  const progress = scan.status === 'done' || scan.status === 'stopped' ? 100 : scan.status === 'error' ? 100 : Number.isFinite(statsProgress) && statsProgress > 0 ? Math.min(99, Math.max(0, Math.round(statsProgress))) : Math.min(95, Math.max(5, Math.round((elapsed / Math.max(scan.estimated_seconds || 60, 1)) * 100)));
  live.style.display = '';
  title.textContent = scan.status === 'done' ? '✅ Nuclei scan complete' : scan.status === 'error' ? '❌ Nuclei scan failed' : scan.status === 'paused' ? '⏸ Nuclei scan paused' : scan.status === 'stopping' ? '■ Stopping nuclei scan…' : '🔄 Nuclei scan running';
  sub.textContent = scan.message || scan.error || `Scanning ${fmt(scan.hosts_scanned || scan.total || 0)} targets`;
  bar.style.width = `${progress}%`;
  stats.innerHTML = `
    <span>Targets: <b>${fmt(scan.stats?.hosts || scan.hosts_scanned || scan.total || 0)}</b></span>
    <span>Requests: <b>${fmt(scan.stats?.requests || 0)}</b></span>
    <span>Findings: <b>${fmt(scan.findings_total || nucleiFindings.length || 0)}</b></span>
    <span>RPS: <b>${esc(String(scan.stats?.rps ?? '—'))}</b></span>
    <span>Status: <b>${esc(scan.status || 'unknown')}</b></span>`;
  meta.textContent = active
    ? `Nuclei scan started · expected to complete around ${scan.estimated_completion_at ? new Date(scan.estimated_completion_at).toLocaleTimeString() : 'soon'} · use Pause, Resume, or Stop while it runs.`
    : `Scanned ${fmt(scan.hosts_scanned || 0)} targets · Findings: ${fmt(scan.findings_total || nucleiFindings.length || 0)} · Status: ${scan.status || 'unknown'}`;
  renderNucleiStatsTerminal(scan);
  renderNucleiLogEntries(scan.logs || []);
  rememberNucleiScan(scan);
  renderNucleiRows(nucleiFindings);
  runBtn.disabled = active;
  pauseBtn.style.display = scan.status === 'running' ? '' : 'none';
  resumeBtn.style.display = scan.status === 'paused' ? '' : 'none';
  stopBtn.style.display = active ? '' : 'none';
  if (!active && nucleiPollTimer) {
    clearInterval(nucleiPollTimer);
    nucleiPollTimer = null;
  }
}

function scheduleNucleiPolling() {
  if (nucleiPollTimer) clearInterval(nucleiPollTimer);
  nucleiPollTimer = setInterval(async () => {
    if (!nucleiCurrentScanId || document.hidden) return;
    const { ok, data } = await apiJSON(`/api/nuclei/scans/${nucleiCurrentScanId}`);
    if (ok) updateNucleiLive(data);
  }, 2500);
}

async function controlNucleiScan(action) {
  if (!nucleiCurrentScanId) return;
  const { ok, data, error } = await apiJSON(`/api/nuclei/scans/${nucleiCurrentScanId}/${action}`, { method:'POST' });
  if (!ok) return toast(error || `Unable to ${action} nuclei scan`, 'err');
  updateNucleiLive(data);
  toast(`Nuclei scan ${action} requested`, 'ok');
}

async function runNucleiScan() {
  const pid = document.getElementById('nuclei-project-select').value;
  if (!pid) return toast('Please choose a project', 'err');
  const btn = document.getElementById('nuclei-run-btn');
  const meta = document.getElementById('nuclei-meta');
  btn.disabled = true;
  nucleiFindings = [];
  renderNucleiRows([]);
  renderNucleiLogEntries([]);
  const mode = document.getElementById('nuclei-scope-select')?.value || 'all_subdomains';
  const scopeLabel = mode === 'all_subdomains' ? 'all subdomains' : 'latest discoveries';
  meta.textContent = `Starting nuclei scan on ${scopeLabel}...`;
  try {
    const { ok, data, error } = await fetch(`/api/projects/${pid}/nuclei/scan?mode=${encodeURIComponent(mode)}`, { method: 'POST' }).then(r => r.json());
    if (!ok) {
      meta.textContent = error || 'Nuclei scan failed to start';
      btn.disabled = false;
      return toast(meta.textContent, 'err');
    }
    updateNucleiLive(data);
    scheduleNucleiPolling();
    toast(data?.message || 'Nuclei scan started', 'ok');
  } catch {
    meta.textContent = 'Nuclei scan failed to start';
    btn.disabled = false;
  }
}

// ════════════════════════════════════════════════════════════
// INIT
// ════════════════════════════════════════════════════════════
initGenericTableSorting();
loadDash();
hydrateTopProjectSelect();
document.getElementById('alerts-search')?.addEventListener('input', debounce(() => {
  alertsCurPage = 1;
  loadAlerts(1);
}, 250));
document.getElementById('nd-search')?.addEventListener('input', debounce(loadDiscoveries, 300));
document.getElementById('bounty-search')?.addEventListener('input', debounce(loadBountyLeads, 300));
scheduleLiveRefresh();
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    clearInterval(clockTimer);
    clearInterval(pollBadgeTimer);
    clearInterval(dashboardRefreshTimer);
    clearInterval(opensslRefreshTimer);
    clockTimer = null;
    pollBadgeTimer = null;
    dashboardRefreshTimer = null;
    opensslRefreshTimer = null;
    if (scanPollTimer) { clearInterval(scanPollTimer); scanPollTimer = null; }
    clearTimeout(sseReconnectTimer);
    sseReconnectTimer = null;
    if (sseConnection) { sseConnection.close(); sseConnection = null; }
    return;
  }
  if (!clockTimer) clockTimer = setInterval(tick, 1000);
  if (!pollBadgeTimer) pollBadgeTimer = setInterval(pollBadge, 30000);
  if (!dashboardRefreshTimer) dashboardRefreshTimer = setInterval(() => {
    if (document.getElementById('page-dashboard').classList.contains('active')) loadDash();
  }, 60000);
  if (!opensslRefreshTimer) opensslRefreshTimer = setInterval(() => {
    if (document.getElementById('page-openssl').classList.contains('active') && opensslPid) loadOpenSSLRows();
  }, 12000);
  connectSSE();
  tick();
  pollBadge();
});
function refreshKpis() {
  const total=Number(document.getElementById('statTotalHosts')?.textContent||0);
  const healthy=Number(document.getElementById('statOk')?.textContent||0);
  const exp=Number(document.getElementById('statExpiring')?.textContent||0);
  const alerts=Number(document.getElementById('alertCount')?.textContent||0);
  const cov=total?Math.round((healthy/total)*100):0;
  const map={kpiCoverage:cov+'%',kpiHealthy:healthy,kpiExpiring:exp,kpiAlerts:alerts};
  Object.entries(map).forEach(([id,val])=>{const el=document.getElementById(id); if(el) el.textContent=val;});
}
refreshKpis();
let refreshKpiTimer = setInterval(() => {
  if (!document.hidden) refreshKpis();
}, 10000);


Object.assign(window, {
  trackNetworkActivity,
  isReadRequest,
  clearApiMemo,
  apiJSON,
  setLastSyncStamp,
  debounce,
  rafThrottle,
  inferCellSortValue,
  sortGenericResultTable,
  enhanceGenericSortableTables,
  initGenericTableSorting,
  setTheme,
  getUiPrefs,
  saveUiPrefs,
  applyUiPrefs,
  loadAlertSettings,
  saveAlertSettings,
  tick,
  nav,
  filterNavItems,
  renderCommandList,
  moveCommandSelection,
  openCommandPalette,
  closeCommandPalette,
  runQuickAction,
  rel,
  sbadge,
  rowStatus,
  daysColor,
  toast,
  openModal,
  closeModal,
  connectSSE,
  queueAlertsRefresh,
  updateAlertBadge,
  pollBadge,
  humanDuration,
  humanBytes,
  loadSystemOverview,
  applyStat,
  calcRiskScore,
  severityLabel,
  pctValue,
  renderMetricRow,
  actionChip,
  updateMissionControl,
  hunterTile,
  hunterSignalCount,
  hunterConfidence,
  hunterKillChain,
  renderHunterPath,
  updateHunterDashboard,
  loadDash,
  loadLogs,
  renderLogs,
  loadLogsPage,
  appendLogRow,
  refreshActiveScans,
  loadDashMismatches,
  renderQuickRows,
  scheduleQuickRender,
  getQuickRowsView,
  quickSortValue,
  updateQuickSortHeader,
  sortQuickTable,
  setQuickFilter,
  updateQuickProgress,
  dedupeQuickHostsInput,
  startQuickScan,
  focusQuickScan,
  insertQuickScanExample,
  clearQuickScanInput,
  loadProjects,
  createProject,
  openProject,
  renderOpenSSLRows,
  queueOpenSSLRender,
  initOpenSSLPage,
  onOpenSSLProjectChange,
  startOpenSSLContinuous,
  loadOpenSSLRows,
  delProject,
  openEditModal,
  saveEdit,
  uploadFile,
  saveHosts,
  doScan,
  startPoll,
  updateScanProgress,
  syncScanActionButtons,
  togglePauseScan,
  stopActiveScan,
  showResults,
  loadResults,
  sortTable,
  filterResTable,
  applyResTableView,
  sortValue,
  renderResTable,
  renderResPagination,
  changePage,
  exportResultsCsv,
  loadScanCompare,
  loadHistory,
  viewScan,
  initAssetsPage,
  ensureAssetsProjectFilter,
  debounceAssets,
  loadAssets,
  showAssetRelationships,
  loadAlerts,
  ensureAlertsProjectFilter,
  renderAlerts,
  renderAlertsPagination,
  changeAlertsPage,
  markOneSeen,
  markAllSeen,
  clearAlerts,
  initSfPage,
  loadSfProject,
  refreshSfPanel,
  runSfNow,
  toggleSf,
  changeSfPage,
  initDiscoveriesPage,
  updateEnumStats,
  updateEnumActiveHostCount,
  renderEnumResults,
  initSfRawPage,
  loadSfRawPage,
  exportEnumScan,
  deleteEnumScan,
  runDomainEnumeration,
  openEnumScan,
  createProjectFromEnumScan,
  hydrateTopProjectSelect,
  loadDiscoveries,
  renderDiscoveriesRows,
  initBountyLeadsPage,
  renderXbowBrief,
  loadXbowBrief,
  renderBountySummary,
  bountySeverityBadge,
  loadBountyLeads,
  exportBountyLeads,
  scheduleLiveRefresh,
  isNucleiActiveStatus,
  rememberNucleiScan,
  getRememberedNucleiScan,
  renderNucleiLogEntries,
  nucleiLogEntryHTML,
  appendNucleiLogEntry,
  initNucleiPage,
  hydrateNucleiScanForProject,
  loadRecentNucleiScans,
  renderNucleiHistory,
  loadNucleiScanById,
  nucleiStatValue,
  renderNucleiStatsTerminal,
  scheduleNucleiRowsRender,
  scheduleNucleiStatsRender,
  renderNucleiRows,
  updateNucleiLive,
  scheduleNucleiPolling,
  controlNucleiScan,
  runNucleiScan,
  refreshKpis
});
