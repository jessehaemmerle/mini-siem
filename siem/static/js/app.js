// Einstieg: Anmeldung, Navigation, Seitenwechsel.
import { api, setUnauthorizedHandler } from './api.js';
import { clear, dialog, field, h, icon, toast } from './ui.js';
import * as overview from './pages/overview.js';
import * as search from './pages/search.js';
import * as alerts from './pages/alerts.js';
import * as rules from './pages/rules.js';
import * as sources from './pages/sources.js';
import * as users from './pages/users.js';
import * as system from './pages/system.js';

const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2 };

const PAGES = [
  { path: 'overview', label: 'Übersicht', icon: 'overview', mod: overview },
  { path: 'search', label: 'Suche', icon: 'search', mod: search },
  { path: 'alerts', label: 'Alarme', icon: 'alerts', mod: alerts },
  { path: 'rules', label: 'Regeln', icon: 'rules', mod: rules },
  { path: 'sources', label: 'Quellen', icon: 'sources', mod: sources },
  { path: 'users', label: 'Benutzer', icon: 'users', mod: users, role: 'admin' },
  { path: 'system', label: 'System', icon: 'system', mod: system },
];

const state = { user: null, cleanup: null, badgeTimer: null };
const root = document.getElementById('app');

// ------------------------------------------------------------------ Design hell/dunkel

function applyTheme() {
  let t = null;
  try { t = localStorage.getItem('siem-theme'); } catch { /* ohne Speicher */ }
  if (t) document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}

function toggleTheme() {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === 'dark'
    : matchMedia('(prefers-color-scheme: dark)').matches;
  try { localStorage.setItem('siem-theme', dark ? 'light' : 'dark'); } catch { /* egal */ }
  applyTheme();
}

// ------------------------------------------------------------------ Routing

export function navigate(hash) {
  if (location.hash === hash) route();
  else location.hash = hash;
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  const [path, qs] = raw.split('?');
  const parts = path.split('/').filter(Boolean);
  return { parts, params: new URLSearchParams(qs || '') };
}

export function setParams(params, replace = true) {
  const { parts } = parseHash();
  const qs = params.toString();
  const hash = `#/${parts.join('/')}${qs ? `?${qs}` : ''}`;
  if (replace) history.replaceState(null, '', hash);
  else location.hash = hash;
}

function can(role) {
  return state.user && ROLE_RANK[state.user.role] >= ROLE_RANK[role];
}

async function route() {
  if (!state.user) return;
  const { parts, params } = parseHash();
  const page = PAGES.find((p) => p.path === parts[0]) || PAGES[0];
  if (!parts.length || page.path !== parts[0]) {
    history.replaceState(null, '', `#/${page.path}`);
  }
  document.querySelectorAll('.nav a').forEach((a) => {
    a.classList.toggle('active', a.dataset.page === page.path);
    if (a.dataset.page === page.path) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  document.body.classList.remove('nav-open');
  if (state.cleanup) { try { state.cleanup(); } catch { /* egal */ } }
  state.cleanup = null;
  const main = clear(document.getElementById('main'));
  if (page.role && !can(page.role)) {
    main.appendChild(h('p', { text: 'Für diese Seite fehlen die Berechtigungen.' }));
    return;
  }
  document.title = `${page.label} – Mini-SIEM`;
  const ctx = { parts: parts.slice(1), params, user: state.user, can, navigate, setParams, refreshBadge };
  try {
    state.cleanup = (await page.mod.render(main, ctx)) || null;
  } catch (e) {
    if (e.status !== 401) {
      main.appendChild(h('div', { class: 'notice notice-error' }, e.message || String(e)));
    }
  }
  main.focus({ preventScroll: true });
}

// ------------------------------------------------------------------ Layout

async function refreshBadge() {
  try {
    const d = await api('/api/alerts', { params: { status: 'open', limit: 1 } });
    const n = d.counts.open || 0;
    const b = document.getElementById('badge-alerts');
    if (b) { b.textContent = n > 99 ? '99+' : String(n); b.hidden = n === 0; }
  } catch { /* still */ }
}

function changePasswordDialog() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password' });
  const neu = h('input', { type: 'password', autocomplete: 'new-password', minlength: 10 });
  const neu2 = h('input', { type: 'password', autocomplete: 'new-password' });
  dialog({
    title: 'Passwort ändern',
    body: h('div', { class: 'form' },
      field('Aktuelles Passwort', cur),
      field('Neues Passwort', neu, 'Mindestens 10 Zeichen.'),
      field('Neues Passwort wiederholen', neu2)),
    actions: [
      { label: 'Abbrechen' },
      {
        label: 'Passwort ändern', primary: true,
        onClick: async () => {
          if (neu.value !== neu2.value) { toast('Die neuen Passwörter stimmen nicht überein', 'error'); return false; }
          try {
            await api('/api/auth/password', { method: 'POST', body: { current: cur.value, new: neu.value } });
            toast('Passwort geändert');
            return true;
          } catch (e) { toast(e.message, 'error'); return false; }
        },
      },
    ],
  });
}

function shell() {
  const nav = h('nav', { class: 'nav', 'aria-label': 'Hauptnavigation' },
    PAGES.filter((p) => !p.role || can(p.role)).map((p) =>
      h('a', { href: `#/${p.path}`, dataset: { page: p.path } },
        icon(p.icon), h('span', { text: p.label }),
        p.path === 'alerts' ? h('span', { class: 'badge', id: 'badge-alerts', hidden: true }) : null)));
  const userBox = h('div', { class: 'userbox' },
    h('button', { type: 'button', class: 'userbox-name', title: 'Passwort ändern', onclick: changePasswordDialog },
      h('span', { class: 'userbox-user', text: state.user.display_name }),
      h('span', { class: 'userbox-role', text: state.user.role_label })),
    h('div', { class: 'userbox-actions' },
      h('button', { type: 'button', class: 'btn-icon', title: 'Hell/Dunkel umschalten', 'aria-label': 'Hell/Dunkel umschalten', onclick: toggleTheme }, icon('moon')),
      h('button', { type: 'button', class: 'btn-icon', title: 'Abmelden', 'aria-label': 'Abmelden', onclick: logout }, icon('logout'))));
  clear(root).append(
    h('aside', { class: 'sidebar' },
      h('div', { class: 'brand' },
        h('a', { href: '#/overview', class: 'brand-name' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }), 'Mini-SIEM'),
        h('button', { type: 'button', class: 'btn-icon nav-toggle', 'aria-label': 'Menü', onclick: () => document.body.classList.toggle('nav-open') }, icon('menu'))),
      nav, userBox),
    h('main', { id: 'main', tabindex: '-1' }));
  refreshBadge();
  clearInterval(state.badgeTimer);
  state.badgeTimer = setInterval(refreshBadge, 30000);
}

// ------------------------------------------------------------------ Anmeldung

function loginView(message) {
  clearInterval(state.badgeTimer);
  const user = h('input', { name: 'username', autocomplete: 'username', required: true, autofocus: true });
  const pass = h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true });
  const err = h('p', { class: 'login-error', role: 'alert', text: message || '' });
  const btn = h('button', { type: 'submit', class: 'btn btn-primary btn-block' }, 'Anmelden');
  const form = h('form', {
    class: 'login-form',
    onsubmit: async (e) => {
      e.preventDefault();
      btn.disabled = true;
      err.textContent = '';
      try {
        state.user = await api('/api/auth/login', { method: 'POST', body: { username: user.value, password: pass.value } });
        start();
      } catch (ex) {
        err.textContent = ex.message;
        btn.disabled = false;
        pass.select();
      }
    },
  },
  h('h1', { class: 'login-title' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }), 'Mini-SIEM'),
  h('p', { class: 'muted', text: 'Bitte melden Sie sich an.' }),
  field('Benutzername', user), field('Passwort', pass), err, btn);
  clear(root).append(h('div', { class: 'login' }, form));
  document.title = 'Anmelden – Mini-SIEM';
  user.focus();
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch { /* egal */ }
  state.user = null;
  if (state.cleanup) state.cleanup();
  loginView();
}

function start() {
  shell();
  route();
}

setUnauthorizedHandler(() => {
  if (state.user) {
    state.user = null;
    if (state.cleanup) state.cleanup();
    loginView('Die Sitzung ist abgelaufen. Bitte erneut anmelden.');
  }
});

window.addEventListener('hashchange', route);
applyTheme();

(async () => {
  try {
    state.user = await api('/api/auth/me');
    start();
  } catch {
    loginView();
  }
})();
