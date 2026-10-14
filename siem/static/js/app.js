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
  { path: 'users', label: 'Benutzer', icon: 'users', mod: users, role: 'admin', secondary: true },
  { path: 'system', label: 'System', icon: 'system', mod: system, secondary: true },
];

const state = { user: null, cleanup: null, badgeTimer: null, routed: false };
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
    if (a.dataset.page === page.path) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
  document.body.classList.remove('nav-open');
  document.querySelector('.nav-toggle')?.setAttribute('aria-expanded', 'false');
  document.querySelector('.usermenu')?.removeAttribute('open');
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
  // Nach einem Seitenwechsel den Fokus auf den Inhalt setzen (nicht beim ersten Laden,
  // damit Tab zuerst "Zum Inhalt springen" und die Navigation erreicht)
  if (state.routed) main.focus({ preventScroll: true });
  state.routed = true;
}

// ------------------------------------------------------------------ Layout

async function refreshBadge() {
  try {
    const d = await api('/api/alerts', { params: { status: 'open', limit: 1 } });
    const n = d.counts.open || 0;
    const b = document.getElementById('badge-alerts');
    if (b) {
      b.textContent = n > 99 ? '99+' : String(n);
      b.hidden = n === 0;
      b.setAttribute('aria-label', `${n} offen`);
    }
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
  const visible = PAGES.filter((p) => !p.role || can(p.role));
  const link = (p) => h('a', { href: `#/${p.path}`, dataset: { page: p.path }, class: p.secondary ? 'nav-secondary' : null },
    h('span', { text: p.label }),
    p.path === 'alerts' ? h('span', { class: 'count', id: 'badge-alerts', hidden: true }) : null);
  const toggle = h('button', {
    type: 'button', class: 'btn-icon nav-toggle', 'aria-label': 'Menü', 'aria-expanded': 'false', 'aria-controls': 'mainnav',
    onclick: () => {
      const open = document.body.classList.toggle('nav-open');
      toggle.setAttribute('aria-expanded', String(open));
    },
  }, icon('menu'));
  const initials = (state.user.display_name || state.user.username).split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase();
  const menu = h('details', { class: 'usermenu' },
    h('summary', { 'aria-label': `Benutzermenü ${state.user.display_name}` },
      h('span', { class: 'avatar', 'aria-hidden': 'true', text: initials }),
      h('span', { class: 'usermenu-name', text: state.user.display_name })),
    h('div', { class: 'usermenu-panel' },
      h('div', { class: 'usermenu-who' }, h('strong', { text: state.user.display_name }),
        h('span', { class: 'small muted', text: `${state.user.username}, ${state.user.role_label}` })),
      h('button', { type: 'button', onclick: () => { menu.removeAttribute('open'); changePasswordDialog(); } }, 'Passwort ändern'),
      h('button', { type: 'button', onclick: () => { menu.removeAttribute('open'); toggleTheme(); } }, 'Hell/Dunkel umschalten'),
      h('button', { type: 'button', onclick: logout }, 'Abmelden')));
  clear(root).append(
    h('header', { class: 'topbar' },
      h('div', { class: 'topbar-inner' },
        h('a', { href: '#/overview', class: 'brand' }, h('span', { class: 'brand-mark', 'aria-hidden': 'true' }), 'Mini-SIEM'),
        h('nav', { class: 'nav', id: 'mainnav', 'aria-label': 'Hauptnavigation' },
          visible.filter((p) => !p.secondary).map(link),
          h('span', { class: 'nav-gap', 'aria-hidden': 'true' }),
          visible.filter((p) => p.secondary).map(link)),
        h('div', { class: 'topbar-tools' }, menu, toggle))),
    h('main', { id: 'main', tabindex: '-1' }));
  refreshBadge();
  clearInterval(state.badgeTimer);
  state.badgeTimer = setInterval(refreshBadge, 30000);
}

// ------------------------------------------------------------------ Anmeldung

const LOGIN_LINES = [
  'sshd: Failed password for invalid user admin from 203.0.113.66',
  'kernel: [UFW BLOCK] SRC=198.51.100.23 DST=10.0.0.1 DPT=3389',
  'Security 4625: Anmeldung fehlgeschlagen (j.mueller)',
  'sudo: anna : COMMAND=/usr/bin/systemctl restart nginx',
  'nginx: GET /shop?id=1 UNION SELECT password FROM users 403',
  'Security 4732: Mitglied zu Administratoren hinzugefügt',
];

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
  h('h1', { text: 'Anmelden' }),
  field('Benutzername', user), field('Passwort', pass), err, btn,
  h('p', { class: 'hint', text: 'Passwort vergessen? Ein Administrator kann es zurücksetzen.' }));
  clear(root).append(h('main', { class: 'login', id: 'main' },
    h('section', { class: 'login-side', 'aria-hidden': 'true' },
      h('span', { class: 'brand' }, h('span', { class: 'brand-mark' }), 'Mini-SIEM'),
      h('p', { class: 'login-claim', text: 'Alle Logs an einem Ort. Auffälliges zuerst.' }),
      h('div', { class: 'login-lines' }, LOGIN_LINES.map((l) => h('span', { text: l })))),
    h('div', { class: 'login-main' }, form)));
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

// Benutzermenü schließen bei Klick daneben oder Escape
document.addEventListener('click', (e) => {
  const menu = document.querySelector('.usermenu[open]');
  if (menu && !menu.contains(e.target)) menu.removeAttribute('open');
});
document.addEventListener('keydown', (e) => {
  const menu = document.querySelector('.usermenu[open]');
  if (e.key === 'Escape' && menu) {
    menu.removeAttribute('open');
    menu.querySelector('summary').focus();
  }
});

// "Zum Inhalt springen" darf das Hash-Routing nicht auslösen
document.querySelector('.skip')?.addEventListener('click', (e) => {
  e.preventDefault();
  document.getElementById('main')?.focus();
});
applyTheme();

(async () => {
  try {
    state.user = await api('/api/auth/me');
    start();
  } catch {
    loginView();
  }
})();
