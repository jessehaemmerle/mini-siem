import { api } from '../api.js';
import { clear, confirmDialog, dialog, field, fmt, h, select, toast } from '../ui.js';

const ROLES = [
  ['viewer', 'Nur lesen', 'Sieht Übersicht, Suche, Alarme und Regeln, kann aber nichts ändern.'],
  ['analyst', 'Analyst', 'Bearbeitet Alarme, pflegt Regeln und Quellen.'],
  ['admin', 'Administrator', 'Zusätzlich Benutzer, Sende-Tokens und Einstellungen.'],
];

function roleSelect(value) {
  return select(ROLES.map(([k, l]) => [k, l]), value);
}

function userDialog(existing, onSaved) {
  const username = h('input', { value: existing?.username || '', disabled: !!existing, autocomplete: 'off', pattern: '[A-Za-z0-9._@\\-]+' });
  const display = h('input', { value: existing?.display_name || '', autocomplete: 'off' });
  const role = roleSelect(existing?.role || 'analyst');
  const pw = h('input', { type: 'password', autocomplete: 'new-password' });
  const roleHint = h('p', { class: 'hint' });
  const updateHint = () => { roleHint.textContent = ROLES.find((r) => r[0] === role.value)[2]; };
  role.addEventListener('change', updateHint);
  updateHint();
  dialog({
    title: existing ? `Benutzer ${existing.username} bearbeiten` : 'Benutzer anlegen',
    body: h('div', { class: 'form' },
      field('Benutzername', username, existing ? null : 'Buchstaben, Ziffern sowie . _ - @'),
      field('Anzeigename', display),
      h('div', { class: 'field' }, h('label', { for: 'role-sel', text: 'Rolle' }), Object.assign(role, { id: 'role-sel' }), roleHint),
      field(existing ? 'Neues Passwort (leer lassen = unverändert)' : 'Passwort', pw, 'Mindestens 10 Zeichen.')),
    actions: [
      { label: 'Abbrechen' },
      {
        label: existing ? 'Änderungen speichern' : 'Benutzer anlegen', primary: true,
        onClick: async () => {
          try {
            if (existing) {
              await api(`/api/users/${existing.id}`, { method: 'PUT', body: { display_name: display.value.trim() || null, role: role.value, password: pw.value || null } });
              toast('Benutzer gespeichert');
            } else {
              await api('/api/users', { method: 'POST', body: { username: username.value.trim(), display_name: display.value.trim() || null, role: role.value, password: pw.value } });
              toast('Benutzer angelegt');
            }
            onSaved();
            return true;
          } catch (e) { toast(e.message, 'error'); return false; }
        },
      },
    ],
  });
}

export async function render(main, ctx) {
  const host = h('div');
  main.append(
    h('div', { class: 'page-head' }, h('h1', { text: 'Benutzer' }), h('div', { class: 'spacer' }),
      h('button', { type: 'button', class: 'btn btn-primary', onclick: () => userDialog(null, load) }, 'Benutzer anlegen')),
    h('dl', { class: 'roles' }, ROLES.map(([, l, d]) => [h('dt', { text: l }), h('dd', { text: d })])),
    host);

  async function load() {
    const { users } = await api('/api/users');
    clear(host).appendChild(h('div', { class: 'table-scroll' }, h('table', { class: 'table' },
      h('thead', {}, h('tr', {}, h('th', { text: 'Benutzer' }), h('th', { text: 'Rolle' }), h('th', { text: 'Letzte Anmeldung' }),
        h('th', { text: 'Status' }), h('th', {}, h('span', { class: 'sr-only', text: 'Aktionen' })))),
      h('tbody', {}, users.map((u) => h('tr', { class: u.active ? null : 'row-off' },
        h('td', {}, h('div', { text: u.display_name || u.username }), u.display_name ? h('div', { class: 'muted small', text: u.username }) : null),
        h('td', { text: u.role_label }),
        h('td', { title: fmt.time(u.last_login), text: fmt.rel(u.last_login) }),
        h('td', {}, h('span', { class: ['status', u.active ? 'status-live' : 'status-closed'] }, u.active ? 'Aktiv' : 'Gesperrt')),
        h('td', { class: 'row-actions' },
          h('button', { type: 'button', class: 'btn btn-small btn-quiet', 'aria-label': `${u.username} bearbeiten`, onclick: () => userDialog(u, load) }, 'Bearbeiten'),
          u.id !== ctx.user.id ? h('button', {
            type: 'button', class: 'btn btn-small btn-quiet', 'aria-label': `${u.username} ${u.active ? 'sperren' : 'entsperren'}`,
            onclick: async () => {
              try {
                await api(`/api/users/${u.id}`, { method: 'PUT', body: { active: !u.active } });
                toast(u.active ? 'Benutzer gesperrt' : 'Benutzer entsperrt');
                load();
              } catch (e) { toast(e.message, 'error'); }
            },
          }, u.active ? 'Sperren' : 'Entsperren') : null,
          u.id !== ctx.user.id ? h('button', {
            type: 'button', class: 'btn btn-small btn-quiet btn-danger', 'aria-label': `${u.username} löschen`,
            onclick: async () => {
              if (!(await confirmDialog(`${u.username} löschen?`, 'Das Konto wird endgültig gelöscht. Seine Notizen und Einträge im Änderungsprotokoll bleiben erhalten.', 'Benutzer löschen'))) return;
              try {
                await api(`/api/users/${u.id}`, { method: 'DELETE' });
                toast('Benutzer gelöscht');
                load();
              } catch (e) { toast(e.message, 'error'); }
            },
          }, 'Löschen') : null)))))));
  }
  await load();
}
