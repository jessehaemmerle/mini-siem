import { api } from '../api.js';
import { clear, field, fmt, h, toast } from '../ui.js';

const AUDIT_LABELS = {
  login: 'Anmeldung', 'login.failed': 'Fehlgeschlagene Anmeldung', 'password.change': 'Passwort geändert',
  'user.create': 'Benutzer angelegt', 'user.update': 'Benutzer geändert', 'user.delete': 'Benutzer gelöscht',
  'token.create': 'Token erstellt', 'token.delete': 'Token gesperrt', 'rule.create': 'Regel angelegt',
  'rule.update': 'Regel geändert', 'rule.delete': 'Regel gelöscht', 'alert.update': 'Alarm bearbeitet',
  'alert.bulk': 'Alarme bearbeitet', 'password.reset': 'Passwort zurückgesetzt', 'settings.update': 'Einstellungen geändert', 'source.delete': 'Quelle entfernt',
};

function meter(used, total) {
  const pct = total ? Math.min(100, (used / total) * 100) : 0;
  return h('div', { class: ['meter', pct > 90 && 'meter-crit', pct > 75 && pct <= 90 && 'meter-warn'], role: 'meter',
    'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(pct) },
  h('span', { style: { width: `${pct}%` } }));
}

export async function render(main, ctx) {
  const statusHost = h('div', { class: 'grid-2' });
  const settingsHost = h('section', { class: 'panel' });
  const auditHost = h('section', { class: 'panel' });
  main.append(h('div', { class: 'page-head' }, h('h1', { text: 'System' })), statusHost, settingsHost,
    ctx.can('admin') ? auditHost : null);

  async function loadStatus() {
    const s = await api('/api/system');
    const p = s.pipeline;
    const st = s.storage;
    const disk = st.disk;
    const perDay = st.partition_count ? st.events_bytes / st.partition_count : 0;
    const daysLeft = disk && perDay ? Math.floor(disk.free / perDay) : null;
    const problems = [];
    if (p.queue > p.queue_max * 0.5) problems.push('Die Warteschlange ist mehr als halb voll – das SIEM kommt mit der Verarbeitung nicht hinterher.');
    if (p.dropped_full) problems.push(`${fmt.num(p.dropped_full)} Events wurden seit dem Start verworfen, weil die Warteschlange voll war.`);
    if (disk && disk.free / disk.total < 0.1) problems.push('Auf dem Datenträger sind weniger als 10 % frei. Aufbewahrungsdauer verkürzen oder Speicher erweitern.');
    clear(statusHost).append(
      h('section', { class: 'panel' },
        h('div', { class: 'panel-head' }, h('h2', { text: 'Verarbeitung' })),
        problems.length ? h('div', { class: 'notice notice-error' }, problems.map((x) => h('p', { text: x }))) : h('p', { class: 'ok-line', text: 'Alles in Ordnung.' }),
        h('dl', { class: 'facts' },
          h('dt', { text: 'Version' }), h('dd', { text: s.version }),
          h('dt', { text: 'Läuft seit' }), h('dd', { text: `${fmt.time(s.started)} (${fmt.duration(Math.round(s.uptime))})` }),
          h('dt', { text: 'Events pro Sekunde' }), h('dd', { text: fmt.num(p.rate) }),
          h('dt', { text: 'Verarbeitet seit Start' }), h('dd', { text: fmt.num(p.processed) }),
          h('dt', { text: 'Warteschlange' }), h('dd', { text: `${fmt.num(p.queue)} von ${fmt.num(p.queue_max)}` }),
          h('dt', { text: 'Aktive Regeln' }), h('dd', { text: fmt.num(s.detection.rules_active) }),
          p.dropped_old ? [h('dt', { text: 'Zu alt verworfen' }), h('dd', { text: fmt.num(p.dropped_old) })] : null,
          h('dt', { text: 'Empfang' }), h('dd', { text: `Web ${s.listeners.http_port}, Syslog UDP ${s.listeners.syslog_udp || 'aus'}, TCP ${s.listeners.syslog_tcp || 'aus'}${s.listeners.syslog_tls ? `, TLS ${s.listeners.syslog_tls}` : ''} (im Container)` }),
          s.listeners.syslog_allow.length ? [h('dt', { text: 'Syslog erlaubt von' }), h('dd', { class: 'mono', text: s.listeners.syslog_allow.join(', ') })] : null)),
      h('section', { class: 'panel' },
        h('div', { class: 'panel-head' }, h('h2', { text: 'Speicher' })),
        disk ? [meter(disk.used, disk.total), h('p', { class: 'muted', text: `${fmt.bytes(disk.free)} frei von ${fmt.bytes(disk.total)}` })] : null,
        h('dl', { class: 'facts' },
          h('dt', { text: 'Events gesamt' }), h('dd', { text: fmt.bytes(st.events_bytes) }),
          h('dt', { text: 'Gespeicherte Tage' }), h('dd', { text: `${fmt.num(st.partition_count)}${st.oldest_day ? ` (ab ${new Date(st.oldest_day).toLocaleDateString('de-DE')})` : ''}` }),
          h('dt', { text: 'Durchschnitt pro Tag' }), h('dd', { text: fmt.bytes(perDay) }),
          daysLeft !== null ? [h('dt', { text: 'Reicht noch für ca.' }), h('dd', { text: `${fmt.num(daysLeft)} Tage` })] : null,
          h('dt', { text: 'Aufbewahrung' }), h('dd', { text: `${s.retention_days} Tage` }),
          h('dt', { text: 'Konfiguration & Alarme' }), h('dd', { text: fmt.bytes(st.main_db_bytes) }))));
  }

  async function loadSettings() {
    const s = await api('/api/settings');
    const admin = ctx.can('admin');
    const inputs = {
      retention_days: h('input', { type: 'number', min: 1, max: 3650, value: s.retention_days, class: 'input-short' }),
      alert_retention_days: h('input', { type: 'number', min: 7, max: 3650, value: s.alert_retention_days, class: 'input-short' }),
      source_silent_minutes: h('input', { type: 'number', min: 5, max: 10080, value: s.source_silent_minutes, class: 'input-short' }),
      session_hours: h('input', { type: 'number', min: 1, max: 720, value: s.session_hours, class: 'input-short' }),
    };
    clear(settingsHost).append(
      h('div', { class: 'panel-head' }, h('h2', { text: 'Einstellungen' })),
      h('form', {
        class: 'form',
        onsubmit: async (e) => {
          e.preventDefault();
          const body = Object.fromEntries(Object.entries(inputs).map(([k, el]) => [k, parseInt(el.value, 10)]));
          try {
            await api('/api/settings', { method: 'PUT', body });
            toast('Einstellungen gespeichert');
            loadStatus();
          } catch (ex) { toast(ex.message, 'error'); }
        },
      },
      h('fieldset', { disabled: !admin, class: 'form-grid' },
        field('Logs aufbewahren (Tage)', inputs.retention_days, 'Ältere Tage werden stündlich automatisch gelöscht.'),
        field('Geschlossene Alarme aufbewahren (Tage)', inputs.alert_retention_days),
        field('Quelle gilt als still nach (Minuten)', inputs.source_silent_minutes, 'Ohne neue Logs wird die Quelle in der Übersicht gemeldet.'),
        field('Automatische Abmeldung nach (Stunden)', inputs.session_hours, 'Bei Inaktivität.')),
      admin ? h('div', { class: 'form-actions' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Einstellungen speichern'))
        : h('p', { class: 'muted', text: 'Nur Administratoren können Einstellungen ändern.' })));
  }

  async function loadAudit() {
    const { entries } = await api('/api/audit', { params: { limit: 200 } });
    clear(auditHost).append(
      h('div', { class: 'panel-head' }, h('h2', { text: 'Protokoll der Änderungen' }), h('span', { class: 'muted', text: 'letzte 200 Einträge' })),
      h('div', { class: 'table-scroll' }, h('table', { class: 'table compact' },
        h('thead', {}, h('tr', {}, h('th', { text: 'Zeit' }), h('th', { text: 'Person' }), h('th', { text: 'Aktion' }), h('th', { text: 'Details' }), h('th', { text: 'IP' }))),
        h('tbody', {}, entries.map((e) => h('tr', { class: e.action === 'login.failed' ? 'row-warn' : null },
          h('td', { class: 'nowrap', text: fmt.time(e.ts) }),
          h('td', { text: e.username || '–' }),
          h('td', { text: AUDIT_LABELS[e.action] || e.action }),
          h('td', { text: e.details || '' }),
          h('td', { class: 'mono', text: e.ip || '' })))))));
  }

  await Promise.all([loadStatus(), loadSettings(), ctx.can('admin') ? loadAudit() : null]);
  const timer = setInterval(() => loadStatus().catch(() => {}), 15000);
  return () => clearInterval(timer);
}
