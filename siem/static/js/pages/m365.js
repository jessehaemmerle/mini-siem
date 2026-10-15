// Quellen → Microsoft 365: Anleitung zur App-Registrierung, Zugangsdaten, Verbindungstest, Status.
import { api } from '../api.js';
import { clear, confirmDialog, field, fmt, h, toast } from '../ui.js';

const AUDIT_SOURCES = new Set(['entra', 'files_teams']);
const SOURCE_HINT = {
  entra: 'Anmeldungen (erfolgreich und fehlgeschlagen), neue Konten, Kennwort- und MFA-Änderungen, Administratorrollen, App-Zustimmungen.',
  files_teams: 'Datei-Zugriffe, Downloads, Löschungen, Freigaben und anonyme Links, Teams-Mitglieder und Gäste.',
  defender: 'Warnungen aus Microsoft Defender (Endpoint, Office 365, Identity, Cloud Apps) und Entra ID Protection.',
  graph_signins: 'Ersetzt die Anmeldungen aus dem Überwachungsprotokoll durch ausführlichere mit Land, Gerät und Risiko. Nur mit Entra ID P1 (z. B. Microsoft 365 Business Premium).',
};

function sourceState(st) {
  if (!st) return h('span', { class: 'status status-closed' }, 'Noch nicht abgerufen');
  if (st.ok) return h('span', { class: 'status status-live' }, 'In Ordnung');
  return h('span', { class: 'status status-silent' }, 'Fehler');
}

function statusTable(data, labels) {
  const entries = Object.entries(data.status.sources || {});
  if (!entries.length) return h('p', { class: 'muted', text: 'Der erste Abruf startet wenige Sekunden nach dem Speichern.' });
  return h('div', { class: 'table-scroll' }, h('table', { class: 'table' },
    h('caption', { class: 'sr-only', text: 'Status je Bereich' }),
    h('thead', {}, h('tr', {}, h('th', { text: 'Bereich' }), h('th', { text: 'Status' }), h('th', { text: 'Letzter erfolgreicher Abruf' }),
      h('th', { class: 'num', text: 'Events gesamt' }))),
    h('tbody', {}, entries.map(([key, st]) => h('tr', {},
      h('td', { class: 'cell-title', text: labels[key] || key }),
      h('td', {}, sourceState(st),
        st.error ? h('div', { class: 'cell-sub', text: st.error }) : null,
        st.ok && AUDIT_SOURCES.has(key) && !st.events
          ? h('div', { class: 'cell-sub', text: 'Noch keine Daten – nach dem ersten Abonnieren stellt Microsoft das Überwachungsprotokoll mit bis zu 12 Stunden Verzögerung bereit.' }) : null),
      h('td', { class: 'nowrap', title: fmt.time(st.last_success), text: st.last_success ? fmt.rel(st.last_success) : '–' }),
      h('td', { class: 'num', text: fmt.num(st.events || 0) }))))));
}

function setupGuide(open) {
  const step = (title, ...body) => h('li', {}, h('p', {}, h('strong', { text: title })), ...body);
  return h('details', { class: 'guide', open },
    h('summary', {}, h('span', { class: 'guide-title', text: 'Anleitung: App-Registrierung in Microsoft Entra' }),
      h('span', { class: 'guide-short', text: 'Einmalig, etwa 10 Minuten – benötigt ein Konto mit der Rolle „Globaler Administrator“' })),
    h('div', { class: 'guide-body' },
      h('ol', { class: 'steps' },
        step('App registrieren',
          h('p', { text: 'entra.microsoft.com → Identität → Anwendungen → App-Registrierungen → „Neue Registrierung“. Name z. B. „Mini-SIEM“, Kontotyp „Nur Konten in diesem Organisationsverzeichnis“, keine Umleitungs-URI.' })),
        step('Berechtigungen hinzufügen',
          h('p', { text: 'In der App: API-Berechtigungen → „Berechtigung hinzufügen“ → jeweils „Anwendungsberechtigungen“ (nicht „Delegiert“) wählen:' }),
          h('ul', { class: 'perm-list' },
            h('li', {}, h('span', { class: 'mono', text: 'Office 365 Management APIs → ActivityFeed.Read' }), ' – Anmeldungen, Konten, SharePoint, OneDrive, Teams'),
            h('li', {}, h('span', { class: 'mono', text: 'Microsoft Graph → SecurityAlert.Read.All' }), ' – Defender-Warnungen'),
            h('li', {}, h('span', { class: 'mono', text: 'Microsoft Graph → AuditLog.Read.All' }), ' – nur für Anmeldedetails (Entra ID P1)')),
          h('p', { text: 'Danach „Administratorzustimmung für … erteilen“ anklicken. Die Spalte Status muss überall „Gewährt“ zeigen.' })),
        step('Geheimen Clientschlüssel erstellen',
          h('p', { text: 'Zertifikate & Geheimnisse → „Neuer geheimer Clientschlüssel“. Den angezeigten Wert sofort kopieren – nicht die „Geheimnis-ID“. Der Schlüssel läuft nach höchstens 24 Monaten ab; am besten gleich eine Erinnerung eintragen.' })),
        step('IDs übernehmen',
          h('p', { text: 'Auf der Übersichtsseite der App stehen „Anwendungs-ID (Client)“ und „Verzeichnis-ID (Mandant)“. Beide unten eintragen.' })),
        step('Überwachungsprotokoll prüfen',
          h('p', { text: 'In neueren Mandanten ist es bereits aktiv. Sonst: purview.microsoft.com → Lösungen → Überwachung → „Aufzeichnung von Benutzer- und Administratoraktivitäten starten“.' }))),
      h('p', { class: 'hint', text: 'Microsoft liefert Ereignisse aus dem Überwachungsprotokoll mit Verzögerung: üblich sind 30 Minuten bis einige Stunden, beim allerersten Abonnieren bis zu 12 Stunden. Defender-Warnungen und Anmeldedetails kommen meist nach wenigen Minuten.' })));
}

export async function renderM365(main, ctx) {
  const statusHost = h('div');
  const formHost = h('div');
  main.append(
    h('p', { class: 'lead', text: 'Das SIEM ruft alle fünf Minuten Ereignisse aus Microsoft 365 ab: Anmeldungen und Kontoänderungen in Entra ID, Aktivitäten in SharePoint, OneDrive und Teams sowie Warnungen aus Microsoft Defender. Dafür wird eine App-Registrierung mit Lesezugriff benötigt.' }),
    statusHost, formHost);

  if (!ctx.can('admin')) {
    const d = await api('/api/m365/status');
    statusHost.append(d.enabled
      ? h('section', { class: 'section' }, h('div', { class: 'section-head' }, h('h2', { text: 'Status' })), statusTable(d, {}))
      : h('p', { class: 'muted', text: 'Microsoft 365 ist nicht angebunden. Einrichten kann es ein Administrator.' }));
    return null;
  }

  const isConfigured = (c) => Boolean(c.secret_set && c.tenant_id && c.client_id);

  function drawStatus(d) {
    const c = d.config;
    clear(statusHost);
    if (!isConfigured(c)) return;
    const labels = Object.fromEntries(d.sources.map((s) => [s.key, s.label]));
    statusHost.appendChild(h('section', { class: 'section', 'aria-labelledby': 'm365-status-h' },
      h('div', { class: 'section-head' },
        h('h2', { id: 'm365-status-h', text: 'Status' }),
        h('span', { class: 'muted', text: d.status.running ? 'Abruf läuft …' : d.status.last_run ? `letzter Abruf ${fmt.rel(d.status.last_run)}` : '' }),
        c.enabled ? h('button', {
          type: 'button', class: 'btn btn-small',
          onclick: async () => {
            await api('/api/m365/poll', { method: 'POST' });
            toast('Abruf gestartet');
            setTimeout(refreshStatus, 4000);
          },
        }, 'Jetzt abrufen') : null,
        h('a', { class: 'btn btn-small btn-quiet', href: `#/search?${new URLSearchParams({ q: 'input:m365', range: '24h' })}` }, 'Events ansehen')),
      c.enabled ? statusTable(d, labels) : h('p', { class: 'muted', text: 'Der Abruf ist ausgeschaltet.' })));
  }

  async function refreshStatus() {
    drawStatus(await api('/api/m365'));
  }

  function drawForm(d) {
    const c = d.config;
    const configured = isConfigured(c);
    const tenant = h('input', { value: c.tenant_id, spellcheck: false, autocomplete: 'off', placeholder: '00000000-0000-0000-0000-000000000000' });
    const client = h('input', { value: c.client_id, spellcheck: false, autocomplete: 'off', placeholder: '00000000-0000-0000-0000-000000000000' });
    const secret = h('input', { type: 'password', autocomplete: 'new-password', spellcheck: false,
      placeholder: c.secret_set ? 'gespeichert – leer lassen, um ihn zu behalten' : 'Wert des geheimen Clientschlüssels' });
    const enabled = h('input', { type: 'checkbox', class: 'switch', checked: c.enabled || !configured });
    const noise = h('input', { type: 'checkbox', checked: c.skip_noise });
    const boxes = {};
    const sourceList = h('div', { class: 'choice-list' }, d.sources.map((s) => {
      boxes[s.key] = h('input', { type: 'checkbox', checked: c.sources[s.key], 'aria-describedby': `src-${s.key}-hint` });
      return h('div', { class: 'choice-item' },
        h('label', { class: 'check' }, boxes[s.key], h('span', { class: 'choice-label', text: s.label })),
        h('p', { class: 'hint', id: `src-${s.key}-hint` }, SOURCE_HINT[s.key] || '', ' ', h('span', { class: 'mono', text: `Berechtigung: ${s.permission}` })));
    }));
    const results = h('div', { class: 'test-results', 'aria-live': 'polite' });

    const body = () => ({
      tenant_id: tenant.value.trim(),
      client_id: client.value.trim(),
      client_secret: secret.value.trim() || null,
      sources: Object.fromEntries(Object.entries(boxes).map(([k, b]) => [k, b.checked])),
      skip_noise: noise.checked,
    });

    const testBtn = h('button', {
      type: 'button', class: 'btn',
      onclick: async () => {
        testBtn.disabled = true;
        clear(results).append(h('p', { class: 'muted', text: 'Verbindung wird getestet …' }));
        try {
          const r = await api('/api/m365/test', { method: 'POST', body: body() });
          clear(results).append(h('ul', { class: 'result-lines' }, r.results.map((x) => h('li', { class: x.ok ? 'line-ok' : 'line-err' },
            h('span', {}, h('strong', { text: `${x.label}: ` }), x.message)))));
        } catch (e) {
          clear(results).append(h('p', { class: 'hint error', text: e.message }));
        } finally { testBtn.disabled = false; }
      },
    }, 'Verbindung testen');

    clear(formHost).append(
      setupGuide(!configured),
      h('section', { class: 'section', 'aria-labelledby': 'm365-form-h' },
        h('div', { class: 'section-head' }, h('h2', { id: 'm365-form-h', text: 'Zugangsdaten und Umfang' })),
        h('form', {
          class: 'form m365-form',
          onsubmit: async (e) => {
            e.preventDefault();
            try {
              const saved = await api('/api/m365', { method: 'PUT', body: { ...body(), enabled: enabled.checked } });
              toast(enabled.checked ? 'Gespeichert – der erste Abruf startet in wenigen Sekunden.' : 'Gespeichert');
              drawForm(saved);
              drawStatus(saved);
              setTimeout(refreshStatus, 6000);
            } catch (ex) { toast(ex.message, 'error'); }
          },
        },
        h('div', { class: 'form-grid form-grid-2' },
          field('Verzeichnis-ID (Mandant)', tenant),
          field('Anwendungs-ID (Client)', client),
          field('Geheimer Clientschlüssel', secret, 'Wird nur im SIEM gespeichert und nie wieder angezeigt.')),
        h('fieldset', { class: 'fieldset' }, h('legend', { text: 'Was soll abgerufen werden?' }), sourceList,
          h('label', { class: 'check noise' }, noise, 'Häufige, wenig aussagekräftige Vorgänge auslassen (Seitenaufrufe, Suchanfragen, Teams-Sitzungen)')),
        h('div', { class: 'switch-field' }, h('label', { class: 'check' }, enabled, h('span', { text: 'Abruf eingeschaltet' }))),
        h('div', { class: 'form-actions' },
          h('button', { type: 'submit', class: 'btn btn-primary' }, 'Speichern'), testBtn,
          configured ? h('span', { class: 'spacer' }) : null,
          configured ? h('button', {
            type: 'button', class: 'btn btn-quiet btn-danger',
            onclick: async () => {
              if (!(await confirmDialog('Verbindung entfernen?', 'Zugangsdaten und Abrufstand werden gelöscht. Bereits gespeicherte Events bleiben erhalten. Die App-Registrierung bitte zusätzlich in Entra löschen.', 'Entfernen'))) return;
              await api('/api/m365', { method: 'DELETE' });
              toast('Verbindung entfernt');
              const d2 = await api('/api/m365');
              drawForm(d2);
              drawStatus(d2);
            },
          }, 'Verbindung entfernen') : null),
        results)));
  }

  const d = await api('/api/m365');
  drawStatus(d);
  drawForm(d);
  const timer = setInterval(() => {
    if (!document.hidden && !document.querySelector('dialog[open]')) refreshStatus().catch(() => {});
  }, 30000);
  return () => clearInterval(timer);
}
