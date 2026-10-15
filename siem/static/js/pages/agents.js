// Quellen → Agenten: Installation, Liste der Agenten, zentrale Einstellungen.
import { api } from '../api.js';
import { quoteValue } from './search.js';
import { clear, codeBlock, confirmDialog, dialog, empty, field, fmt, h, select, toast } from '../ui.js';

const OS_LABEL = { linux: 'Linux', windows: 'Windows' };
const LINUX_PRIO = [[3, 'Nur Fehler und schwerer'], [4, 'Warnungen und schwerer'], [5, 'Hinweise und schwerer'],
  [6, 'Alles außer Debug (empfohlen)'], [7, 'Alles, auch Debug']];
// Stufe bis einschließlich: „Warnung“ = kritisch, Fehler und Warnungen
const WIN_LEVEL = [[1, 'Kritisch'], [2, 'Fehler'], [3, 'Warnung'], [4, 'Information'], [5, 'Alles']];
const COLLECTOR_OK = 'läuft';

function list(text) {
  return text.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
}

function switchField(label, checked, hint) {
  const input = h('input', { type: 'checkbox', class: 'switch', checked });
  const el = h('div', { class: 'switch-field' },
    h('label', { class: 'check' }, input, h('span', { text: label })),
    hint ? h('p', { class: 'hint', text: hint }) : null);
  return { el, input };
}

// ------------------------------------------------------------------ Formular für die Sammel-Einstellungen

export function configForm(cfg) {
  const rows = h('tbody');
  const addRow = (ch = { name: '', max_level: 4, event_ids: [], exclude_ids: [] }) => {
    const name = h('input', { value: ch.name, 'aria-label': 'Kanal', placeholder: 'z. B. Microsoft-Windows-Sysmon/Operational', spellcheck: false });
    const level = select(WIN_LEVEL, ch.max_level, { 'aria-label': `Stufe für ${ch.name || 'neuen Kanal'}` });
    const only = h('input', { value: ch.event_ids.join(', '), 'aria-label': `Nur diese Ereignis-IDs für ${ch.name || 'neuen Kanal'}`, placeholder: 'alle', inputmode: 'numeric' });
    const skip = h('input', { value: ch.exclude_ids.join(', '), 'aria-label': `Ausgenommene Ereignis-IDs für ${ch.name || 'neuen Kanal'}`, placeholder: 'keine', inputmode: 'numeric' });
    const tr = h('tr', {},
      h('td', {}, name), h('td', {}, level), h('td', {}, only), h('td', {}, skip),
      h('td', { class: 'row-actions' }, h('button', {
        type: 'button', class: 'btn btn-small btn-quiet btn-danger', 'aria-label': `Kanal ${ch.name || ''} entfernen`.trim(),
        onclick: () => tr.remove(),
      }, 'Entfernen')));
    tr.read = () => ({ name: name.value.trim(), max_level: Number(level.value), event_ids: list(only.value), exclude_ids: list(skip.value) });
    rows.appendChild(tr);
    return name;
  };
  cfg.windows.channels.forEach((ch) => addRow(ch));

  const journald = switchField('systemd-Journal erfassen', cfg.linux.journald,
    'Enthält die Meldungen aller Dienste, Anmeldungen (sshd), sudo und Kernel-Meldungen.');
  const prio = select(LINUX_PRIO, cfg.linux.min_priority);
  const files = h('textarea', { rows: 3, spellcheck: false, placeholder: '/var/log/nginx/access.log\n/opt/app/logs/*.log', value: cfg.linux.files.join('\n') });
  const dockerOn = switchField('Docker-Container überwachen', cfg.docker.enabled,
    'Nur auf Rechnern, auf denen Docker läuft. Der Agent liest dazu den Docker-Socket.');
  const dockerLogs = switchField('Ausgaben der Container (Logs)', cfg.docker.logs);
  const dockerEvents = switchField('Docker-Ereignisse: Start, Stopp, Absturz, „docker exec“, privilegierte Container', cfg.docker.events);
  const exclude = h('input', { value: cfg.docker.exclude.join(', '), spellcheck: false, placeholder: 'z. B. mini-siem, watchtower' });

  const el = h('div', { class: 'config-form' },
    h('fieldset', { class: 'fieldset' },
      h('legend', { text: 'Windows-Ereignisprotokolle' }),
      h('p', { class: 'hint', text: '„Erfassen bis Warnung“ heißt: kritische Ereignisse, Fehler und Warnungen. Überwachungsereignisse (z. B. im Sicherheitsprotokoll) werden unabhängig davon immer erfasst. Kanäle, die es auf einem Rechner nicht gibt (z. B. Sysmon), werden übersprungen und in der Agentenliste angezeigt.' }),
      h('div', { class: 'table-scroll' }, h('table', { class: 'table compact edit-table' },
        h('colgroup', {}, h('col', { class: 'w-name' }), h('col', { class: 'w-level' }), h('col', { class: 'w-ids' }), h('col', { class: 'w-ids' }), h('col', { class: 'w-act' })),
        h('thead', {}, h('tr', {}, h('th', { text: 'Kanal' }), h('th', { text: 'Erfassen bis' }), h('th', { text: 'Nur Ereignis-IDs' }),
          h('th', { text: 'Ausgenommen' }), h('th', {}, h('span', { class: 'sr-only', text: 'Aktionen' })))),
        rows)),
      h('button', { type: 'button', class: 'btn btn-small', onclick: () => addRow().focus() }, 'Kanal hinzufügen')),
    h('fieldset', { class: 'fieldset' },
      h('legend', { text: 'Linux' }),
      journald.el,
      field('Schweregrad im Journal', prio),
      field('Zusätzliche Logdateien', files, 'Ein Pfad pro Zeile, Platzhalter erlaubt. Gelesen wird ab der Installation – ältere Zeilen nicht.')),
    h('fieldset', { class: 'fieldset' },
      h('legend', { text: 'Docker' }),
      dockerOn.el, dockerLogs.el, dockerEvents.el,
      field('Container ausnehmen', exclude, 'Containernamen, durch Komma getrennt.')));

  const syncDocker = () => {
    dockerLogs.input.disabled = !dockerOn.input.checked;
    dockerEvents.input.disabled = !dockerOn.input.checked;
  };
  dockerOn.input.addEventListener('change', syncDocker);
  syncDocker();

  return {
    el,
    read: () => ({
      linux: { journald: journald.input.checked, min_priority: Number(prio.value), files: list(files.value) },
      windows: { channels: [...rows.children].map((tr) => tr.read()).filter((c) => c.name) },
      docker: { enabled: dockerOn.input.checked, logs: dockerLogs.input.checked, events: dockerEvents.input.checked, exclude: list(exclude.value) },
    }),
  };
}

// ------------------------------------------------------------------ Darstellung eines Agenten

function agentStatus(a) {
  if (a.disabled) return h('span', { class: 'status status-closed' }, 'Gesperrt');
  if (a.online) return h('span', { class: 'status status-live' }, 'Verbunden');
  return h('span', { class: 'status status-silent' }, 'Keine Verbindung');
}

function collectorInfo(a) {
  const st = a.stats || {};
  const out = [];
  for (const [name, state] of Object.entries(st.collectors || {}).sort()) {
    let label = name;
    if (name === 'Docker' && st.docker_containers !== undefined) label += ` (${fmt.num(st.docker_containers)} Container)`;
    if (state === COLLECTOR_OK) out.push(h('span', { class: 'collector', text: label }));
    else out.push(h('span', { class: 'collector collector-off', text: `${label}: ${state}` }));
  }
  const notes = [];
  if (st.missing_channels?.length) notes.push(`Nicht vorhanden: ${st.missing_channels.join(', ')}`);
  if (st.spool_files) notes.push(`${fmt.bytes(st.spool_bytes)} gepuffert, noch nicht gesendet`);
  if (st.last_error && st.last_error_at && Date.now() / 1000 - st.last_error_at < 600) notes.push(`Sendefehler: ${st.last_error}`);
  if (st.dropped) notes.push(`${fmt.num(st.dropped)} Events verworfen (Puffer voll)`);
  return [
    out.length ? h('div', { class: 'collectors' }, out) : h('span', { class: 'muted', text: a.online ? 'startet …' : '–' }),
    notes.map((n) => h('div', { class: 'cell-sub', text: n })),
  ];
}

// ------------------------------------------------------------------ Seite

export async function renderAgents(main, ctx) {
  const isAdmin = ctx.can('admin');
  const listHost = h('section', { class: 'section', 'aria-labelledby': 'agents-h' });
  const installHost = h('section', { class: 'section', 'aria-labelledby': 'install-h' });
  const settingsHost = h('section', { class: 'section', 'aria-labelledby': 'agent-settings-h' });
  main.append(
    h('p', { class: 'lead', text: 'Der Mini-SIEM-Agent läuft als Dienst auf Windows- und Linux-Rechnern. Er sammelt Ereignisprotokolle, das systemd-Journal, Logdateien und Docker-Container und schickt sie gepuffert an das SIEM. Was er sammelt, wird hier zentral eingestellt.' }),
    ...(isAdmin ? [listHost, installHost, settingsHost] : [listHost]));

  let settings = null;
  let timer = null;

  async function loadList() {
    const d = await api('/api/agents');
    const online = d.agents.filter((a) => a.online).length;
    const offline = d.agents.filter((a) => !a.online && !a.disabled).length;
    clear(listHost).append(
      h('div', { class: 'section-head' },
        h('h2', { id: 'agents-h', text: 'Agenten' }),
        d.agents.length ? h('span', { class: 'muted', text: `${fmt.num(online)} verbunden${offline ? `, ${fmt.num(offline)} ohne Verbindung` : ''}` }) : null),
      d.agents.length ? h('div', { class: 'table-scroll' }, h('table', { class: 'table agents-table' },
        h('caption', { class: 'sr-only', text: 'Installierte Agenten' }),
        h('thead', {}, h('tr', {}, h('th', { text: 'Status' }), h('th', { text: 'Rechner' }), h('th', { text: 'Erfasst' }),
          h('th', { text: 'Version' }), h('th', { text: 'Letzter Kontakt' }), h('th', { class: 'num', text: 'Events' }),
          h('th', {}, h('span', { class: 'sr-only', text: 'Aktionen' })))),
        h('tbody', {}, d.agents.map((a) => {
          const title = a.name || a.hostname;
          const outdated = a.version && d.server_version && a.version !== d.server_version;
          return h('tr', {},
            h('td', {}, agentStatus(a)),
            h('td', {},
              h('span', { class: 'cell-title', text: title }),
              h('div', { class: 'cell-sub' },
                h('span', { text: [OS_LABEL[a.os] || a.os, a.os_version, a.arch].filter(Boolean).join(' · ') }),
                a.name && a.name !== a.hostname ? h('span', { class: 'mono', text: a.hostname }) : null,
                a.has_own_config ? h('span', { class: 'tag', text: 'eigene Einstellungen' }) : null)),
            h('td', {}, collectorInfo(a)),
            h('td', { class: 'nowrap' }, a.version || '–',
              outdated ? h('div', { class: 'cell-sub', text: settings?.auto_update ? 'Update folgt automatisch' : `aktuell: ${d.server_version}` }) : null),
            h('td', { class: 'nowrap', title: fmt.time(a.last_seen), text: fmt.rel(a.last_seen) }),
            h('td', { class: 'num', text: fmt.num(a.events) }),
            h('td', { class: 'row-actions' },
              h('a', { class: 'btn btn-small btn-quiet', href: `#/search?${new URLSearchParams({ q: `host:${quoteValue(a.hostname)} input:agent`, range: '24h' })}`, 'aria-label': `Events von ${title} ansehen` }, 'Events'),
              isAdmin ? h('button', { type: 'button', class: 'btn btn-small btn-quiet', 'aria-label': `Einstellungen für ${title}`, onclick: () => editAgent(a) }, 'Einstellungen') : null,
              isAdmin ? h('button', {
                type: 'button', class: 'btn btn-small btn-quiet', 'aria-label': `${title} ${a.disabled ? 'entsperren' : 'sperren'}`,
                onclick: async () => {
                  if (!a.disabled && !(await confirmDialog('Agent sperren?', `„${title}“ kann danach keine Events mehr senden, bis er wieder entsperrt wird.`, 'Sperren'))) return;
                  await api(`/api/agents/${a.id}`, { method: 'PATCH', body: { disabled: !a.disabled } });
                  toast(a.disabled ? 'Agent entsperrt' : 'Agent gesperrt');
                  loadList();
                },
              }, a.disabled ? 'Entsperren' : 'Sperren') : null,
              isAdmin ? h('button', {
                type: 'button', class: 'btn btn-small btn-quiet btn-danger', 'aria-label': `${title} löschen`,
                onclick: async () => {
                  if (!(await confirmDialog('Agent löschen?', `„${title}“ wird aus der Liste entfernt und kann keine Events mehr senden. Gespeicherte Events bleiben erhalten. Auf dem Rechner selbst: „mini-siem-agent uninstall“.`, 'Löschen'))) return;
                  await api(`/api/agents/${a.id}`, { method: 'DELETE' });
                  toast('Agent gelöscht');
                  loadList();
                },
              }, 'Löschen') : null));
        })))) : empty('Noch kein Agent installiert', isAdmin
        ? 'Führen Sie den passenden Befehl unten auf dem Rechner aus. Nach etwa einer Minute erscheint er hier.'
        : 'Agenten kann ein Administrator installieren.'));
  }

  function editAgent(a) {
    const title = a.name || a.hostname;
    const nameIn = h('input', { value: a.name || '', placeholder: a.hostname, maxlength: 100 });
    const own = h('input', { type: 'radio', name: 'cfg-mode', value: 'own', checked: a.has_own_config });
    const std = h('input', { type: 'radio', name: 'cfg-mode', value: 'default', checked: !a.has_own_config });
    const formHost = h('div');
    let form = null;
    const draw = async () => {
      clear(formHost);
      if (!own.checked) return;
      if (!form) form = configForm((await api(`/api/agents/${a.id}/config`)).config);
      formHost.appendChild(form.el);
    };
    own.addEventListener('change', draw);
    std.addEventListener('change', draw);
    dialog({
      title: `Einstellungen für ${title}`,
      wide: true,
      body: h('div', { class: 'form' },
        field('Anzeigename', nameIn, `Leer lassen, um den Rechnernamen „${a.hostname}“ zu verwenden.`),
        h('fieldset', { class: 'choice' },
          h('legend', { text: 'Was soll dieser Agent sammeln?' }),
          h('label', { class: 'check' }, std, 'Standard-Einstellungen für alle Agenten'),
          h('label', { class: 'check' }, own, 'Eigene Einstellungen nur für diesen Rechner')),
        formHost),
      actions: [
        { label: 'Abbrechen' },
        {
          label: 'Speichern', primary: true,
          onClick: async () => {
            const body = { name: nameIn.value.trim() || null };
            if (own.checked && form) body.config = form.read();
            else body.use_default = true;
            try {
              await api(`/api/agents/${a.id}`, { method: 'PATCH', body });
            } catch (e) { toast(e.message, 'error'); return false; }
            toast('Gespeichert – der Agent übernimmt die Änderung beim nächsten Melden (spätestens nach einer Minute).');
            loadList();
            return true;
          },
        },
      ],
    });
    draw();
  }

  async function loadSettings() {
    settings = await api('/api/agents-settings');
    const s = settings;
    const missing = ['linux-amd64', 'windows-amd64'].filter((p) => !s.platforms.includes(p));
    const autoUpdate = switchField('Agenten automatisch aktualisieren', s.auto_update,
      'Nach einem Update des SIEM-Containers holen sich die Agenten die neue Version selbst (Prüfsumme wird kontrolliert).');
    autoUpdate.input.addEventListener('change', async () => {
      try {
        settings = await api('/api/agents-settings', { method: 'PUT', body: { auto_update: autoUpdate.input.checked } });
        toast(autoUpdate.input.checked ? 'Automatische Updates eingeschaltet' : 'Automatische Updates ausgeschaltet');
      } catch (e) { toast(e.message, 'error'); autoUpdate.input.checked = !autoUpdate.input.checked; }
    });
    // Element.append() würde null als Text „null“ einfügen – deshalb filtern
    clear(installHost).append(...[
      h('div', { class: 'section-head' }, h('h2', { id: 'install-h', text: 'Agent installieren' })),
      s.server_url.startsWith('http://') ? h('div', { class: 'notice' },
        h('p', { text: `Das SIEM wird über ${s.server_url} angesprochen, also ohne Verschlüsselung. Im eigenen Netz ist das möglich; über Standorte oder das Internet hinweg bitte HTTPS einrichten (siehe Dokumentation „Betrieb“).` })) : null,
      missing.length ? h('div', { class: 'notice notice-error' },
        h('p', { text: `In diesem Container fehlen Agent-Programmdateien (${missing.join(', ')}). Sie werden beim Bauen des Docker-Images erstellt – bitte das offizielle Image verwenden oder neu bauen.` })) : null,
      h('div', { class: 'install-grid' },
        h('div', {},
          h('h3', { text: 'Linux (Debian, Ubuntu)' }),
          h('p', { class: 'muted', text: 'Im Terminal mit Administratorrechten ausführen:' }),
          h('div', { class: 'code-wrap' }, codeBlock(s.commands.linux)),
          h('p', { class: 'hint', text: 'Erfasst das systemd-Journal und – falls vorhanden – alle Docker-Container. Benötigt systemd und curl.' })),
        h('div', {},
          h('h3', { text: 'Windows (ab Server 2016 bzw. Windows 10)' }),
          h('p', { class: 'muted', text: 'In PowerShell „Als Administrator ausführen“:' }),
          h('div', { class: 'code-wrap' }, codeBlock(s.commands.windows)),
          h('p', { class: 'hint', text: 'Erfasst Sicherheit, System, Anwendung, PowerShell, Defender und – falls installiert – Sysmon.' }))),
      h('dl', { class: 'facts' },
        h('dt', { text: 'Adresse für die Agenten' }),
        h('dd', {}, h('span', { class: 'mono', text: s.server_url }),
          h('p', { class: 'hint', text: 'Muss von den Rechnern aus erreichbar sein. Festlegen über die Umgebungsvariable SIEM_PUBLIC_URL.' })),
        h('dt', { text: 'Registrierungsschlüssel' }),
        h('dd', {}, h('span', { class: 'mono', text: s.enroll_key }),
          h('p', { class: 'hint', text: 'Steckt in den Befehlen oben. Ein neuer Schlüssel macht die alten Befehle ungültig; installierte Agenten laufen weiter.' }),
          h('button', {
            type: 'button', class: 'btn btn-small',
            onclick: async () => {
              if (!(await confirmDialog('Neuen Registrierungsschlüssel erzeugen?', 'Die bisherigen Installationsbefehle funktionieren danach nicht mehr. Bereits installierte Agenten sind nicht betroffen.', 'Neuen Schlüssel erzeugen', false))) return;
              await api('/api/agents-settings/enroll-key', { method: 'POST' });
              toast('Neuer Registrierungsschlüssel erzeugt');
              loadSettings();
            },
          }, 'Neuen Schlüssel erzeugen')),
        h('dt', { text: 'Agent-Version' }),
        h('dd', { text: s.version || 'keine Programmdateien im Container' }),
        h('dt', { text: 'Updates' }),
        h('dd', {}, autoUpdate.el)),
      h('details', { class: 'guide' },
        h('summary', {}, h('span', { class: 'guide-title', text: 'Weitere Hinweise' }), h('span', { class: 'guide-short', text: 'Selbst signiertes Zertifikat, Status prüfen, Deinstallation' })),
        h('div', { class: 'guide-body' },
          h('p', { text: 'Mit einem selbst signierten Zertifikat (nur zum Testen) unter Linux „curl -fsSLk …“ verwenden und am Ende „--insecure“ anhängen, unter Windows „-Insecure“. Besser ist ein Zertifikat, dem die Rechner vertrauen, etwa aus der Firmen-CA.' }),
          h('p', { text: 'Auf dem Rechner zeigt „mini-siem-agent status“ Version, Verbindung und gepufferte Events. Ist das SIEM nicht erreichbar, puffert der Agent bis zu 256 MB auf der Festplatte und sendet sie später nach.' }),
          h('p', { text: 'Entfernen: „sudo mini-siem-agent uninstall“ (Linux) bzw. „& \"$env:ProgramFiles\\MiniSIEM\\mini-siem-agent.exe\" uninstall“ als Administrator (Windows).' })))].filter(Boolean));

    const form = configForm(s.config);
    clear(settingsHost).append(
      h('div', { class: 'section-head' }, h('h2', { id: 'agent-settings-h', text: 'Was die Agenten sammeln' }),
        h('span', { class: 'muted', text: 'Standard für alle Agenten ohne eigene Einstellungen' })),
      h('form', {
        class: 'form',
        onsubmit: async (e) => {
          e.preventDefault();
          try {
            settings = await api('/api/agents-settings', { method: 'PUT', body: { config: form.read() } });
            toast('Gespeichert – die Agenten übernehmen die Änderung innerhalb einer Minute.');
          } catch (ex) { toast(ex.message, 'error'); }
        },
      }, form.el, h('div', { class: 'form-actions' }, h('button', { type: 'submit', class: 'btn btn-primary' }, 'Einstellungen speichern'))));
  }

  if (isAdmin) await loadSettings();
  await loadList();
  timer = setInterval(() => { if (!document.hidden && !document.querySelector('dialog[open]')) loadList().catch(() => {}); }, 30000);
  return () => clearInterval(timer);
}
