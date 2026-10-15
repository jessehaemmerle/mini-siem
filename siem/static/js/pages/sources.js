import { api } from '../api.js';
import { renderAgents } from './agents.js';
import { renderM365 } from './m365.js';
import { quoteValue } from './search.js';
import { clear, codeBlock, confirmDialog, copyText, dialog, empty, field, fmt, h, toast } from '../ui.js';

const INPUT_LABELS = { syslog: 'Syslog', http: 'HTTP/JSON', hec: 'Docker (HEC)', agent: 'Agent', m365: 'Microsoft 365' };

function tabs(ctx, active) {
  const items = [['', 'Verbundene Quellen'], ['agents', 'Agenten'], ['m365', 'Microsoft 365'], ['setup', 'Neue Quelle anbinden']];
  if (ctx.can('admin')) items.push(['tokens', 'Sende-Tokens']);
  return h('nav', { class: 'tabs', 'aria-label': 'Bereiche' }, items.map(([k, l]) =>
    h('a', { href: `#/sources${k ? `/${k}` : ''}`, class: ['tab', k === active && 'active'], 'aria-current': k === active ? 'page' : null }, l)));
}

export async function render(main, ctx) {
  const sub = ctx.parts[0] || '';
  main.append(h('div', { class: 'page-head' }, h('h1', { text: 'Quellen' })), tabs(ctx, sub));
  if (sub === 'setup') return renderSetup(main, ctx);
  if (sub === 'agents') return renderAgents(main, ctx);
  if (sub === 'm365') return renderM365(main, ctx);
  if (sub === 'tokens' && ctx.can('admin')) return renderTokens(main);
  return renderList(main, ctx);
}

// ------------------------------------------------------------------ Liste

async function renderList(main, ctx) {
  const host = h('div');
  main.appendChild(host);
  const d = await api('/api/sources');
  if (!d.sources.length) {
    host.appendChild(empty('Noch keine Quelle verbunden',
      'Sobald ein Gerät Logs sendet, erscheint es hier automatisch.',
      h('a', { class: 'btn btn-primary', href: '#/sources/setup' }, 'Erste Quelle anbinden')));
    return;
  }
  const silent = d.sources.filter((s) => s.silent).length;
  host.append(
    h('p', { class: 'lead', text: silent
      ? `${fmt.num(d.sources.length)} Quellen, davon ${fmt.num(silent)} seit über ${d.silent_minutes} Minuten ohne neue Logs. Stille Quellen können auf einen Ausfall oder eine geänderte Konfiguration hinweisen.`
      : `${fmt.num(d.sources.length)} Quellen, alle haben in den letzten ${d.silent_minutes} Minuten Logs gesendet.` }),
    h('div', { class: 'table-scroll' }, h('table', { class: 'table' },
      h('caption', { class: 'sr-only', text: 'Verbundene Quellen' }),
      h('thead', {}, h('tr', {}, h('th', { text: 'Status' }), h('th', { text: 'Host' }), h('th', { text: 'Eingang' }),
        h('th', { text: 'Absender-IP' }), h('th', { text: 'Letztes Event' }), h('th', { class: 'num', text: 'Events' }),
        h('th', {}, h('span', { class: 'sr-only', text: 'Aktionen' })))),
      h('tbody', {}, d.sources.map((s) => h('tr', {},
        h('td', {}, h('span', { class: ['status', s.silent ? 'status-silent' : 'status-live'] }, s.silent ? 'Still' : 'Aktiv')),
        h('td', {}, h('span', { class: 'cell-title', text: s.host }),
          h('div', { class: 'cell-sub', text: `zuerst am ${fmt.time(s.first_seen)}` })),
        h('td', { text: INPUT_LABELS[s.input] || s.input }),
        h('td', { class: 'mono', text: s.source_ip || '–' }),
        h('td', { class: 'nowrap', title: fmt.time(s.last_seen), text: fmt.rel(s.last_seen) }),
        h('td', { class: 'num', text: fmt.num(s.events) }),
        h('td', { class: 'row-actions' },
          h('a', { class: 'btn btn-small btn-quiet', href: `#/search?${new URLSearchParams({ q: `host:${quoteValue(s.host)}`, range: '24h' })}` }, 'Events ansehen'),
          ctx.can('analyst') ? h('span', { class: 'quick' }, h('button', {
          type: 'button', class: 'btn btn-small btn-quiet btn-danger', 'aria-label': `${s.host} aus der Liste entfernen`,
          onclick: async () => {
            if (!(await confirmDialog('Quelle entfernen?', `„${s.host}“ wird aus der Liste entfernt. Gespeicherte Events bleiben erhalten; sendet die Quelle wieder, erscheint sie erneut.`, 'Entfernen'))) return;
            await api(`/api/sources/${s.id}`, { method: 'DELETE' });
            toast('Quelle entfernt');
            clear(host);
            host.remove();
            renderList(main, ctx);
          },
        }, 'Entfernen')) : null)))))));
}

// ------------------------------------------------------------------ Anleitungen

function guides(c) {
  const httpTls = location.protocol === 'https:';
  const httpPort = location.port || (httpTls ? '443' : '80');
  const T = c.token;
  return [
    {
      id: 'agent', title: 'Mini-SIEM-Agent für Windows und Linux (empfohlen)', short: 'Ereignisprotokolle, systemd-Journal, Logdateien und Docker-Container – mit einem Befehl installiert',
      text: 'Der Agent läuft als Dienst, puffert bei Verbindungsproblemen und wird zentral im SIEM eingestellt. Auf Docker-Hosts erfasst er zusätzlich die Ausgaben aller Container und Ereignisse wie Start, Absturz, „docker exec“ oder privilegierte Container.',
      steps: [],
      link: ['#/sources/agents', 'Installationsbefehl anzeigen'],
    },
    {
      id: 'm365', title: 'Microsoft 365', short: 'Anmeldungen, Konten und Rollen, SharePoint, OneDrive, Teams und Defender-Warnungen',
      text: 'Das SIEM ruft die Ereignisse selbst über die Schnittstellen von Microsoft ab (Office 365 Management Activity API und Microsoft Graph). Nötig ist nur eine App-Registrierung mit Lesezugriff.',
      steps: [],
      link: ['#/sources/m365', 'Microsoft 365 einrichten'],
    },
    {
      id: 'linux', title: 'Linux-Server (rsyslog)', short: 'Ubuntu, Debian, Red Hat, SUSE und andere Distributionen',
      text: 'Fast alle Linux-Distributionen bringen rsyslog mit. Diese Datei leitet alle Logs per TCP weiter und puffert sie, falls das SIEM kurz nicht erreichbar ist.',
      steps: [
        ['Datei /etc/rsyslog.d/90-siem.conf anlegen:', `# Alle Logs an das Mini-SIEM senden
*.* action(type="omfwd" target="${c.host}" port="${c.syslogPort}" protocol="tcp"
           action.resumeRetryCount="-1"
           queue.type="linkedList" queue.size="50000"
           queue.filename="siem_fwd" queue.saveOnShutdown="on")`],
        ['rsyslog neu starten und eine Testmeldung senden:', `sudo systemctl restart rsyslog
logger -t siem-test "Hallo Mini-SIEM"`],
      ],
      after: 'Die Testmeldung erscheint nach wenigen Sekunden in der Suche (app:siem-test).',
    },
    {
      id: 'network', title: 'Firewall, Router, Switch, NAS', short: 'Alle Geräte mit Syslog-Funktion, z. B. OPNsense, FortiGate, UniFi, Synology',
      text: 'Netzwerkgeräte haben in ihrer Verwaltungsoberfläche eine Einstellung „Syslog“ oder „Remote Logging“. Tragen Sie dort folgende Werte ein:',
      steps: [['', `Syslog-Server:  ${c.host}
Port:           ${c.syslogPort}
Protokoll:      UDP oder TCP (TCP bevorzugt, falls angeboten)
Format:         Standard / RFC 3164 oder RFC 5424`]],
      after: 'Firewall-Logs mit Quell-IP, Ziel-IP und Port (z. B. iptables, UFW, OPNsense, FortiGate im key=value-Format) werden automatisch erkannt – damit funktioniert auch die Portscan-Erkennung.',
    },
    {
      id: 'windows', title: 'Windows ohne Agent (Fluent Bit)', short: 'Alternative, falls Fluent Bit bereits im Einsatz ist',
      text: 'Fluent Bit ist ein kostenloser, schlanker Agent. Er liest die Windows-Ereignisprotokolle und schickt sie per HTTP an das SIEM. Download: fluentbit.io (Windows-Installer).',
      steps: [
        ['C:\\Program Files\\fluent-bit\\conf\\fluent-bit.conf ersetzen durch:', `[SERVICE]
    Flush        5
    Log_Level    warn

[INPUT]
    Name         winevtlog
    Channels     Security,System,Application,Microsoft-Windows-PowerShell/Operational
    Interval_Sec 1
    DB           C:\\Program Files\\fluent-bit\\winevtlog.db

[OUTPUT]
    Name         http
    Match        *
    Host         ${c.host}
    Port         ${httpPort}
    URI          /api/ingest
    Format       json
    Header       X-API-Key ${T}
    tls          ${httpTls ? 'On' : 'Off'}
    Retry_Limit  False`],
        ['Als Dienst einrichten (PowerShell als Administrator):', `New-Service fluent-bit -BinaryPathName '"C:\\Program Files\\fluent-bit\\bin\\fluent-bit.exe" -c "C:\\Program Files\\fluent-bit\\conf\\fluent-bit.conf"' -StartupType Automatic
Start-Service fluent-bit`],
      ],
      after: 'Wichtige Anmelde-Ereignisse (4624, 4625, 4740 …) erzeugt Windows nur, wenn die Überwachungsrichtlinie „Anmeldeereignisse überwachen“ aktiviert ist (Gruppenrichtlinie → Erweiterte Überwachungsrichtlinie).',
    },
    {
      id: 'nxlog', title: 'Windows mit NXLog (Alternative)', short: 'Falls NXLog bereits installiert ist',
      text: 'Wenn bereits NXLog Community Edition im Einsatz ist, können die Ereignisse auch per Syslog im JSON-Format geschickt werden.',
      steps: [['Ausschnitt für nxlog.conf:', `<Extension json>
    Module  xm_json
</Extension>
<Extension syslog>
    Module  xm_syslog
</Extension>
<Input eventlog>
    Module  im_msvistalog
</Input>
<Output siem>
    Module  om_tcp
    Host    ${c.host}
    Port    ${c.syslogPort}
    Exec    $Message = to_json(); to_syslog_bsd();
</Output>
<Route siem>
    Path    eventlog => siem
</Route>`]],
      after: 'Neuere NXLog-Versionen erwarten statt Host/Port die Schreibweise „Host ' + c.host + ':' + c.syslogPort + '“.',
    },
    {
      id: 'docker', title: 'Docker-Container ohne Agent', short: 'Nur die Ausgaben der Container, über den eingebauten Logging-Treiber',
      text: 'Docker kann die Ausgaben aller Container direkt an das SIEM schicken – ganz ohne zusätzlichen Agenten. Dafür wird der eingebaute Logging-Treiber „splunk“ verwendet, dessen Schnittstelle das SIEM versteht. „docker logs“ funktioniert weiterhin.',
      steps: [
        ['Für alle Container eines Hosts: /etc/docker/daemon.json', JSON.stringify({
          'log-driver': 'splunk',
          'log-opts': {
            'splunk-url': c.url,
            'splunk-token': T,
            'splunk-insecureskipverify': 'true',
            'splunk-verify-connection': 'false',
            'splunk-format': 'inline',
            tag: '{{.Name}}',
            mode: 'non-blocking',
            'max-buffer-size': '4m',
          },
        }, null, 2)],
        ['Danach Docker neu starten (gilt für neu erstellte Container):', 'sudo systemctl restart docker'],
        ['Oder nur für einzelne Dienste in docker-compose.yml:', `    logging:
      driver: splunk
      options:
        splunk-url: "${c.url}"
        splunk-token: "${T}"
        splunk-insecureskipverify: "true"
        splunk-verify-connection: "false"
        tag: "{{.Name}}"
        mode: non-blocking`],
      ],
      after: 'Der Containername steht danach im Feld „Anwendung“ (z. B. app:nginx).',
    },
    {
      id: 'http', title: 'Eigene Anwendungen und Skripte (HTTP/JSON)', short: 'curl, PowerShell, Fluent Bit, Vector, Logstash',
      text: 'Jedes Programm kann Events als JSON senden – einzeln, als Liste oder zeilenweise (NDJSON). Bekannte Felder wie message, host, level, user oder src_ip werden automatisch zugeordnet, alles andere ist unter data.<feld> durchsuchbar.',
      steps: [['Beispiel mit curl:', `curl -X POST "${c.url}/api/ingest" \\
  -H "X-API-Key: ${T}" \\
  -H "Content-Type: application/json" \\
  -d '{"message": "Backup abgeschlossen", "host": "nas01", "app": "backup", "level": "info", "dauer_s": 512}'`]],
      after: 'Auch Fluent Bit, Vector, Logstash oder Graylog-Sidecar können mit ihrer HTTP-Ausgabe an /api/ingest senden.',
    },
  ];
}

async function renderSetup(main, ctx) {
  const sys = await api('/api/system');
  const conf = {
    host: location.hostname,
    url: location.origin,
    syslogPort: sys.listeners.public_syslog_port || 514,
    token: '<INGEST-TOKEN>',
  };
  const host = h('div', { class: 'guides' });
  const tokenBox = h('div', { class: 'notice' });

  function drawToken() {
    clear(tokenBox).append(
      h('p', {}, 'Fluent Bit, der Docker-Logging-Treiber und eigene Anwendungen senden über HTTP und brauchen dafür ein Sende-Token. Syslog, der Agent und Microsoft 365 kommen ohne aus.'),
      conf.token.startsWith('siem_')
        ? h('p', {}, 'Das neue Token ist unten in allen Beispielen eingesetzt. Es wird nur jetzt angezeigt – bitte sicher aufbewahren.')
        : ctx.can('admin')
          ? h('button', {
            type: 'button', class: 'btn btn-primary',
            onclick: async () => {
              const t = await api('/api/tokens', { method: 'POST', body: { name: `Einrichtung ${new Date().toLocaleDateString('de-DE')}` } });
              conf.token = t.token;
              toast('Token erstellt und eingesetzt');
              drawToken();
              drawGuides();
            },
          }, 'Token erstellen und in die Beispiele einsetzen')
          : h('p', { class: 'muted' }, 'Sende-Tokens kann nur ein Administrator erstellen (Quellen, Bereich Sende-Tokens).'));
  }

  function drawGuides() {
    clear(host).append(...guides(conf).map((g) => h('details', { class: 'guide', id: `guide-${g.id}` },
      h('summary', {}, h('span', { class: 'guide-title', text: g.title }), h('span', { class: 'guide-short', text: g.short })),
      h('div', { class: 'guide-body' },
        h('p', { text: g.text }),
        g.steps.length > 1
          ? h('ol', { class: 'steps' }, g.steps.map(([label, code]) => h('li', {}, label ? h('p', { text: label }) : null, codeBlock(code))))
          : g.steps.map(([label, code]) => [label ? h('p', { text: label }) : null, codeBlock(code)]),
        g.after ? h('p', { class: 'hint', text: g.after }) : null,
        g.link ? h('a', { class: 'btn btn-primary', href: g.link[0] }, g.link[1]) : null))));
  }

  main.append(
    h('p', { class: 'lead' }, `Das SIEM empfängt Syslog auf ${conf.host}:${conf.syslogPort} (UDP und TCP) und HTTP unter ${conf.url}. Wählen Sie die Art der Quelle:`),
    tokenBox, host);
  drawToken();
  drawGuides();
}

// ------------------------------------------------------------------ Tokens

async function renderTokens(main) {
  const host = h('div');
  const nameIn = h('input', { placeholder: 'z. B. Docker-Host 1 oder Windows-Server', maxlength: 100 });
  main.append(
    h('p', { class: 'lead', text: 'Sende-Tokens berechtigen ausschließlich zum Senden von Logs. Verwenden Sie pro Standort oder Gerätegruppe ein eigenes Token, damit sich einzelne Zugänge gezielt sperren lassen.' }),
    h('form', {
      class: 'inline-form',
      onsubmit: async (e) => {
        e.preventDefault();
        if (!nameIn.value.trim()) { nameIn.focus(); return; }
        const t = await api('/api/tokens', { method: 'POST', body: { name: nameIn.value.trim() } });
        nameIn.value = '';
        dialog({
          title: 'Token erstellt',
          body: h('div', {}, h('p', { text: 'Kopieren Sie das Token jetzt. Es wird aus Sicherheitsgründen nicht noch einmal angezeigt.' }), codeBlock(t.token)),
          actions: [{ label: 'Kopieren und schließen', primary: true, onClick: () => copyText(t.token) }],
        });
        load();
      },
    }, field('Name für neues Token', nameIn), h('button', { type: 'submit', class: 'btn btn-primary' }, 'Token erstellen')),
    host);

  async function load() {
    const { tokens } = await api('/api/tokens');
    clear(host);
    if (!tokens.length) { host.appendChild(empty('Noch keine Sende-Tokens', 'Erstellen Sie oben ein Token für die erste HTTP-Quelle.')); return; }
    host.appendChild(h('div', { class: 'table-scroll' }, h('table', { class: 'table' },
      h('thead', {}, h('tr', {}, h('th', { text: 'Name' }), h('th', { text: 'Beginnt mit' }), h('th', { text: 'Erstellt' }),
        h('th', { text: 'Zuletzt verwendet' }), h('th', { class: 'num', text: 'Events' }), h('th', {}, h('span', { class: 'sr-only', text: 'Aktionen' })))),
      h('tbody', {}, tokens.map((t) => h('tr', {},
        h('td', { text: t.name }),
        h('td', { class: 'mono', text: `${t.prefix}…` }),
        h('td', { text: `${fmt.time(t.created)} (${t.created_by || '–'})` }),
        h('td', { text: fmt.rel(t.last_used) }),
        h('td', { class: 'num', text: fmt.num(t.events) }),
        h('td', { class: 'row-actions' }, h('button', {
          type: 'button', class: 'btn btn-small btn-quiet btn-danger', 'aria-label': `Token ${t.name} sperren`,
          onclick: async () => {
            if (!(await confirmDialog('Token sperren?', `Quellen mit dem Token „${t.name}“ können danach keine Logs mehr senden.`, 'Token sperren'))) return;
            await api(`/api/tokens/${t.id}`, { method: 'DELETE' });
            toast('Token gesperrt');
            load();
          },
        }, 'Sperren'))))))));
  }
  await load();
}
