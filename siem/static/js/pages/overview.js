import { api } from '../api.js';
import { picker, resolve } from '../timerange.js';
import { ALERT_SEV, ALERT_SEV_ORDER, SYSLOG_SEV, barList, clear, fmt, h, pegel, sevBadge, statusBadge, syslogLevel, timeChart } from '../ui.js';

const INPUT_LABELS = { syslog: 'Syslog', http: 'HTTP/JSON', hec: 'Docker (HEC)' };
const RANGE_LABELS = {
  '15m': 'In den letzten 15 Minuten', '1h': 'In der letzten Stunde', '4h': 'In den letzten 4 Stunden',
  '24h': 'In den letzten 24 Stunden', '7d': 'In den letzten 7 Tagen', '30d': 'In den letzten 30 Tagen',
  '90d': 'In den letzten 90 Tagen', custom: 'Im gewählten Zeitraum',
};

function plural(n, one, many) { return `${fmt.num(n)} ${n === 1 ? one : many}`; }

function situation(d, rangeKey) {
  const bySev = d.alerts.open_by_severity;
  const open = Object.values(bySev).reduce((a, b) => a + b, 0);
  const worst = ALERT_SEV_ORDER.find((s) => bySev[s]) || 'none';
  const lines = [];
  let title;
  if (!d.events.total && !d.sources.total) {
    title = 'Noch keine Logs empfangen.';
    lines.push(['Binden Sie die ersten Server, Firewalls oder Container an. Die Anleitung zeigt jeden Schritt.']);
  } else if (open === 0) {
    title = 'Alles ruhig.';
    lines.push(['Keine offenen Alarme.']);
  } else {
    title = `${plural(open, 'Alarm wartet', 'Alarme warten')} auf Bearbeitung.`;
    const parts = [];
    ALERT_SEV_ORDER.filter((s) => bySev[s]).forEach((s, i, arr) => {
      parts.push(h('a', { href: `#/alerts?severity=${s}`, text: `${fmt.num(bySev[s])} ${ALERT_SEV[s].toLowerCase()}` }));
      if (i < arr.length - 1) parts.push(i === arr.length - 2 ? ' und ' : ', ');
    });
    lines.push(['Davon ', ...parts, '.']);
  }
  if (d.events.total) {
    lines.push([`${RANGE_LABELS[rangeKey]} kamen ${plural(d.events.total, 'Event', 'Events')} von ${plural(d.sources.total, 'Quelle', 'Quellen')}, derzeit ${fmt.num(d.rate)} pro Sekunde.`]);
  }
  if (d.sources.silent) {
    lines.push([h('a', { href: '#/sources', text: plural(d.sources.silent, 'Quelle sendet', 'Quellen senden') }), ' seit längerer Zeit keine Logs mehr.']);
  }
  return { title, lines, worst, open };
}

export async function render(main, ctx) {
  const tr = resolve(ctx.params, '24h');
  const body = h('div', { class: 'overview' });
  const rangeHost = h('div');
  main.append(body);
  rangeHost.appendChild(picker(tr, (sel) => {
    const p = new URLSearchParams();
    if (sel.range) p.set('range', sel.range); else { p.set('from', sel.from); p.set('to', sel.to); }
    ctx.setParams(p, false);
  }));

  const searchLink = (q) => `#/search?${new URLSearchParams({ q, ...(tr.key === 'custom' ? { from: tr.from, to: tr.to } : { range: tr.key }) })}`;

  async function load() {
    const range = resolve(ctx.params, '24h');
    body.querySelector('.chart')?.classList.add('loading');
    const d = await api('/api/dashboard', { params: { from: range.from, to: range.to } });
    const s = situation(d, tr.key);
    const active = d.sources.total - d.sources.silent;
    clear(body).append(
      h('section', { class: 'situation', 'aria-live': 'polite' },
        h('div', { class: 'situation-row' },
          pegel(s.worst),
          h('div', { class: 'situation-text' },
            h('h1', { class: 'situation-title' }, h('span', { class: 'sr-only', text: 'Übersicht: ' }), s.title),
            s.lines.map((l) => h('p', {}, l)),
            h('div', { class: 'situation-actions' },
              s.open ? h('a', { class: 'btn btn-primary', href: '#/alerts' }, 'Alarme bearbeiten') : null,
              !d.sources.total ? h('a', { class: 'btn btn-primary', href: '#/sources/setup' }, 'Erste Quelle anbinden') : null)),
          rangeHost)),

      h('div', { class: 'cols' },
        h('div', { class: 'stack' },
          h('section', { class: 'section' },
            h('div', { class: 'section-head' },
              h('h2', { text: 'Eingehende Events' }),
              h('p', { class: 'legend' },
                h('span', { class: 'key key-events' }, 'übrige'),
                h('span', { class: 'key key-errors' }, 'Fehler und schwerer'))),
            timeChart({
              start: d.events.start, bucket: d.events.bucket, label: 'Eingehende Events',
              series: [
                { values: d.events.series_errors, cls: 'c-errors', color: '--chart-errors', label: 'Fehler und schwerer' },
                { values: d.events.series.map((v, i) => v - d.events.series_errors[i]), cls: 'c-events', color: '--chart-events', label: 'übrige' },
              ],
              onSelect: (f, t) => ctx.navigate(`#/search?from=${f}&to=${t}`),
            })),

          h('section', { class: 'section' },
            h('div', { class: 'section-head' },
              h('h2', { text: 'Offene Alarme' }),
              h('a', { href: '#/alerts', text: 'Alle Alarme' })),
            d.alerts.recent.length
              ? h('table', { class: 'table compact' },
                h('caption', { class: 'sr-only', text: 'Zuletzt aktive offene Alarme' }),
                h('thead', {}, h('tr', {},
                  h('th', { text: 'Schweregrad' }), h('th', { text: 'Alarm' }), h('th', { class: 'num', text: 'Treffer' }), h('th', { text: 'Zuletzt' }))),
                h('tbody', {}, d.alerts.recent.map((a) => h('tr', { class: `clickable edge-${a.severity}`, onclick: () => ctx.navigate(`#/alerts/${a.id}`) },
                  h('td', {}, sevBadge(a.severity)),
                  h('td', {}, h('a', { href: `#/alerts/${a.id}`, class: 'cell-title', text: a.rule_name }),
                    h('div', { class: 'cell-sub' }, a.group_value ? h('span', { class: 'mono', text: a.group_value }) : null, statusBadge(a.status))),
                  h('td', { class: 'num', text: fmt.num(a.count) }),
                  h('td', { class: 'nowrap', title: fmt.time(a.last_seen), text: fmt.rel(a.last_seen) })))))
              : h('p', { class: 'muted', text: 'Keine offenen Alarme. Neue Alarme erscheinen hier, sobald eine Regel anschlägt.' }))),

        h('div', { class: 'stack' },
          h('section', { class: 'section' },
            h('div', { class: 'section-head' }, h('h2', { text: 'Aktivste Hosts' })),
            barList(d.events.top_hosts, { onClick: (v) => ctx.navigate(searchLink(`host:"${v}"`)) })),
          h('section', { class: 'section' },
            h('div', { class: 'section-head' }, h('h2', { text: 'Schweregrade der Events' })),
            barList(Object.entries(d.events.by_severity).map(([k, v]) => ({ value: Number(k), count: v })), {
              label: (v) => SYSLOG_SEV[v],
              marker: (v) => (syslogLevel(v) === 'info' ? null : pegel(syslogLevel(v))),
              onClick: (v) => ctx.navigate(searchLink(`severity:${v}`)),
            })),
          h('section', { class: 'section' },
            h('div', { class: 'section-head' },
              h('h2', { text: 'Quellen' }),
              h('a', { href: '#/sources', text: 'Alle Quellen' })),
            h('p', { class: 'inline' },
              h('span', { class: 'status status-live', text: `${fmt.num(active)} aktiv` }),
              d.sources.silent ? h('span', { class: 'status status-silent', text: `${fmt.num(d.sources.silent)} still` }) : null),
            barList(d.events.by_input, { label: (v) => INPUT_LABELS[v] || v, onClick: (v) => ctx.navigate(searchLink(`input:${v}`)) })))));
  }

  await load();
  const timer = setInterval(() => load().catch(() => {}), 30000);
  return () => clearInterval(timer);
}
