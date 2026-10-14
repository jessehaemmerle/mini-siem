import { api } from '../api.js';
import { picker, resolve } from '../timerange.js';
import { ALERT_SEV, ALERT_SEV_ORDER, SYSLOG_SEV, barList, clear, fmt, h, sevBadge, statusBadge, timeChart } from '../ui.js';

const INPUT_LABELS = { syslog: 'Syslog', http: 'HTTP/JSON', hec: 'Docker / HEC' };

function plural(n, one, many) { return `${fmt.num(n)} ${n === 1 ? one : many}`; }

function situation(d, rangeLabel) {
  const open = Object.values(d.alerts.open_by_severity).reduce((a, b) => a + b, 0);
  const worst = ALERT_SEV_ORDER.find((s) => d.alerts.open_by_severity[s]) || 'none';
  let title;
  const lines = [];
  if (!d.events.total && !d.sources.total) {
    title = 'Noch keine Logs empfangen.';
    lines.push('Binden Sie die ersten Server, Firewalls oder Container an – die Anleitung zeigt jeden Schritt.');
  } else if (open === 0) {
    title = 'Alles ruhig.';
    lines.push('Keine offenen Alarme.');
  } else {
    title = `${plural(open, 'Alarm wartet', 'Alarme warten')} auf Bearbeitung.`;
    const parts = ALERT_SEV_ORDER.filter((s) => d.alerts.open_by_severity[s])
      .map((s) => `${fmt.num(d.alerts.open_by_severity[s])} ${ALERT_SEV[s].toLowerCase()}`);
    lines.push(`Davon ${parts.join(', ')}.`);
  }
  if (d.events.total) {
    lines.push(`${rangeLabel}: ${plural(d.events.total, 'Event', 'Events')} von ${plural(d.sources.total, 'Quelle', 'Quellen')}, aktuell ${fmt.num(d.rate)} pro Sekunde.`);
  }
  if (d.sources.silent) {
    lines.push(`${plural(d.sources.silent, 'Quelle sendet', 'Quellen senden')} seit längerer Zeit keine Logs mehr.`);
  }
  return { title, lines, worst, open };
}

export async function render(main, ctx) {
  const tr = resolve(ctx.params, '24h');
  const rangeLabel = tr.key === 'custom' ? 'Im Zeitraum' : {
    '15m': 'Letzte 15 Minuten', '1h': 'Letzte Stunde', '4h': 'Letzte 4 Stunden', '24h': 'Letzte 24 Stunden',
    '7d': 'Letzte 7 Tage', '30d': 'Letzte 30 Tage', '90d': 'Letzte 90 Tage' }[tr.key];
  const body = h('div', { class: 'overview' });
  main.append(
    h('div', { class: 'page-head' },
      h('h1', { text: 'Übersicht' }),
      h('div', { class: 'spacer' }),
      picker(tr, (sel) => {
        const p = new URLSearchParams();
        if (sel.range) p.set('range', sel.range); else { p.set('from', sel.from); p.set('to', sel.to); }
        ctx.setParams(p, false);
      })),
    body);

  const searchLink = (q) => `#/search?${new URLSearchParams({ q, ...(tr.key === 'custom' ? { from: tr.from, to: tr.to } : { range: tr.key }) })}`;

  async function load() {
    const range = resolve(ctx.params, '24h');
    const d = await api('/api/dashboard', { params: { from: range.from, to: range.to } });
    const s = situation(d, rangeLabel);
    clear(body).append(
      h('section', { class: `situation situation-${s.worst}`, 'aria-live': 'polite' },
        h('h2', { class: 'situation-title', text: s.title }),
        s.lines.map((l) => h('p', { text: l })),
        h('div', { class: 'situation-actions' },
          s.open ? h('a', { class: 'btn btn-primary', href: '#/alerts' }, 'Alarme bearbeiten') : null,
          !d.sources.total ? h('a', { class: 'btn btn-primary', href: '#/sources/setup' }, 'Quellen anbinden') : null,
          d.sources.silent ? h('a', { class: 'btn', href: '#/sources' }, 'Stille Quellen ansehen') : null)),

      h('section', { class: 'panel' },
        h('div', { class: 'panel-head' },
          h('h2', { text: 'Eingehende Events' }),
          h('p', { class: 'legend' },
            h('span', { class: 'key key-events' }, 'alle'),
            h('span', { class: 'key key-errors' }, 'Fehler und schlimmer'))),
        timeChart({
          start: d.events.start, bucket: d.events.bucket,
          series: [
            { values: d.events.series_errors, cls: 'bar-err' },
            { values: d.events.series.map((v, i) => v - d.events.series_errors[i]), cls: 'bar' },
          ],
          onSelect: (f, t) => ctx.navigate(`#/search?from=${f}&to=${t}`),
        })),

      h('div', { class: 'grid-2' },
        h('section', { class: 'panel' },
          h('div', { class: 'panel-head' },
            h('h2', { text: 'Offene Alarme' }),
            h('a', { href: '#/alerts', text: 'Alle Alarme' })),
          d.alerts.recent.length
            ? h('ul', { class: 'alert-mini' }, d.alerts.recent.map((a) =>
              h('li', {}, h('a', { href: `#/alerts/${a.id}`, class: `alert-mini-row edge-${a.severity}` },
                h('span', { class: 'alert-mini-name', text: a.rule_name }),
                h('span', { class: 'alert-mini-meta' },
                  sevBadge(a.severity), statusBadge(a.status),
                  a.group_value ? h('span', { class: 'mono', text: a.group_value }) : null,
                  h('span', { class: 'muted', text: `${fmt.num(a.count)} Treffer, ${fmt.rel(a.last_seen)}` }))))))
            : h('p', { class: 'muted', text: 'Keine offenen Alarme.' }),
          d.alerts.top_rules.length ? [
            h('h3', { class: 'subhead', text: 'Häufigste Regeln im Zeitraum' }),
            barList(d.alerts.top_rules.map((r) => ({ value: r.rule_name, count: r.n }))),
          ] : null),

        h('div', { class: 'stack' },
          h('section', { class: 'panel' },
            h('div', { class: 'panel-head' }, h('h2', { text: 'Aktivste Hosts' })),
            barList(d.events.top_hosts, { onClick: (v) => ctx.navigate(searchLink(`host:"${v}"`)) })),
          h('section', { class: 'panel' },
            h('div', { class: 'panel-head' }, h('h2', { text: 'Schweregrade' })),
            barList(Object.entries(d.events.by_severity).map(([k, v]) => ({ value: Number(k), count: v })),
              { label: (v) => SYSLOG_SEV[v], onClick: (v) => ctx.navigate(searchLink(`severity:${v}`)) })),
          h('section', { class: 'panel' },
            h('div', { class: 'panel-head' }, h('h2', { text: 'Eingänge' })),
            barList(d.events.by_input, { label: (v) => INPUT_LABELS[v] || v, onClick: (v) => ctx.navigate(searchLink(`input:${v}`)) })))));
  }

  await load();
  const timer = setInterval(() => load().catch(() => {}), 30000);
  return () => clearInterval(timer);
}
