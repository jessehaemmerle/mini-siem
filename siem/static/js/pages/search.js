import { api } from '../api.js';
import { picker, resolve } from '../timerange.js';
import { FIELD_LABELS, SYSLOG_SEV, clear, codeBlock, empty, fmt, h, syslogSev, timeChart, toast } from '../ui.js';

const FACETS = ['host', 'app', 'severity', 'src_ip', 'user', 'event_id'];
const DETAIL_FIELDS = ['ts', 'received', 'host', 'app', 'severity', 'facility', 'category', 'action', 'event_id',
  'user', 'src_ip', 'dst_ip', 'dst_port', 'input', 'source_ip'];

const HELP = [
  ['Failed password', 'Freitext: alle Wörter müssen vorkommen'],
  ['"Failed password"', 'genau diese Wortfolge'],
  ['pass*', 'Wortanfang'],
  ['host:web01', 'Feld hat diesen Wert (Groß/Klein egal)'],
  ['host:web*', 'Platzhalter * (beliebig viele) und ? (ein Zeichen)'],
  ['src_ip:10.0.0.0/8', 'IP-Adresse liegt im Netz'],
  ['severity:<=warning', 'Vergleich mit > >= < <='],
  ['user:*', 'Feld ist vorhanden'],
  ['-app:cron', 'ausschließen (auch: NOT app:cron)'],
  ['host:a OR host:b', 'eines von beiden, Klammern erlaubt'],
  ['data.status:500', 'Feld aus den Originaldaten (JSON)'],
  ['user:~"^adm"', 'regulärer Ausdruck'],
];

export function quoteValue(v) {
  const s = String(v);
  return /^[\w.\-@/]+$/.test(s) ? s : `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function addTerm(query, term) {
  const q = query.trim();
  return q ? `${q} ${term}` : term;
}

function toCsv(events) {
  const cols = ['ts', 'host', 'app', 'severity', 'user', 'src_ip', 'dst_ip', 'dst_port', 'event_id', 'message'];
  const esc = (v) => {
    let s = v === null || v === undefined ? '' : String(v);
    if (/^[=+\-@]/.test(s)) s = `'${s}`; // Schutz vor Formel-Injektion in Excel
    return /[";\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [cols.join(';')];
  for (const e of events) {
    lines.push(cols.map((c) => esc(c === 'ts' ? new Date(e.ts * 1000).toISOString() : e[c])).join(';'));
  }
  return lines.join('\n');
}

export async function render(main, ctx) {
  const params = ctx.params;
  let query = params.get('q') || '';
  let tr = resolve(params, '24h');
  let cursor = null;
  let loaded = [];
  let liveTimer = null;
  let controller = null;

  const input = h('input', {
    type: 'search', class: 'query-input', value: query, spellcheck: false, autocomplete: 'off',
    placeholder: 'Suchen, z. B. host:web01 "Failed password" oder event_id:4625', 'aria-label': 'Suchabfrage',
  });
  const error = h('p', { class: 'query-error', role: 'alert' });
  const help = h('div', { class: 'help hidden', id: 'search-help' },
    h('table', { class: 'help-table' }, h('tbody', {}, HELP.map(([ex, txt]) =>
      h('tr', {}, h('td', {}, h('button', { type: 'button', class: 'linklike mono', onclick: () => { input.value = ex; run(); } }, ex)),
        h('td', { text: txt }))))),
    h('p', { class: 'hint', text: `Felder: ${Object.keys(FIELD_LABELS).filter((f) => !['ts', 'received'].includes(f)).join(', ')}. Schweregrade: ${SYSLOG_SEV.join(', ')} (0–7).` }));
  const live = h('input', { type: 'checkbox', id: 'live' });
  const helpBtn = h('button', {
    type: 'button', class: 'btn btn-quiet', 'aria-expanded': 'false', 'aria-controls': 'search-help',
    onclick: () => {
      const open = help.classList.toggle('hidden') === false;
      helpBtn.setAttribute('aria-expanded', String(open));
    },
  }, 'Hilfe zur Suche');
  const rangeBox = h('span', { class: 'range-host' });
  const form = h('form', {
    class: 'searchbar', role: 'search',
    onsubmit: (e) => { e.preventDefault(); run(); },
  },
  input, rangeBox,
  h('button', { type: 'submit', class: 'btn btn-primary' }, 'Suchen'));

  const histHost = h('div', { class: 'hist' });
  const summary = h('p', { class: 'result-summary', 'aria-live': 'polite' });
  const facetHost = h('aside', { class: 'facets', 'aria-label': 'Häufige Werte' });
  const tbody = h('tbody');
  const table = h('table', { class: 'events' },
    h('thead', {}, h('tr', {},
      h('th', { class: 'col-time', text: 'Zeit' }), h('th', { class: 'col-host', text: 'Host' }),
      h('th', { class: 'col-app', text: 'Anwendung' }), h('th', { class: 'col-sev', text: 'Schwere' }),
      h('th', { text: 'Nachricht' }))),
    tbody);
  const more = h('button', { type: 'button', class: 'btn hidden', onclick: () => loadPage(false) }, '100 ältere Events laden');
  const resultsHost = h('div', { class: 'results' }, h('div', { class: 'table-scroll' }, table), h('div', { class: 'more' }, more));

  function renderPicker() {
    clear(rangeBox).appendChild(picker(tr, (sel) => {
      tr = sel.range ? resolve(new URLSearchParams({ range: sel.range })) : { ...sel, key: 'custom' };
      renderPicker();
      run();
    }));
  }
  renderPicker();

  main.append(
    h('div', { class: 'page-head' },
      h('h1', { text: 'Suche' }),
      h('label', { class: 'check', for: 'live' }, live, 'Alle 10 Sekunden aktualisieren'),
      helpBtn),
    form, error, help,
    h('div', { class: 'search-layout' },
      facetHost,
      h('div', { class: 'search-main' },
        h('div', { class: 'result-head' }, summary, h('div', { class: 'result-actions' },
          ctx.can('analyst') ? h('button', { type: 'button', class: 'btn btn-small', onclick: saveAsRule }, 'Als Regel speichern') : null,
          h('button', { type: 'button', class: 'btn btn-small btn-quiet', onclick: exportCsv }, 'Als CSV exportieren'))),
        histHost, resultsHost)));

  function saveAsRule() {
    ctx.navigate(`#/rules/new?${new URLSearchParams({ q: input.value.trim() })}`);
  }

  function exportCsv() {
    if (!loaded.length) { toast('Keine Events zum Exportieren', 'error'); return; }
    const blob = new Blob(['﻿', toCsv(loaded)], { type: 'text/csv;charset=utf-8' });
    const a = h('a', { href: URL.createObjectURL(blob), download: `siem-export-${new Date().toISOString().slice(0, 19)}.csv` });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  function syncUrl() {
    const p = new URLSearchParams();
    if (query) p.set('q', query);
    if (tr.key === 'custom') { p.set('from', Math.floor(tr.from)); p.set('to', Math.ceil(tr.to)); } else p.set('range', tr.key);
    ctx.setParams(p);
  }

  function currentRange() {
    return tr.key === 'custom' ? tr : resolve(new URLSearchParams({ range: tr.key }));
  }

  function applyFilter(fieldName, value, exclude = false) {
    input.value = addTerm(input.value, `${exclude ? '-' : ''}${fieldName}:${quoteValue(value)}`);
    run();
  }

  async function run() {
    query = input.value.trim();
    error.textContent = '';
    input.classList.remove('invalid');
    syncUrl();
    if (controller) controller.abort();
    controller = new AbortController();
    const range = currentRange();
    const p = { q: query, from: range.from, to: range.to };
    const signal = controller.signal;
    summary.textContent = 'Suche läuft …';
    summary.classList.add('busy');
    histHost.querySelector('.chart')?.classList.add('loading');
    // Fehler werden erst unten ausgewertet – sonst gäbe es eine unbehandelte Ablehnung
    const histP = api('/api/events/histogram', { params: p, signal }).then((v) => ({ v }), (e) => ({ e }));
    try {
      await loadPage(true, signal);
    } catch (e) {
      if (e.name === 'AbortError') return;
      error.textContent = e.message;
      input.classList.add('invalid');
      summary.textContent = '';
      clear(histHost);
      clear(facetHost);
      return;
    }
    const res = await histP;
    try {
      if (res.e) throw res.e;
      const hist = res.v;
      summary.classList.remove('busy');
      summary.textContent = hist.total === 0 ? 'Keine Treffer'
        : `${fmt.num(hist.total)} Treffer`;
      clear(histHost).appendChild(timeChart({
        start: hist.start, bucket: hist.bucket, height: 104, label: 'Treffer im Zeitverlauf',
        series: [{ values: hist.counts, cls: 'c-events', color: '--chart-events', label: 'Treffer' }],
        onSelect: (f, t) => { tr = { from: f, to: t, key: 'custom' }; renderPicker(); run(); },
      }));
    } catch (e) {
      if (e.name !== 'AbortError') summary.textContent = e.message;
    }
    loadFacets(p, signal);
  }

  async function loadFacets(p, signal) {
    clear(facetHost);
    const results = await Promise.allSettled(FACETS.map((f) => api('/api/events/top', { params: { ...p, field: f, limit: 6 }, signal })));
    if (signal.aborted) return;
    results.forEach((r, i) => {
      if (r.status !== 'fulfilled' || !r.value.values.length) return;
      const f = FACETS[i];
      facetHost.appendChild(h('section', { class: 'facet' },
        h('h2', { text: FIELD_LABELS[f] }),
        h('ul', {}, r.value.values.map((v) => h('li', {},
          h('button', { type: 'button', class: 'facet-val', title: `Nur ${FIELD_LABELS[f]} = ${v.value}`, onclick: () => applyFilter(f, v.value) },
            h('span', { class: 'facet-label', text: f === 'severity' ? SYSLOG_SEV[v.value] : String(v.value) }),
            h('span', { class: 'facet-count', text: fmt.num(v.count) })),
          h('button', { type: 'button', class: 'facet-not', title: 'Ausschließen', 'aria-label': `${v.value} ausschließen`, onclick: () => applyFilter(f, v.value, true) }, '−'))))));
    });
  }

  async function loadPage(reset, signal) {
    const range = currentRange();
    if (reset) { cursor = null; loaded = []; }
    const d = await api('/api/events', { params: { q: query, from: range.from, to: range.to, limit: 100, cursor }, signal });
    if (reset) clear(tbody);
    cursor = d.next_cursor;
    loaded = loaded.concat(d.events);
    for (const ev of d.events) tbody.append(...row(ev));
    more.classList.toggle('hidden', !cursor);
    if (reset && !d.events.length) {
      tbody.appendChild(h('tr', {}, h('td', { colspan: 5 }, empty('Keine Events gefunden',
        'Zeitraum vergrößern oder Suchbegriffe entfernen. Groß-/Kleinschreibung spielt keine Rolle.'))));
    }
  }

  function row(ev) {
    const btn = h('button', { type: 'button', class: 'ev-toggle', 'aria-expanded': 'false', title: 'Details anzeigen' }, fmt.time(ev.ts));
    const tr1 = h('tr', { class: `ev ev-sev${ev.severity}` },
      h('td', { class: 'col-time' }, btn),
      h('td', { class: 'col-host', text: ev.host || '–' }),
      h('td', { class: 'col-app', text: ev.app || '–' }),
      h('td', { class: 'col-sev' }, syslogSev(ev.severity)),
      h('td', { class: 'col-msg mono', text: ev.message }));
    const detailRow = h('tr', { class: 'ev-detail hidden' }, h('td', { colspan: 5 }));
    const toggle = () => {
      const open = detailRow.classList.toggle('hidden') === false;
      btn.setAttribute('aria-expanded', String(open));
      tr1.classList.toggle('open', open);
      if (open && !detailRow.firstChild.firstChild) detailRow.firstChild.appendChild(detail(ev));
    };
    btn.addEventListener('click', (e) => { e.stopPropagation(); toggle(); });
    tr1.addEventListener('click', () => { if (!window.getSelection().toString()) toggle(); });
    return [tr1, detailRow];
  }

  function detail(ev) {
    const dl = h('dl', { class: 'kv' });
    for (const f of DETAIL_FIELDS) {
      const v = ev[f];
      if (v === null || v === undefined || v === '') continue;
      const shown = f === 'ts' || f === 'received' ? fmt.time(v) : f === 'severity' ? `${SYSLOG_SEV[v]} (${v})` : String(v);
      dl.append(h('dt', { text: FIELD_LABELS[f] || f }), h('dd', {},
        h('span', { class: 'mono', text: shown }),
        f !== 'ts' && f !== 'received'
          ? h('span', { class: 'kv-actions' },
            h('button', { type: 'button', class: 'linklike', onclick: () => applyFilter(f, v), 'aria-label': `Nur ${FIELD_LABELS[f] || f} ${shown}` }, 'nur diesen Wert'),
            h('button', { type: 'button', class: 'linklike', onclick: () => applyFilter(f, v, true), 'aria-label': `${FIELD_LABELS[f] || f} ${shown} ausschließen` }, 'ausschließen'))
          : null));
    }
    const context = () => {
      input.value = `host:${quoteValue(ev.host)}`;
      tr = { from: ev.ts - 300, to: ev.ts + 300, key: 'custom' };
      renderPicker();
      run();
    };
    return h('div', { class: 'detail' },
      h('div', { class: 'detail-actions' },
        ev.host ? h('button', { type: 'button', class: 'btn btn-small', onclick: context }, 'Umgebung anzeigen (±5 Min. auf diesem Host)') : null),
      dl,
      h('h3', { text: 'Nachricht' }), codeBlock(ev.message || ''),
      ev.data ? [h('h3', { text: 'Weitere Felder (durchsuchbar als data.<name>)' }), codeBlock(JSON.stringify(ev.data, null, 2))] : null,
      ev.raw ? [h('h3', { text: 'Originalzeile' }), codeBlock(ev.raw)] : null);
  }

  live.addEventListener('change', () => {
    clearInterval(liveTimer);
    if (live.checked) liveTimer = setInterval(() => { if (tr.key !== 'custom') run(); }, 10000);
  });

  run();
  input.focus();
  return () => { clearInterval(liveTimer); if (controller) controller.abort(); };
}
