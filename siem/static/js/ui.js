// Kleine UI-Bibliothek ohne Abhängigkeiten.
// Wichtig: Logdaten können von Angreifern stammen – deshalb wird hier
// ausschließlich mit textContent gearbeitet, nie mit innerHTML.

export function h(tag, props, ...children) {
  const el = tag === 'svg' || props?.svg ? document.createElementNS('http://www.w3.org/2000/svg', tag) : document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false || k === 'svg') continue;
      if (k === 'class') el.setAttribute('class', Array.isArray(v) ? v.filter(Boolean).join(' ') : v);
      else if (k === 'text') el.textContent = v;
      else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === 'value' && 'value' in el) el.value = v;
      else if (k === 'checked' || k === 'disabled' || k === 'selected' || k === 'open') el[k] = !!v;
      else el.setAttribute(k, v === true ? '' : v);
    }
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

export function svg(tag, attrs = {}, ...children) {
  return h(tag, { ...attrs, svg: true }, ...children);
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

// ------------------------------------------------------------------ Symbole

const ICONS = {
  overview: 'M3 13h8V3H3zm10 8h8V11h-8zM3 21h8v-6H3zm10-18v6h8V3z',
  search: 'M10 2a8 8 0 0 1 6.32 12.9l5.39 5.4-1.42 1.4-5.39-5.38A8 8 0 1 1 10 2zm0 2a6 6 0 1 0 0 12 6 6 0 0 0 0-12z',
  alerts: 'M12 2a7 7 0 0 1 7 7v4.5l2 3.5H3l2-3.5V9a7 7 0 0 1 7-7zm-2.5 17h5a2.5 2.5 0 0 1-5 0z',
  rules: 'M4 4h16v2H4zm0 7h10v2H4zm0 7h16v2H4zm13-8.5 5 2.5-5 2.5z',
  sources: 'M4 5h16v4H4zm0 5h16v4H4zm0 5h16v4H4zm2-8.5v1h2v-1zm0 5v1h2v-1zm0 5v1h2v-1z',
  users: 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm-7 9a7 7 0 0 1 14 0zm15.5-9a3 3 0 1 0 0-6v6zm1 9H22a6 6 0 0 0-4-5.6 8.9 8.9 0 0 1 .5 5.6z',
  system: 'M12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8zm9 2.6v2.8l-2.3.6-.6 1.5 1.2 2-2 2-2-1.2-1.5.6-.6 2.3h-2.8l-.6-2.3-1.5-.6-2 1.2-2-2 1.2-2-.6-1.5L3 13.4v-2.8l2.3-.6.6-1.5-1.2-2 2-2 2 1.2 1.5-.6.6-2.3h2.8l.6 2.3 1.5.6 2-1.2 2 2-1.2 2 .6 1.5z',
  moon: 'M21 14.5A9 9 0 0 1 9.5 3a9 9 0 1 0 11.5 11.5z',
  logout: 'M10 3H4v18h6v-2H6V5h4zm5.5 4.5L14 9l2 2H9v2h7l-2 2 1.5 1.5L20 12z',
  menu: 'M3 6h18v2H3zm0 5h18v2H3zm0 5h18v2H3z',
  copy: 'M8 3h11v13h-2V5H8zm-3 4h10v14H5z',
  close: 'M6.4 5 12 10.6 17.6 5 19 6.4 13.4 12l5.6 5.6-1.4 1.4-5.6-5.6L6.4 19 5 17.6 10.6 12 5 6.4z',
};

export function icon(name, size = 18) {
  return svg('svg', { viewBox: '0 0 24 24', width: size, height: size, 'aria-hidden': 'true', class: 'icon' },
    svg('path', { d: ICONS[name] || '' }));
}

// ------------------------------------------------------------------ Formatierung

const dtf = new Intl.DateTimeFormat('de-DE', { dateStyle: 'short', timeStyle: 'medium' });
const tf = new Intl.DateTimeFormat('de-DE', { hour: '2-digit', minute: '2-digit' });
const df = new Intl.DateTimeFormat('de-DE', { day: '2-digit', month: '2-digit' });
const nf = new Intl.NumberFormat('de-DE');

export const fmt = {
  time: (ts) => (ts ? dtf.format(new Date(ts * 1000)) : '–'),
  clock: (ts) => tf.format(new Date(ts * 1000)),
  day: (ts) => df.format(new Date(ts * 1000)),
  num: (n) => (n === null || n === undefined ? '–' : nf.format(n)),
  bytes(b) {
    if (b === null || b === undefined) return '–';
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return `${b.toLocaleString('de-DE', { maximumFractionDigits: i ? 1 : 0 })} ${u[i]}`;
  },
  rel(ts) {
    if (!ts) return 'nie';
    const s = Date.now() / 1000 - ts;
    if (s < 60) return 'gerade eben';
    if (s < 3600) return `vor ${Math.floor(s / 60)} Min.`;
    if (s < 86400) return `vor ${Math.floor(s / 3600)} Std.`;
    const d = Math.floor(s / 86400);
    return d === 1 ? 'gestern' : `vor ${d} Tagen`;
  },
  duration(sec) {
    if (sec < 60) return `${sec} Sek.`;
    if (sec < 3600) return `${Math.round(sec / 60)} Min.`;
    if (sec < 86400) { const hrs = sec / 3600; return `${hrs.toLocaleString('de-DE', { maximumFractionDigits: 1 })} Std.`; }
    const d = sec / 86400;
    return `${d.toLocaleString('de-DE', { maximumFractionDigits: 1 })} ${d === 1 ? 'Tag' : 'Tage'}`;
  },
};

export const SYSLOG_SEV = ['Notfall', 'Dringend', 'Kritisch', 'Fehler', 'Warnung', 'Hinweis', 'Info', 'Debug'];
export const ALERT_SEV = { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig' };
export const ALERT_SEV_ORDER = ['critical', 'high', 'medium', 'low'];
export const STATUS = { open: 'Offen', ack: 'In Bearbeitung', closed: 'Geschlossen' };

export const FIELD_LABELS = {
  host: 'Host', app: 'Anwendung', severity: 'Schweregrad', facility: 'Facility', category: 'Kategorie',
  event_id: 'Ereignis-ID', user: 'Benutzer', src_ip: 'Quell-IP', dst_ip: 'Ziel-IP', dst_port: 'Zielport',
  action: 'Aktion', input: 'Eingang', source_ip: 'Absender-IP', message: 'Nachricht', ts: 'Zeit',
  received: 'Empfangen',
};

// Pegel-Symbol: 1–4 Balken, damit Schweregrade auch ohne Farbsehen unterscheidbar sind
export function pegel(level) {
  return h('span', { class: `pegel pegel-${level}`, 'aria-hidden': 'true' }, h('i'), h('i'), h('i'), h('i'));
}

export function sevBadge(sev) {
  return h('span', { class: `sev sev-${sev}` }, pegel(sev), ALERT_SEV[sev] || sev);
}

export function syslogLevel(n) {
  return n <= 2 ? 'critical' : n === 3 ? 'high' : n === 4 ? 'medium' : 'info';
}

export function syslogSev(n) {
  return h('span', { class: `lvl lvl-${syslogLevel(n)}`, title: `Syslog-Schweregrad ${n}` }, SYSLOG_SEV[n] ?? n);
}

export function statusBadge(status) {
  return h('span', { class: `status status-${status}` }, STATUS[status] || status);
}

// ------------------------------------------------------------------ Rückmeldungen

export function toast(message, kind = 'ok') {
  const host = document.getElementById('toasts');
  const t = h('div', { class: `toast toast-${kind}`, role: kind === 'error' ? 'alert' : 'status' }, message);
  host.appendChild(t);
  setTimeout(() => t.classList.add('out'), kind === 'error' ? 6000 : 3000);
  setTimeout(() => t.remove(), kind === 'error' ? 6500 : 3500);
}

export function dialog({ title, body, actions = [], wide = false, onClose }) {
  const dlg = h('dialog', { class: ['dialog', wide && 'dialog-wide'] });
  const close = () => { dlg.close(); };
  dlg.addEventListener('close', () => { dlg.remove(); onClose?.(); });
  const footer = h('div', { class: 'dialog-actions' });
  for (const a of actions) {
    footer.appendChild(h('button', {
      type: 'button',
      class: ['btn', a.primary && 'btn-primary', a.danger && 'btn-danger'],
      onclick: async (e) => {
        e.preventDefault();
        const keep = await a.onClick?.(close);
        if (keep !== false) close();
      },
    }, a.label));
  }
  dlg.append(
    h('header', { class: 'dialog-head' },
      h('h2', { text: title }),
      h('button', { class: 'btn-icon', type: 'button', 'aria-label': 'Schließen', onclick: close }, icon('close'))),
    h('div', { class: 'dialog-body' }, body),
    actions.length ? footer : null,
  );
  document.body.appendChild(dlg);
  dlg.showModal();
  return { el: dlg, close };
}

export function confirmDialog(title, text, label = 'Bestätigen', danger = true) {
  return new Promise((resolve) => {
    let ok = false;
    dialog({
      title,
      body: h('p', { text }),
      actions: [
        { label: 'Abbrechen' },
        { label, primary: !danger, danger, onClick: () => { ok = true; } },
      ],
      onClose: () => resolve(ok),
    });
  });
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h('textarea', { value: text, style: { position: 'fixed', opacity: '0' } });
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  toast('In die Zwischenablage kopiert');
}

export function codeBlock(text) {
  return h('div', { class: 'code' },
    h('pre', {}, h('code', { text })),
    h('button', { class: 'btn btn-small code-copy', type: 'button', onclick: () => copyText(text) }, icon('copy', 14), 'Kopieren'));
}

export function empty(title, text, action) {
  return h('div', { class: 'empty' }, h('p', { class: 'empty-title', text: title }), text ? h('p', { text }) : null, action || null);
}

let fieldSeq = 0;
export function field(label, input, hint) {
  if (!input.id) input.id = `f${++fieldSeq}`;
  return h('div', { class: 'field' },
    h('label', { for: input.id, text: label }),
    input,
    hint ? h('p', { class: 'hint', text: hint }) : null);
}

export function select(options, value, props = {}) {
  return h('select', props, options.map(([v, l]) => h('option', { value: v, selected: String(v) === String(value) }, l)));
}

// ------------------------------------------------------------------ Diagramme

function niceMax(v) {
  if (v <= 4) return Math.max(1, Math.ceil(v));
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function compact(v) {
  if (v >= 1e6) return `${(v / 1e6).toLocaleString('de-DE', { maximumFractionDigits: 1 })} Mio.`;
  if (v >= 1e4) return `${(v / 1e3).toLocaleString('de-DE', { maximumFractionDigits: 0 })} Tsd.`;
  return fmt.num(v);
}

function spanLabel(t0, bucket) {
  const t1 = t0 + bucket;
  if (bucket >= 86400) return fmt.day(t0);
  const sameDay = new Date(t0 * 1000).toDateString() === new Date(Date.now()).toDateString();
  return `${sameDay ? '' : `${fmt.day(t0)} `}${fmt.clock(t0)}–${fmt.clock(t1)}`;
}

// Säulendiagramm über die Zeit, gestapelt. series: [{values, cls, label}] – unten zuerst.
// Hover und Tastatur (Pfeiltasten) zeigen dieselben Werte; darunter eine Tabellenansicht.
export function timeChart({ start, bucket, series, height = 180, onSelect, label = 'Verlauf' }) {
  const n = series[0].values.length;
  const totals = Array.from({ length: n }, (_, i) => series.reduce((s, x) => s + (x.values[i] || 0), 0));
  const top = niceMax(Math.max(1, ...totals));
  const wrap = h('div', { class: ['chart', onSelect && 'clickable'] });
  const tip = h('div', { class: 'chart-tip hidden' });
  const root = svg('svg', {
    role: 'img', tabindex: 0, height,
    'aria-label': `${label}: insgesamt ${fmt.num(totals.reduce((a, b) => a + b, 0))}, höchster Wert ${fmt.num(Math.max(...totals))}. Mit den Pfeiltasten durch die Zeitabschnitte gehen.`,
  });
  wrap.append(root, tip);
  let active = -1;
  let geo = null;

  function render() {
    const W = Math.max(280, wrap.clientWidth || 800);
    const axisL = 52;
    const axisB = 24;
    const plotH = height - axisB;
    const slot = (W - axisL) / n;
    const bw = Math.max(1, Math.min(24, slot - 2));
    geo = { W, axisL, slot };
    while (root.firstChild) root.removeChild(root.firstChild);
    root.setAttribute('viewBox', `0 0 ${W} ${height}`);
    root.setAttribute('width', W);
    const y = (v) => plotH - (v / top) * (plotH - 6);
    for (const f of [0, 0.5, 1]) {
      const yy = Math.round(y(top * f)) + 0.5;
      root.appendChild(svg('line', { x1: axisL, x2: W, y1: yy, y2: yy, class: f === 0 ? 'c-base' : 'c-grid' }));
      root.appendChild(svg('text', { x: axisL - 8, y: yy + 4, 'text-anchor': 'end', class: 'c-tick' }, compact(top * f)));
    }
    for (let i = 0; i < n; i++) {
      const x0 = axisL + i * slot;
      const g = svg('g', { class: ['c-col', i === active && 'active'].filter(Boolean).join(' '), 'data-i': i });
      g.appendChild(svg('rect', { x: x0, y: 0, width: slot, height: plotH, class: 'c-hit' }));
      let base = plotH;
      const segs = series.map((s) => ({ v: s.values[i] || 0, cls: s.cls })).filter((s) => s.v > 0);
      segs.forEach((s, k) => {
        const hh = Math.max(2, plotH - y(s.v) - (k > 0 ? 2 : 0));
        const yTop = base - hh;
        const x = x0 + (slot - bw) / 2;
        const r = k === segs.length - 1 ? Math.min(4, bw / 2, hh) : 0;
        const d = `M${x},${base} V${yTop + r} Q${x},${yTop} ${x + r},${yTop} H${x + bw - r} Q${x + bw},${yTop} ${x + bw},${yTop + r} V${base} Z`;
        g.appendChild(svg('path', { d, class: s.cls }));
        base = yTop - 2;
      });
      root.appendChild(g);
    }
    const multiDay = n * bucket > 86400 * 1.5;
    const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((W - axisL) / 90))));
    for (let i = 0; i < n; i += every) {
      if (i / n > 0.92) break;
      const t = start + i * bucket;
      root.appendChild(svg('text', { x: axisL + i * slot + 2, y: height - 6, class: 'c-tick' }, multiDay ? fmt.day(t) : fmt.clock(t)));
    }
  }

  function showTip(i) {
    active = i;
    root.querySelectorAll('.c-col').forEach((g) => g.classList.toggle('active', Number(g.dataset.i) === i));
    clear(tip).append(
      h('div', { class: 'tip-when', text: spanLabel(start + i * bucket, bucket) }),
      ...series.slice().reverse().map((s) => h('div', { class: 'tip-row' },
        h('span', { class: `tip-key ${s.keyCls || ''}`, style: { background: `var(${s.color})` } }),
        h('strong', { text: fmt.num(s.values[i] || 0) }), h('span', { class: 'muted', text: s.label }))));
    tip.classList.remove('hidden');
    // neben die Säule setzen, damit sie sichtbar bleibt
    const rect = root.getBoundingClientRect();
    const scale = rect.width / geo.W || 1;
    const cx = (geo.axisL + (i + 0.5) * geo.slot) * scale;
    const tw = tip.offsetWidth || 160;
    const gap = (geo.slot * scale) / 2 + 8;
    tip.style.left = `${cx + gap + tw <= rect.width ? cx + gap : Math.max(0, cx - gap - tw)}px`;
    tip.style.top = '0px';
  }
  function hideTip() {
    active = -1;
    tip.classList.add('hidden');
    root.querySelectorAll('.c-col.active').forEach((g) => g.classList.remove('active'));
  }
  const indexAt = (ev) => {
    const rect = root.getBoundingClientRect();
    const x = (ev.clientX - rect.left) * (geo.W / rect.width);
    return Math.max(0, Math.min(n - 1, Math.floor((x - geo.axisL) / geo.slot)));
  };
  root.addEventListener('pointermove', (ev) => { if (geo) showTip(indexAt(ev)); });
  root.addEventListener('pointerleave', hideTip);
  root.addEventListener('blur', hideTip);
  root.addEventListener('focus', () => {
    let last = n - 1;
    while (last > 0 && !totals[last]) last--;
    showTip(last);
  });
  root.addEventListener('keydown', (ev) => {
    const keys = { ArrowLeft: -1, ArrowRight: 1, Home: -Infinity, End: Infinity };
    if (ev.key in keys) {
      ev.preventDefault();
      showTip(Math.max(0, Math.min(n - 1, (active < 0 ? n - 1 : active) + keys[ev.key])));
    } else if (ev.key === 'Escape') hideTip();
    else if ((ev.key === 'Enter' || ev.key === ' ') && onSelect && active >= 0) {
      ev.preventDefault();
      onSelect(start + active * bucket, start + (active + 1) * bucket);
    }
  });
  if (onSelect) {
    root.addEventListener('click', (ev) => {
      const i = indexAt(ev);
      onSelect(start + i * bucket, start + (i + 1) * bucket);
    });
  }
  const ro = new ResizeObserver(() => { if (wrap.isConnected) render(); });
  ro.observe(wrap);
  requestAnimationFrame(render);

  // Tabellenansicht (nur Zeitabschnitte mit Werten)
  const rows = [];
  for (let i = 0; i < n; i++) if (totals[i]) rows.push(i);
  const table = h('details', { class: 'chart-data' },
    h('summary', { class: 'small muted', text: 'Werte als Tabelle' }),
    h('table', { class: 'table compact chart-table' },
      h('thead', {}, h('tr', {}, h('th', { text: 'Zeitraum' }), series.slice().reverse().map((s) => h('th', { class: 'num', text: s.label })))),
      h('tbody', {}, rows.length ? rows.map((i) => h('tr', {},
        h('td', { text: spanLabel(start + i * bucket, bucket) }),
        series.slice().reverse().map((s) => h('td', { class: 'num', text: fmt.num(s.values[i] || 0) }))))
        : h('tr', {}, h('td', { colspan: series.length + 1, class: 'muted', text: 'Keine Werte im Zeitraum.' })))));
  return h('div', { class: 'chart-block' }, wrap, table);
}

// Horizontale Balkenliste – eine Serie, eine Farbe
export function barList(items, { onClick, label = (v) => v, marker } = {}) {
  if (!items.length) return h('p', { class: 'muted', text: 'Keine Daten im gewählten Zeitraum.' });
  const max = Math.max(...items.map((i) => i.count));
  return h('ul', { class: 'barlist' }, items.map((it) => {
    const content = [
      h('span', { class: 'barlist-label' }, marker ? marker(it.value) : null, h('span', { text: label(it.value) })),
      h('span', { class: 'barlist-count', text: fmt.num(it.count) }),
      h('span', { class: 'barlist-track', 'aria-hidden': 'true' },
        h('span', { class: 'barlist-fill', style: { width: `${Math.max(1, (it.count / max) * 100)}%` } })),
    ];
    return h('li', {}, onClick
      ? h('button', { type: 'button', class: 'barlist-row', onclick: () => onClick(it.value) }, content)
      : h('div', { class: 'barlist-row' }, content));
  }));
}
