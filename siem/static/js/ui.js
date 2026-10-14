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

export const SYSLOG_SEV = ['Notfall', 'Alarm', 'Kritisch', 'Fehler', 'Warnung', 'Hinweis', 'Info', 'Debug'];
export const ALERT_SEV = { critical: 'Kritisch', high: 'Hoch', medium: 'Mittel', low: 'Niedrig' };
export const ALERT_SEV_ORDER = ['critical', 'high', 'medium', 'low'];
export const STATUS = { open: 'Offen', ack: 'In Bearbeitung', closed: 'Geschlossen' };

export const FIELD_LABELS = {
  host: 'Host', app: 'Anwendung', severity: 'Schweregrad', facility: 'Facility', category: 'Kategorie',
  event_id: 'Ereignis-ID', user: 'Benutzer', src_ip: 'Quell-IP', dst_ip: 'Ziel-IP', dst_port: 'Zielport',
  action: 'Aktion', input: 'Eingang', source_ip: 'Absender-IP', message: 'Nachricht', ts: 'Zeit',
  received: 'Empfangen',
};

export function sevBadge(sev) {
  return h('span', { class: `sev sev-${sev}` }, ALERT_SEV[sev] || sev);
}

export function syslogSev(n) {
  const cls = n <= 2 ? 'critical' : n === 3 ? 'high' : n === 4 ? 'medium' : 'info';
  return h('span', { class: `lvl lvl-${cls}`, title: `Syslog-Schweregrad ${n}` }, SYSLOG_SEV[n] ?? n);
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

// Säulendiagramm über die Zeit. series: [{values, cls}] (gestapelt, unten zuerst)
export function timeChart({ start, bucket, series, height = 160, onSelect }) {
  const n = series[0].values.length;
  const totals = Array.from({ length: n }, (_, i) => series.reduce((s, x) => s + (x.values[i] || 0), 0));
  const max = Math.max(1, ...totals);
  const W = 1000;
  const H = height;
  const bw = W / n;
  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', class: 'chart', role: 'img',
    'aria-label': `Verlauf, maximal ${fmt.num(max)} pro Intervall`, style: { height: `${H}px` } });
  for (const f of [0.5, 1]) {
    const y = H * (1 - f) + 0.5;
    root.appendChild(svg('line', { x1: 0, x2: W, y1: y, y2: y, class: 'chart-grid' }));
  }
  root.appendChild(svg('line', { x1: 0, x2: W, y1: H - 0.5, y2: H - 0.5, class: 'chart-base' }));
  for (let i = 0; i < n; i++) {
    let y = H;
    const g = svg('g', { class: onSelect ? 'chart-col clickable' : 'chart-col' });
    const t0 = start + i * bucket;
    g.appendChild(svg('title', {}, `${fmt.time(t0)}: ${fmt.num(totals[i])}`));
    g.appendChild(svg('rect', { x: i * bw, y: 0, width: bw, height: H, class: 'chart-hit' }));
    for (const s of series) {
      const v = s.values[i] || 0;
      if (!v) continue;
      const bh = Math.max(2, (v / max) * (H - 6));
      y -= bh;
      g.appendChild(svg('rect', { x: i * bw + bw * 0.14, y, width: Math.max(1, bw * 0.72), height: bh, class: s.cls }));
    }
    if (onSelect) g.addEventListener('click', () => onSelect(t0, t0 + bucket));
    root.appendChild(g);
  }
  const axis = h('div', { class: 'chart-axis' });
  const step = Math.max(1, Math.round(n / 6));
  const multiDay = n * bucket > 86400 * 1.5;
  for (let i = 0; i < n; i += step) {
    if (i / n > 0.9) break; // letzte Beschriftung würde abgeschnitten
    const t = start + i * bucket;
    axis.appendChild(h('span', { style: { left: `${(i / n) * 100}%` } }, multiDay ? fmt.day(t) : fmt.clock(t)));
  }
  return h('div', { class: 'chart-wrap' }, h('span', { class: 'chart-max', text: fmt.num(max) }), root, axis);
}

// Horizontale Balkenliste
export function barList(items, { onClick, label = (v) => v } = {}) {
  if (!items.length) return h('p', { class: 'muted', text: 'Keine Daten im gewählten Zeitraum.' });
  const max = Math.max(...items.map((i) => i.count));
  return h('ul', { class: 'barlist' }, items.map((it) => {
    const content = [
      h('span', { class: 'barlist-fill', style: { width: `${(it.count / max) * 100}%` } }),
      h('span', { class: 'barlist-label', text: label(it.value) }),
      h('span', { class: 'barlist-count', text: fmt.num(it.count) }),
    ];
    return h('li', {}, onClick
      ? h('button', { type: 'button', class: 'barlist-row', onclick: () => onClick(it.value) }, content)
      : h('div', { class: 'barlist-row' }, content));
  }));
}
