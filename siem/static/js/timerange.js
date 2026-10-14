// Zeitraum-Auswahl, die sich in der URL speichern lässt (range=24h oder from/to).
import { h, select } from './ui.js';

export const PRESETS = [
  ['15m', 'Letzte 15 Minuten', 900],
  ['1h', 'Letzte Stunde', 3600],
  ['4h', 'Letzte 4 Stunden', 4 * 3600],
  ['24h', 'Letzte 24 Stunden', 86400],
  ['7d', 'Letzte 7 Tage', 7 * 86400],
  ['30d', 'Letzte 30 Tage', 30 * 86400],
  ['90d', 'Letzte 90 Tage', 90 * 86400],
];

export function resolve(params, fallback = '24h') {
  const from = parseFloat(params.get('from'));
  const to = parseFloat(params.get('to'));
  if (from && to && from < to) return { from, to, key: 'custom' };
  const key = params.get('range') || fallback;
  const p = PRESETS.find((x) => x[0] === key) || PRESETS.find((x) => x[0] === fallback);
  const now = Date.now() / 1000;
  return { from: now - p[2], to: now + 1, key: p[0] };
}

function toLocalInput(ts) {
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// onChange({range}|{from,to})
export function picker(current, onChange) {
  const opts = PRESETS.map(([k, l]) => [k, l]).concat([['custom', 'Eigener Zeitraum …']]);
  const sel = select(opts, current.key, { 'aria-label': 'Zeitraum', class: 'range-select' });
  const fromIn = h('input', { type: 'datetime-local', value: toLocalInput(current.from), 'aria-label': 'Von' });
  const toIn = h('input', { type: 'datetime-local', value: toLocalInput(Math.min(current.to, Date.now() / 1000)), 'aria-label': 'Bis' });
  const custom = h('span', { class: ['range-custom', current.key !== 'custom' && 'hidden'] },
    fromIn, h('span', { class: 'muted', text: 'bis' }), toIn,
    h('button', { type: 'button', class: 'btn', onclick: apply }, 'Anwenden'));
  function apply() {
    const f = new Date(fromIn.value).getTime() / 1000;
    const t = new Date(toIn.value).getTime() / 1000;
    if (f && t && f < t) onChange({ from: Math.floor(f), to: Math.floor(t) });
  }
  sel.addEventListener('change', () => {
    if (sel.value === 'custom') custom.classList.remove('hidden');
    else onChange({ range: sel.value });
  });
  return h('div', { class: 'range' }, sel, custom);
}
