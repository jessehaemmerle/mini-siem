import { api } from '../api.js';
import { quoteValue } from './search.js';
import { ALERT_SEV, FIELD_LABELS, STATUS, clear, dialog, empty, field, fmt, h, select, sevBadge, statusBadge, toast } from '../ui.js';

const TABS = [
  ['active', 'Aktiv'], ['open', 'Offen'], ['ack', 'In Bearbeitung'], ['closed', 'Geschlossen'], ['all', 'Alle'],
];
const RESOLUTIONS = ['Echter Vorfall – behoben', 'Fehlalarm', 'Erwartetes Verhalten', 'Doppelt', 'Sonstiges'];

export async function render(main, ctx) {
  if (ctx.parts[0]) return renderDetail(main, ctx, Number(ctx.parts[0]));
  return renderList(main, ctx);
}

// ------------------------------------------------------------------ Liste

async function renderList(main, ctx) {
  const p = ctx.params;
  const status = p.get('status') || 'active';
  const severity = p.get('severity') || '';
  const searchVal = p.get('search') || '';
  const selected = new Set();
  const editable = ctx.can('analyst');

  const sevSel = select([['', 'Alle Schweregrade'], ...Object.entries(ALERT_SEV)], severity, { 'aria-label': 'Schweregrad' });
  const searchIn = h('input', { type: 'search', value: searchVal, placeholder: 'Regel, IP, Host, Person …', 'aria-label': 'Alarme durchsuchen' });
  const tabsHost = h('div', { class: 'tabs', role: 'tablist' });
  const bulk = h('div', { class: 'bulkbar hidden' });
  const listHost = h('div');

  function update(changes) {
    const np = new URLSearchParams(p);
    for (const [k, v] of Object.entries(changes)) { if (v) np.set(k, v); else np.delete(k); }
    ctx.setParams(np, false);
  }
  sevSel.addEventListener('change', () => update({ severity: sevSel.value }));
  let t;
  searchIn.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => update({ search: searchIn.value.trim() }), 400); });

  main.append(
    h('div', { class: 'page-head' }, h('h1', { text: 'Alarme' })),
    h('div', { class: 'toolbar' }, tabsHost, h('div', { class: 'spacer' }), sevSel, searchIn),
    bulk, listHost);

  function renderBulk() {
    clear(bulk);
    bulk.classList.toggle('hidden', selected.size === 0);
    if (!selected.size) return;
    bulk.append(
      h('span', { text: `${selected.size} ausgewählt` }),
      h('button', { type: 'button', class: 'btn btn-small', onclick: () => doBulk('ack') }, 'In Bearbeitung setzen'),
      h('button', { type: 'button', class: 'btn btn-small', onclick: () => doBulk('closed') }, 'Schließen'),
      status === 'closed' ? h('button', { type: 'button', class: 'btn btn-small', onclick: () => doBulk('open') }, 'Wieder öffnen') : null);
  }

  async function doBulk(st) {
    try {
      const r = await api('/api/alerts/bulk', { method: 'POST', body: { ids: [...selected], status: st } });
      toast(`${r.updated} Alarm(e) auf „${STATUS[st]}“ gesetzt`);
      selected.clear();
      await load();
      ctx.refreshBadge();
    } catch (e) { toast(e.message, 'error'); }
  }

  async function load() {
    const d = await api('/api/alerts', { params: { status, severity, search: searchVal, limit: 300 } });
    const counts = d.counts;
    const n = { active: (counts.open || 0) + (counts.ack || 0), open: counts.open || 0, ack: counts.ack || 0,
      closed: counts.closed || 0, all: (counts.open || 0) + (counts.ack || 0) + (counts.closed || 0) };
    clear(tabsHost).append(...TABS.map(([k, l]) => h('button', {
      type: 'button', role: 'tab', class: ['tab', k === status && 'active'], 'aria-selected': String(k === status),
      onclick: () => update({ status: k === 'active' ? '' : k }),
    }, l, h('span', { class: 'tab-count', text: fmt.num(n[k]) }))));

    clear(listHost);
    if (!d.alerts.length) {
      listHost.appendChild(empty(status === 'closed' ? 'Keine geschlossenen Alarme' : 'Keine Alarme in dieser Ansicht',
        status === 'active' ? 'Neue Alarme erscheinen hier, sobald eine Erkennungsregel anschlägt.' : null,
        status === 'active' ? h('a', { href: '#/rules', class: 'btn' }, 'Erkennungsregeln ansehen') : null));
      renderBulk();
      return;
    }
    const all = h('input', { type: 'checkbox', 'aria-label': 'Alle auswählen' });
    all.addEventListener('change', () => {
      listHost.querySelectorAll('input[data-id]').forEach((c) => { c.checked = all.checked; if (all.checked) selected.add(Number(c.dataset.id)); else selected.delete(Number(c.dataset.id)); });
      renderBulk();
    });
    listHost.appendChild(h('div', { class: 'table-scroll' }, h('table', { class: 'table alerts' },
      h('thead', {}, h('tr', {},
        editable ? h('th', { class: 'col-check' }, all) : null,
        h('th', { text: 'Alarm' }), h('th', { text: 'Betrifft' }), h('th', { class: 'num', text: 'Treffer' }),
        h('th', { text: 'Zuletzt' }), h('th', { text: 'Status' }), h('th', { text: 'Zuständig' }))),
      h('tbody', {}, d.alerts.map((a) => {
        const cb = editable ? h('input', { type: 'checkbox', dataset: { id: a.id }, 'aria-label': `Alarm ${a.id} auswählen`, checked: selected.has(a.id) }) : null;
        cb?.addEventListener('change', () => { if (cb.checked) selected.add(a.id); else selected.delete(a.id); renderBulk(); });
        cb?.addEventListener('click', (e) => e.stopPropagation());
        const tr = h('tr', { class: `clickable edge-${a.severity}`, onclick: () => ctx.navigate(`#/alerts/${a.id}`) },
          editable ? h('td', { class: 'col-check' }, cb) : null,
          h('td', {}, h('a', { href: `#/alerts/${a.id}`, class: 'alert-name', text: a.rule_name }),
            h('div', { class: 'alert-sub' }, sevBadge(a.severity), h('span', { class: 'muted', text: `#${a.id}` }),
              a.comments ? h('span', { class: 'muted', text: `${a.comments} Notiz${a.comments === 1 ? '' : 'en'}` }) : null)),
          h('td', {}, a.group_value ? h('div', { class: 'mono', text: a.group_value }) : null,
            a.hosts?.length ? h('div', { class: 'muted small', text: a.hosts.slice(0, 3).join(', ') + (a.hosts.length > 3 ? ` +${a.hosts.length - 3}` : '') }) : null),
          h('td', { class: 'num', text: fmt.num(a.count) }),
          h('td', { title: fmt.time(a.last_seen), text: fmt.rel(a.last_seen) }),
          h('td', {}, statusBadge(a.status)),
          h('td', { text: a.assignee || '–' }));
        return tr;
      })))));
    if (d.total > d.alerts.length) {
      listHost.appendChild(h('p', { class: 'muted', text: `Es werden die ersten ${d.alerts.length} von ${fmt.num(d.total)} Alarmen angezeigt. Filter verwenden, um die Liste einzugrenzen.` }));
    }
    renderBulk();
  }

  await load();
  const timer = setInterval(() => { if (!selected.size) load().catch(() => {}); }, 30000);
  return () => clearInterval(timer);
}

// ------------------------------------------------------------------ Detail

async function renderDetail(main, ctx, id) {
  const editable = ctx.can('analyst');
  const host = h('div', { class: 'alert-detail' });
  main.append(h('div', { class: 'crumbs' }, h('a', { href: '#/alerts', text: 'Alarme' }), h('span', { text: ` / #${id}` })), host);

  async function save(body, msg) {
    try {
      const a = await api(`/api/alerts/${id}`, { method: 'PATCH', body });
      toast(msg);
      draw(a);
      ctx.refreshBadge();
    } catch (e) { toast(e.message, 'error'); }
  }

  function closeDialog() {
    const res = select(RESOLUTIONS.map((r) => [r, r]), RESOLUTIONS[0]);
    const note = h('textarea', { rows: 3, placeholder: 'Optional: Was wurde festgestellt oder unternommen?' });
    dialog({
      title: 'Alarm schließen',
      body: h('div', { class: 'form' }, field('Ergebnis', res), field('Notiz', note)),
      actions: [
        { label: 'Abbrechen' },
        {
          label: 'Alarm schließen', primary: true,
          onClick: async () => {
            const text = note.value.trim();
            await save({ status: 'closed', resolution: res.value + (text ? `: ${text}` : '') }, 'Alarm geschlossen');
          },
        },
      ],
    });
  }

  function searchHref(a) {
    let q = a.rule?.query || '';
    if (a.rule?.group_by && a.group_value && a.group_value !== '(unbekannt)') {
      q = `(${q}) ${a.rule.group_by}:${quoteValue(a.group_value)}`;
    }
    return `#/search?${new URLSearchParams({ q, from: Math.floor(a.first_seen - 300), to: Math.ceil(a.last_seen + 300) })}`;
  }

  function draw(a) {
    const groupLabel = a.rule?.group_by ? (FIELD_LABELS[a.rule.group_by] || a.rule.group_by) : 'Gruppe';
    const actions = [];
    if (editable) {
      if (a.status !== 'closed') {
        if (a.status === 'open' || a.assignee !== ctx.user.username) {
          actions.push(h('button', { type: 'button', class: 'btn btn-primary', onclick: () => save({ status: 'ack', assignee: ctx.user.username }, 'Alarm übernommen') }, 'Übernehmen'));
        }
        actions.push(h('button', { type: 'button', class: 'btn', onclick: closeDialog }, 'Schließen …'));
      } else {
        actions.push(h('button', { type: 'button', class: 'btn', onclick: () => save({ status: 'open' }, 'Alarm wieder geöffnet') }, 'Wieder öffnen'));
      }
    }
    actions.push(h('a', { class: 'btn', href: searchHref(a) }, 'Events in der Suche öffnen'));
    if (a.rule) actions.push(h('a', { class: 'btn', href: `#/rules/${a.rule.id}` }, 'Regel ansehen'));

    const note = h('textarea', { rows: 3, placeholder: 'Notiz für das Team, z. B. was geprüft wurde' });
    clear(host).append(
      h('header', { class: `detail-head edge-${a.severity}` },
        h('div', {},
          h('h1', { text: a.rule_name }),
          h('div', { class: 'detail-badges' }, sevBadge(a.severity), statusBadge(a.status),
            a.assignee ? h('span', { class: 'muted', text: `zuständig: ${a.assignee}` }) : null)),
        h('div', { class: 'detail-actions' }, actions)),
      a.rule?.description ? h('p', { class: 'lead', text: a.rule.description }) : null,
      h('dl', { class: 'facts' },
        a.group_value ? [h('dt', { text: groupLabel }), h('dd', { class: 'mono', text: a.group_value })] : null,
        h('dt', { text: 'Treffer' }), h('dd', { text: fmt.num(a.count) }),
        h('dt', { text: 'Erstes Auftreten' }), h('dd', { text: fmt.time(a.first_seen) }),
        h('dt', { text: 'Letztes Auftreten' }), h('dd', { text: `${fmt.time(a.last_seen)} (${fmt.rel(a.last_seen)})` }),
        a.hosts.length ? [h('dt', { text: 'Hosts' }), h('dd', { text: a.hosts.join(', ') })] : null,
        a.resolution ? [h('dt', { text: 'Ergebnis' }), h('dd', { text: a.resolution })] : null,
        a.rule ? [h('dt', { text: 'Regel' }), h('dd', { class: 'mono', text: a.rule.query })] : null),

      h('section', { class: 'panel' },
        h('div', { class: 'panel-head' }, h('h2', { text: 'Beispiel-Events' }),
          h('span', { class: 'muted', text: `die letzten ${a.samples.length} von ${fmt.num(a.count)}` })),
        h('div', { class: 'table-scroll' }, h('table', { class: 'events compact' },
          h('thead', {}, h('tr', {}, h('th', { class: 'col-time', text: 'Zeit' }), h('th', { class: 'col-host', text: 'Host' }), h('th', { text: 'Nachricht' }))),
          h('tbody', {}, a.samples.slice().reverse().map((s) => h('tr', {},
            h('td', { class: 'col-time', text: fmt.time(s.ts) }),
            h('td', { class: 'col-host', text: s.host || '–' }),
            h('td', { class: 'col-msg mono', text: s.message }))))))),

      h('section', { class: 'panel' },
        h('div', { class: 'panel-head' }, h('h2', { text: 'Verlauf' })),
        h('ol', { class: 'timeline' },
          h('li', {}, h('span', { class: 'tl-when', text: fmt.time(a.created) }), h('span', { text: 'Alarm ausgelöst' })),
          a.comments.map((c) => h('li', {},
            h('span', { class: 'tl-when', text: fmt.time(c.ts) }),
            h('span', { class: 'tl-who', text: c.username }),
            h('p', { class: 'tl-text', text: c.text })))),
        editable ? h('form', {
          class: 'comment-form',
          onsubmit: async (e) => {
            e.preventDefault();
            if (!note.value.trim()) return;
            try {
              draw(await api(`/api/alerts/${id}/comments`, { method: 'POST', body: { text: note.value } }));
              toast('Notiz gespeichert');
            } catch (ex) { toast(ex.message, 'error'); }
          },
        }, note, h('button', { type: 'submit', class: 'btn' }, 'Notiz speichern')) : null));
  }

  draw(await api(`/api/alerts/${id}`));
}
