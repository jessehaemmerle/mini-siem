import { api } from '../api.js';
import { quoteValue } from './search.js';
import { ALERT_SEV, FIELD_LABELS, STATUS, clear, dialog, empty, field, fmt, h, select, sevBadge, statusBadge, toast } from '../ui.js';

const TABS = [
  ['active', 'Zu bearbeiten'], ['open', 'Offen'], ['ack', 'In Bearbeitung'], ['closed', 'Geschlossen'], ['all', 'Alle'],
];
const RESOLUTIONS = ['Echter Vorfall – behoben', 'Fehlalarm', 'Erwartetes Verhalten', 'Doppelt gemeldet', 'Sonstiges'];

export async function render(main, ctx) {
  if (ctx.parts[0]) return renderDetail(main, ctx, Number(ctx.parts[0]));
  return renderList(main, ctx);
}

// Dialog "Alarm schließen" – auf Liste und Detailseite gleich
function closeDialog(alertName, onConfirm) {
  const res = select(RESOLUTIONS.map((r) => [r, r]), RESOLUTIONS[0]);
  const note = h('textarea', { rows: 3, placeholder: 'Optional: Was wurde festgestellt oder unternommen?' });
  dialog({
    title: 'Alarm schließen',
    body: h('div', { class: 'form' },
      h('p', { class: 'muted', text: alertName }),
      field('Ergebnis', res), field('Notiz für das Team', note)),
    actions: [
      { label: 'Abbrechen' },
      {
        label: 'Alarm schließen', primary: true,
        onClick: () => {
          const text = note.value.trim();
          return onConfirm(res.value + (text ? `: ${text}` : ''));
        },
      },
    ],
  });
}

async function patch(id, body) {
  return api(`/api/alerts/${id}`, { method: 'PATCH', body });
}

// ------------------------------------------------------------------ Liste

async function renderList(main, ctx) {
  const p = ctx.params;
  const status = p.get('status') || 'active';
  const severity = p.get('severity') || '';
  const searchVal = p.get('search') || '';
  const selected = new Set();
  const editable = ctx.can('analyst');

  const sevSel = select([['', 'Alle Schweregrade'], ...Object.entries(ALERT_SEV)], severity, { 'aria-label': 'Nach Schweregrad filtern' });
  const searchIn = h('input', { type: 'search', value: searchVal, placeholder: 'Regel, IP, Host, Person …', 'aria-label': 'Alarme durchsuchen' });
  const tabsHost = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Status' });
  const bulk = h('div', { class: 'bulkbar hidden', role: 'region', 'aria-label': 'Sammelaktionen' });
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
    h('div', { class: 'toolbar filterbar' }, tabsHost, h('div', { class: 'spacer' }), sevSel, searchIn),
    bulk, listHost);

  function renderBulk() {
    clear(bulk);
    bulk.classList.toggle('hidden', selected.size === 0);
    if (!selected.size) return;
    bulk.append(
      h('span', { text: `${selected.size} ausgewählt` }),
      h('button', { type: 'button', class: 'btn btn-small', onclick: () => doBulk('ack') }, 'Auf „In Bearbeitung“ setzen'),
      h('button', { type: 'button', class: 'btn btn-small', onclick: () => doBulk('closed') }, 'Schließen'),
      status === 'closed' ? h('button', { type: 'button', class: 'btn btn-small', onclick: () => doBulk('open') }, 'Wieder öffnen') : null,
      h('button', { type: 'button', class: 'btn btn-small btn-quiet', onclick: () => { selected.clear(); load(); } }, 'Auswahl aufheben'));
  }

  async function doBulk(st) {
    try {
      const r = await api('/api/alerts/bulk', { method: 'POST', body: { ids: [...selected], status: st } });
      toast(`${r.updated} ${r.updated === 1 ? 'Alarm' : 'Alarme'} auf „${STATUS[st]}“ gesetzt`);
      selected.clear();
      await load();
      ctx.refreshBadge();
    } catch (e) { toast(e.message, 'error'); }
  }

  async function quick(a, body, msg) {
    try {
      await patch(a.id, body);
      toast(msg);
      await load();
      ctx.refreshBadge();
    } catch (e) { toast(e.message, 'error'); }
  }

  function quickActions(a) {
    if (!editable || a.status === 'closed') return null;
    const mine = a.status === 'ack' && a.assignee === ctx.user.username;
    return h('span', { class: 'quick' },
      mine ? null : h('button', {
        type: 'button', class: 'btn btn-small', 'aria-label': `${a.rule_name} übernehmen`,
        onclick: (e) => { e.stopPropagation(); quick(a, { status: 'ack', assignee: ctx.user.username }, 'Alarm übernommen'); },
      }, 'Übernehmen'),
      h('button', {
        type: 'button', class: 'btn btn-small btn-quiet', 'aria-label': `${a.rule_name} schließen`,
        onclick: (e) => {
          e.stopPropagation();
          closeDialog(a.rule_name, (resolution) => quick(a, { status: 'closed', resolution }, 'Alarm geschlossen'));
        },
      }, 'Schließen …'));
  }

  async function load() {
    const d = await api('/api/alerts', { params: { status, severity, search: searchVal, limit: 300 } });
    const c = d.counts;
    const n = { active: (c.open || 0) + (c.ack || 0), open: c.open || 0, ack: c.ack || 0,
      closed: c.closed || 0, all: (c.open || 0) + (c.ack || 0) + (c.closed || 0) };
    clear(tabsHost).append(...TABS.map(([k, l]) => h('button', {
      type: 'button', role: 'tab', class: 'tab', 'aria-selected': String(k === status),
      onclick: () => update({ status: k === 'active' ? '' : k }),
    }, l, h('span', { class: 'tab-count', text: fmt.num(n[k]) }))));

    clear(listHost);
    if (!d.alerts.length) {
      const filtered = severity || searchVal;
      listHost.appendChild(filtered
        ? empty('Keine Alarme für diesen Filter', 'Filter zurücksetzen, um alle Alarme dieser Ansicht zu sehen.',
          h('button', { type: 'button', class: 'btn', onclick: () => update({ severity: '', search: '' }) }, 'Filter zurücksetzen'))
        : status === 'active'
          ? empty('Nichts zu bearbeiten', 'Neue Alarme erscheinen hier, sobald eine Erkennungsregel anschlägt.',
            h('a', { href: '#/rules', class: 'btn' }, 'Erkennungsregeln ansehen'))
          : empty(`Keine Alarme mit Status „${TABS.find((x) => x[0] === status)[1]}“`));
      renderBulk();
      return;
    }
    const all = h('input', { type: 'checkbox', 'aria-label': 'Alle angezeigten Alarme auswählen' });
    all.addEventListener('change', () => {
      listHost.querySelectorAll('input[data-id]').forEach((cb) => {
        cb.checked = all.checked;
        if (all.checked) selected.add(Number(cb.dataset.id)); else selected.delete(Number(cb.dataset.id));
      });
      renderBulk();
    });
    listHost.appendChild(h('div', { class: 'table-scroll' }, h('table', { class: 'table alerts' },
      h('caption', { class: 'sr-only', text: 'Alarme' }),
      h('thead', {}, h('tr', {},
        editable ? h('th', { class: 'col-check' }, h('label', { class: 'check-hit' }, all)) : null,
        h('th', { class: 'col-sev', text: 'Schweregrad' }), h('th', { text: 'Alarm' }), h('th', { class: 'num', text: 'Treffer' }),
        h('th', { class: 'col-last', text: 'Zuletzt' }), h('th', { class: 'col-who', text: 'Status' }),
        editable ? h('th', {}, h('span', { class: 'sr-only', text: 'Aktionen' })) : null)),
      h('tbody', {}, d.alerts.map((a) => {
        const cb = editable ? h('input', { type: 'checkbox', dataset: { id: a.id }, 'aria-label': `${a.rule_name} auswählen`, checked: selected.has(a.id) }) : null;
        cb?.addEventListener('change', () => { if (cb.checked) selected.add(a.id); else selected.delete(a.id); renderBulk(); });
        const hosts = (a.hosts || []).filter((x) => x !== a.group_value);
        return h('tr', { class: `clickable edge-${a.severity}`, onclick: () => ctx.navigate(`#/alerts/${a.id}`) },
          editable ? h('td', { class: 'col-check', onclick: (e) => e.stopPropagation() }, h('label', { class: 'check-hit' }, cb)) : null,
          h('td', { class: 'col-sev' }, sevBadge(a.severity)),
          h('td', {},
            h('a', { href: `#/alerts/${a.id}`, class: 'cell-title', text: a.rule_name }),
            h('div', { class: 'cell-sub' },
              h('span', { class: 'only-mobile' }, sevBadge(a.severity)),
              a.group_value ? h('span', { class: 'mono', text: a.group_value }) : null,
              hosts.length ? h('span', { text: `auf ${hosts.slice(0, 3).join(', ')}${hosts.length > 3 ? ` und ${hosts.length - 3} weiteren` : ''}` }) : null,
              a.comments ? h('span', { text: `${a.comments} ${a.comments === 1 ? 'Notiz' : 'Notizen'}` }) : null)),
          h('td', { class: 'num', text: fmt.num(a.count) }),
          h('td', { class: 'col-last nowrap', title: fmt.time(a.last_seen), text: fmt.rel(a.last_seen) }),
          h('td', { class: 'col-who' }, statusBadge(a.status), a.assignee ? h('div', { class: 'small muted', text: a.assignee }) : null),
          editable ? h('td', { class: 'row-actions' }, quickActions(a)) : null);
      })))));
    if (d.total > d.alerts.length) {
      listHost.appendChild(h('p', { class: 'muted', text: `Angezeigt werden die ersten ${d.alerts.length} von ${fmt.num(d.total)} Alarmen. Mit Filtern lässt sich die Liste eingrenzen.` }));
    }
    renderBulk();
  }

  await load();
  const timer = setInterval(() => { if (!selected.size && !document.querySelector('dialog[open]')) load().catch(() => {}); }, 30000);
  return () => clearInterval(timer);
}

// ------------------------------------------------------------------ Detail

async function renderDetail(main, ctx, id) {
  const editable = ctx.can('analyst');
  const host = h('div');
  main.append(h('nav', { class: 'crumbs', 'aria-label': 'Brotkrumen' }, h('a', { href: '#/alerts', text: 'Alarme' }), h('span', { text: ` / Alarm ${id}` })), host);

  async function save(body, msg) {
    try {
      draw(await patch(id, body));
      toast(msg);
      ctx.refreshBadge();
    } catch (e) { toast(e.message, 'error'); }
  }

  function searchHref(a) {
    let q = a.rule?.query || '';
    if (a.rule?.group_by && a.group_value && a.group_value !== '(unbekannt)') {
      q = `(${q}) ${a.rule.group_by}:${quoteValue(a.group_value)}`;
    }
    return `#/search?${new URLSearchParams({ q, from: Math.floor(a.first_seen - 300), to: Math.ceil(a.last_seen + 300) })}`;
  }

  function draw(a) {
    const groupLabel = a.rule?.group_by ? (FIELD_LABELS[a.rule.group_by] || a.rule.group_by) : 'Betrifft';
    const actions = [];
    if (editable) {
      if (a.status !== 'closed') {
        if (a.status === 'open' || a.assignee !== ctx.user.username) {
          actions.push(h('button', { type: 'button', class: 'btn btn-primary', onclick: () => save({ status: 'ack', assignee: ctx.user.username }, 'Alarm übernommen') }, 'Übernehmen'));
        }
        actions.push(h('button', { type: 'button', class: 'btn', onclick: () => closeDialog(a.rule_name, (resolution) => save({ status: 'closed', resolution }, 'Alarm geschlossen')) }, 'Schließen …'));
      } else {
        actions.push(h('button', { type: 'button', class: 'btn', onclick: () => save({ status: 'open' }, 'Alarm wieder geöffnet') }, 'Wieder öffnen'));
      }
    }
    actions.push(h('a', { class: 'btn btn-quiet', href: searchHref(a) }, 'Events in der Suche'));

    const note = h('textarea', { rows: 3, placeholder: 'Was wurde geprüft? Was ist der nächste Schritt?', 'aria-label': 'Notiz' });
    clear(host).append(
      h('header', { class: 'detail-head' },
        h('div', {},
          h('h1', { text: a.rule_name }),
          h('div', { class: 'detail-badges' }, sevBadge(a.severity), statusBadge(a.status),
            a.assignee ? h('span', { class: 'small muted', text: `zuständig: ${a.assignee}` }) : null)),
        h('div', { class: 'detail-actions' }, actions)),
      a.rule?.description ? h('p', { class: 'lead', text: a.rule.description }) : null,

      h('div', { class: 'detail-layout' },
        h('div', {},
          h('section', { class: 'section' },
            h('div', { class: 'section-head' }, h('h2', { text: 'Beispiel-Events' }),
              h('span', { class: 'muted', text: a.count > a.samples.length ? `die letzten ${a.samples.length} von ${fmt.num(a.count)}` : `${fmt.num(a.count)} insgesamt` })),
            h('div', { class: 'table-scroll' }, h('table', { class: 'events compact' },
              h('thead', {}, h('tr', {}, h('th', { class: 'col-time', text: 'Zeit' }), h('th', { class: 'col-host', text: 'Host' }), h('th', { text: 'Nachricht' }))),
              h('tbody', {}, a.samples.slice().reverse().map((s) => h('tr', {},
                h('td', { class: 'col-time', text: fmt.time(s.ts) }),
                h('td', { class: 'col-host', text: s.host || '–' }),
                h('td', { class: 'col-msg mono', text: s.message })))))))),

        h('aside', {},
          h('dl', { class: 'facts' },
            a.group_value ? [h('dt', { text: groupLabel }), h('dd', { class: 'mono', text: a.group_value })] : null,
            h('dt', { text: 'Treffer' }), h('dd', { text: fmt.num(a.count) }),
            h('dt', { text: 'Erstes Auftreten' }), h('dd', { text: fmt.time(a.first_seen) }),
            h('dt', { text: 'Letztes Auftreten' }), h('dd', { text: `${fmt.time(a.last_seen)} (${fmt.rel(a.last_seen)})` }),
            a.hosts.length ? [h('dt', { text: 'Hosts' }), h('dd', { text: a.hosts.join(', ') })] : null,
            a.resolution ? [h('dt', { text: 'Ergebnis' }), h('dd', { text: a.resolution })] : null,
            a.rule ? [h('dt', { text: 'Regel' }), h('dd', {}, h('a', { href: `#/rules/${a.rule.id}`, text: 'Regel ansehen' }))] : null),

          h('section', { class: 'section' },
            h('div', { class: 'section-head' }, h('h2', { text: 'Verlauf' })),
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
                if (!note.value.trim()) { note.focus(); return; }
                try {
                  draw(await api(`/api/alerts/${id}/comments`, { method: 'POST', body: { text: note.value } }));
                  toast('Notiz gespeichert');
                } catch (ex) { toast(ex.message, 'error'); }
              },
            }, note, h('button', { type: 'submit', class: 'btn' }, 'Notiz speichern')) : null))));
    document.title = `${a.rule_name} – Mini-SIEM`;
  }

  draw(await api(`/api/alerts/${id}`));
}
