import { api } from '../api.js';
import { ALERT_SEV, FIELD_LABELS, clear, confirmDialog, empty, field, fmt, h, select, sevBadge, toast } from '../ui.js';

const GROUP_FIELDS = ['host', 'src_ip', 'dst_ip', 'user', 'app', 'event_id', 'dst_port', 'category', 'source_ip'];

export function describe(r) {
  const win = fmt.duration(r.window);
  const by = r.group_by ? ` je ${FIELD_LABELS[r.group_by] || r.group_by}` : '';
  if (r.distinct_field) {
    return `Alarm, wenn ${fmt.num(r.threshold)} verschiedene Werte von „${FIELD_LABELS[r.distinct_field] || r.distinct_field}“ innerhalb von ${win}${by} auftreten.`;
  }
  if (r.threshold <= 1) return `Alarm bei jedem Treffer${by}. Weitere Treffer innerhalb von ${win} werden zusammengefasst.`;
  return `Alarm ab ${fmt.num(r.threshold)} Treffern innerhalb von ${win}${by}.`;
}

export async function render(main, ctx) {
  if (ctx.parts[0]) return renderEditor(main, ctx, ctx.parts[0] === 'new' ? null : Number(ctx.parts[0]));
  return renderList(main, ctx);
}

async function renderList(main, ctx) {
  const editable = ctx.can('analyst');
  const listHost = h('div');
  main.append(
    h('div', { class: 'page-head' },
      h('h1', { text: 'Erkennungsregeln' }),
      h('div', { class: 'spacer' }),
      editable ? h('a', { class: 'btn btn-primary', href: '#/rules/new' }, 'Neue Regel') : null),
    h('p', { class: 'lead', text: 'Regeln durchsuchen alle eingehenden Events laufend und lösen Alarme aus. Sie verwenden dieselbe Abfragesprache wie die Suche.' }),
    listHost);

  async function load() {
    const { rules } = await api('/api/rules');
    clear(listHost);
    if (!rules.length) {
      listHost.appendChild(empty('Noch keine Regeln', 'Legen Sie eine Regel an oder speichern Sie eine Suche als Regel.'));
      return;
    }
    listHost.appendChild(h('ul', { class: 'rule-list' }, rules.map((r) => {
      const toggle = h('input', { type: 'checkbox', class: 'switch', checked: !!r.enabled, disabled: !editable,
        'aria-label': `${r.name} ${r.enabled ? 'deaktivieren' : 'aktivieren'}` });
      toggle.addEventListener('change', async () => {
        try {
          await api(`/api/rules/${r.id}`, { method: 'PUT', body: { ...r, enabled: toggle.checked } });
          toast(toggle.checked ? `„${r.name}“ aktiviert` : `„${r.name}“ deaktiviert`);
          load();
        } catch (e) { toggle.checked = !toggle.checked; toast(e.message, 'error'); }
      });
      return h('li', { class: ['rule', !r.enabled && 'rule-off'] },
        h('div', { class: 'rule-toggle' }, toggle),
        h('div', { class: 'rule-main' },
          h('a', { href: `#/rules/${r.id}`, class: 'rule-name', text: r.name }),
          r.description ? h('p', { class: 'rule-desc', text: r.description }) : null,
          h('p', { class: 'rule-logic', text: describe(r) }),
          h('code', { class: 'rule-query', text: r.query })),
        h('div', { class: 'rule-side' },
          sevBadge(r.severity),
          r.alerts_open ? h('a', { href: `#/alerts?status=active&search=${encodeURIComponent(r.name)}`, class: 'rule-open', text: `${r.alerts_open} offen` }) : null,
          h('span', { class: 'muted small', text: r.last_alert ? `zuletzt ${fmt.rel(r.last_alert)}` : 'noch nie ausgelöst' })));
    })));
  }
  await load();
}

async function renderEditor(main, ctx, id) {
  const editable = ctx.can('analyst');
  let rule = { name: '', description: '', query: ctx.params.get('q') || '', severity: 'medium', threshold: 1,
    window: 3600, group_by: 'host', distinct_field: null, enabled: true };
  if (id) rule = await api(`/api/rules/${id}`);

  const name = h('input', { value: rule.name, required: true, maxlength: 200, placeholder: 'z. B. VPN: Anmeldung aus dem Ausland' });
  const desc = h('textarea', { rows: 2, placeholder: 'Wozu dient die Regel und was ist im Alarmfall zu tun?' }, rule.description || '');
  const query = h('textarea', { rows: 3, class: 'mono', spellcheck: false, placeholder: 'z. B. app:sshd action:failure' }, rule.query);
  const queryState = h('p', { class: 'hint', 'aria-live': 'polite' });
  const sev = select(Object.entries(ALERT_SEV), rule.severity);
  const mode = rule.distinct_field ? 'distinct' : rule.threshold > 1 ? 'count' : 'each';
  const modeSel = select([['each', 'bei jedem Treffer'], ['count', 'ab einer Anzahl von Treffern'], ['distinct', 'ab einer Anzahl verschiedener Werte']], mode);
  const threshold = h('input', { type: 'number', min: 1, value: Math.max(rule.threshold, 1), class: 'input-short' });
  const windowMin = h('input', { type: 'number', min: 1, max: 10080, value: Math.max(1, Math.round(rule.window / 60)), class: 'input-short' });
  const groupSel = select([['', 'nicht getrennt (alle zusammen)'], ...GROUP_FIELDS.map((f) => [f, FIELD_LABELS[f]])], rule.group_by || '');
  const distinctSel = select(GROUP_FIELDS.map((f) => [f, FIELD_LABELS[f]]), rule.distinct_field || 'dst_port');
  const enabled = h('input', { type: 'checkbox', checked: !!rule.enabled, id: 'rule-enabled' });
  const sentence = h('p', { class: 'rule-logic big' });
  const testHours = select([[1, 'letzte Stunde'], [24, 'letzte 24 Stunden'], [168, 'letzte 7 Tage'], [720, 'letzte 30 Tage']], 24);
  const testHost = h('div', { class: 'test-result' });
  const thresholdField = field('Anzahl', threshold);
  const distinctField = field('Verschiedene Werte von', distinctSel, 'z. B. Zielport für einen Portscan oder Benutzer für Password-Spraying.');

  function current() {
    const m = modeSel.value;
    return {
      name: name.value.trim(), description: desc.value.trim(), query: query.value.trim(), severity: sev.value,
      threshold: m === 'each' ? 1 : Math.max(1, parseInt(threshold.value, 10) || 1),
      window: Math.max(1, parseInt(windowMin.value, 10) || 5) * 60,
      group_by: groupSel.value || null,
      distinct_field: m === 'distinct' ? distinctSel.value : null,
      enabled: enabled.checked,
    };
  }

  function refresh() {
    const m = modeSel.value;
    thresholdField.classList.toggle('hidden', m === 'each');
    distinctField.classList.toggle('hidden', m !== 'distinct');
    sentence.textContent = describe(current());
  }
  [modeSel, threshold, windowMin, groupSel, distinctSel].forEach((el) => el.addEventListener('input', refresh));

  let checkTimer;
  query.addEventListener('input', () => {
    clearTimeout(checkTimer);
    checkTimer = setTimeout(async () => {
      const q = query.value.trim();
      if (!q) { queryState.textContent = ''; return; }
      const r = await api('/api/query/check', { params: { q } });
      queryState.textContent = r.ok ? 'Abfrage ist gültig.' : r.error;
      queryState.classList.toggle('error', !r.ok);
      query.classList.toggle('invalid', !r.ok);
    }, 350);
  });

  async function runTest() {
    clear(testHost).appendChild(h('p', { class: 'muted', text: 'Test läuft …' }));
    try {
      const r = await api('/api/rules/test', { method: 'POST', body: { ...current(), name: current().name || 'Test', hours: Number(testHours.value) } });
      clear(testHost).append(
        h('p', { class: 'test-summary', text: r.matched
          ? `${fmt.num(r.matched)}${r.truncated ? '+' : ''} passende Events – ${r.alert_count === 0 ? 'daraus wäre kein Alarm entstanden' : r.alert_count === 1 ? 'daraus wäre 1 Alarm entstanden' : `daraus wären ${fmt.num(r.alert_count)} Alarme entstanden`}.`
          : 'Keine passenden Events in diesem Zeitraum.' }),
        r.alerts.length ? h('table', { class: 'table compact' },
          h('thead', {}, h('tr', {}, h('th', { text: 'Betrifft' }), h('th', { class: 'num', text: 'Treffer' }), h('th', { text: 'Von' }), h('th', { text: 'Bis' }))),
          h('tbody', {}, r.alerts.slice(0, 15).map((a) => h('tr', {},
            h('td', { class: 'mono', text: a.group_value || '–' }), h('td', { class: 'num', text: fmt.num(a.count) }),
            h('td', { text: fmt.time(a.first_seen) }), h('td', { text: fmt.time(a.last_seen) }))))) : null,
        r.samples.length ? [h('h4', { text: 'Zuletzt passende Events' }),
          h('ul', { class: 'samples' }, r.samples.map((s) => h('li', { class: 'mono' },
            h('span', { class: 'muted', text: `${fmt.time(s.ts)}  ${s.host || ''}  ` }), s.message)))] : null);
    } catch (e) {
      clear(testHost).appendChild(h('p', { class: 'error', text: e.message }));
    }
  }

  async function saveRule(e) {
    e.preventDefault();
    try {
      const body = current();
      const saved = id ? await api(`/api/rules/${id}`, { method: 'PUT', body }) : await api('/api/rules', { method: 'POST', body });
      toast(id ? 'Regel gespeichert' : 'Regel angelegt');
      if (!id) ctx.navigate(`#/rules/${saved.id}`);
    } catch (ex) { toast(ex.message, 'error'); }
  }

  async function deleteRule() {
    if (!(await confirmDialog('Regel löschen?', `„${rule.name}“ wird gelöscht. Bestehende Alarme bleiben erhalten.`, 'Regel löschen'))) return;
    try {
      await api(`/api/rules/${id}`, { method: 'DELETE' });
      toast('Regel gelöscht');
      ctx.navigate('#/rules');
    } catch (e) { toast(e.message, 'error'); }
  }

  const fs = h('fieldset', { disabled: !editable, class: 'form' },
    field('Name', name),
    field('Beschreibung', desc),
    h('div', { class: 'field' },
      h('label', { for: 'rule-query', text: 'Abfrage' }),
      Object.assign(query, { id: 'rule-query' }),
      queryState,
      h('p', { class: 'hint' }, 'Gleiche Syntax wie in der Suche. ',
        h('button', { type: 'button', class: 'linklike', onclick: () => ctx.navigate(`#/search?${new URLSearchParams({ q: query.value.trim(), range: '24h' })}`) }, 'In der Suche ausprobieren'))),
    h('div', { class: 'form-row' }, field('Schweregrad des Alarms', sev), field('Alarm auslösen', modeSel)),
    h('div', { class: 'form-row' }, thresholdField, distinctField, field('Zeitfenster in Minuten', windowMin)),
    field('Getrennt zählen je', groupSel, 'Für jeden Wert entsteht ein eigener Alarm – z. B. je angreifender IP-Adresse.'),
    sentence,
    h('label', { class: 'check', for: 'rule-enabled' }, enabled, 'Regel ist aktiv'));

  main.append(
    h('div', { class: 'crumbs' }, h('a', { href: '#/rules', text: 'Regeln' }), h('span', { text: id ? ` / ${rule.name}` : ' / Neue Regel' })),
    h('div', { class: 'page-head' }, h('h1', { text: id ? 'Regel bearbeiten' : 'Neue Regel' }),
      rule.builtin ? h('span', { class: 'tag', text: 'mitgeliefert' }) : null),
    h('div', { class: 'editor-layout' },
      h('form', { class: 'panel', onsubmit: saveRule }, fs,
        editable ? h('div', { class: 'form-actions' },
          h('button', { type: 'submit', class: 'btn btn-primary' }, id ? 'Regel speichern' : 'Regel anlegen'),
          h('a', { class: 'btn', href: '#/rules' }, 'Abbrechen'),
          h('div', { class: 'spacer' }),
          id ? h('button', { type: 'button', class: 'btn btn-danger', onclick: deleteRule }, 'Löschen') : null) : null),
      h('section', { class: 'panel' },
        h('div', { class: 'panel-head' }, h('h2', { text: 'Regel testen' })),
        h('p', { class: 'muted', text: 'Spielt die Regel gegen bereits gespeicherte Events ab, ohne Alarme zu erzeugen.' }),
        h('div', { class: 'inline' }, testHours, h('button', { type: 'button', class: 'btn', onclick: runTest }, 'Test starten')),
        testHost)));
  refresh();
  if (!id) name.focus();
}
