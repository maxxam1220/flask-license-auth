/* Real DOM form serialization plus the actual offline core; requests stay mocked. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM, VirtualConsole } = require('jsdom');
const { IDBFactory } = require('fake-indexeddb');
const script = name => fs.readFileSync(path.join(__dirname, '../static', name), 'utf8');
const stamp = Date.parse('2026-11-09T02:00:00Z');
const labels = (zh, id, vi) => ({ 'zh-Hant': zh, id, vi });
const checklist = { key: 'dining_v1', version: 1, title: labels('餐廳點檢', 'Pemeriksaan ruang makan', 'Kiểm tra nhà ăn'), items: [
  { id: 'dining.a1', label: labels('洗手槽', 'Wastafel', 'Bồn rửa'), source_code: 'A1' },
  { id: 'dining.a2', label: labels('廚餘箱', 'Tempat sisa makanan', 'Thùng đựng thức ăn thừa'), source_code: 'A2' }
] };
const response = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
const waitFor = async (read, description) => {
  const until = Date.now() + 2000;
  do { if (await read()) return; await new Promise(resolve => setTimeout(resolve, 5)); } while (Date.now() < until);
  assert.fail('Timed out: ' + description);
};
async function setup(t, { shell = false, stage = 'execute' } = {}) {
  const hidden = { personal_day: '2026-11-09', slot: 'am', stage, frequency: 'daily2', workflow_mode: 'two_stage', period_key: '2026-11-09', point_revision: 'revision-1' };
  const inputs = Object.entries(hidden).map(([name, value]) => `<input type="hidden" name="${name}" value="${value}">`).join('');
  const fields = `<div data-offline-report-fields><textarea name="note"></textarea><input type="checkbox" name="is_abnormal"><input type="file" name="photos" multiple></div>`;
  const offline = `<div data-offline-status></div><div data-offline-point><h2 data-offline-point-name></h2><form data-offline-checkin action="/offline">
    <button type="submit" data-offline-save disabled>OK</button><fieldset data-offline-fields disabled>
    <fieldset data-offline-checklist hidden><legend data-offline-checklist-title></legend><div data-offline-checklist-options></div><p data-offline-checklist-count></p></fieldset>${fields}</fieldset></form></div><ul data-offline-queue></ul>`;
  const normal = `<main><div class="checkin-card"><form id="inspection-form" method="post" action="/c/test-point/confirm">${inputs}<fieldset data-checklist><p class="checklist-count"></p>
    <label class="checklist-option"><input type="checkbox" name="checklist" value="dining.a1">A1</label><label class="checklist-option"><input type="checkbox" name="checklist" value="dining.a2">A2</label>
    </fieldset><button type="submit">OK</button></form></div></main>`;
  const errors = [], console = new VirtualConsole();
  console.on('jsdomError', error => { if (!error.message.includes('Not implemented: navigation')) errors.push(error); });
  const dom = new JSDOM(`<body ${shell ? 'data-offline-shell' : 'data-offline-workspace="true" data-offline-user="12" data-offline-version="1"'}>${shell ? offline : normal}</body>`,
    { url: 'https://local.invalid/' + (shell ? 'offline?point=test-point' : 'c/test-point'), runScripts: 'outside-only', virtualConsole: console });
  const win = dom.window, uploads = [];
  const manifest = { ok: true, version: 1, checklist_version: 1, owner: 'test-owner', identity: { id: 12, auth_version: 1, binding_id: 8, name: 'Test', ui_language: 'vi', role: stage === 'inspect' ? 'inspector' : 'executor' },
    server_time: new Date(stamp).toISOString(), day: '2026-11-09', capture_until: '2026-11-09T16:00:00Z', sync_until: '2026-11-10T16:00:00Z', csrf_token: 'csrf',
    points: [{ token: 'test-point', code: '4M-G01', name: 'Dining', floor: '4M', frequency: 'daily2', workflow_mode: 'two_stage', stage,
      period_key: '2026-11-09', slots: ['am', 'pm'], used_slots: [], executed_slots: [], grant: 'grant', revision: 'revision-1', checklist }] };
  win.indexedDB = new IDBFactory(); win.isSecureContext = true; win.Date.now = () => stamp; win.HTMLElement.prototype.scrollIntoView = () => {};
  class Channel {
    constructor() { this.port1 = { close() {} }; this.port2 = { close() {}, postMessage: data => this.port1.onmessage?.({ data }) }; }
  }
  win.MessageChannel = Channel;
  Object.defineProperty(win.navigator, 'serviceWorker', { value: { register: async () => ({ active: { postMessage: (_, ports) => ports[0].postMessage({ ready: true, audioReady: true, audioVersion: 'patrol-v1', audioRevision: 'natural-female-1', checklistVersion: 1, calendarVersion: 1 }) } }) } });
  let locale = 'vi';
  win.PatrolI18n = { t: (text, values = {}) => text.replace(/\{(\w+)\}/g, (_, key) => values[key] ?? ''), getLocale: () => locale,
    setLocale: value => { locale = value; }, getPreferences: () => ({ ui_language: locale }), acceptPreferences: () => false };
  win.fetch = async (url, init) => {
    if (url === '/api/offline/prepare') return response(manifest);
    if (url === '/api/offline/status') return response({ ok: true, owner: manifest.owner, csrf_token: 'fresh' });
    if (url === '/api/ui-preferences') return response({ ok: true, ui_language: locale });
    assert.equal(url, '/api/offline/sync'); const entry = JSON.parse(init.body.get('entry')); uploads.push(entry);
    return response({ ok: true, status: 'saved', client_id: entry.client_id, receipt_url: '/executions/1/success' });
  };
  if (!shell) win.eval(script('checklist.js'));
  win.eval(script('offline.js'));
  t.after(async () => {
    await waitFor(() => win.document.querySelector('form').dataset.submitting !== 'true', 'submission cleanup');
    await new Promise(resolve => setTimeout(resolve, 20));
    await win.PatrolOffline?.close(); win.close(); assert.deepEqual(errors, []);
  });
  await new Promise(resolve => win.document.readyState === 'loading' ? win.document.addEventListener('DOMContentLoaded', resolve, { once: true }) : resolve());
  if (shell) await win.PatrolOffline.prepare();
  await waitFor(async () => (await win.PatrolOffline.getState()).prepared, 'prepared manifest');
  if (shell) await waitFor(() => win.document.querySelectorAll('[name="checklist"]').length === 2, 'offline choices');
  return { win, uploads, manifest, form: win.document.querySelector('form'), core: win.PatrolOffline, changeLocale(value) { locale = value; win.document.dispatchEvent(new win.CustomEvent('patrol:locale-changed')); } };
}

for (const stage of ['execute', 'visit', 'inspect']) test(`prepared-online ${stage} serializes checked inputs before disabling and sends one selected ID`, async t => {
  const ui = await setup(t, { stage });
  const choices = ui.form.querySelectorAll('[name="checklist"]');
  choices[0].checked = true; choices[0].dispatchEvent(new ui.win.Event('change', { bubbles: true }));
  assert.equal(ui.form.querySelector('button').disabled, false);
  ui.form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true }));
  await waitFor(() => ui.uploads.length === 1, 'actual sync POST');
  assert.deepEqual(ui.uploads[0].checklist, ['dining.a1']); assert(!Object.hasOwn(ui.uploads[0], 'checklist_snapshot'));
  await waitFor(async () => (await ui.core.getState()).pending === 0, 'ACK removes queue');
  assert.equal(ui.win.document.querySelector('[data-offline-form-error]'), null);
});

test('offline execute keeps checklist outside inspector-only fields, disables empty confirmation, and preserves locale selections', async t => {
  const ui = await setup(t, { shell: true });
  const group = ui.form.querySelector('[data-offline-checklist]'), button = ui.form.querySelector('button');
  assert.equal(group.hidden, false); assert.equal(ui.form.querySelector('[data-offline-report-fields]').hidden, true); assert.equal(button.disabled, true);
  let choices = ui.form.querySelectorAll('[name="checklist"]');
  assert(choices[0].closest('label').textContent.includes('Bồn rửa')); assert.equal(choices[0].checked, false);
  choices[1].checked = true; choices[1].dispatchEvent(new ui.win.Event('change', { bubbles: true }));
  await waitFor(() => !button.disabled, 'checked confirmation');
  const leave = new ui.win.Event('beforeunload', { cancelable: true }); ui.win.dispatchEvent(leave); assert.equal(leave.defaultPrevented, true);
  ui.changeLocale('id'); await waitFor(() => group.textContent.includes('Wastafel'), 'Indonesian labels');
  choices = ui.form.querySelectorAll('[name="checklist"]'); assert.equal(choices[0].checked, false); assert.equal(choices[1].checked, true);
  ui.form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true }));
  await waitFor(async () => (await ui.core.getState()).pending === 1, 'saved offline draft');
  const row = (await ui.core.getState()).queue[0]; assert.deepEqual(Array.from(row.checklist), ['dining.a2']); assert.equal(ui.uploads.length, 0);
  assert(ui.win.document.querySelector('[data-offline-queue]').textContent.includes('Tempat sisa makanan'));
});

test('forced offline empty submit cannot bypass button state and keeps form available', async t => {
  const ui = await setup(t, { shell: true, stage: 'visit' });
  ui.form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true }));
  await waitFor(() => ui.win.document.querySelector('[data-offline-status]').textContent.includes('至少勾選'), 'empty validation');
  assert.equal((await ui.core.getState()).pending, 0); assert.equal(ui.uploads.length, 0);
  assert.equal(ui.form.querySelector('[data-offline-checklist]').hidden, false);
});

for (const defaultChecked of [false, true]) test(`saved prepared-online checklist stays disabled when navigation remains on a ${defaultChecked ? 'server-returned draft' : 'fresh form'}`, async t => {
  const ui = await setup(t);
  const choice = ui.form.querySelector('[name="checklist"]'), button = ui.form.querySelector('button');
  choice.defaultChecked = defaultChecked;
  choice.checked = true; choice.dispatchEvent(new ui.win.Event('change', { bubbles: true }));
  ui.form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true }));
  await waitFor(async () => ui.uploads.length === 1 && (await ui.core.getState()).pending === 0 && ui.form.dataset.submitting !== 'true', 'saved form settled');
  assert.equal(choice.checked, false);
  assert.equal(button.disabled, true, 'a saved and reset form must still require a fresh selection');
  assert.equal(ui.form.querySelector('.checklist-count').textContent, '0 / 2');
});

test('failed local save preserves a server-returned checklist draft for review', async t => {
  const ui = await setup(t);
  const choice = ui.form.querySelector('[name="checklist"]'), button = ui.form.querySelector('button');
  choice.defaultChecked = true; choice.checked = true;
  choice.dispatchEvent(new ui.win.Event('change', { bubbles: true }));
  ui.manifest.points[0].revision = 'changed-point';
  await ui.core.prepare();
  ui.form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true }));
  await waitFor(() => ui.win.document.querySelector('[data-offline-form-error]') && ui.form.dataset.submitting !== 'true', 'failed form settled');
  assert.equal((await ui.core.getState()).pending, 0);
  assert.equal(ui.uploads.length, 0);
  assert.equal(choice.checked, true);
  assert.equal(button.disabled, false);
  assert.equal(ui.form.querySelector('.checklist-count').textContent, '1 / 2');
});
