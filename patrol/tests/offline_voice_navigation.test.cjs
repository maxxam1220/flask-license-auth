/* Actual IndexedDB/save UI; only network, media and final navigation are controlled. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM, VirtualConsole } = require('jsdom');
const { IDBFactory } = require('fake-indexeddb');
const stamp = Date.parse('2026-11-09T02:00:00Z');
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
async function waitFor(read, description) {
  const until = Date.now() + 2500;
  do { if (await read()) return; await new Promise(resolve => setTimeout(resolve, 5)); } while (Date.now() < until);
  assert.fail('Timed out: ' + description);
}
async function setup(t, options = {}) {
  const hidden = { personal_day: '2026-11-09', slot: 'any', stage: 'execute', frequency: 'daily', workflow_mode: 'two_stage', period_key: '2026-11-09', point_revision: 'r1' };
  const errors = [], console = new VirtualConsole(), events = [], uploads = [], routes = [];
  console.on('jsdomError', error => errors.push(error));
  const shellUI = '<div data-offline-status></div><section data-offline-saved hidden><h2 id="offline-saved-title"></h2><p data-offline-saved-message></p></section><button data-offline-sync>Sync</button><button data-offline-cancel-sync>Cancel</button><ul data-offline-queue></ul>';
  const dom = new JSDOM(`<body ${options.shell ? 'data-offline-shell' : ''} data-offline-workspace="true" data-offline-user="12" data-offline-version="1"><main>${options.shell ? shellUI : ''}<div class="checkin-card"><form id="inspection-form" action="/c/test-point/confirm" method="post">${Object.entries(hidden).map(([key, value]) => `<input type="hidden" name="${key}" value="${value}">`).join('')}<textarea name="note"></textarea><button type="submit">OK</button></form></div></main></body>`,
    { url: `https://local.invalid/${options.shell ? 'offline' + (options.queuedId ? '?queued=' + options.queuedId : '') : 'c/test-point'}`, runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: console });
  const win = dom.window, form = win.document.querySelector('form');
  win.indexedDB = new IDBFactory(); win.isSecureContext = true; win.Date.now = () => stamp;
  if (options.queuedId) win.crypto.randomUUID = () => options.queuedId;
  win.HTMLElement.prototype.scrollIntoView = () => {};
  class Channel {
    constructor() { this.port1 = { close() {} }; this.port2 = { close() {}, postMessage: data => this.port1.onmessage?.({ data }) }; }
  }
  win.MessageChannel = Channel;
  Object.defineProperty(win.navigator, 'serviceWorker', { value: { register: async () => ({ active: { postMessage: (_, ports) => ports[0].postMessage({ ready: true, audioReady: true, audioVersion: 'patrol-v1', audioRevision: 'natural-female-1', checklistVersion: 1 }) } }) } });
  win.PatrolI18n = { t: (text, values = {}) => text.replace(/\{(\w+)\}/g, (_, key) => values[key] ?? ''), getLocale: () => 'vi', setLocale() {}, getPreferences: () => ({}), acceptPreferences: () => false };
  const manifest = { ok: true, version: 1, checklist_version: 1, owner: 'owner-12', identity: { id: 12, auth_version: 1, binding_id: 8, name: 'Test', ui_language: 'vi', role: 'executor' },
    server_time: new Date(stamp).toISOString(), day: '2026-11-09', capture_until: '2026-11-09T16:00:00Z', sync_until: '2026-11-10T16:00:00Z', csrf_token: 'csrf',
    points: [{ token: 'test-point', code: '4M-G01', name: 'Dining', floor: '4M', frequency: 'daily', workflow_mode: 'two_stage', stage: 'execute',
      period_key: '2026-11-09', slots: ['any'], used_slots: [], executed_slots: [], grant: 'grant', revision: 'r1', checklist: null }] };
  const wait = deferred(), upload = deferred();
  const voice = {
    armResult(kind, id, destination, actor) { events.push(['arm', kind, id, destination, actor]); },
    report(kind, details) { events.push(['report', kind, details.id, details.auto]); this.lastResult = { kind, id: details.id }; if (options.reportThrows) throw new Error('Optional audio failed'); },
    state() { return { lastResult: this.lastResult || null }; },
    waitForIdle(ms) { events.push(['wait', ms]); if (options.waitThrows) throw new Error('Optional wait failed'); return options.waitRejects ? Promise.reject(new Error('Audio denied')) : wait.promise; },
    cancel() { events.push(['cancel']); }, clearResult() { events.push(['clear']); }
  };
  if (!options.noVoice) win.PatrolVoice = voice;
  win.fetch = async (url, init) => {
    if (url === '/api/offline/prepare') return response(manifest);
    if (url === '/api/offline/status') return response({ ok: true, owner: manifest.owner, csrf_token: 'fresh' });
    if (url === '/api/ui-preferences') return response({ ok: true, ui_language: 'vi' });
    assert.equal(url, '/api/offline/sync'); const entry = JSON.parse(init.body.get('entry')); uploads.push(entry); events.push(['upload']);
    if (options.holdUpload) await (options.abortableUpload ? new Promise((resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(new win.DOMException('Cancelled', 'AbortError')), { once: true });
      upload.promise.then(resolve, reject);
    }) : upload.promise);
    if (options.uploadThrows) throw new Error('Offline');
    if (options.blockedReply) return response({ ok: false, retryable: false, code: 'quota', message_source: '此點今日可登記的次數已完成或已暫存。' }, 409);
    events.push(['ack']);
    return response({ ok: true, status: 'saved', client_id: entry.client_id, receipt_url: options.noReceiptURL ? undefined : '/executions/1/success' });
  };
  win.__navigate = destination => { routes.push(destination); events.push(['navigate', destination]); if (options.navigationThrows) throw new Error('Navigation unavailable'); };
  if (options.fastDeadline) {
    const realTimeout = win.setTimeout.bind(win);
    win.setTimeout = (callback, ms, ...args) => realTimeout(callback, ms === 4500 ? 25 : ms, ...args);
  }
  // jsdom cannot navigate documents; intercept only the final browser boundary.
  win.eval(fs.readFileSync(path.join(__dirname, '../static/offline.js'), 'utf8').replaceAll('location.assign(', 'window.__navigate('));
  t.after(async () => {
    upload.resolve(); wait.resolve();
    await waitFor(() => form.dataset.submitting !== 'true', 'submission cleanup');
    await new Promise(resolve => setTimeout(resolve, 20)); await win.PatrolOffline.close(); win.close(); assert.deepEqual(errors, []);
  });
  await new Promise(resolve => win.document.readyState === 'loading' ? win.document.addEventListener('DOMContentLoaded', resolve, { once: true }) : resolve());
  if (options.shell) await win.PatrolOffline.prepare();
  await waitFor(async () => (await win.PatrolOffline.getState()).prepared, 'prepared manifest');
  return { win, form, voice, manifest, core: win.PatrolOffline, events, uploads, routes, wait, upload,
    submit() { form.dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true })); } };
}

test('server ACK precedes same-document result audio, and navigation waits only for audio completion', async t => {
  const ui = await setup(t, { holdUpload: true }); ui.submit();
  await waitFor(() => ui.uploads.length === 1, 'upload starts');
  assert.equal(ui.events.some(row => row[0] === 'report'), false, 'no success before ACK'); assert.equal(ui.routes.length, 0);
  ui.upload.resolve(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'result playback');
  assert.equal((await ui.core.getState()).pending, 0); assert.equal(ui.routes.length, 0);
  assert(ui.events.findIndex(row => row[0] === 'ack') < ui.events.findIndex(row => row[0] === 'report'));
  assert.deepEqual(ui.events.find(row => row[0] === 'wait'), ['wait', 4500]);
  assert.equal(ui.events.find(row => row[0] === 'report')[1], 'saved_execute');
  assert.equal(ui.win.document.querySelector('[data-offline-form-progress]').textContent, '已同步完成');
  assert.equal(ui.win.document.querySelector('[data-offline-cancel-submit]').textContent, '查看結果');
  await ui.core.getState(); assert.equal(ui.win.document.querySelector('[data-offline-form-progress]').textContent, '已同步完成', 'state rendering cannot erase result');
  ui.wait.resolve(); await waitFor(() => ui.routes.length === 1, 'receipt route');
  assert.deepEqual(ui.routes, ['/executions/1/success']); assert.equal(ui.uploads.length, 1);
});

test('view result skips unfinished audio immediately without another save', async t => {
  const ui = await setup(t); ui.submit(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'audio wait');
  ui.win.document.querySelector('[data-offline-cancel-submit]').click();
  await waitFor(() => ui.routes.length === 1, 'skip navigates');
  assert(ui.events.some(row => row[0] === 'cancel')); assert.equal(ui.uploads.length, 1);
  ui.wait.resolve(); await new Promise(resolve => setTimeout(resolve, 10)); assert.equal(ui.routes.length, 1);
});

for (const option of ['noVoice', 'reportThrows', 'waitThrows', 'waitRejects']) test(`${option} cannot turn a confirmed save into a retry or block navigation`, async t => {
  const ui = await setup(t, { [option]: true }); ui.submit();
  await waitFor(() => ui.routes.length === 1, 'receipt without optional audio');
  assert.deepEqual(ui.routes, ['/executions/1/success']); assert.equal(ui.uploads.length, 1);
  assert.equal((await ui.core.getState()).pending, 0); assert.equal(ui.win.document.querySelector('[data-offline-form-error]'), null);
});

test('a stalled audio helper is independently capped at 4500 ms', async t => {
  const ui = await setup(t, { fastDeadline: true }); ui.submit();
  await waitFor(() => ui.routes.length === 1, 'bounded navigation');
  assert.deepEqual(ui.events.find(row => row[0] === 'wait'), ['wait', 4500]); assert.equal(ui.uploads.length, 1);
});

test('durable offline save reports only local storage and then opens its pending record', async t => {
  const ui = await setup(t); Object.defineProperty(ui.win.navigator, 'onLine', { value: false, configurable: true }); ui.submit();
  await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'local result playback');
  assert.equal((await ui.core.getState()).pending, 1); assert.equal(ui.uploads.length, 0);
  assert.equal(ui.events.find(row => row[0] === 'report')[1], 'offline_stored');
  assert.equal(ui.win.document.querySelector('[data-offline-form-progress]').textContent, '已暫存在這支手機');
  ui.wait.resolve(); await waitFor(() => ui.routes.length === 1, 'pending record route'); assert.match(ui.routes[0], /^\/offline\?queued=/);
});

test('owner change before ACK never plays the previous account result', async t => {
  const ui = await setup(t, { holdUpload: true }); ui.submit(); await waitFor(() => ui.uploads.length === 1, 'upload pending');
  await ui.core.lock(); ui.upload.resolve(); await waitFor(() => ui.routes.length === 1, 'locked route');
  assert.deepEqual(ui.routes, ['/offline']); assert.equal(ui.events.some(row => row[0] === 'report'), false);
});

test('owner change during audio wait opens only the neutral offline page', async t => {
  const ui = await setup(t); ui.submit(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'audio wait');
  ui.manifest.owner = 'owner-99'; ui.manifest.identity.id = 99;
  await ui.core.prepare(); ui.wait.resolve(); await waitFor(() => ui.routes.length === 1, 'changed owner route');
  assert.deepEqual(ui.routes, ['/offline']); assert(ui.events.some(row => row[0] === 'clear')); assert.equal(ui.uploads.length, 1);
});

test('unexpected upload failure after durable save still offers local result once', async t => {
  const ui = await setup(t); ui.core.sync = async () => { throw new Error('Optional transport unavailable'); }; ui.submit();
  await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'durable catch feedback');
  assert.equal((await ui.core.getState()).pending, 1); assert.equal(ui.uploads.length, 0);
  assert.equal(ui.events.find(row => row[0] === 'report')[1], 'offline_stored');
  ui.wait.resolve(); await waitFor(() => ui.routes.length === 1, 'durable catch route');
  assert.match(ui.routes[0], /^\/offline\?queued=/); assert.equal(ui.events.filter(row => row[0] === 'report').length, 1);
});

test('a rejected local save never waits for or announces successful result audio', async t => {
  const ui = await setup(t); ui.manifest.points[0].revision = 'changed'; await ui.core.prepare(); ui.submit();
  await waitFor(() => ui.win.document.querySelector('[data-offline-form-error]') && ui.form.dataset.submitting !== 'true', 'validation rejected');
  assert.equal(ui.uploads.length, 0); assert.equal(ui.routes.length, 0); assert.equal((await ui.core.getState()).pending, 0);
  assert.deepEqual(ui.events.filter(row => row[0] === 'report').map(row => row[1]), ['not_saved']);
  assert.equal(ui.events.some(row => row[0] === 'wait'), false);
});

test('pagehide cancels pending receipt navigation even when BFCache restores before the waiter settles', async t => {
  const ui = await setup(t); ui.submit(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'audio wait');
  ui.win.dispatchEvent(new ui.win.PageTransitionEvent('pagehide', { persisted: true }));
  ui.win.dispatchEvent(new ui.win.PageTransitionEvent('pageshow', { persisted: true }));
  await waitFor(() => ui.form.dataset.submitting !== 'true', 'abandoned result cleanup');
  ui.wait.resolve(); await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(ui.routes.length, 0); assert.equal(ui.uploads.length, 1); assert(ui.events.some(row => row[0] === 'clear'));
});

test('ACK arriving after a pagehide cannot speak or redirect the restored old form', async t => {
  const ui = await setup(t, { holdUpload: true }); ui.submit(); await waitFor(() => ui.uploads.length === 1, 'upload pending');
  ui.win.dispatchEvent(new ui.win.PageTransitionEvent('pagehide', { persisted: true }));
  ui.win.dispatchEvent(new ui.win.PageTransitionEvent('pageshow', { persisted: true }));
  ui.upload.resolve(); await waitFor(() => ui.form.dataset.submitting !== 'true', 'late ACK cleanup');
  assert.equal(ui.routes.length, 0); assert.equal(ui.events.some(row => row[0] === 'report'), false); assert.equal((await ui.core.getState()).pending, 0);
});

test('a deliberate Home click abandons delayed receipt navigation without undoing the saved result', async t => {
  const ui = await setup(t); ui.submit(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'audio wait');
  const home = ui.win.document.createElement('a'); home.href = '/dashboard'; ui.win.document.body.append(home);
  // Prevent jsdom's unavailable navigation only after the real document handler.
  ui.win.addEventListener('click', event => event.preventDefault(), { once: true });
  home.dispatchEvent(new ui.win.MouseEvent('click', { bubbles: true, cancelable: true, button: 0 }));
  await waitFor(() => ui.form.dataset.submitting !== 'true', 'Home result cleanup');
  ui.wait.resolve(); await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(ui.routes.length, 0); assert.equal((await ui.core.getState()).pending, 0); assert.equal(ui.uploads.length, 1);
});

test('navigation failure cannot announce local pending after an acknowledged record or route twice', async t => {
  const ui = await setup(t, { navigationThrows: true }); ui.submit(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'audio wait');
  ui.wait.resolve(); await waitFor(() => ui.form.dataset.submitting !== 'true', 'form restored');
  assert.deepEqual(ui.routes, ['/executions/1/success']); assert.equal(ui.events.filter(row => row[0] === 'report').length, 1);
  assert.equal(ui.win.document.querySelector('[data-offline-form-error]'), null); assert.equal(ui.form.querySelector('button').disabled, true);
  assert.equal(ui.win.document.querySelector('[data-offline-form-progress]').textContent, '已同步完成');
  ui.submit(); await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(ui.uploads.length, 1); assert.equal(ui.events.filter(row => row[0] === 'report').length, 1, 'the old saved form cannot become a new failed attempt');
  ui.win.document.querySelector('[data-offline-cancel-submit]').click();
  assert.deepEqual(ui.routes, ['/executions/1/success', '/executions/1/success'], 'explicit result retry never submits attendance');
});

test('permanent server refusal reports not_saved and preserves its reason instead of pending success', async t => {
  const ui = await setup(t, { blockedReply: true }); ui.submit(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'blocked feedback');
  assert.equal(ui.events.find(row => row[0] === 'report')[1], 'not_saved');
  assert.equal(ui.win.document.querySelector('.offline-submit-progress').dataset.resultState, 'blocked');
  assert.match(ui.win.document.querySelector('[data-offline-form-progress]').textContent, /此點今日可登記的次數已完成或已暫存/);
  assert.equal((await ui.core.getState()).blocked, 1); ui.wait.resolve(); await waitFor(() => ui.routes.length === 1, 'blocked details');
  assert.match(ui.routes[0], /^\/offline\?queued=/);
});

test('offline saved banner keeps permanent refusal reason and replay meaning after sync', async t => {
  const ui = await setup(t, { shell: true, blockedReply: true, queuedId: '5f289294-9d29-4b67-a940-c556efb9a4ed' });
  await ui.core.enqueue({ token: 'test-point', checklist: [] });
  ui.win.document.querySelector('[data-offline-sync]').click();
  await waitFor(async () => (await ui.core.getState()).blocked === 1 && !(await ui.core.getState()).sync.running, 'rejected queue');
  const banner = ui.win.document.querySelector('[data-offline-saved]');
  assert.equal(banner.hidden, false); assert.equal(banner.dataset.resultState, 'blocked');
  assert.match(banner.textContent, /本筆未完成/); assert.match(banner.textContent, /此點今日可登記的次數已完成或已暫存/);
  await waitFor(() => !ui.win.document.querySelector('[data-offline-sync]').disabled, 'UI handler settled after rejection');
  assert.equal(ui.voice.state().lastResult.kind, 'not_saved');
  assert.equal(ui.win.document.querySelector('[data-offline-sync]').disabled, false, 'existing explicit retry/remove workflow remains available');
});

test('rapid sync clicks cannot narrate a stale result while the first upload is running', async t => {
  const ui = await setup(t, { shell: true, holdUpload: true }); await ui.core.enqueue({ token: 'test-point', checklist: [] }); ui.events.length = 0;
  const button = ui.win.document.querySelector('[data-offline-sync]'); button.click(); button.click();
  await waitFor(() => ui.uploads.length === 1, 'one upload');
  assert.equal(ui.events.some(row => row[0] === 'report'), false, 'no stale offline_stored announcement from the second click');
  ui.upload.resolve(); await waitFor(() => ui.events.some(row => row[0] === 'report'), 'one final result');
  assert.deepEqual(ui.events.filter(row => row[0] === 'report').map(row => row[1]), ['sync_confirmed']);
});

test('cancelled sync with no ACK announces unfinished result and can retry afterwards', async t => {
  const ui = await setup(t, { shell: true, holdUpload: true, abortableUpload: true }); await ui.core.enqueue({ token: 'test-point', checklist: [] });
  const button = ui.win.document.querySelector('[data-offline-sync]'); button.click(); await waitFor(() => ui.uploads.length === 1, 'cancellable upload');
  ui.win.document.querySelector('[data-offline-cancel-sync]').click();
  await waitFor(() => ui.events.some(row => row[0] === 'report'), 'cancel outcome');
  assert.equal(ui.voice.state().lastResult.kind, 'not_saved'); assert.equal((await ui.core.getState()).pending, 1); assert.equal(button.disabled, false);
  ui.upload.resolve(); button.click(); await waitFor(() => ui.voice.state().lastResult.kind === 'sync_confirmed', 'retry after cancel');
  assert.equal((await ui.core.getState()).pending, 0); assert.equal(ui.uploads.length, 2);
});

for (const accountAction of ['lock', 'switch']) test(`retained saved result is removed after account ${accountAction}`, async t => {
  const ui = await setup(t, { navigationThrows: true }); ui.submit(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'result ready');
  ui.wait.resolve(); await waitFor(() => ui.form.dataset.submitting !== 'true', 'result retained');
  assert(ui.win.document.querySelector('.offline-submit-progress')); assert.equal(ui.form.querySelector('button').disabled, true);
  if (accountAction === 'lock') await ui.core.lock();
  else { ui.manifest.owner = 'owner-99'; ui.manifest.identity.id = 99; await ui.core.prepare(); }
  assert.equal(ui.win.document.querySelector('.offline-submit-progress'), null, 'no old result or rejection reason in another identity');
});

test('offline sync click reports unfinished synchronization without an upload', async t => {
  const ui = await setup(t, { shell: true }); await ui.core.enqueue({ token: 'test-point', checklist: [] });
  Object.defineProperty(ui.win.navigator, 'onLine', { value: false, configurable: true });
  ui.win.document.querySelector('[data-offline-sync]').click(); await waitFor(() => ui.voice.state().lastResult, 'offline sync result');
  assert.equal(ui.voice.state().lastResult.kind, 'not_saved'); assert.equal(ui.uploads.length, 0); assert.equal((await ui.core.getState()).pending, 1);
});

test('synchronization ACK after pagehide and BFCache does not narrate an abandoned action', async t => {
  const ui = await setup(t, { shell: true, holdUpload: true }); await ui.core.enqueue({ token: 'test-point', checklist: [] });
  ui.win.document.querySelector('[data-offline-sync]').click(); await waitFor(() => ui.uploads.length === 1, 'upload pending');
  ui.win.dispatchEvent(new ui.win.PageTransitionEvent('pagehide', { persisted: true }));
  ui.win.dispatchEvent(new ui.win.PageTransitionEvent('pageshow', { persisted: true }));
  ui.upload.resolve(); await waitFor(async () => (await ui.core.getState()).pending === 0 && !(await ui.core.getState()).sync.running, 'late ACK committed');
  await new Promise(resolve => setTimeout(resolve, 10)); assert.equal(ui.events.some(row => row[0] === 'report'), false); assert.equal(ui.routes.length, 0);
});

test('ACK without a usable receipt URL retains confirmed meaning and opens the local confirmed entry', async t => {
  const ui = await setup(t, { noReceiptURL: true }); ui.submit(); await waitFor(() => ui.events.some(row => row[0] === 'wait'), 'ACK feedback');
  assert.equal(ui.events.find(row => row[0] === 'report')[1], 'saved_execute'); assert.equal((await ui.core.getState()).pending, 0);
  assert.equal(ui.win.document.querySelector('.offline-submit-progress').dataset.resultState, 'saved');
  ui.wait.resolve(); await waitFor(() => ui.routes.length === 1, 'confirmed entry route'); assert.match(ui.routes[0], /^\/offline\?queued=/);
});
