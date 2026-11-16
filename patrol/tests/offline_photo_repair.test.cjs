/* Recovery changes photo bytes only after an owned, unreceived UUID is verified. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { indexedDB, IDBFactory } = require('fake-indexeddb');
const { JSDOM, VirtualConsole } = require('jsdom');
const fs = require('node:fs');
const path = require('node:path');
const { createCore } = require('../static/offline.js');
const stamp = Date.parse('2026-11-16T01:44:31Z');
const response = (json, status = 200) => new Response(JSON.stringify(json), { status });
const photo = (text = 'original', name = '現場照片.jpg') => new File([text], name, { type: 'image/jpeg' });
const nativeRead = Blob.prototype.arrayBuffer;
const input = { token: 'photo-point', note: '有煙蒂和廚餘', is_abnormal: true, checklist: ['clean'] };
const labels = text => ({ 'zh-Hant': text, id: text, vi: text });
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }

async function store(h, name = 'queue', mutation) {
  return new Promise((resolve, reject) => {
    const open = (h.indexedDB || indexedDB).open(h.databaseName);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result, tx = db.transaction(name, mutation ? 'readwrite' : 'readonly');
      const target = tx.objectStore(name), req = target.getAll(); let result;
      req.onsuccess = () => { result = req.result; if (mutation) for (const item of result) { mutation(item); target.put(item); } };
      tx.oncomplete = () => { db.close(); resolve(result); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  });
}
async function harness(t, options = {}, shared) {
  const server = shared || {
    now: stamp, receipts: [], uploads: [], received: new Map(), receipt: null, upload: null,
    navigator: { onLine: true },
    manifest: { ok: true, version: 1, checklist_version: 1, owner: 'u1v1b1-inspector-general',
      identity: { id: 1, auth_version: 1, binding_id: 1, role: 'inspector', category: 'general' },
      server_time: new Date(stamp).toISOString(), day: '2026-11-16', capture_until: '2026-11-16T16:00:00Z',
      sync_until: '2026-11-17T16:00:00Z', csrf_token: 'test-csrf',
      points: [{ id: 1, token: 'photo-point', code: '1F-G011', name: '人行道', frequency: 'daily2', workflow_mode: 'spot',
        stage: 'inspect', period_key: '2026-11-16', slots: ['am', 'pm'], used_slots: [], executed_slots: [],
        revision: 'test-revision', grant: 'test-grant', checklist: { key: 'test', version: 1, title: labels('點檢'),
          items: [{ id: 'clean', label: labels('清潔') }] } }] }
  };
  const databaseName = options.databaseName || 'offline-repair-' + crypto.randomUUID();
  const fetch = async (url, init) => {
    if (url.endsWith('/prepare')) return response(server.manifest);
    if (url.endsWith('/status')) return response({ ok: true, owner: server.manifest.owner, csrf_token: 'fresh',
      server_time: server.manifest.server_time, identity: server.manifest.identity });
    if (url.startsWith('/api/offline/receipt/')) {
      const parsed = new URL(url, 'https://local.test'), id = parsed.pathname.split('/').pop();
      assert.equal(parsed.searchParams.get('owner'), server.manifest.owner);
      server.receipts.push(id);
      return server.receipt ? server.receipt(id, init) : response({ ok: true, status: server.received.has(id) ? 'already_synced' : 'not_received',
        owner: server.manifest.owner, client_id: id, ...(server.received.get(id) || {}) });
    }
    assert.equal(url, '/api/offline/sync');
    const entry = JSON.parse(init.body.get('entry'));
    const photos = await Promise.all(init.body.getAll('photos').map(async file => ({ name: file.name, bytes: await file.text() })));
    server.uploads.push({ entry, photos });
    if (server.upload) return server.upload(entry, init);
    server.received.set(entry.client_id, { receipt_url: '/checkins/1', record_id: 1 });
    return response({ ok: true, status: 'saved', client_id: entry.client_id });
  };
  const core = createCore({ indexedDB, crypto: globalThis.crypto, databaseName, now: () => server.now,
    navigator: server.navigator, fetch, broadcast: false, ...options });
  t.after(() => core.close());
  if (!shared) await core.prepare();
  return { core, server, databaseName };
}
async function failed(h) {
  const draft = await h.core.enqueue({ ...input, photos: [photo('old 1'), photo('old 2')] });
  await store(h, 'queue', row => { row.status = 'blocked'; row.error = '照片格式錯誤'; row.retryable = false; });
  return draft;
}
async function snapshot(h) {
  return Promise.all((await store(h)).map(async row => ({ ...row,
    photos: await Promise.all(row.photos.map(async item => ({ ...item, blob: await item.blob.text() }))) })));
}

test('explicit replacement preserves UUID, original confirmation and all non-photo evidence', async t => {
  const h = await harness(t), draft = await failed(h), [before] = await snapshot(h);
  h.server.now += 3600000;
  assert.deepEqual(await h.core.repairPhotos(draft.client_id, [photo('replacement 1'), photo('replacement 2')], true),
    { status: 'repaired', client_id: draft.client_id });
  const [after] = await snapshot(h);
  const { photos: oldPhotos, status, error, retryable, ...identity } = before;
  const { photos, photo_revision, status: nextStatus, error: nextError, retryable: nextRetryable, ...remaining } = after;
  assert.deepEqual(remaining, identity); assert.equal(photo_revision, 1);
  assert.equal(nextStatus, 'pending'); assert.equal(nextError, ''); assert.equal(nextRetryable, true);
  assert.deepEqual(photos.map(item => item.blob), ['replacement 1', 'replacement 2']);
  await h.core.sync();
  assert.equal(h.server.receipts.length, 2);
  const sent = h.server.uploads[0];
  assert.equal(sent.entry.client_id, before.client_id); assert.equal(sent.entry.observed_at, before.observed_at);
  assert.equal(sent.entry.note, before.note); assert.equal(sent.entry.grant, before.grant);
  assert.equal(sent.entry.is_abnormal, true); assert.deepEqual(sent.entry.checklist, ['clean']);
  assert.deepEqual(sent.photos.map(item => item.bytes), ['replacement 1', 'replacement 2']);
  assert.equal((await store(h)).length, 0);
});

for (const mode of ['not-confirmed', 'empty', 'too-many', 'invalid-type', 'offline']) test(mode + ' replacement retains exact original draft', async t => {
  const h = await harness(t), draft = await failed(h), before = await snapshot(h);
  const files = mode === 'empty' ? [] : mode === 'too-many' ? [photo(), photo(), photo(), photo()] :
    mode === 'invalid-type' ? [new File(['x'], 'wrong.txt', { type: 'text/plain' })] : [photo('replacement')];
  if (mode === 'offline') h.server.navigator.onLine = false;
  await assert.rejects(h.core.repairPhotos(draft.client_id, files, mode !== 'not-confirmed'));
  assert.deepEqual(await snapshot(h), before); assert.equal(h.server.receipts.length, 0);
});

for (const mode of ['unknown-status', 'wrong-id', 'not-ok', 'server-error', 'wrong-owner']) test(mode + ' receipt fails closed without replacing photos', async t => {
  const h = await harness(t), draft = await failed(h), before = await snapshot(h);
  h.server.receipt = id => response({ ok: mode !== 'not-ok', status: mode === 'unknown-status' ? 'saved' : 'not_received',
    owner: mode === 'wrong-owner' ? 'someone-else' : h.server.manifest.owner,
    client_id: mode === 'wrong-id' ? crypto.randomUUID() : id }, mode === 'server-error' ? 503 : 200);
  await assert.rejects(h.core.repairPhotos(draft.client_id, [photo('replacement')], true));
  assert.deepEqual(await snapshot(h), before); assert.equal(h.server.uploads.length, 0);
  if (mode === 'wrong-owner') assert.equal((await h.core.getState()).locked, true);
});

test('known server receipt clears stuck row without reading or overwriting selected photos', async t => {
  const h = await harness(t), draft = await failed(h), replacement = photo('replacement');
  replacement.arrayBuffer = () => { throw new Error('New photo must not be read'); };
  h.server.received.set(draft.client_id, { receipt_url: '/checkins/42', record_id: 42 });
  assert.equal((await h.core.repairPhotos(draft.client_id, [replacement], true)).status, 'already_synced');
  assert.equal((await store(h)).length, 0); assert.equal(h.server.uploads.length, 0);
  assert.equal((await store(h, 'receipts'))[0].ack.record_id, 42);
  assert.match((await h.core.getState()).message, /新選的照片未覆蓋原紀錄/);
});

test('late acceptance of original upload settles repaired row before new bytes are sent', async t => {
  const h = await harness(t), draft = await failed(h);
  await h.core.repairPhotos(draft.client_id, [photo('replacement')], true);
  h.server.received.set(draft.client_id, { receipt_url: '/checkins/42', record_id: 42 });
  await h.core.sync(); assert.equal(h.server.uploads.length, 0); assert.equal((await store(h)).length, 0);
  assert.match((await h.core.getState()).message, /新選的照片未覆蓋原紀錄/);
});

test('old in-flight ACK settles revised photos with an explicit non-overwrite notice', async t => {
  const h = await harness(t), draft = await failed(h), begun = deferred(), finish = deferred();
  const peer = await harness(t, { databaseName: h.databaseName }, h.server);
  h.server.upload = entry => { begun.resolve(); return finish.promise.then(() => response({ ok: true, status: 'saved', client_id: entry.client_id })); };
  const syncing = h.core.sync(); await begun.promise; h.server.now += 46000;
  await store(h, 'queue', row => { row.status = 'retry'; row.error = '尚未確認收件'; });
  await peer.core.repairPhotos(draft.client_id, [photo('replacement')], true);
  assert.equal((await store(h))[0].photo_revision, 1);
  finish.resolve(); await syncing;
  assert.equal((await store(h)).length, 0); assert.equal(h.server.uploads.length, 1);
  assert.deepEqual(h.server.uploads[0].photos.map(item => item.bytes), ['old 1', 'old 2']);
  assert.match((await h.core.getState()).message, /新選的照片未覆蓋原紀錄/);
  assert.match((await peer.core.getState()).message, /新選的照片未覆蓋原紀錄/);
});

test('old in-flight rejection cannot overwrite a newer photo repair or its pending status', async t => {
  const h = await harness(t), draft = await failed(h), begun = deferred(), finish = deferred();
  const peer = await harness(t, { databaseName: h.databaseName }, h.server);
  h.server.upload = () => { begun.resolve(); return finish.promise.then(() => response({ ok: false, retryable: false, message: 'Old format failure' }, 400)); };
  const syncing = h.core.sync(); await begun.promise; h.server.now += 46000;
  await store(h, 'queue', row => { row.status = 'retry'; row.error = '尚未確認收件'; });
  await peer.core.repairPhotos(draft.client_id, [photo('replacement')], true);
  const repaired = await snapshot(h); finish.resolve(); await syncing;
  assert.deepEqual(await snapshot(h), repaired);
});

test('same-tab sync, removal and repeat repair are excluded while receipt verification waits', async t => {
  const h = await harness(t), draft = await failed(h), begun = deferred(), receipt = deferred();
  h.server.receipt = id => { begun.resolve(); return receipt.promise.then(() => response({ ok: true, status: 'not_received', owner: h.server.manifest.owner, client_id: id })); };
  const repair = h.core.repairPhotos(draft.client_id, [photo('replacement')], true); await begun.promise;
  assert.equal((await h.core.getState()).sync.running, true);
  await assert.rejects(h.core.remove(draft.client_id, true), { code: 'busy' });
  await assert.rejects(h.core.repairPhotos(draft.client_id, [photo()], true), { code: 'busy' });
  await h.core.sync(); assert.equal(h.server.uploads.length, 0);
  receipt.resolve(); await repair; assert.equal((await h.core.getState()).sync.running, false);
});

test('cross-tab lease blocks replacement and deletion while another tab verifies a receipt', async t => {
  const h = await harness(t), draft = await failed(h), before = await snapshot(h), begun = deferred(), receipt = deferred();
  const peer = await harness(t, { databaseName: h.databaseName }, h.server);
  h.server.receipt = id => { begun.resolve(); return receipt.promise.then(() => response({ ok: true, status: 'not_received', owner: h.server.manifest.owner, client_id: id })); };
  const repair = h.core.repairPhotos(draft.client_id, [photo('replacement')], true); await begun.promise;
  await assert.rejects(peer.core.repairPhotos(draft.client_id, [photo('other')], true), { code: 'busy' });
  await assert.rejects(peer.core.remove(draft.client_id, true), { code: 'busy' });
  await peer.core.sync(); assert.equal(h.server.uploads.length, 0); assert.deepEqual(await snapshot(h), before);
  receipt.resolve(); await repair;
});

for (const mode of ['cancel', 'logout', 'refresh-owner']) test(mode + ' during reading retains old photos and identity', async t => {
  const h = await harness(t), draft = await failed(h), before = await snapshot(h), begun = deferred(), reading = deferred();
  const source = photo('replacement'); source.arrayBuffer = () => { begun.resolve(); return reading.promise.then(() => nativeRead.call(source)); };
  const repair = h.core.repairPhotos(draft.client_id, [source], true); await begun.promise;
  if (mode === 'cancel') h.core.cancelSync();
  else if (mode === 'logout') await h.core.lock();
  else await h.core.prepare();
  reading.resolve(); await assert.rejects(repair, error => ['cancelled', 'owner'].includes(error.code));
  assert.deepEqual(await snapshot(h), before);
});

test('account change during receipt lookup cannot claim original draft or show its receipt', async t => {
  const h = await harness(t), draft = await failed(h), before = await snapshot(h), begun = deferred(), receipt = deferred();
  const owner = h.server.manifest.owner;
  h.server.receipt = id => { begun.resolve(); return receipt.promise.then(() => response({ ok: true, status: 'already_synced', owner, client_id: id })); };
  const repair = h.core.repairPhotos(draft.client_id, [photo('replacement')], true); await begun.promise;
  h.server.manifest.owner = 'u2v1b2-inspector-general'; h.server.manifest.identity = { ...h.server.manifest.identity, id: 2, binding_id: 2 };
  await h.core.prepare(); receipt.resolve(); await assert.rejects(repair, { code: 'owner' });
  assert.deepEqual(await snapshot(h), before); assert.deepEqual((await h.core.getState()).queue, []);
  assert.equal((await store(h, 'receipts')).length, 0);
});

test('expired sync lease and concurrent photo repair cannot upload stale bytes', async t => {
  const h = await harness(t), draft = await failed(h), begun = deferred(), reading = deferred();
  const peer = await harness(t, { databaseName: h.databaseName }, h.server);
  let intercepted = false;
  Blob.prototype.arrayBuffer = function () {
    if (intercepted) return nativeRead.call(this);
    intercepted = true; const source = this; begun.resolve();
    return reading.promise.then(() => nativeRead.call(source));
  };
  try {
    const syncing = h.core.sync(); await begun.promise; h.server.now += 46000;
    // Another tab already diagnosed the stalled file and released its lease.
    await store(h, 'queue', row => { row.status = 'retry'; row.error = '照片讀取失敗'; });
    await peer.core.repairPhotos(draft.client_id, [photo('replacement')], true);
    reading.resolve(); await syncing;
    assert.equal(h.server.uploads.length, 0); assert.equal((await store(h))[0].photo_revision, 1);
    await peer.core.sync(); assert.equal(h.server.uploads[0].photos[0].bytes, 'replacement');
  } finally { reading.resolve(); Blob.prototype.arrayBuffer = nativeRead; }
});

for (const first of ['reject', 'incomplete']) test('native reader fallback preserves exact replacement bytes after ' + first, async t => {
  let readerCalls = 0;
  class Reader { readAsArrayBuffer(file) { readerCalls++; nativeRead.call(file).then(value => { this.result = value; this.onload(); }); } }
  const env = Object.create(globalThis); env.FileReader = Reader;
  const h = await harness(t, { env }), draft = await failed(h), source = photo('fallback bytes');
  source.arrayBuffer = () => first === 'reject' ? Promise.reject(new Error('Native reader failed')) : Promise.resolve(new ArrayBuffer(1));
  await h.core.repairPhotos(draft.client_id, [source], true);
  assert.equal(readerCalls, 1); assert.equal((await snapshot(h))[0].photos[0].blob, 'fallback bytes');
});

test('Response reader remains available after arrayBuffer and FileReader both reject', async t => {
  const env = Object.create(globalThis);
  env.FileReader = class { readAsArrayBuffer() { this.onerror(); } };
  env.Response = class { constructor(file) { this.file = file; } arrayBuffer() { return nativeRead.call(this.file); } };
  const h = await harness(t, { env }), draft = await failed(h), source = photo('response bytes');
  source.arrayBuffer = () => Promise.reject(new Error('Native reader failed'));
  await h.core.repairPhotos(draft.client_id, [source], true);
  assert.equal((await snapshot(h))[0].photos[0].blob, 'response bytes');
});

for (const kind of ['reject', 'incomplete', 'timeout']) test('all readers ' + kind + ' preserves original photos and original failure detail', async t => {
  const env = Object.create(globalThis); env.FileReader = undefined; env.Response = undefined;
  const h = await harness(t, { env, photoReadTimeout: 15 }), draft = await failed(h), before = await snapshot(h), source = photo('replacement');
  source.arrayBuffer = () => kind === 'reject' ? Promise.reject(new Error('Unavailable')) :
    kind === 'incomplete' ? Promise.resolve(new ArrayBuffer(1)) : new Promise(() => {});
  await assert.rejects(h.core.repairPhotos(draft.client_id, [source], true), { code: 'photo_read' });
  assert.deepEqual(await snapshot(h), before); assert.equal(h.server.uploads.length, 0);
});

test('same account with new phone binding cannot repair an old owner grant', async t => {
  const h = await harness(t), draft = await failed(h), before = await snapshot(h);
  h.server.manifest.owner = 'u1v1b2-inspector-general'; h.server.manifest.identity.binding_id = 2;
  await h.core.prepare(); await assert.rejects(h.core.repairPhotos(draft.client_id, [photo('replacement')], true), { code: 'owner' });
  assert.deepEqual(await snapshot(h), before); assert.equal(h.server.receipts.length, 0);
});

async function waitFor(read, description) {
  const until = Date.now() + 2000;
  do { if (await read()) return; await new Promise(resolve => setTimeout(resolve, 5)); } while (Date.now() < until);
  assert.fail('Timed out: ' + description);
}
async function repairUI(t) {
  const errors = [], console = new VirtualConsole(); console.on('jsdomError', error => errors.push(error));
  const dom = new JSDOM('<body data-offline-shell><div data-offline-status></div><ul data-offline-queue></ul></body>',
    { url: 'https://local.invalid/offline', runScripts: 'outside-only', virtualConsole: console });
  const win = dom.window, manifest = {
    ok: true, version: 1, checklist_version: 1, owner: 'repair-owner', identity: { id: 1, auth_version: 1, binding_id: 1, role: 'inspector', ui_language: 'zh-Hant' },
    server_time: new Date(stamp).toISOString(), day: '2026-11-16', capture_until: '2026-11-16T16:00:00Z', sync_until: '2026-11-17T16:00:00Z', csrf_token: 'csrf',
    points: [{ token: 'photo-point', code: '1F-G011', name: '人行道', frequency: 'daily', workflow_mode: 'spot', stage: 'inspect',
      period_key: '2026-11-16', slots: ['any'], used_slots: [], executed_slots: [], grant: 'grant', revision: 'r1', checklist: null }]
  };
  const receiptStarted = deferred(), receiptReady = deferred();
  win.indexedDB = new IDBFactory(); win.isSecureContext = true; win.Date.now = () => stamp;
  win.Blob = Blob; win.File = File; win.FileReader = undefined; win.Response = undefined;
  win.confirm = () => true;
  win.PatrolI18n = { t: (text, values = {}) => text.replace(/\{(\w+)\}/g, (_, key) => values[key] ?? ''), getLocale: () => 'zh-Hant', setLocale() {}, getPreferences: () => ({}), acceptPreferences: () => false };
  class Channel { constructor() { this.port1 = { close() {} }; this.port2 = { close() {}, postMessage: data => this.port1.onmessage?.({ data }) }; } }
  win.MessageChannel = Channel;
  Object.defineProperty(win.navigator, 'serviceWorker', { value: { register: async () => ({ active: { postMessage: (_, ports) => ports[0].postMessage({ ready: true, audioReady: true, audioVersion: 'patrol-v1', audioRevision: 'natural-female-1', checklistVersion: 1, calendarVersion: 1 }) } }) } });
  win.fetch = async url => {
    if (url === '/api/offline/prepare') return response(manifest);
    if (url === '/api/ui-preferences') return response({ ok: true });
    if (url.startsWith('/api/offline/receipt/')) {
      receiptStarted.resolve(); await receiptReady.promise;
      return response({ ok: true, status: 'not_received', owner: manifest.owner, client_id: new URL(url, 'https://local.invalid').pathname.split('/').pop() });
    }
    assert.fail('Unexpected request: ' + url);
  };
  win.eval(fs.readFileSync(path.join(__dirname, '../static/offline.js'), 'utf8'));
  await new Promise(resolve => win.document.readyState === 'loading' ? win.document.addEventListener('DOMContentLoaded', resolve, { once: true }) : resolve());
  const core = win.PatrolOffline;
  t.after(async () => { receiptReady.resolve(); await new Promise(resolve => setTimeout(resolve, 20)); await core.close(); win.close(); assert.deepEqual(errors, []); });
  await core.prepare();
  const h = { core, databaseName: 'patrol-offline-v1', indexedDB: win.indexedDB };
  await core.enqueue({ token: 'photo-point', note: '有煙蒂和廚餘', is_abnormal: true, photos: [photo('old')] });
  await store(h, 'queue', row => { row.status = 'retry'; row.error = '照片讀取失敗'; }); await core.getState();
  await waitFor(() => win.document.querySelector('.offline-photo-repair'), 'repair action');
  return { ...h, win, receiptStarted, receiptReady };
}

for (const result of ['success', 'read-failure', 'logout']) test('photo picker stays connected during receipt lookup and byte copying: ' + result, async t => {
  const ui = await repairUI(t), before = await snapshot(ui), input = ui.win.document.querySelector('.offline-queue-actions input[type=file]');
  const source = photo('replacement'), reading = deferred(), readStarted = deferred(); let fileValue = 'C:\\fakepath\\現場照片.jpg';
  Object.defineProperty(input, 'files', { configurable: true, value: [source] });
  Object.defineProperty(input, 'value', { configurable: true, get: () => fileValue, set: value => { fileValue = value; } });
  source.arrayBuffer = () => {
    assert.equal(input.isConnected, true, 'native picker remains in the document when copying starts');
    assert.notEqual(fileValue, '', 'native selection has not been cleared'); readStarted.resolve();
    return reading.promise.then(() => {
      if (result === 'read-failure') throw new Error('Camera file unavailable');
      if (result !== 'logout') assert.equal(input.isConnected, true, 'native picker remains attached until bytes materialize');
      return nativeRead.call(source);
    });
  };
  input.dispatchEvent(new ui.win.Event('change', { bubbles: true })); await ui.receiptStarted.promise;
  assert.equal(input.isConnected, true, 'receipt-check busy rendering must preserve the file input');
  assert([...ui.win.document.querySelectorAll('.offline-queue-actions button')].every(button => button.disabled));
  ui.receiptReady.resolve(); await readStarted.promise;
  await ui.core.getState();
  assert.equal(ui.win.document.querySelector('.offline-queue-actions input[type=file]'), input);
  // A repeated programmatic change cannot clear or remove the ongoing picker.
  input.dispatchEvent(new ui.win.Event('change', { bubbles: true })); assert.notEqual(fileValue, '');
  if (result === 'logout') {
    await ui.core.lock(); assert.equal(input.isConnected, false, 'privacy locking must still remove account data immediately');
    assert.equal(ui.win.document.querySelector('[data-offline-queue]').children.length, 0);
  }
  reading.resolve(); await waitFor(() => fileValue === '', 'picker cleanup only after repair finishes');
  if (result === 'success') {
    assert.equal(input.isConnected, false, 'completed replacement may rebuild the queue');
    assert.equal((await snapshot(ui))[0].photos[0].blob, 'replacement');
  } else assert.deepEqual(await snapshot(ui), before);
  assert.equal((await ui.core.getState()).sync.running, false);
});
