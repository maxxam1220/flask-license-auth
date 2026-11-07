/* Run with fake-indexeddb on NODE_PATH; no live service or production data. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { indexedDB, IDBObjectStore, IDBDatabase } = require('fake-indexeddb');
const { createCore, validatePhotos, requestPersistence } = require('../static/offline.js');
const stamp = Date.parse('2026-11-06T01:10:00Z');
const response = (json, status = 200) => new Response(JSON.stringify(json), { status, headers: { 'Content-Type': 'application/json' } });
function manifest(overrides = {}) {
  return { ok: true, version: 1, owner: 'u1v1b11inspectorgeneral', identity: { id: 1, auth_version: 1, binding_id: 11, name: 'Test', role: 'inspector', category: 'general' },
    server_time: new Date(stamp).toISOString(), day: '2026-11-06', capture_until: '2026-11-06T16:00:00Z', sync_until: '2026-11-07T16:00:00Z', csrf_token: 'csrf-current',
    points: [{ id: 1, token: 'test-point', code: '1F-G01', name: 'Point', floor: '1F', frequency: 'daily2', workflow_mode: 'spot', stage: 'inspect',
      period_key: '2026-11-06', slots: ['am', 'pm'], used_slots: [], executed_slots: [], grant: 'signed-grant', revision: 'revision-1' }], ...overrides };
}
function harness(options = {}) {
  const state = { manifest: manifest(), now: stamp, calls: [], uploads: [], navigator: { onLine: true }, sync: null, prepare: null, status: null };
  const dbName = options.databaseName || 'offline-test-' + crypto.randomUUID();
  const fetch = async (url, init) => {
    state.calls.push(url);
    if (url.endsWith('/prepare')) return state.prepare ? state.prepare(init) : response(state.manifest);
    if (url.endsWith('/status')) return state.status ? state.status(init) : response({ ok: true, owner: state.manifest.owner, csrf_token: 'fresh-csrf', server_time: new Date(state.now).toISOString(), identity: state.manifest.identity });
    assert.equal(url, '/api/offline/sync');
    const entry = JSON.parse(init.body.get('entry')); state.uploads.push({ entry, init });
    return state.sync ? state.sync(entry, init) : response({ ok: true, status: 'saved', client_id: entry.client_id, receipt_url: '/checkins/1', record_id: 1, received_at: new Date(state.now).toISOString(), observed_at: entry.observed_at });
  };
  const core = createCore({ indexedDB, databaseName: dbName, now: () => state.now, navigator: state.navigator, fetch, broadcast: false, ...options });
  return { core, state, dbName, fetch };
}
async function rows(dbName, store) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(dbName); open.onerror = () => reject(open.error);
    open.onsuccess = () => { const db = open.result, request = db.transaction([store]).objectStore(store).getAll(); request.onsuccess = () => { db.close(); resolve(request.result); }; };
  });
}
async function prepared(t, options) { const h = harness(options); t.after(() => h.core.close()); await h.core.prepare(); return h; }
const input = { token: 'test-point', note: '現場備註', is_abnormal: true };
const waitAbort = init => new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))));

test('another tab ACK advances only the notice for the last locally saved UUID', async t => {
  const h = await prepared(t), peer = harness({ databaseName: h.dbName }); t.after(() => peer.core.close());
  const first = await h.core.enqueue(input), second = await h.core.enqueue(input);
  assert.equal((await h.core.getState()).message, '已暫存此手機，尚未收到伺服器確認。');
  await peer.core.sync({ client_id: first.client_id });
  assert.equal((await h.core.getState()).message, '已暫存此手機，尚未收到伺服器確認。');
  await peer.core.sync({ client_id: second.client_id });
  assert.equal((await h.core.getState()).message, '已同步完成');
});

test('cross-tab ACK cannot replace a more recent preparation or connection error notice', async t => {
  for (const action of ['prepare', 'error']) {
    const h = await prepared(t), peer = harness({ databaseName: h.dbName }); t.after(() => peer.core.close());
    await h.core.enqueue(input);
    if (action === 'prepare') await h.core.prepare();
    else { h.state.status = () => response({ ok: false }, 503); await h.core.sync(); }
    const before = (await h.core.getState()).message;
    await peer.core.sync(); const after = await h.core.getState();
    assert.equal(after.pending, 0); assert.equal(after.message, before, action);
  }
});

for (const status of [401, 403]) test('late ACK never replaces a ' + status + ' lock message or reveals receipts', async t => {
  const h = await prepared(t), peer = harness({ databaseName: h.dbName }); t.after(() => peer.core.close());
  await h.core.enqueue(input);
  let resolveUpload, started; const uploading = new Promise(resolve => { started = resolve; });
  peer.state.sync = entry => new Promise(resolve => { resolveUpload = () => resolve(response({ ok:true,status:'saved',client_id:entry.client_id })); started(); });
  const sync = peer.core.sync(); await uploading;
  h.state.prepare = () => response({ ok:false,code:'auth',message:'登入或核准狀態已變更' },status);
  await assert.rejects(h.core.prepare()); const locked = await h.core.getState(); assert(locked.locked);
  resolveUpload(); await sync; const final = await h.core.getState();
  assert.equal(final.message,locked.message); assert.equal(final.locked,true); assert.deepEqual(final.receipts,[]);
});

test('offline enqueue persists immutable metadata and photo Blob atomically', async t => {
  const h = await prepared(t); h.state.navigator.onLine = false;
  const photo = new File(['photo bytes'], 'test.png', { type: 'image/png' });
  const entry = await h.core.enqueue({ ...input, photos: [photo] });
  const [saved] = await rows(h.dbName, 'queue');
  assert.equal(saved.client_id, entry.client_id); assert.equal(saved.owner, h.state.manifest.owner);
  assert.equal(saved.slot, 'am'); assert.equal(saved.note, input.note); assert.equal(saved.is_abnormal, true);
  assert.equal(await saved.photos[0].blob.text(), 'photo bytes'); assert.equal(saved.photos[0].name, 'test.png');
  assert.equal(saved.user_id, 1); assert.equal(saved.auth_version, 1); assert.equal(saved.binding_id, 11);
});
test('concurrent tabs allocate each round only once', async t => {
  const h = await prepared(t), second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  const saved = await Promise.all([h.core.enqueue(input), second.core.enqueue(input)]);
  assert.deepEqual(saved.map(r => r.slot).sort(), ['am', 'pm']);
  await assert.rejects(second.core.enqueue(input), { code: 'quota' });
  assert.equal((await rows(h.dbName, 'queue')).length, 2);
});
test('server used slots, local queue and ACK receipts are a union, not summed counts', async t => {
  const h = await prepared(t); await h.core.enqueue(input); await h.core.sync();
  assert.deepEqual((await h.core.getPoint('test-point')).availableSlots, ['pm']);
  h.state.manifest.points[0].used_slots = ['am']; await h.core.prepare();
  assert.equal((await h.core.enqueue(input)).slot, 'pm');
  await assert.rejects(h.core.enqueue(input), { code: 'quota' });
});
test('explicit matching ACK alone moves queue to receipt, with exact multipart fields', async t => {
  const h = await prepared(t); const entry = await h.core.enqueue(input); await h.core.sync();
  assert.equal((await rows(h.dbName, 'queue')).length, 0);
  assert.equal((await rows(h.dbName, 'receipts'))[0].client_id, entry.client_id);
  const sent = h.state.uploads[0]; assert.equal(sent.init.headers['X-CSRF-Token'], 'fresh-csrf');
  assert.deepEqual(Object.keys(sent.entry).sort(), ['client_id', 'grant', 'is_abnormal', 'note', 'observed_at', 'owner', 'slot', 'token']);
});
test('unknown ACK ID never removes queue or advances local quota', async t => {
  const h = await prepared(t); const entry = await h.core.enqueue(input);
  h.state.sync = () => response({ ok: true, status: 'saved', client_id: crypto.randomUUID() });
  await h.core.sync(); assert.equal((await rows(h.dbName, 'queue'))[0].client_id, entry.client_id);
  assert.equal((await rows(h.dbName, 'receipts')).length, 0);
  assert.deepEqual((await h.core.getPoint('test-point')).availableSlots, ['pm']);
});
test('saved server response lost in transit retries same UUID and accepts already_synced', async t => {
  const h = await prepared(t); await h.core.enqueue(input); const server = new Set(); let first = true;
  h.state.sync = entry => { server.add(entry.client_id); if (first) { first = false; throw new TypeError('network lost'); }
    return response({ ok: true, status: 'already_synced', client_id: entry.client_id, receipt_url: '/checkins/1' }); };
  await h.core.sync(); assert.equal((await rows(h.dbName, 'queue')).length, 1);
  await h.core.sync(); assert.equal((await rows(h.dbName, 'queue')).length, 0); assert.equal(server.size, 1);
  assert.equal(h.state.uploads[0].entry.client_id, h.state.uploads[1].entry.client_id);
});
test('unknown JSON response preserves photo and note for manual retry', async t => {
  const h = await prepared(t); await h.core.enqueue({ ...input, photos: [new File(['keep'], 'p.jpg', { type: 'image/jpeg' })] });
  h.state.sync = () => new Response('<html>proxy failure</html>', { status: 502 }); await h.core.sync();
  const [row] = await rows(h.dbName, 'queue'); assert.equal(row.note, input.note); assert.equal(await row.photos[0].blob.text(), 'keep');
});
test('offline sync exits immediately without making any request', async t => {
  const h = await prepared(t); await h.core.enqueue(input); h.state.navigator.onLine = false; const before = h.state.calls.length;
  const result = await h.core.sync(); assert.equal(h.state.calls.length, before); assert.equal(result.pending, 1); assert.equal(result.online, false);
});
test('status connection timeout is bounded and retains pending', async t => {
  const h = await prepared(t, { connectTimeout: 15 }); await h.core.enqueue(input); h.state.status = waitAbort;
  await h.core.sync(); assert.equal((await rows(h.dbName, 'queue')).length, 1); assert.equal(h.state.uploads.length, 0);
});
test('upload timeout retains entry and ends busy state with attempt progress', async t => {
  const h = await prepared(t, { uploadTimeout: 15 }); await h.core.enqueue(input); h.state.sync = (_, init) => waitAbort(init);
  const state = await h.core.sync(); assert.equal(state.pending, 1); assert.equal(state.sync.running, false); assert.equal(state.sync.processed, 1);
});
test('cancel only stops waiting and leaves the UUID and Blob intact', async t => {
  const h = await prepared(t); const entry = await h.core.enqueue(input);
  h.state.sync = (_, init) => { setTimeout(() => h.core.cancelSync(), 5); return waitAbort(init); };
  const state = await h.core.sync(); assert.equal(state.queue[0].client_id, entry.client_id); assert.equal(state.sync.cancelled, true);
});
test('dependency and permanent failures are retained with different states', async t => {
  const h = await prepared(t); await h.core.enqueue(input); await h.core.enqueue(input);
  h.state.sync = entry => response({ ok: false, code: entry.slot === 'am' ? 'waiting_execution' : 'point_changed', message: '待處理', retryable: entry.slot === 'am' }, 409);
  const state = await h.core.sync(); assert.deepEqual(state.queue.map(r => r.status), ['retry', 'blocked']); assert.equal(state.pending, 2);
});
test('logout locks local data without deleting pending; a different user cannot see or send it', async t => {
  const h = await prepared(t); const entry = await h.core.enqueue(input); await h.core.lock();
  assert.equal((await h.core.getState()).pending, 0); assert.equal((await rows(h.dbName, 'queue')).length, 1);
  h.state.manifest = manifest({ owner: 'u2v1b22inspectorgeneral', identity: { id: 2, auth_version: 1, binding_id: 22, name: 'Other', role: 'inspector', category: 'general' } });
  await h.core.prepare(); await h.core.sync(); assert.equal(h.state.uploads.length, 0); assert.equal((await h.core.getState()).pending, 0);
  await assert.rejects(h.core.remove(entry.client_id, true), { code: 'owner' });
});
test('same user with new auth version sees old entry as blocked and cannot regrant it', async t => {
  const h = await prepared(t); const entry = await h.core.enqueue(input); await h.core.lock();
  h.state.manifest = manifest({ owner: 'u1v2b11inspectorgeneral', identity: { ...manifest().identity, auth_version: 2 } });
  await h.core.prepare(); const state = await h.core.sync(); assert.equal(state.pending, 1); assert.equal(state.blocked, 1);
  assert.equal(state.queue[0].stale_owner, true); assert.equal(h.state.uploads.length, 0);
  assert.equal((await rows(h.dbName, 'queue'))[0].grant, 'signed-grant');
  await h.core.remove(entry.client_id, true); assert.equal((await rows(h.dbName, 'queue')).length, 0);
});
test('status owner mismatch never submits existing queue', async t => {
  const h = await prepared(t); await h.core.enqueue(input); h.state.status = () => response({ ok: true, owner: 'different-owner', csrf_token: 'x' });
  await h.core.sync(); assert.equal(h.state.uploads.length, 0); assert.equal((await rows(h.dbName, 'queue')).length, 1); assert.equal((await h.core.getState()).locked, true);
});
test('cross-tab lock during prepare prevents stale response unlocking browser', async t => {
  const h = await prepared(t), second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  let release; h.state.prepare = () => new Promise(resolve => { release = () => resolve(response(h.state.manifest)); });
  const preparing = h.core.prepare(); while (!release) await new Promise(resolve => setTimeout(resolve, 0));
  await second.core.lock(); release(); await assert.rejects(preparing, { code: 'owner' }); assert.equal((await h.core.getState()).locked, true);
});
test('new capture expires at midnight, but original pending remains available to sync', async t => {
  const h = await prepared(t); await h.core.enqueue(input); h.state.now = Date.parse('2026-11-06T16:00:00Z');
  await assert.rejects(h.core.enqueue(input), { code: 'expired' }); assert.equal((await h.core.getState()).prepared, false);
  await h.core.sync(); assert.equal((await rows(h.dbName, 'receipts'))[0].day, '2026-11-06');
});
test('normal old form cannot consume a new round, stage or owner', async t => {
  const h = await prepared(t); const expected = { user_id: 1, auth_version: 1, day: '2026-11-06', slot: 'am', stage: 'inspect', frequency: 'daily2', workflow_mode: 'spot', period_key: '2026-11-06', revision: 'revision-1' };
  await h.core.enqueue({ ...input, expected });
  await assert.rejects(h.core.enqueue({ ...input, expected }), { code: 'stale' });
  await assert.rejects(h.core.enqueue({ ...input, expected: { ...expected, slot: 'pm', stage: 'execute' } }), { code: 'stale' });
  await assert.rejects(h.core.enqueue({ ...input, expected: { ...expected, slot: 'pm', user_id: 2 } }), { code: 'stale' });
  await assert.rejects(h.core.enqueue({ ...input, expected: { ...expected, slot: 'pm', revision: 'renamed' } }), { code: 'stale' });
  assert.equal((await rows(h.dbName, 'queue')).length, 1);
});
test('storage write failure never leaves partial queue or uses a slot', async t => {
  const h = await prepared(t), original = IDBObjectStore.prototype.add;
  IDBObjectStore.prototype.add = function (...args) { if (this.name === 'queue') throw new DOMException('full', 'QuotaExceededError'); return original.apply(this, args); };
  try { await assert.rejects(h.core.enqueue(input), { code: 'storage' }); } finally { IDBObjectStore.prototype.add = original; }
  assert.equal((await rows(h.dbName, 'queue')).length, 0); assert.deepEqual((await h.core.getPoint('test-point')).availableSlots, ['am', 'pm']);
});
test('photo validation rejects oversized, empty and wrong types before a write', () => {
  assert.throws(() => validatePhotos([new File([], 'blank.jpg', { type: 'image/jpeg' })]));
  assert.throws(() => validatePhotos([{ size: 9 * 1024 * 1024, name: 'big.jpg', type: 'image/jpeg' }]));
  assert.throws(() => validatePhotos([new File(['<svg/>'], 'x.svg', { type: 'image/svg+xml' })]));
  assert.throws(() => validatePhotos(Array.from({ length: 4 }, () => new File(['a'], 'p.jpg', { type: 'image/jpeg' }))));
});
test('cross-tab synchronization lease prevents simultaneous duplicate uploads', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  const second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  let release, uploaded; const reached = new Promise(resolve => { uploaded = resolve; });
  h.state.sync = entry => new Promise(resolve => { release = () => resolve(response({ ok: true, status: 'saved', client_id: entry.client_id })); uploaded(); });
  const first = h.core.sync(); await reached; await second.core.sync(); assert.equal(second.state.uploads.length, 0); release(); await first;
  assert.equal((await rows(h.dbName, 'queue')).length, 0);
});
test('unconfirmed delete is refused and never affects server receipts', async t => {
  const h = await prepared(t), entry = await h.core.enqueue(input);
  await assert.rejects(h.core.remove(entry.client_id), { code: 'confirm' }); assert.equal((await rows(h.dbName, 'queue')).length, 1);
  await h.core.remove(entry.client_id, true); assert.equal((await rows(h.dbName, 'queue')).length, 0);
});
test('normal confirmation syncs only its selected UUID, not a long queue', async t => {
  const h = await prepared(t); const first = await h.core.enqueue(input), second = await h.core.enqueue(input);
  const state = await h.core.sync({ client_id: second.client_id });
  assert.equal(h.state.uploads.length, 1); assert.equal(h.state.uploads[0].entry.client_id, second.client_id);
  assert.equal(state.queue[0].client_id, first.client_id); assert.equal(state.sync.total, 1);
});
test('two shell forms showing the same first round cannot consume both rounds', async t => {
  const h = await prepared(t), second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  const point = await h.core.getPoint('test-point');
  const expected = { user_id: point.identity.id, auth_version: point.identity.auth_version, day: point.day, slot: point.availableSlots[0], stage: point.stage,
    frequency: point.frequency, workflow_mode: point.workflow_mode, period_key: point.period_key, revision: point.revision };
  const results = await Promise.allSettled([h.core.enqueue({ ...input, expected }), second.core.enqueue({ ...input, expected })]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(results.find(r => r.status === 'rejected').reason.code, 'stale');
  assert.deepEqual((await h.core.getPoint('test-point')).availableSlots, ['pm']);
});
test('late prepare response cannot overwrite a newer owner and reveal old private data', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  let release; h.state.prepare = () => new Promise(resolve => { release = () => resolve(response(h.state.manifest)); });
  const stale = h.core.prepare(); while (!release) await new Promise(resolve => setTimeout(resolve, 0));
  const second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  second.state.manifest = manifest({ owner: 'u2v1b22inspectorgeneral', identity: { id: 2, auth_version: 1, binding_id: 22, name: 'Other', role: 'inspector', category: 'general' } });
  await second.core.prepare(); release(); await assert.rejects(stale, { code: 'owner' });
  const state = await second.core.getState(); assert.equal(state.identity.id, 2); assert.equal(state.pending, 0);
  assert.equal((await rows(h.dbName, 'queue')).length, 1);
});

test('temporary status failure keeps preparation and all pending content visible', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  h.state.status = () => response({ ok: false, message: 'temporarily unavailable' }, 503);
  const state = await h.core.sync();
  assert.equal(state.locked, false); assert.equal(state.prepared, true); assert.equal(state.pending, 1);
  assert.equal(state.sync.errorCode, 'response');
  assert.equal(h.state.uploads.length, 0); assert.equal(state.sync.running, false);
  assert.equal((await rows(h.dbName, 'queue'))[0].note, input.note);
});

test('same-tab rapid sync clicks do not launch overlapping status or upload runs', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  const before = h.state.calls.length;
  await Promise.all([h.core.sync(), h.core.sync(), h.core.sync()]);
  assert.deepEqual(h.state.calls.slice(before), ['/api/offline/status', '/api/offline/sync']);
  assert.equal(h.state.uploads.length, 1); assert.equal((await rows(h.dbName, 'receipts')).length, 1);
});

test('response body timeout stops this sync round instead of waiting on the next item', async t => {
  const h = await prepared(t, { uploadTimeout: 15 }); await h.core.enqueue(input); await h.core.enqueue(input);
  h.state.sync = (_, init) => Promise.resolve({ ok: true, status: 200, json: () => waitAbort(init) });
  const state = await h.core.sync();
  assert.equal(h.state.uploads.length, 1); assert.equal(state.pending, 2);
  assert.equal(state.queue[0].status, 'retry'); assert.match(state.queue[0].error, /逾時/);
  assert.equal(state.queue[1].attempts, 0); assert.equal(state.sync.running, false);
});

test('offline shell installation delay does not backdate the calibrated visit time', async t => {
  const h = harness({ ensureShell: async () => { h.state.now += 14000; } }); t.after(() => h.core.close());
  await h.core.prepare(); await h.core.enqueue(input);
  assert.equal(Date.parse((await rows(h.dbName, 'queue'))[0].observed_at), stamp + 14000);
});

test('late rejected prepare cannot lock a more recently prepared account', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  let release; h.state.prepare = () => new Promise(resolve => { release = () => resolve(response({ ok: false, code: 'login_required' }, 401)); });
  const stale = h.core.prepare(); while (!release) await new Promise(resolve => setTimeout(resolve, 0));
  const second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  second.state.manifest = manifest({ owner: 'u2v1b22inspectorgeneral', identity: { id: 2, auth_version: 1, binding_id: 22, name: 'Other', role: 'inspector', category: 'general' } });
  await second.core.prepare(); release(); await assert.rejects(stale, { code: 'login_required' });
  const state = await second.core.getState(); assert.equal(state.identity.id, 2); assert.equal(state.locked, false); assert.equal(state.prepared, true);
  assert.equal(state.pending, 0); assert.equal((await rows(h.dbName, 'queue')).length, 1);
});

test('cancel sync does not abort a concurrent preparation or reset cancellation state', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  let statusReached, prepareReached, releasePrepare;
  const statusReady = new Promise(resolve => { statusReached = resolve; });
  const prepareReady = new Promise(resolve => { prepareReached = resolve; });
  h.state.status = init => { statusReached(); return waitAbort(init); };
  h.state.prepare = init => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    releasePrepare = () => resolve(response(h.state.manifest)); prepareReached();
  });
  const syncing = h.core.sync(); await statusReady;
  const preparing = h.core.prepare(); await prepareReady;
  h.core.cancelSync(); const stopped = await syncing; assert.equal(stopped.sync.cancelled, true);
  releasePrepare(); await preparing;
  const state = await h.core.getState(); assert.equal(state.pending, 1); assert.equal(state.prepared, true);
  assert.equal(h.state.uploads.length, 0);
});

test('cancelling before first IndexedDB read completes avoids every network request', async t => {
  const h = await prepared(t); await h.core.enqueue(input); const before = h.state.calls.length;
  const syncing = h.core.sync(); h.core.cancelSync(); await syncing;
  assert.equal(h.state.calls.length, before); assert.equal((await h.core.getState()).pending, 1);
});

test('one forbidden point stays blocked while the next permitted point can synchronize', async t => {
  const h = await prepared(t); await h.core.enqueue(input); await h.core.enqueue(input);
  h.state.sync = entry => entry.slot === 'am' ? response({ ok: false, code: 'forbidden', message: '不可巡檢自己的執行紀錄', retryable: false }, 403) :
    response({ ok: true, status: 'saved', client_id: entry.client_id });
  const state = await h.core.sync(); assert.equal(state.locked, false); assert.equal(state.prepared, true);
  assert.equal(state.queue.length, 1); assert.equal(state.queue[0].status, 'blocked'); assert.equal(state.receipts.length, 1);
});

test('stale sync authentication failure cannot clear a newer preparation for the same owner', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  let release, reached; const ready = new Promise(resolve => { reached = resolve; });
  h.state.status = () => new Promise(resolve => { release = () => resolve(response({ ok: false, code: 'login_required' }, 401)); reached(); });
  const pending = h.core.sync(); await ready;
  const second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  await second.core.prepare(); release(); await pending;
  const state = await second.core.getState(); assert.equal(state.owner, h.state.manifest.owner);
  assert.equal(state.locked, false); assert.equal(state.prepared, true); assert.equal(state.pending, 1);
  assert.equal(h.state.uploads.length, 0);
});

test('a committed enqueue stays successful when its following display read fails', async t => {
  const h = await prepared(t), originalAdd = IDBObjectStore.prototype.add, originalRead = IDBObjectStore.prototype.getAll;
  let failRead = false;
  IDBObjectStore.prototype.add = function (...args) {
    if (this.name === 'queue') this.transaction.addEventListener('complete', () => { failRead = true; });
    return originalAdd.apply(this, args);
  };
  IDBObjectStore.prototype.getAll = function (...args) {
    if (failRead && this.transaction.mode === 'readonly') throw new DOMException('temporarily unavailable', 'UnknownError');
    return originalRead.apply(this, args);
  };
  let entry;
  try { entry = await h.core.enqueue({ ...input, photos: [new File(['keep'], 'p.jpg', { type: 'image/jpeg' })] }); }
  finally { IDBObjectStore.prototype.add = originalAdd; IDBObjectStore.prototype.getAll = originalRead; }
  const [saved] = await rows(h.dbName, 'queue');
  assert.equal(saved.client_id, entry.client_id); assert.equal(await saved.photos[0].blob.text(), 'keep');
  assert.deepEqual((await h.core.getPoint('test-point')).availableSlots, ['pm']);
});

test('storage failure during sync cleanup always publishes a stopped state', async t => {
  const h = await prepared(t); const entry = await h.core.enqueue(input);
  const originalPut = IDBObjectStore.prototype.put, originalTransaction = IDBDatabase.prototype.transaction;
  let failStorage = false, latest;
  h.core.subscribe(value => { latest = value; });
  IDBObjectStore.prototype.put = function (...args) {
    if (this.name === 'receipts') this.transaction.addEventListener('complete', () => { failStorage = true; });
    return originalPut.apply(this, args);
  };
  IDBDatabase.prototype.transaction = function (...args) {
    if (failStorage) throw new DOMException('temporarily unavailable', 'UnknownError');
    return originalTransaction.apply(this, args);
  };
  let result;
  try { result = await h.core.sync(); }
  finally { IDBObjectStore.prototype.put = originalPut; IDBDatabase.prototype.transaction = originalTransaction; }
  assert.equal(result.sync.running, false); assert.equal(latest.sync.running, false);
  assert.equal(result.sync.errorCode, 'storage');
  assert.equal((await rows(h.dbName, 'receipts'))[0].client_id, entry.client_id);
  assert.equal((await rows(h.dbName, 'queue')).length, 0);
});

test('notes reject server-invalid controls and lone surrogates before consuming a slot', async t => {
  const h = await prepared(t);
  for (const note of ['text\u0000bad', 'text\u000bbad', 'text\u007fbad', 'text\ud800bad', 'text\udc00bad']) {
    await assert.rejects(h.core.enqueue({ ...input, note }), { code: 'note' });
  }
  assert.equal((await rows(h.dbName, 'queue')).length, 0);
  const note = '備註\t第一行\n第二行😀';
  await h.core.enqueue({ ...input, note });
  assert.equal((await rows(h.dbName, 'queue'))[0].note, note);
});

test('failed ACK persistence retains the UUID and photo, then replays the server receipt safely', async t => {
  const h = await prepared(t), originalPut = IDBObjectStore.prototype.put;
  const entry = await h.core.enqueue({ ...input, photos: [new File(['keep'], 'p.jpg', { type: 'image/jpeg' })] });
  IDBObjectStore.prototype.put = function (...args) {
    if (this.name === 'receipts') throw new DOMException('full', 'QuotaExceededError');
    return originalPut.apply(this, args);
  };
  try { const result = await h.core.sync(); assert.equal(result.sync.running, false); assert.equal(result.sync.saved, 0); }
  finally { IDBObjectStore.prototype.put = originalPut; }
  const [pending] = await rows(h.dbName, 'queue');
  assert.equal(pending.client_id, entry.client_id); assert.equal(await pending.photos[0].blob.text(), 'keep');
  assert.equal((await rows(h.dbName, 'receipts')).length, 0);
  h.state.sync = received => response({ ok: true, status: 'already_synced', client_id: received.client_id });
  await h.core.sync();
  assert.equal(h.state.uploads[0].entry.client_id, h.state.uploads[1].entry.client_id);
  assert.equal((await rows(h.dbName, 'queue')).length, 0); assert.equal((await rows(h.dbName, 'receipts')).length, 1);
});

test('failed logout lock stops in-flight upload and hides data until a successful retry', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  let reached, latest;
  const uploading = new Promise(resolve => { reached = resolve; });
  h.state.sync = (_, init) => { reached(); return waitAbort(init); };
  h.core.subscribe(value => { latest = value; });
  const pending = h.core.sync(); await uploading;
  const originalPut = IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put = function (...args) {
    if (this.name === 'meta' && args[0]?.key === 'active') throw new DOMException('full', 'QuotaExceededError');
    return originalPut.apply(this, args);
  };
  try { await assert.rejects(h.core.lock(), { code: 'storage' }); }
  finally { IDBObjectStore.prototype.put = originalPut; }
  await pending;
  assert.equal(latest.locked, true); assert.equal(latest.identity, null); assert.equal(latest.pending, 0); assert.equal(latest.sync.running, false);
  assert.equal(latest.storageUnavailable, false);
  assert.equal((await h.core.getState()).locked, true); assert.equal(await h.core.getPoint('test-point'), null);
  assert.equal((await rows(h.dbName, 'queue')).length, 1);
  await h.core.lock();
  const reopened = harness({ databaseName: h.dbName }); t.after(() => reopened.core.close());
  assert.equal((await reopened.core.getState()).locked, true);
  await h.core.prepare(); assert.equal((await h.core.getState()).pending, 1);
});

test('a matching ACK arriving after cancellation remains authoritative without a second upload', async t => {
  const h = await prepared(t); const entry = await h.core.enqueue(input);
  h.state.sync = received => { h.core.cancelSync(); return response({ ok: true, status: 'saved', client_id: received.client_id }); };
  const result = await h.core.sync();
  assert.equal(result.sync.cancelled, true); assert.equal(result.sync.running, false);
  assert.equal((await rows(h.dbName, 'queue')).length, 0);
  assert.equal((await rows(h.dbName, 'receipts'))[0].client_id, entry.client_id);
  await h.core.sync(); assert.equal(h.state.uploads.length, 1);
});

test('storage read failures hide private state and never reveal a prior account queue', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  let latest; h.core.subscribe(value => { latest = value; });
  const originalRead = IDBObjectStore.prototype.getAll;
  IDBObjectStore.prototype.getAll = function () { throw new DOMException('temporarily unavailable', 'UnknownError'); };
  try { await assert.rejects(h.core.getState(), { code: 'storage' }); }
  finally { IDBObjectStore.prototype.getAll = originalRead; }
  assert.equal(latest.identity, null); assert.equal(latest.owner, null); assert.equal(latest.pending, 0); assert.deepEqual(latest.queue, []);
  assert.equal(latest.storageUnavailable, true);
  const second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  second.state.manifest = manifest({ owner: 'u2v1b22inspectorgeneral', identity: { id: 2, auth_version: 1, binding_id: 22, name: 'Other', role: 'inspector', category: 'general' } });
  await second.core.prepare();
  const state = await h.core.getState(); assert.equal(state.identity.id, 2); assert.equal(state.pending, 0);
  assert.equal(state.storageUnavailable, false);
  assert.equal((await rows(h.dbName, 'queue')).length, 1);
});

test('a resumed tab skips a UUID already acknowledged by another tab after lease expiry', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  let reached, release;
  const checking = new Promise(resolve => { reached = resolve; });
  h.state.status = () => new Promise(resolve => { release = () => resolve(response({ ok: true, owner: h.state.manifest.owner, csrf_token: 'fresh' })); reached(); });
  const oldSync = h.core.sync(); await checking;
  const second = harness({ databaseName: h.dbName }); t.after(() => second.core.close());
  h.state.now += 46000; second.state.now = h.state.now;
  await second.core.sync(); assert.equal(second.state.uploads.length, 1);
  release(); const resumed = await oldSync;
  assert.equal(h.state.uploads.length, 0); assert.equal(resumed.sync.errorCode, undefined);
  assert.equal(resumed.locked, false); assert.equal(resumed.pending, 0); assert.equal(resumed.receipts.length, 1);
});

test('preparation committing during a failed logout cannot clear the privacy hold', async t => {
  const h = await prepared(t); await h.core.enqueue(input);
  const originalPut = IDBObjectStore.prototype.put;
  let locking, started = false;
  IDBObjectStore.prototype.put = function (...args) {
    if (this.name === 'manifests' && !started) {
      started = true; locking = h.core.lock().then(() => null, error => error.code);
    }
    if (this.name === 'meta' && args[0]?.key === 'active' && args[0]?.locked === true) throw new DOMException('full', 'QuotaExceededError');
    return originalPut.apply(this, args);
  };
  try {
    await assert.rejects(h.core.prepare(), { code: 'owner' });
    assert.equal(await locking, 'storage');
  } finally { IDBObjectStore.prototype.put = originalPut; }
  const state = await h.core.getState();
  assert.equal(state.locked, true); assert.equal(state.identity, null); assert.equal(state.pending, 0);
  assert.equal(await h.core.getPoint('test-point'), null);
  assert.equal((await rows(h.dbName, 'queue')).length, 1);
  await h.core.lock();
  const reopened = harness({ databaseName: h.dbName }); t.after(() => reopened.core.close());
  assert.equal((await reopened.core.getState()).locked, true);
});

test('older Safari without randomUUID uses cryptographic RFC 4122 version 4 identifiers', async t => {
  const fallbackCrypto = { getRandomValues(bytes) { assert.equal(this, fallbackCrypto); return crypto.getRandomValues(bytes); } };
  const h = await prepared(t, { crypto: fallbackCrypto });
  const first = await h.core.enqueue(input), second = await h.core.enqueue(input);
  for (const id of [first.client_id, second.client_id]) assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(first.client_id, second.client_id);
  await h.core.sync(); assert.equal((await rows(h.dbName, 'receipts')).length, 2);
});

test('randomUUID denial can use getRandomValues without weakening version or variant bits', async t => {
  const h = await prepared(t, { crypto: { randomUUID() { throw new DOMException('unavailable', 'NotSupportedError'); }, getRandomValues(bytes) { return bytes.fill(255); } } });
  const entry = await h.core.enqueue(input);
  assert.equal(entry.client_id, 'ffffffff-ffff-4fff-bfff-ffffffffffff');
});

test('missing secure randomness exposes online-only state instead of crashing initialization', async t => {
  const h = harness({ crypto: {} }); t.after(() => h.core.close());
  const state = await h.core.getState();
  assert.equal(state.supported, false); assert.equal(state.prepared, false); assert.equal(state.locked, true);
  assert.match(state.supportMessage, /線上/);
  await assert.rejects(h.core.prepare(), { code: 'support' });
  await assert.rejects(h.core.enqueue(input), { code: 'support' });
  await assert.rejects(h.core.sync(), { code: 'support' });
  assert.equal(await h.core.route('/c/test-point'), '/c/test-point');
  assert.equal(h.state.calls.length, 0);
});

test('unsupported randomness still permits logout to lock existing local data without deleting pending', async t => {
  const original = await prepared(t); await original.core.enqueue(input);
  const limited = harness({ crypto: {}, databaseName: original.dbName }); t.after(() => limited.core.close());
  await limited.core.lock();
  assert.equal((await rows(original.dbName, 'queue')).length, 1);
  assert.equal((await original.core.getState()).locked, true);
});

test('insecure contexts disable offline capture before making network requests', async t => {
  const env = Object.assign(Object.create(globalThis), { isSecureContext: false });
  const h = harness({ env, crypto }); t.after(() => h.core.close());
  const state = await h.core.getState(); assert.equal(state.supported, false); assert.match(state.supportMessage, /HTTPS/);
  await assert.rejects(h.core.prepare(), { code: 'support' });
  await assert.rejects(h.core.enqueue(input), { code: 'support' });
  assert.equal(h.state.calls.length, 0);
});

test('denied BroadcastChannel construction does not prevent preparation and safe queue operation', async t => {
  const env = Object.assign(Object.create(globalThis), { BroadcastChannel: class { constructor() { throw new DOMException('denied', 'SecurityError'); } } });
  const h = await prepared(t, { env, crypto, broadcast: true });
  const entry = await h.core.enqueue(input); await h.core.sync();
  assert.equal((await rows(h.dbName, 'receipts'))[0].client_id, entry.client_id);
});

test('optional storage persistence failures never interrupt offline preparation', async () => {
  for (const navigator of [{}, { storage: {} }, { storage: { persist() { return false; } } },
    { storage: { persist() { throw new DOMException('denied', 'SecurityError'); } } },
    { storage: { persist() { return Promise.reject(new DOMException('denied', 'SecurityError')); } } }]) {
    assert.doesNotThrow(() => requestPersistence(navigator));
  }
  await new Promise(resolve => setImmediate(resolve));
});

test('account locale and private point translations survive offline reopen without translating user content', async t => {
  const h = harness(); t.after(() => h.core.close());
  h.state.manifest.identity = { ...h.state.manifest.identity, ui_language: 'id', simple_executor_ui: true };
  h.state.manifest.points[0].name_i18n = { id: 'Ruang mesin', vi: 'Phòng máy' };
  await h.core.prepare();
  const note = '姓名不可翻譯：Nguyễn / Budi；點位備註保持原文';
  const entry = await h.core.enqueue({ ...input, note });
  const reopened = harness({ databaseName: h.dbName }); t.after(() => reopened.core.close());
  const state = await reopened.core.getState();
  assert.equal(state.identity.ui_language, 'id'); assert.equal(state.identity.simple_executor_ui, true);
  assert.equal(state.queue[0].note, note); assert.equal(state.queue[0].name, 'Point');
  assert.deepEqual(state.queue[0].name_i18n, { id: 'Ruang mesin', vi: 'Phòng máy' });
  await reopened.core.sync();
  const [receipt] = await rows(h.dbName, 'receipts');
  assert.equal(receipt.client_id, entry.client_id); assert.equal(receipt.name_i18n.vi, 'Phòng máy');
  await reopened.core.lock(); assert.equal((await reopened.core.getState()).identity, null);
});

test('locale preference refresh preserves the queued grant and never leaks the previous account identity', async t => {
  const h = await prepared(t); const entry = await h.core.enqueue(input);
  h.state.manifest.identity = { ...h.state.manifest.identity, ui_language: 'vi', simple_executor_ui: true };
  await h.core.prepare();
  const same = await h.core.getState(); assert.equal(same.identity.ui_language, 'vi'); assert.equal(same.pending, 1);
  const [queued] = await rows(h.dbName, 'queue'); assert.equal(queued.client_id, entry.client_id); assert.equal(queued.grant, 'signed-grant');
  await h.core.lock();
  h.state.manifest = manifest({ owner: 'u2v1b22inspectorgeneral', identity: { id: 2, auth_version: 1, binding_id: 22, name: 'Other', role: 'inspector', category: 'general', ui_language: 'id', simple_executor_ui: false } });
  await h.core.prepare();
  const other = await h.core.getState(); assert.equal(other.identity.ui_language, 'id'); assert.equal(other.pending, 0); assert.equal(other.receipts.length, 0);
  assert.equal((await rows(h.dbName, 'queue')).length, 1);
});
