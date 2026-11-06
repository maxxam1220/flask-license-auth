/* Run with fake-indexeddb on NODE_PATH; no live service or production data. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { indexedDB, IDBObjectStore } = require('fake-indexeddb');
const { createCore, validatePhotos } = require('../static/offline.js');
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
