/* Phone camera bytes must survive local storage and exact multipart retries. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { indexedDB } = require('fake-indexeddb');
const { createCore } = require('../static/offline.js');
const stamp = Date.parse('2026-11-16T01:20:00Z');
const response = (json, status = 200) => new Response(JSON.stringify(json), { status });
const photo = () => new File([Uint8Array.from([0, 1, 2, 127, 128, 255])], '現場照片.png', { type: 'image/png' });
const nativeRead = Blob.prototype.arrayBuffer;

async function harness(t, options = {}) {
  const manifest = { ok: true, version: 1, checklist_version: 1, owner: 'u1v1b1-inspector-general',
    identity: { id: 1, auth_version: 1, binding_id: 1, role: 'inspector', category: 'general' },
    server_time: new Date(stamp).toISOString(), day: '2026-11-16', capture_until: '2026-11-16T16:00:00Z',
    sync_until: '2026-11-17T16:00:00Z', csrf_token: 'test-csrf',
    points: [{ id: 1, token: 'photo-point', code: '1F-G01', name: 'Test', frequency: 'daily2', workflow_mode: 'spot',
      stage: 'inspect', period_key: '2026-11-16', slots: ['am', 'pm'], used_slots: [], executed_slots: [],
      revision: 'test-revision', grant: 'test-grant', checklist: null }] };
  const state = { uploads: [], failNext: false };
  const databaseName = options.databaseName || 'offline-photo-' + crypto.randomUUID();
  const fetch = async (url, init) => {
    if (url.endsWith('/prepare')) return response(manifest);
    if (url.endsWith('/status')) return response({ ok: true, owner: manifest.owner, csrf_token: 'fresh',
      server_time: manifest.server_time, identity: manifest.identity });
    if (url.startsWith('/api/offline/receipt/')) return response({ ok: true, owner: manifest.owner,
      client_id: new URL(url, 'https://local.test').pathname.split('/').pop(), status: 'not_received' });
    const entry = JSON.parse(init.body.get('entry'));
    const files = await Promise.all(init.body.getAll('photos').map(async file => ({ name: file.name, type: file.type,
      bytes: Array.from(new Uint8Array(await file.arrayBuffer())) })));
    const request = new Request('https://local.test/sync', { method: 'POST', body: init.body });
    const multipart = await request.text();
    assert.match(request.headers.get('content-type'), /^multipart\/form-data; boundary=/);
    assert.match(multipart, /name="entry"/);
    state.uploads.push({ entry, files });
    if (state.failNext) { state.failNext = false; throw new TypeError('Acknowledgement lost'); }
    return response({ ok: true, status: 'saved', client_id: entry.client_id });
  };
  const core = createCore({ indexedDB, crypto: globalThis.crypto, databaseName, now: () => stamp, navigator: { onLine: true },
    fetch, retryDelay: 0, broadcast: false, ...options });
  t.after(() => core.close()); await core.prepare();
  return { core, state, databaseName, manifest };
}

async function queue(h, mutate) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(h.databaseName);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result, tx = db.transaction('queue', mutate ? 'readwrite' : 'readonly');
      const store = tx.objectStore('queue'), request = store.getAll(); let result;
      request.onsuccess = () => { result = request.result; if (mutate) for (const row of result) { mutate(row); store.put(row); } };
      tx.oncomplete = () => { db.close(); resolve(result); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  });
}
const input = { token: 'photo-point', note: '現場異常 😀', is_abnormal: true };

test('new camera files become detached byte copies before storing and multipart upload', async t => {
  const h = await harness(t), source = photo();
  const saved = await h.core.enqueue({ ...input, photos: [source] });
  const [row] = await queue(h);
  assert.equal(row.client_id, saved.client_id);
  assert.equal(row.photos[0].blob.constructor.name, 'Blob');
  assert.deepEqual(Array.from(new Uint8Array(await row.photos[0].blob.arrayBuffer())), [0, 1, 2, 127, 128, 255]);
  await h.core.sync();
  assert.deepEqual(h.state.uploads[0].files, [{ name: source.name, type: source.type, bytes: [0, 1, 2, 127, 128, 255] }]);
  assert.equal(h.state.uploads[0].entry.note, input.note);
  assert.equal(h.state.uploads[0].entry.is_abnormal, true);
  assert.equal((await queue(h)).length, 0);
});

for (const kind of ['rejects', 'incomplete', 'timeout']) test('unreadable camera ' + kind + ' cannot consume a round or create a queue item', async t => {
  const env = Object.create(globalThis); env.FileReader = undefined; env.Response = undefined;
  const h = await harness(t, { env, photoReadTimeout: 15 }), source = photo();
  source.arrayBuffer = () => kind === 'rejects' ? Promise.reject(new Error('Camera source gone')) :
    kind === 'incomplete' ? Promise.resolve(new ArrayBuffer(1)) : new Promise(() => {});
  await assert.rejects(h.core.enqueue({ ...input, photos: [source] }), error => error.code === 'photo_read' && /第 1 張照片.*尚未暫存/.test(error.message));
  assert.equal((await queue(h)).length, 0);
  assert.deepEqual((await h.core.getPoint('photo-point')).availableSlots, ['am', 'pm']);
  const next = await h.core.enqueue({ ...input, photos: [photo()] }); assert.equal(next.slot, 'am');
});

test('legacy Safari FileReader handles a File without arrayBuffer', async t => {
  let reads = 0;
  class Reader {
    readAsArrayBuffer(file) { reads++; nativeRead.call(file).then(value => { this.result = value; this.onload(); }); }
  }
  const env = Object.create(globalThis); env.FileReader = Reader;
  const h = await harness(t, { env }), source = photo(); source.arrayBuffer = undefined;
  await h.core.enqueue({ ...input, photos: [source] }); await h.core.sync();
  assert.equal(reads, 1); assert.deepEqual(h.state.uploads[0].files[0].bytes, [0, 1, 2, 127, 128, 255]);
});

test('Response fallback reads bytes when FileReader and File.arrayBuffer are absent', async t => {
  let reads = 0;
  const env = Object.create(globalThis); env.FileReader = undefined;
  env.Response = class { constructor(file) { this.file = file; } arrayBuffer() { reads++; return nativeRead.call(this.file); } };
  const h = await harness(t, { env }), source = photo(); source.arrayBuffer = undefined;
  await h.core.enqueue({ ...input, photos: [source] }); assert.equal(reads, 1);
  assert.equal((await queue(h))[0].photos[0].size, 6);
});

test('lost stored photo is retained with its UUID and does not stop another valid draft', async t => {
  const h = await harness(t);
  const broken = await h.core.enqueue({ ...input, photos: [photo()] });
  const good = await h.core.enqueue({ ...input, photos: [photo()] });
  await queue(h, row => { if (row.client_id === broken.client_id) row.photos[0].blob = new Blob([], { type: 'image/png' }); });
  await h.core.sync();
  assert.deepEqual(h.state.uploads.map(row => row.entry.client_id), [good.client_id]);
  const [remaining] = await queue(h);
  const [failure] = (await h.core.getState()).queue;
  assert.equal(remaining.client_id, broken.client_id); assert.equal(failure.status, 'retry');
  assert.match(failure.error, /第 1 張暫存照片.*資料仍保留/);
  assert.equal(remaining.photos[0].blob.size, 0); assert.equal(remaining.photos[0].size, 6);
  await h.core.sync();
  const [retried] = (await h.core.getState()).queue; assert.equal(retried.client_id, broken.client_id);
  assert.equal(h.state.uploads.length, 1); assert.equal(retried.attempts, 2);
});

test('photo multipart append failure stays on its own row and other drafts upload', async t => {
  let fail = true;
  class Forms extends FormData {
    append(name, ...args) { if (name === 'photos' && fail) { fail = false; throw new TypeError('Invalid Blob'); } return super.append(name, ...args); }
  }
  const h = await harness(t, { FormData: Forms });
  const first = await h.core.enqueue({ ...input, photos: [photo()] });
  const second = await h.core.enqueue({ ...input, photos: [photo()] });
  await h.core.sync();
  assert.deepEqual(h.state.uploads.map(row => row.entry.client_id), [second.client_id]);
  const [row] = (await h.core.getState()).queue; assert.equal(row.client_id, first.client_id); assert.equal(row.status, 'retry');
  await h.core.sync(); assert.equal((await queue(h)).length, 0);
  assert.equal(h.state.uploads[1].entry.client_id, first.client_id);
});

test('verified unreceived upload automatically resends unchanged UUID, observed time, note and exact photo bytes', async t => {
  const h = await harness(t); await h.core.enqueue({ ...input, photos: [photo()] });
  h.state.failNext = true; await h.core.sync();
  assert.equal(h.state.uploads.length, 2); assert.deepEqual(h.state.uploads[1], h.state.uploads[0]);
  assert.equal((await queue(h)).length, 0);
});

test('logout while camera bytes are reading cannot save under a new account', async t => {
  const h = await harness(t), source = photo(); let finishRead, started;
  const begun = new Promise(resolve => { started = resolve; });
  source.arrayBuffer = () => new Promise(resolve => { finishRead = () => nativeRead.call(source).then(resolve); started(); });
  const saving = h.core.enqueue({ ...input, photos: [source] }); await begun;
  await h.core.lock(); finishRead(); await assert.rejects(saving, { code: 'owner' });
  assert.equal((await queue(h)).length, 0);
});

test('photo read latency does not change the recorded OK confirmation time', async t => {
  let clock = stamp;
  const h = await harness(t, { now: () => clock }), source = photo();
  source.arrayBuffer = () => { clock += 3000; return nativeRead.call(source); };
  const saved = await h.core.enqueue({ ...input, photos: [source] });
  assert.equal(saved.observed_at, new Date(stamp).toISOString());
  assert.equal((await queue(h))[0].captured_device_at, new Date(stamp).toISOString());
});

test('preparing another account during camera read cannot transfer a draft to that owner', async t => {
  const h = await harness(t), source = photo(); let finishRead, started;
  const begun = new Promise(resolve => { started = resolve; });
  source.arrayBuffer = () => new Promise(resolve => { finishRead = () => nativeRead.call(source).then(resolve); started(); });
  const saving = h.core.enqueue({ ...input, photos: [source] }); await begun;
  h.manifest.owner = 'u2v1b2-inspector-general'; h.manifest.identity = { ...h.manifest.identity, id: 2, binding_id: 2 };
  await h.core.prepare(); finishRead(); await assert.rejects(saving, { code: 'owner' });
  assert.equal((await queue(h)).length, 0);
});

test('photo read suspended beyond lease cannot revive a draft deleted in another tab', async t => {
  let clock = stamp;
  const h = await harness(t, { now: () => clock });
  const saved = await h.core.enqueue({ ...input, photos: [photo()] });
  let finish, begun, intercepted = false;
  const started = new Promise(resolve => { begun = resolve; });
  Blob.prototype.arrayBuffer = function () {
    if (intercepted) return nativeRead.call(this);
    intercepted = true;
    return new Promise(resolve => { finish = () => nativeRead.call(this).then(resolve); begun(); });
  };
  try {
    const syncing = h.core.sync(); await started; clock += 46000;
    const peer = await harness(t, { databaseName: h.databaseName, now: () => clock });
    await peer.core.remove(saved.client_id, true); finish(); await syncing;
    assert.equal(h.state.uploads.length, 0); assert.equal((await queue(h)).length, 0);
  } finally { Blob.prototype.arrayBuffer = nativeRead; }
});
