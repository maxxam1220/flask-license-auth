const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const { createHash, webcrypto } = require('node:crypto');
const source = fs.readFileSync(require.resolve('../static/offline-sw.js'), 'utf8');
const origin = 'https://patrol.test';
const audioRoot = '/static/audio/patrol-v1/';
const kinds = ['saved_execute', 'saved_inspect', 'saved_visit', 'already_recorded', 'waiting_execution', 'device_required', 'point_unavailable',
  'offline_stored', 'sync_confirmed', 'sync_partial', 'not_saved', 'login_required', 'receipt_confirmed'];
const audioPaths = ['zh-Hant', 'id', 'vi'].flatMap(locale => kinds.map(kind => audioRoot + locale + '/' + kind + '.mp3'));
const audioBytes = new Uint8Array([73, 68, 51, 3, 0, 0, 0, 0, 0, 0, 255, 251, 144, 0, 17, 32, 48, 64, 80, 96]);
const manifest = { version: 'patrol-v1', revision: 'natural-female-1', files: audioPaths.map(path => ({ path, locale: path.split('/').at(-2), kind: path.split('/').at(-1).slice(0, -4),
  bytes: audioBytes.byteLength, sha256: createHash('sha256').update(audioBytes).digest('hex') })) };
const required = ['/offline', '/static/app.css', '/static/offline.css', '/static/checklist.css', '/static/executor-locale.css', '/static/i18n.js', '/static/offline.js', '/static/offline-update.js', '/static/patrol-scanner.js', '/static/patrol-voice.js', '/static/patrol-voice.css', '/static/vendor/jsqr-1.4.0.js', '/static/logo.ico', audioRoot + 'manifest.json', ...audioPaths];
function defaultResponse(path) {
  return path === audioRoot + 'manifest.json' ? new Response(JSON.stringify(manifest), { headers: { 'Content-Type': 'application/json' } }) :
    audioPaths.includes(path) ? new Response(audioBytes, { headers: { 'Content-Type': 'audio/mpeg', 'Content-Length': String(audioBytes.length), ETag: '"qa-audio-v1"' } }) :
      new Response(path === '/offline' ? 'GENERIC OFFLINE SHELL' : 'asset', { status: 200 });
}
function worker(options = {}) {
  const hooks = {}, stores = new Map(), requests = [], writes = [], actions = [];
  const key = value => typeof value === 'string' ? new URL(value, origin).pathname : new URL(value.url).pathname;
  let responder = request => Promise.resolve(defaultResponse(key(request)));
  const caches = { async keys() { return [...stores.keys()]; }, async delete(name) { return stores.delete(name); }, async open(name) {
    if (options.openError) throw new Error('Storage unavailable');
    if (!stores.has(name)) stores.set(name, new Map()); const entries = stores.get(name);
    return { async put(path, response) { if (options.failPut === key(path)) throw new Error('QuotaExceededError'); writes.push(key(path)); entries.set(key(path), response.clone()); }, async match(path) { return entries.get(key(path))?.clone(); } };
  } };
  const self = { location: new URL(origin), navigator: { onLine: true }, addEventListener(name, fn) { hooks[name] = fn; }, skipWaiting: async () => actions.push('skipWaiting'), clients: { claim: async () => actions.push('claim') } };
  class WorkerRequest extends Request { constructor(value, init) { super(typeof value === 'string' ? new URL(value, origin) : value, init); } }
  vm.runInNewContext(source, { self, caches, URL, Request: WorkerRequest, Response, Headers, AbortController, crypto: webcrypto,
    setTimeout: (fn, delay) => setTimeout(fn, (delay === 25000 ? options.installTimeoutMs : options.timeoutMs) || delay), clearTimeout,
    fetch(request, init) { requests.push(request); return responder(request, init); } });
  async function lifecycle(name, extras = {}) { let waited; hooks[name]({ ...extras, waitUntil(promise) { waited = promise; } }); await waited; }
  async function fetchPage(path, { method = 'GET', mode = 'navigate', headers = {} } = {}) {
    let intercepted; const request = { url: new URL(path, origin).href, method, mode, headers: new Headers(headers) };
    hooks.fetch({ request, respondWith(promise) { intercepted = promise; } }); return intercepted ? await intercepted : null;
  }
  return { stores, writes, requests, actions, self, lifecycle, fetchPage, respond(fn) { responder = fn; } };
}
test('install caches every required asset and only a generic offline shell', async () => {
  const w = worker(); await w.lifecycle('install');
  assert.deepEqual(w.writes.sort(), required.slice().sort());
  assert(w.requests.every(request => request.credentials === 'omit' && request.redirect === 'error'));
});
test('one missing required asset fails install before any cache write', async () => {
  const w = worker(); w.respond(request => Promise.resolve(new URL(request.url).pathname.includes('jsqr') ? new Response('missing', { status: 404 }) : defaultResponse(new URL(request.url).pathname)));
  await assert.rejects(w.lifecycle('install')); assert.equal(w.writes.length, 0);
});
test('API, private HTML, photos, records, POST, and arbitrary assets are never intercepted', async () => {
  const w = worker(); await w.lifecycle('install'); const before = w.writes.length;
  for (const path of ['/api/offline/status', '/api/offline/prepare', '/records', '/checkins/1', '/photos/1', '/dashboard', '/login', '/static/private.json']) assert.equal(await w.fetchPage(path), null);
  assert.equal(await w.fetchPage('/api/offline/sync', { method: 'POST' }), null);
  assert.equal(await w.fetchPage('/c/token/confirm', { method: 'POST' }), null);
  assert.equal(await w.fetchPage('https://external.test/c/token'), null); assert.equal(w.writes.length, before);
});
test('offline scan navigation returns shell immediately without network access', async () => {
  const w = worker(); await w.lifecycle('install'); w.self.navigator.onLine = false; const before = w.requests.length;
  assert.equal(await (await w.fetchPage('/c/test-token')).text(), 'GENERIC OFFLINE SHELL'); assert.equal(w.requests.length, before);
});
test('weak network falls back for scan navigation without caching returned private page', async () => {
  const w = worker(); await w.lifecycle('install'); const before = w.writes.length;
  w.respond(() => Promise.reject(new TypeError('network failed')));
  assert.equal(await (await w.fetchPage('/c/test-token')).text(), 'GENERIC OFFLINE SHELL');
  w.respond(() => Promise.resolve(new Response('PRIVATE CONFIRMATION')));
  assert.equal(await (await w.fetchPage('/c/test-token')).text(), 'PRIVATE CONFIRMATION'); assert.equal(w.writes.length, before);
});
test('readiness requires every cached asset; activation deletes only old patrol shell caches', async () => {
  const w = worker(); await w.lifecycle('install'); let answer;
  await w.lifecycle('message', { data: { type: 'PATROL_OFFLINE_READY' }, ports: [{ postMessage(value) { answer = value; } }] }); assert.equal(answer.ready, true);
  assert.equal(answer.audioReady, true); assert.equal(answer.audioVersion, 'patrol-v1');
  assert.equal(answer.audioRevision, 'natural-female-1');
  assert.equal(answer.checklistVersion, 1);
  assert.equal(answer.calendarVersion, 1);
  const current = [...w.stores.keys()][0]; w.stores.get(current).delete('/static/offline.js');
  await w.lifecycle('message', { data: { type: 'PATROL_OFFLINE_READY' }, ports: [{ postMessage(value) { answer = value; } }] }); assert.equal(answer.ready, false);
  w.stores.set('patrol-offline-shell-old', new Map()); w.stores.set('unrelated-app-cache', new Map()); await w.lifecycle('activate');
  assert.equal(w.stores.has('patrol-offline-shell-old'), true); assert.equal(w.actions.includes('claim'), false);
  w.stores.get(current).set('/static/offline.js', defaultResponse('/static/offline.js')); await w.lifecycle('activate');
  assert.equal(w.stores.has('patrol-offline-shell-old'), false); assert.equal(w.stores.has('unrelated-app-cache'), true);
});

test('versioned checklist script reads the current cached asset offline without widening the allowlist', async () => {
  const w = worker(); await w.lifecycle('install'); w.self.navigator.onLine = false;
  const before = w.requests.length;
  assert.equal(await (await w.fetchPage('/static/offline.js?v=checklist-1', { mode: 'cors' })).text(), 'asset');
  assert.equal(await (await w.fetchPage('/static/offline.js?v=checklist-2', { mode: 'cors' })).text(), 'asset');
  assert.equal(await (await w.fetchPage('/static/offline.js?v=ios-audio-1', { mode: 'cors' })).text(), 'asset');
  assert.equal(await (await w.fetchPage('/static/patrol-voice.js?v=ios-audio-1', { mode: 'cors' })).text(), 'asset');
  assert.equal(await (await w.fetchPage('/static/offline.js?v=ios-audio-2', { mode: 'cors' })).text(), 'asset');
  assert.equal(await (await w.fetchPage('/static/offline.js?v=three-day-1', { mode: 'cors' })).text(), 'asset');
  assert.equal(await (await w.fetchPage('/static/patrol-voice.js?v=ios-audio-2', { mode: 'cors' })).text(), 'asset');
  assert.equal(await (await w.fetchPage('/static/offline.css?v=ios-audio-2', { mode: 'cors' })).text(), 'asset');
  assert.equal(w.requests.length, before);
  for (const path of ['/static/offline.js?v=checklist-0', '/static/offline.js?v=checklist-1&extra=1', '/static/private.json?v=checklist-1', '/static/patrol-voice.js?v=ios-audio-1&extra=1', '/static/private.json?v=ios-audio-1']) assert.equal(await w.fetchPage(path, { mode: 'cors' }), null);
});

test('missing checklist stylesheet cannot advertise a prepared shell', async () => {
  const w = worker(); await w.lifecycle('install'); let answer;
  w.stores.get([...w.stores.keys()][0]).delete('/static/checklist.css');
  await w.lifecycle('message', { data: { type: 'PATROL_OFFLINE_READY' }, ports: [{ postMessage(value) { answer = value; } }] });
  assert.equal(answer.ready, false); assert.equal(answer.checklistVersion, 1);
  await w.lifecycle('activate'); assert.equal(w.actions.includes('claim'), false);
});

test('stale audio manifest fails update without replacing an older usable cache', async () => {
  const w = worker(); const old = new Map([['/offline', new Response('previous usable shell')]]);
  w.stores.set('patrol-offline-shell-old', old);
  w.respond(request => Promise.resolve(new URL(request.url).pathname === audioRoot + 'manifest.json'
    ? new Response(JSON.stringify({ ...manifest, revision: 'old-voice' }), { headers: { 'Content-Type': 'application/json' } })
    : defaultResponse(new URL(request.url).pathname)));
  await assert.rejects(w.lifecycle('install'), /Incomplete audio manifest/);
  assert.equal(w.writes.length, 0); assert.equal(w.actions.includes('skipWaiting'), false);
  assert.equal(await w.stores.get('patrol-offline-shell-old').get('/offline').text(), 'previous usable shell');
});

test('already-open pages keep their fixed audio paths after voice upgrade', async () => {
  const w = worker(); await w.lifecycle('install'); await w.lifecycle('activate'); w.self.navigator.onLine = false;
  w.respond(() => { throw new Error('offline; no network'); });
  for (const path of audioPaths) {
    const response = await w.fetchPage(path, { mode: 'cors', headers: { Range: 'bytes=0-9' } });
    assert.equal(response.status, 206); assert.deepEqual(new Uint8Array(await response.arrayBuffer()), audioBytes.slice(0, 10));
  }
});

test('failed updated shell installation preserves the existing usable offline cache', async () => {
  const w = worker(); const old = new Map([['/offline', new Response('previous usable shell')]]);
  w.stores.set('patrol-offline-shell-20261106-v1', old);
  w.respond(request => Promise.resolve(new URL(request.url).pathname.endsWith('offline.js') ? new Response('unavailable', { status: 503 }) : defaultResponse(new URL(request.url).pathname)));
  await assert.rejects(w.lifecycle('install'));
  assert.equal(await w.stores.get('patrol-offline-shell-20261106-v1').get('/offline').text(), 'previous usable shell');
  assert.equal(w.writes.length, 0);
});

test('navigation timeout covers a stalled response body after headers arrived', async () => {
  const w = worker({ timeoutMs: 15 }); await w.lifecycle('install'); const before = w.writes.length;
  w.respond((_, init) => Promise.resolve(new Response(new ReadableStream({ start(controller) {
    controller.enqueue(new TextEncoder().encode('PARTIAL PRIVATE HTML'));
    init.signal.addEventListener('abort', () => controller.error(new DOMException('aborted', 'AbortError')));
  } }))));
  let deadline;
  const result = await Promise.race([
    w.fetchPage('/c/test-token').then(response => response.text()),
    new Promise(resolve => { deadline = setTimeout(() => resolve('BODY NEVER FINISHED'), 150); })
  ]);
  clearTimeout(deadline);
  assert.equal(result, 'GENERIC OFFLINE SHELL'); assert.equal(w.writes.length, before);
});

test('buffered online navigation returns the original response with its redirect metadata', async () => {
  const w = worker(); await w.lifecycle('install');
  const original = new Response('LOGIN PAGE', { headers: { 'Content-Type': 'text/html', 'Content-Security-Policy': "default-src 'self'" } });
  Object.defineProperties(original, { url: { value: origin + '/login' }, redirected: { value: true } });
  w.respond(() => Promise.resolve(original));
  const result = await w.fetchPage('/c/test-token');
  assert.equal(result, original); assert.equal(result.url, origin + '/login'); assert.equal(result.redirected, true);
  assert.equal(await result.text(), 'LOGIN PAGE'); assert.equal(result.headers.get('Content-Security-Policy'), "default-src 'self'");
});

test('missing cached shell offers recovery instructions in all account languages without identity', async () => {
  const w = worker(); w.self.navigator.onLine = false;
  const result = await w.fetchPage('/c/test-token'); const text = await result.text();
  assert.equal(result.status, 503); assert.match(result.headers.get('Content-Type'), /utf-8/);
  assert.match(text, /離線頁面尚未備妥/); assert.match(text, /Halaman offline/); assert.match(text, /Trang ngoại tuyến/);
  assert.equal(w.requests.length, 0); assert.equal(w.writes.length, 0);
});

async function readiness(w, type = 'PATROL_OFFLINE_READY') {
  let answer;
  await w.lifecycle('message', { data: { type }, ports: [{ postMessage(value) { answer = value; } }] });
  return answer;
}
const currentStore = w => w.stores.get(source.match(/const CACHE = '([^']+)'/)[1]);

test('audio pack is a fixed complete 39-file whitelist independent of manifest paths', async () => {
  assert.equal(audioPaths.length, 39);
  const w = worker();
  const injected = structuredClone(manifest); injected.files[0].path = '/photos/private';
  w.respond(request => Promise.resolve(new URL(request.url).pathname === audioRoot + 'manifest.json' ? new Response(JSON.stringify(injected)) : defaultResponse(new URL(request.url).pathname)));
  await assert.rejects(w.lifecycle('install'), /manifest/i);
  assert.equal(w.requests.length, 1); assert.equal(w.writes.length, 0);
});

test('missing, duplicate or differently versioned manifest entries cannot advertise ready audio', async () => {
  for (const mutate of [value => value.files.pop(), value => { value.files[1] = value.files[0]; }, value => { value.version = 'other'; }]) {
    const w = worker(), invalid = structuredClone(manifest); mutate(invalid);
    w.respond(request => Promise.resolve(new URL(request.url).pathname === audioRoot + 'manifest.json' ? new Response(JSON.stringify(invalid)) : defaultResponse(new URL(request.url).pathname)));
    await assert.rejects(w.lifecycle('install'), /manifest/i); assert.equal(w.writes.length, 0);
  }
});

test('installation downloads at most four public assets concurrently', async () => {
  const w = worker(); let active = 0, peak = 0;
  w.respond(async request => {
    active++; peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 1)); active--;
    return defaultResponse(new URL(request.url).pathname);
  });
  await w.lifecycle('install'); assert.equal(peak, 4); assert.equal(w.requests.length, required.length);
  assert(w.requests.every(request => request.headers.get('Range') === null && request.cache === 'reload' && request.credentials === 'omit'));
});

for (const [label, response] of [
  ['missing audio', () => new Response('missing', { status: 404 })],
  ['partial audio', () => new Response(audioBytes.slice(0, 2), { status: 206, headers: { 'Content-Type': 'audio/mpeg', 'Content-Range': 'bytes 0-1/20' } })],
  ['empty audio', () => new Response(null, { headers: { 'Content-Type': 'audio/mpeg' } })],
  ['incorrect content type', () => new Response(audioBytes, { headers: { 'Content-Type': 'text/html' } })],
  ['truncated audio', () => new Response(audioBytes.slice(0, -1), { headers: { 'Content-Type': 'audio/mpeg' } })],
  ['same-length corrupt audio', () => new Response(new Uint8Array(audioBytes.length), { headers: { 'Content-Type': 'audio/mpeg' } })]
]) {
  test(label + ' fails install without deleting the prior working pack', async () => {
    const w = worker(); w.stores.set('patrol-offline-shell-previous', new Map([['/offline', new Response('previous')]]));
    w.respond(request => Promise.resolve(new URL(request.url).pathname === audioPaths[0] ? response() : defaultResponse(new URL(request.url).pathname)));
    await assert.rejects(w.lifecycle('install')); assert.equal(w.writes.length, 0);
    assert(w.stores.has('patrol-offline-shell-previous')); assert(!w.actions.includes('skipWaiting'));
  });
}

test('full-body installation deadline aborts a stalled audio download before any cache write', async () => {
  const w = worker({ installTimeoutMs: 50 }); let aborted = false;
  w.respond(request => Promise.resolve(new URL(request.url).pathname !== audioPaths[0] ? defaultResponse(new URL(request.url).pathname) :
    new Response(new ReadableStream({ start(controller) {
      controller.enqueue(audioBytes.slice(0, 2));
      request.signal.addEventListener('abort', () => { aborted = true; controller.error(new DOMException('aborted', 'AbortError')); });
    } }), { headers: { 'Content-Type': 'audio/mpeg' } })));
  await assert.rejects(w.lifecycle('install')); assert(aborted); assert.equal(w.writes.length, 0);
});

test('a cache write failure leaves old cache intact and cannot activate the new pack', async () => {
  const w = worker({ failPut: audioPaths[0] }); w.stores.set('patrol-offline-shell-previous', new Map());
  await assert.rejects(w.lifecycle('install'), /QuotaExceededError/);
  assert(w.stores.has('patrol-offline-shell-previous')); assert(!w.actions.includes('skipWaiting'));
  assert.equal((await readiness(w)).audioReady, false);
  await w.lifecycle('activate'); assert(w.stores.has('patrol-offline-shell-previous')); assert(!w.actions.includes('claim'));
});

test('readiness refuses an evicted audio, partial cached response or unvalidated replacement', async () => {
  const w = worker(); await w.lifecycle('install'); const store = currentStore(w), saved = store.get(audioPaths[0]);
  assert.equal((await readiness(w)).ready, true);
  for (const replacement of [null, new Response(audioBytes.slice(0, 2), { status: 206 }), defaultResponse(audioPaths[0])]) {
    if (replacement) store.set(audioPaths[0], replacement); else store.delete(audioPaths[0]);
    const answer = await readiness(w); assert.equal(answer.ready, false); assert.equal(answer.audioReady, false);
  }
  store.set(audioPaths[0], saved); assert.equal((await readiness(w)).ready, true);
});

test('cache storage denial responds not-ready instead of a misleading success or silent timeout', async () => {
  const answer = await readiness(worker({ openError: true }));
  assert.equal(answer.ready, false); assert.equal(answer.audioReady, false);
});

for (const [range, start, end] of [
  ['bytes=0-1', 0, 1], ['bytes=2-7', 2, 7], ['bytes=15-', 15, 19], ['bytes=-4', 16, 19],
  ['bytes=0-9999999999999999999999', 0, 19], ['bytes=-9999999999999999999999', 0, 19]
]) {
  test('cached MP3 responds correctly to ' + range, async () => {
    const w = worker(); await w.lifecycle('install'); w.self.navigator.onLine = false;
    const requests = w.requests.length, writes = w.writes.length;
    const response = await w.fetchPage(audioPaths[0], { mode: 'no-cors', headers: { Range: range } });
    assert.equal(response.status, 206); assert.equal(response.headers.get('Content-Type'), 'audio/mpeg');
    assert.equal(response.headers.get('Content-Range'), `bytes ${start}-${end}/20`);
    assert.equal(response.headers.get('Content-Length'), String(end - start + 1)); assert.equal(response.headers.get('Accept-Ranges'), 'bytes');
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), audioBytes.slice(start, end + 1));
    assert.equal(w.requests.length, requests); assert.equal(w.writes.length, writes);
    assert.equal(currentStore(w).get(audioPaths[0]).status, 200);
  });
}

test('unsatisfiable audio ranges return 416 and the full resource length', async () => {
  const w = worker(); await w.lifecycle('install');
  for (const range of ['bytes=20-', 'bytes=999999999999999999999999-', 'bytes=-0', 'bytes=10-4']) {
    const response = await w.fetchPage(audioPaths[0], { headers: { Range: range } });
    assert.equal(response.status, 416, range); assert.equal(response.headers.get('Content-Range'), 'bytes */20');
    assert.equal(response.headers.get('Content-Length'), '0'); assert.equal((await response.arrayBuffer()).byteLength, 0);
  }
});

test('unsupported or multiple ranges safely return full cached audio without a network dependency', async () => {
  const w = worker(); await w.lifecycle('install'); w.self.navigator.onLine = false; const before = w.requests.length;
  for (const range of ['bytes=0-1,4-5', 'items=0-1', 'bytes=oops', 'bytes=-', 'bytes=+1-2']) {
    const response = await w.fetchPage(audioPaths[0], { headers: { Range: range } });
    assert.equal(response.status, 200); assert.deepEqual(new Uint8Array(await response.arrayBuffer()), audioBytes);
  }
  const conditional = await w.fetchPage(audioPaths[0], { headers: { Range: 'bytes=0-1', 'If-Range': '"different-version"' } });
  assert.equal(conditional.status, 200); assert.equal(w.requests.length, before);
});

test('range interception cannot expand the whitelist or accept arbitrary query/private URLs', async () => {
  const w = worker(); await w.lifecycle('install'); const before = w.writes.length;
  for (const path of [audioRoot + 'vi/user-note.mp3', audioRoot + 'en/saved_inspect.mp3', '/photos/secret.mp3',
    audioPaths[0] + '?user=1', audioPaths[0] + '?rev=old', audioPaths[0] + '?rev=natural-female-1&user=1',
    '/static/app.css?rev=natural-female-1', audioRoot + 'manifest.json?rev=natural-female-1',
    'https://external.test' + audioPaths[0], '/api/offline/status', '/records']) {
    assert.equal(await w.fetchPage(path, { mode: 'no-cors', headers: { Range: 'bytes=0-1' } }), null, path);
  }
  assert.equal(await w.fetchPage(audioPaths[0], { method: 'POST', headers: { Range: 'bytes=0-1' } }), null);
  assert.equal(await w.fetchPage(audioPaths[0], { method: 'HEAD', headers: { Range: 'bytes=0-1' } }), null);
  const css = await w.fetchPage('/static/app.css', { headers: { Range: 'bytes=0-1' } }); assert.equal(css.status, 200);
  assert.equal(w.writes.length, before);
});

test('exact public audio revision plays cached bytes and ranges without a network request', async () => {
  const w = worker(); await w.lifecycle('install'); w.self.navigator.onLine = false;
  const requests = w.requests.length, writes = w.writes.length;
  w.respond(() => { throw new Error('network unavailable'); });
  for (const path of audioPaths) {
    const full = await w.fetchPage(path + '?rev=natural-female-1', { mode: 'cors' });
    assert.equal(full.status, 200); assert.deepEqual(new Uint8Array(await full.arrayBuffer()), audioBytes);
    const partial = await w.fetchPage(path + '?rev=natural-female-1', { mode: 'cors', headers: { Range: 'bytes=0-9' } });
    assert.equal(partial.status, 206); assert.deepEqual(new Uint8Array(await partial.arrayBuffer()), audioBytes.slice(0, 10));
  }
  assert.equal(w.requests.length, requests); assert.equal(w.writes.length, writes);
});

test('uncached audio Range passes through without caching a network 206', async () => {
  const w = worker(); await w.lifecycle('install'); currentStore(w).delete(audioPaths[0]); const before = w.writes.length;
  w.respond(request => {
    assert.equal(request.headers.get('Range'), 'bytes=0-1');
    return Promise.resolve(new Response(audioBytes.slice(0, 2), { status: 206, headers: { 'Content-Type': 'audio/mpeg' } }));
  });
  assert.equal((await w.fetchPage(audioPaths[0], { headers: { Range: 'bytes=0-1' } })).status, 206);
  assert.equal(w.writes.length, before); assert.equal((await readiness(w)).ready, false);
});

test('explicit preparation repairs evicted same-version assets without reinstalling the worker', async () => {
  const w = worker(); await w.lifecycle('install'); currentStore(w).delete(audioPaths[0]);
  const before = w.requests.length, lifecycleCalls = w.actions.slice();
  assert.equal((await readiness(w)).ready, false); assert.equal(w.requests.length, before);
  const result = await readiness(w, 'PATROL_OFFLINE_PREPARE');
  assert.equal(result.ready, true); assert.equal(result.audioReady, true);
  assert.equal(w.requests.length, before + required.length); assert.deepEqual(w.actions, lifecycleCalls);
  const now = w.requests.length; assert.equal((await readiness(w, 'PATROL_OFFLINE_PREPARE')).ready, true);
  assert.equal(w.requests.length, now);
});

test('concurrent preparation messages share one bounded download instead of duplicating the pack', async () => {
  const w = worker();
  const results = await Promise.all([readiness(w, 'PATROL_OFFLINE_PREPARE'), readiness(w, 'PATROL_OFFLINE_PREPARE'), readiness(w, 'PATROL_OFFLINE_PREPARE')]);
  assert(results.every(value => value.ready && value.audioReady)); assert.equal(w.requests.length, required.length);
  assert.equal(w.actions.length, 0);
});

test('offline preparation returns not-ready promptly and does not contact the network', async () => {
  const w = worker(); w.self.navigator.onLine = false;
  const result = await readiness(w, 'PATROL_OFFLINE_PREPARE');
  assert.equal(result.ready, false); assert.equal(result.audioReady, false); assert.equal(w.requests.length, 0);
});

test('failed repair preserves surviving cache entries and a subsequent retry can succeed', async () => {
  const w = worker(); await w.lifecycle('install'); const store = currentStore(w), oldShell = store.get('/offline');
  store.delete(audioPaths[0]); const before = w.writes.length;
  w.respond(request => Promise.resolve(new URL(request.url).pathname === audioPaths[0] ? new Response('temporarily unavailable', { status: 503 }) : defaultResponse(new URL(request.url).pathname)));
  assert.equal((await readiness(w, 'PATROL_OFFLINE_PREPARE')).ready, false);
  assert.equal(w.writes.length, before); assert.equal(store.get('/offline'), oldShell);
  w.respond(request => Promise.resolve(defaultResponse(new URL(request.url).pathname)));
  assert.equal((await readiness(w, 'PATROL_OFFLINE_PREPARE')).ready, true);
});
