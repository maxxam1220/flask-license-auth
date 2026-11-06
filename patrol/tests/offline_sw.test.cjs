const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require.resolve('../static/offline-sw.js'), 'utf8');
const origin = 'https://patrol.test';
function worker() {
  const hooks = {}, stores = new Map(), requests = [], writes = [];
  const key = value => typeof value === 'string' ? new URL(value, origin).pathname : new URL(value.url).pathname;
  let responder = request => Promise.resolve(new Response(key(request) === '/offline' ? 'GENERIC OFFLINE SHELL' : 'asset', { status: 200 }));
  const caches = { async keys() { return [...stores.keys()]; }, async delete(name) { return stores.delete(name); }, async open(name) {
    if (!stores.has(name)) stores.set(name, new Map()); const entries = stores.get(name);
    return { async put(path, response) { writes.push(key(path)); entries.set(key(path), response.clone()); }, async match(path) { return entries.get(key(path))?.clone(); } };
  } };
  const self = { location: new URL(origin), navigator: { onLine: true }, addEventListener(name, fn) { hooks[name] = fn; }, skipWaiting: async () => {}, clients: { claim: async () => {} } };
  class WorkerRequest extends Request { constructor(value, init) { super(typeof value === 'string' ? new URL(value, origin) : value, init); } }
  vm.runInNewContext(source, { self, caches, URL, Request: WorkerRequest, Response, AbortController, setTimeout, clearTimeout,
    fetch(request, init) { requests.push(request); return responder(request, init); } });
  async function lifecycle(name, extras = {}) { let waited; hooks[name]({ ...extras, waitUntil(promise) { waited = promise; } }); await waited; }
  async function fetchPage(path, { method = 'GET', mode = 'navigate' } = {}) {
    let intercepted; const request = { url: new URL(path, origin).href, method, mode };
    hooks.fetch({ request, respondWith(promise) { intercepted = promise; } }); return intercepted ? await intercepted : null;
  }
  return { stores, writes, requests, self, lifecycle, fetchPage, respond(fn) { responder = fn; } };
}
test('install caches every required asset and only a generic offline shell', async () => {
  const w = worker(); await w.lifecycle('install');
  assert.deepEqual(w.writes.sort(), ['/offline', '/static/app.css', '/static/offline.css', '/static/offline.js', '/static/patrol-scanner.js', '/static/vendor/jsqr-1.4.0.js', '/static/logo.ico'].sort());
  assert(w.requests.every(request => request.credentials === 'omit' && request.redirect === 'error'));
});
test('one missing required asset fails install before any cache write', async () => {
  const w = worker(); w.respond(request => Promise.resolve(new Response('missing', { status: new URL(request.url).pathname.includes('jsqr') ? 404 : 200 })));
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
  const current = [...w.stores.keys()][0]; w.stores.get(current).delete('/static/offline.js');
  await w.lifecycle('message', { data: { type: 'PATROL_OFFLINE_READY' }, ports: [{ postMessage(value) { answer = value; } }] }); assert.equal(answer.ready, false);
  w.stores.set('patrol-offline-shell-old', new Map()); w.stores.set('unrelated-app-cache', new Map()); await w.lifecycle('activate');
  assert.equal(w.stores.has('patrol-offline-shell-old'), false); assert.equal(w.stores.has('unrelated-app-cache'), true);
});

test('failed updated shell installation preserves the existing usable offline cache', async () => {
  const w = worker(); const old = new Map([['/offline', new Response('previous usable shell')]]);
  w.stores.set('patrol-offline-shell-20261106-v1', old);
  w.respond(request => Promise.resolve(new Response('unavailable', { status: new URL(request.url).pathname.endsWith('offline.js') ? 503 : 200 })));
  await assert.rejects(w.lifecycle('install'));
  assert.equal(await w.stores.get('patrol-offline-shell-20261106-v1').get('/offline').text(), 'previous usable shell');
  assert.equal(w.writes.length, 0);
});
