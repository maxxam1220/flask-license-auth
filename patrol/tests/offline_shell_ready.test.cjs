const test = require('node:test');
const assert = require('node:assert/strict');
const { createShellReadiness } = require('../static/offline.js');
const complete = { ready: true, audioReady: true, audioVersion: 'patrol-v1', audioRevision: 'natural-female-1', checklistVersion: 1, calendarVersion: 1 };
function fixture(options = {}) {
  const calls = [], channels = [];
  class Channel {
    constructor() {
      const one = { closed: false, close() { this.closed = true; } };
      const two = { closed: false, close() { this.closed = true; }, postMessage(data) { if (!one.closed) one.onmessage?.({ data }); } };
      this.port1 = one; this.port2 = two; channels.push(this);
    }
  }
  const worker = (reply = complete) => ({ postMessage(message, ports) {
    calls.push(message.type); if (reply === null) return;
    queueMicrotask(() => ports[0].postMessage(typeof reply === 'function' ? reply(message.type) : reply));
  } });
  const registration = { active: worker(), installing: null, waiting: null,
    async update() { calls.push('update'); registration.active = worker(); } };
  const env = { navigator: { onLine: true, serviceWorker: { async register(path, settings) { calls.push(['register', path, settings]); return registration; } } },
    MessageChannel: Channel, isSecureContext: true, deadline: 120, pollInterval: 2, probeTimeout: 40, repairTimeout: 80, ...options };
  return { env, calls, channels, registration, worker, ensure: createShellReadiness(env) };
}
test('offline readiness requires all audio assets and exact version', async () => {
  const x = fixture(); await x.ensure();
  assert.deepEqual(x.calls, [['register', '/offline-sw.js', { scope: '/', updateViaCache: 'none' }], 'PATROL_OFFLINE_READY']);
  assert(x.channels.every(c => c.port1.closed && c.port2.closed));
});
test('older ready:true worker cannot claim built-in audio ready', async () => {
  const x = fixture(); x.registration.active = x.worker({ ready: true }); await x.ensure();
  assert.deepEqual(x.calls.slice(1), ['PATROL_OFFLINE_READY', 'update', 'PATROL_OFFLINE_READY']);
});

test('previous voice revision cannot satisfy the new audio preparation', async () => {
  const x = fixture(); const old = { ...complete }; delete old.audioRevision;
  x.registration.active = x.worker(old); await x.ensure();
  assert.deepEqual(x.calls.slice(1), ['PATROL_OFFLINE_READY', 'update', 'PATROL_OFFLINE_READY']);
  assert(!x.calls.includes('PATROL_OFFLINE_PREPARE'));
});

test('audio-ready legacy shell must update before it can capture checklist entries', async () => {
  const x = fixture(), legacy = { ...complete }; delete legacy.checklistVersion;
  x.registration.active = x.worker(legacy); await x.ensure();
  assert.deepEqual(x.calls.slice(1), ['PATROL_OFFLINE_READY', 'update', 'PATROL_OFFLINE_READY']);
  assert(!x.calls.includes('PATROL_OFFLINE_PREPARE'));
});

test('legacy cached checklist shell fails offline without replacing stored drafts', async () => {
  const x = fixture(); x.env.navigator.onLine = false; x.registration.active = x.worker({ ...complete, checklistVersion: 0 });
  await assert.rejects(x.ensure(), /尚未備妥/); assert(!x.calls.includes('update'));
});

test('old calendar labels must update before preparing fixed weekday points', async () => {
  const x = fixture(), legacy = { ...complete }; delete legacy.calendarVersion;
  x.registration.active = x.worker(legacy); await x.ensure();
  assert.deepEqual(x.calls.slice(1), ['PATROL_OFFLINE_READY', 'update', 'PATROL_OFFLINE_READY']);
});

test('old calendar shell cannot claim readiness while offline', async () => {
  const x = fixture(), legacy = { ...complete }; delete legacy.calendarVersion;
  x.env.navigator.onLine = false; x.registration.active = x.worker(legacy);
  await assert.rejects(x.ensure(), /尚未備妥/); assert(!x.calls.includes('update'));
});

test('offline old audio revision fails promptly without network repair', async () => {
  const x = fixture(); x.env.navigator.onLine = false;
  x.registration.active = x.worker({ ...complete, audioRevision: 'old-voice' });
  await assert.rejects(x.ensure(), /離線頁面與提示音尚未備妥/);
  assert(!x.calls.includes('PATROL_OFFLINE_PREPARE')); assert(!x.calls.includes('update'));
});
test('waits for already-installing new worker before accepting readiness', async () => {
  const x = fixture(); x.registration.active = x.worker({ ready: true }); x.registration.installing = {};
  setTimeout(() => { x.registration.active = x.worker(); x.registration.installing = null; }, 10);
  await x.ensure(); assert(!x.calls.includes('update')); assert.equal(x.calls.filter(v => v === 'PATROL_OFFLINE_READY').length, 2);
});
test('an evicted current cache is repaired once then validated', async () => {
  const x = fixture(); x.registration.active = x.worker(type => type === 'PATROL_OFFLINE_PREPARE' ? complete : { ...complete, ready: false, audioReady: false });
  await x.ensure(); assert.deepEqual(x.calls.slice(1), ['PATROL_OFFLINE_READY', 'PATROL_OFFLINE_PREPARE']);
});
test('failed audio repair rejects without reporting success', async () => {
  const x = fixture(); x.registration.active = x.worker({ ...complete, ready: true, audioReady: false });
  await assert.rejects(x.ensure(), /離線頁面與提示音尚未備妥/);
  assert.equal(x.calls.filter(v => v === 'PATROL_OFFLINE_PREPARE').length, 1);
});
test('offline missing audio never starts a repair fetch', async () => {
  const x = fixture(); x.env.navigator.onLine = false; x.registration.active = x.worker({ ...complete, ready: false });
  await assert.rejects(x.ensure(), /離線頁面與提示音尚未備妥/); assert(!x.calls.includes('PATROL_OFFLINE_PREPARE'));
});
test('complete cached audio is accepted offline', async () => {
  const x = fixture(); x.env.navigator.onLine = false; await x.ensure(); assert(!x.calls.includes('update'));
});
test('parallel callers share installation but next prepare rechecks cache', async () => {
  const x = fixture(); const first = x.ensure(), second = x.ensure(); assert.equal(first, second); await first;
  await x.ensure(); assert.equal(x.calls.filter(v => Array.isArray(v)).length, 2);
});
test('message timeout closes ports and subsequent retry works', async () => {
  const x = fixture(); x.registration.active = x.worker(null); await assert.rejects(x.ensure(), /尚未備妥/);
  assert(x.channels.every(c => c.port1.closed && c.port2.closed)); x.registration.active = x.worker(); await x.ensure();
});
test('overall deadline cancels hanging probes and closes channels', async () => {
  const x = fixture({ deadline: 15, probeTimeout: 80 }); x.registration.active = x.worker(null);
  await assert.rejects(x.ensure(), /準備逾時/); assert(x.channels.every(c => c.port1.closed && c.port2.closed));
});
test('insecure or unsupported contexts fail before registration', async () => {
  const x = fixture({ isSecureContext: false }); await assert.rejects(x.ensure(), /HTTPS/); assert.equal(x.calls.length, 0);
});
test('a failed registration can be retried without stale success', async () => {
  const x = fixture(); const original = x.env.navigator.serviceWorker.register;
  x.env.navigator.serviceWorker.register = async () => { throw new Error('network'); };
  await assert.rejects(x.ensure(), /network/); x.env.navigator.serviceWorker.register = original; await x.ensure();
});
