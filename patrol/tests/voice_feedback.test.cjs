'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createFeedback, install, MESSAGES } = require('../static/patrol-voice.js');

class MemoryStorage {
  constructor() { this.values = new Map(); }
  getItem(key) { return this.values.get(key) ?? null; }
  setItem(key, value) { this.values.set(key, String(value)); }
  removeItem(key) { this.values.delete(key); }
}
class Clock {
  constructor() { this.time = 0; this.next = 1; this.jobs = new Map(); }
  setTimeout(callback, delay) { const id = this.next++; this.jobs.set(id, { at: this.time + delay, callback }); return id; }
  clearTimeout(id) { this.jobs.delete(id); }
  advance(milliseconds) {
    const end = this.time + milliseconds;
    for (let limit = 0; limit < 100; limit++) {
      const due = [...this.jobs].filter(([, task]) => task.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) { this.time = end; return; }
      this.time = due[1].at; this.jobs.delete(due[0]); due[1].callback();
    }
    throw Error('Unexpected timer loop');
  }
}
function event(audio, type) { audio['on' + type]?.({ target: audio }); }
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function setup(options = {}) {
  const clock = new Clock(), audios = [], states = [];
  let locale = options.locale || 'vi', online = true, visible = true;
  function createAudio(src) {
    if (options.factoryThrows) throw Error('Audio constructor unavailable');
    const audio = { src, originalSrc: src, playedSources: [], playCalls: 0, pauseCalls: 0, loadCalls: 0, removed: [],
      play() { this.playCalls++; this.playedSources.push(this.src); return options.play?.(this); },
      pause() { this.pauseCalls++; options.pause?.(this); },
      removeAttribute(name) { this.removed.push(name); if (name === 'src') this.src = ''; },
      load() { this.loadCalls++; } };
    let currentSrc = src;
    Object.defineProperty(audio, 'src', { configurable: true, get: () => currentSrc, set(value) { currentSrc = value; if (!audio.originalSrc && value) audio.originalSrc = value; } });
    audios.push(audio); return audio;
  }
  const localStorage = options.localStorage || new MemoryStorage(), sessionStorage = options.sessionStorage || new MemoryStorage();
  const api = createFeedback({ createAudio: options.unsupported ? undefined : createAudio,
    localStorage, sessionStorage, getLocale: () => locale, primeSource: options.primeSource,
    isVisible: () => visible, isOnline: () => online, onState: state => states.push(state),
    setTimeout: (fn, ms) => clock.setTimeout(fn, ms), clearTimeout: id => clock.clearTimeout(id) });
  return { api, createAudio, audios, states, clock, localStorage, sessionStorage,
    setLocale: value => { locale = value; }, setOnline: value => { online = value; }, setVisible: value => { visible = value; } };
}

test('confirmed audio starts synchronously and reuses its element until disposal', () => {
  const { api, audios } = setup(); api.setEnabled(true);
  api.report('saved_execute', { id: 'execute-1' });
  assert.equal(audios.length, 1); assert.equal(audios[0].playCalls, 1);
  assert.equal(audios[0].originalSrc, '/static/audio/patrol-v1/vi/saved_execute.mp3?rev=natural-female-1');
  assert.equal(audios[0].preload, 'auto'); assert.equal(audios[0].volume, 1); assert.equal(audios[0].muted, false);
  event(audios[0], 'playing'); assert.equal(api.state().status, 'playing');
  event(audios[0], 'ended'); assert.equal(api.state().status, 'played');
  assert.equal(audios[0].pauseCalls, 1); assert.deepEqual(audios[0].removed, []); assert.equal(audios[0].loadCalls, 0);
  api.replay(); assert.equal(audios.length, 1); assert.equal(audios[0].playCalls, 2); api.dispose();
  assert.deepEqual(audios[0].removed, ['src']); assert.equal(audios[0].loadCalls, 1);
});

for (const locale of ['zh-Hant', 'id', 'vi']) {
  test(locale + ' uses only the 13 public fixed audio assets, without installed speech voices', () => {
    const { api, audios } = setup({ locale }); assert.equal(Object.keys(MESSAGES).length, 13);
    for (const kind of Object.keys(MESSAGES)) {
      api.report(kind, { id: locale + ':' + kind });
      assert.equal(audios[0].src, '/static/audio/patrol-v1/' + locale + '/' + kind + '.mp3?rev=natural-female-1');
      assert.equal(new URL(audios[0].src, 'https://patrol.test').search, '?rev=natural-female-1');
    }
    assert.equal(audios.length, 1); assert.equal(audios[0].playCalls, 13); api.dispose();
  });
}

test('unknown kinds and invalid ids cannot create success audio or request arbitrary paths', () => {
  const { api, audios } = setup();
  for (const kind of ['arbitrary success text', '../secret', '__proto__', 'constructor', 'saved_execute?user=1'])
    assert.equal(api.report(kind, { id: 'untrusted' }), false);
  for (const id of ['', 'x'.repeat(181), null, 7]) assert.equal(api.report('saved_execute', { id }), false);
  assert.equal(audios.length, 0); api.dispose();
});

test('unrecognized locale cannot escape the public locale allowlist', () => {
  const f = setup();
  for (const value of ['../private', '__proto__', 'constructor', 'toString', 'en', 'zh-TW', null]) {
    f.setLocale(value); f.api.report('saved_execute', { id: 'locale:' + String(value) });
    assert.equal(f.audios[0].src, '/static/audio/patrol-v1/zh-Hant/saved_execute.mp3?rev=natural-female-1');
  }
  f.api.dispose();
});

test('muted reports and enabling sound do not replay old results automatically', () => {
  const { api, audios, localStorage } = setup();
  api.setEnabled(false); api.report('offline_stored', { id: 'local-1' });
  assert.equal(audios.length, 0); assert.equal(api.state().status, 'off');
  assert.equal(localStorage.getItem('patrol-voice-enabled-v1'), 'off');
  api.setEnabled(true); assert.equal(audios.length, 0);
  api.replay(); assert.equal(audios.length, 1); api.dispose();
});

test('a result id is auto-consumed once per tab, including a newly loaded module', () => {
  const first = setup(); first.api.setEnabled(true);
  first.api.report('saved_inspect', { id: 'receipt-1' }); first.api.report('saved_inspect', { id: 'receipt-1' });
  assert.equal(first.audios.length, 1); first.api.dispose();
  const next = setup({ localStorage: first.localStorage, sessionStorage: first.sessionStorage });
  next.api.report('saved_inspect', { id: 'receipt-1' }); assert.equal(next.audios.length, 0);
  next.api.replay(); assert.equal(next.audios.length, 1); next.api.dispose();
});

test('history receipt auto=false needs explicit replay', () => {
  const { api, audios } = setup(); api.setEnabled(true);
  api.report('receipt_confirmed', { id: 'old-receipt-1', auto: false });
  assert.equal(audios.length, 0); api.replay(); assert.equal(audios.length, 1); api.dispose();
});

test('play promise resolution and playing event share one playback watchdog', async () => {
  const play = deferred(), f = setup({ play: () => play.promise });
  f.api.report('saved_execute', { id: 'promise' }); assert.equal(f.api.state().status, 'waiting');
  play.resolve(); await Promise.resolve(); assert.equal(f.api.state().status, 'playing');
  assert.equal(f.clock.jobs.size, 1); event(f.audios[0], 'playing'); assert.equal(f.clock.jobs.size, 1);
  event(f.audios[0], 'ended'); assert.equal(f.api.state().status, 'played'); assert.equal(f.clock.jobs.size, 0); f.api.dispose();
});

for (const online of [true, false]) {
  test((online ? 'online' : 'offline') + ' media error and bounded loading timeout retain the result for replay', () => {
    const f = setup(); f.setOnline(online);
    f.api.report('offline_stored', { id: 'media-error' }); event(f.audios[0], 'error');
    assert.equal(f.api.state().status, online ? 'audio_missing' : 'offline_audio');
    assert.equal(f.api.state().lastResult.kind, 'offline_stored');
    f.api.replay(); f.clock.advance(4999); assert.equal(f.api.state().status, 'waiting');
    f.clock.advance(1); assert.equal(f.api.state().status, online ? 'audio_missing' : 'offline_audio');
    assert.equal(f.audios.length, 1); assert.equal(f.audios[0].pauseCalls, 2); f.api.dispose();
  });
}

test('offline playback still attempts the same local asset without requiring a device speech voice', () => {
  const f = setup(); f.setOnline(false); f.api.report('offline_stored', { id: 'cached-local' });
  assert.equal(f.audios.length, 1); event(f.audios[0], 'playing'); event(f.audios[0], 'ended');
  assert.equal(f.api.state().status, 'played'); f.api.dispose();
});

test('a media ended event without confirmed playback never claims played', () => {
  const f = setup(); f.api.report('saved_execute', { id: 'ended-early' }); event(f.audios[0], 'ended');
  assert.equal(f.api.state().status, 'audio_missing'); assert.equal(f.api.state().speaking, false); f.api.dispose();
});

test('a stalled started audio stops at the bounded playback watchdog', () => {
  const f = setup(); f.api.report('saved_execute', { id: 'stalled' }); event(f.audios[0], 'playing');
  f.clock.advance(19999); assert.equal(f.api.state().status, 'playing');
  f.clock.advance(1); assert.equal(f.api.state().status, 'audio_missing'); assert.equal(f.audios[0].pauseCalls, 1); f.api.dispose();
});

test('autoplay rejection offers manual retry without losing or relabeling the confirmed result', async () => {
  const play = deferred(), f = setup({ play: () => play.promise });
  f.api.report('saved_inspect', { id: 'blocked' }); play.reject(Object.assign(new Error('gesture required'), { name: 'NotAllowedError' }));
  await Promise.resolve(); assert.equal(f.api.state().status, 'blocked');
  assert.equal(f.api.state().lastResult.kind, 'saved_inspect'); f.api.replay(); assert.equal(f.audios.length, 1); assert.equal(f.audios[0].playCalls, 2); f.api.dispose();
});

test('synchronous play failure and broken Audio constructors cannot throw into save callers', () => {
  for (const options of [{ play: () => { throw Object.assign(new Error('blocked'), { name: 'NotAllowedError' }); } }, { factoryThrows: true }]) {
    const f = setup(options); assert.doesNotThrow(() => f.api.report('saved_execute', { id: 'throw' }));
    assert.equal(f.api.state().status, options.factoryThrows ? 'unavailable' : 'blocked'); f.api.dispose();
  }
});

test('cancel and mute ignore captured late handlers and settled play promises', async () => {
  for (const [cancel, released] of [[f => f.api.cancel(true), false], [f => f.api.setEnabled(false), false], [f => f.api.dispose(), true]]) {
    const play = deferred(), f = setup({ play: () => play.promise });
    f.api.report('saved_inspect', { id: 'cancel-1' });
    const audio = f.audios[0], callbacks = [audio.onplaying, audio.onended, audio.onerror];
    cancel(f); const after = f.api.state();
    callbacks.forEach(fn => fn()); play.resolve(); await Promise.resolve(); f.clock.advance(25000);
    assert.deepEqual(f.api.state(), after); assert.equal(audio.pauseCalls, 1);
    assert.equal(audio.src, released ? '' : audio.originalSrc);
    assert.equal(audio.onplaying, null); assert.equal(audio.onended, null); assert.equal(audio.onerror, null); f.api.dispose();
  }
});

test('a superseded result cannot be overwritten by the old audio rejection', async () => {
  const old = deferred(), f = setup({ play: audio => new URL(audio.src, 'https://patrol.test').pathname.endsWith('/saved_execute.mp3') ? old.promise : undefined });
  f.api.report('saved_execute', { id: 'old' }); f.api.report('offline_stored', { id: 'new' });
  event(f.audios[0], 'playing'); old.reject(new Error('late network failure')); await Promise.resolve();
  assert.equal(f.api.state().lastResult.kind, 'offline_stored'); assert.equal(f.api.state().status, 'playing'); f.api.dispose();
});

test('hidden result and disposed module cannot start audio', () => {
  const f = setup(); f.setVisible(false); f.api.report('saved_execute', { id: 'hidden' });
  assert.equal(f.audios.length, 0); f.api.dispose(); f.setVisible(true); f.api.replay(); f.api.report('saved_execute', { id: 'disposed' });
  assert.equal(f.audios.length, 0);
});

test('locale refresh cancels old playback and manual replay selects the new language', () => {
  const f = setup(); f.api.report('saved_visit', { id: 'language' });
  f.setLocale('id'); f.api.refresh(); assert.equal(f.audios[0].pauseCalls, 1); assert.equal(f.audios.length, 1);
  f.api.replay(); assert.equal(f.audios.length, 1); assert.equal(f.audios[0].src, '/static/audio/patrol-v1/id/saved_visit.mp3?rev=natural-female-1'); f.api.dispose();
});

test('missing Audio API and denied storage remain nonfatal to check-in callers', () => {
  const storage = { getItem() { throw Error('denied'); }, setItem() { throw Error('denied'); }, removeItem() { throw Error('denied'); } };
  const { api } = setup({ unsupported: true, localStorage: storage, sessionStorage: storage });
  assert.doesNotThrow(() => { api.setEnabled(true); api.report('offline_stored', { id: 'without-api' }); api.replay(); api.cancel(true); api.dispose(); });
  assert.equal(api.state().supported, false);
});

test('older browsers without Object.hasOwn can report optional feedback', () => {
  const original = Object.hasOwn;
  try {
    Object.hasOwn = undefined;
    const { api, audios } = setup(); assert.doesNotThrow(() => api.report('saved_visit', { id: 'old-browser' }));
    assert.equal(audios.length, 1); api.dispose();
  } finally { Object.hasOwn = original; }
});

function installed(options = {}) {
  const fixture = setup(options), root = new EventTarget(), doc = new EventTarget();
  fixture.api.dispose();
  doc.visibilityState = 'visible'; doc.documentElement = { lang: 'vi' };
  doc.body = { dataset: { offlineUser: options.actor || 'actor-a' }, hasAttribute: () => Boolean(options.shell) };
  doc.querySelectorAll = selector => selector === '[data-voice-controls]' ? options.panels || [] : [];
  doc.querySelector = selector => selector === '[data-voice-result]' && options.result ? { dataset: options.result } : null;
  root.document = doc; root.localStorage = fixture.localStorage; root.sessionStorage = fixture.sessionStorage;
  root.location = new URL(options.path || '/c/point-a?round=2', 'https://patrol.test');
  root.navigator = { onLine: true }; root.audioConstruction = [];
  root.Blob = Blob; root.primeBlobs = []; root.revokedURLs = [];
  root.URL = { createObjectURL(blob) { root.primeBlobs.push(blob); return 'blob:patrol-prime'; }, revokeObjectURL(value) { root.revokedURLs.push(value); } };
  root.Audio = function (...args) {
    root.audioConstruction.push(args);
    const audio = fixture.createAudio(args[0]);
    if (options.strictCORS) {
      const descriptor = Object.getOwnPropertyDescriptor(audio, 'src');
      Object.defineProperty(audio, 'src', { configurable: true, get: descriptor.get, set(value) {
        assert.equal(audio.crossOrigin, 'anonymous', 'CORS must be set before the MP3 URL enters the media loader'); descriptor.set(value);
      } });
    }
    return audio;
  };
  for (const name of ['speechSynthesis', 'SpeechSynthesisUtterance']) Object.defineProperty(root, name, { get() { throw Error('Device speech API must not be read'); } });
  root.PatrolI18n = { getLocale: () => 'vi', t: text => text };
  const api = install(root);
  return { ...fixture, root, doc, api };
}
function dispatch(target, name, extra = {}) {
  const value = new Event(name);
  for (const [key, item] of Object.entries(extra)) Object.defineProperty(value, key, { value: item });
  target.dispatchEvent(value);
}

test('scanner intent is same-origin, exact destination and one-time', () => {
  const storage = new MemoryStorage();
  let first = installed({ sessionStorage: storage });
  first.api.armScan('https://external.test/c/point-a?round=2');
  assert.equal(storage.getItem('patrol-voice-scan-v1'), null);
  first.api.armScan('/c/point-a?round=2'); first.api.dispose();
  const next = installed({ sessionStorage: storage, shell: true });
  assert.equal(next.api.takeScan(), true); assert.equal(next.api.takeScan(), false); next.api.dispose();
  first = installed({ sessionStorage: storage }); first.api.armScan('/c/point-a?round=1'); first.api.dispose();
  const mismatch = installed({ sessionStorage: storage }); assert.equal(mismatch.api.takeScan(), false); mismatch.api.dispose();
});

test('stale and future scanner intent do not trigger automatic playback', () => {
  for (const at of [Date.now() - 91000, Date.now() + 10000]) {
    const storage = new MemoryStorage();
    storage.setItem('patrol-voice-scan-v1', JSON.stringify({ path: '/c/point-a?round=2', at }));
    const fixture = installed({ sessionStorage: storage, result: { voiceResult: 'waiting_execution', voiceResultId: 'scan-blocked', voiceAuto: 'scan' } });
    assert.equal(fixture.audios.length, 0); fixture.api.dispose();
  }
});

test('a scan outcome speaks only when it consumes the exact scanner intent', () => {
  const storage = new MemoryStorage();
  storage.setItem('patrol-voice-scan-v1', JSON.stringify({ path: '/c/point-a?round=2', at: Date.now() }));
  const fixture = installed({ sessionStorage: storage, result: { voiceResult: 'waiting_execution', voiceResultId: 'scan-wait', voiceAuto: 'scan' } });
  assert.equal(fixture.audios.length, 1); assert.equal(fixture.api.takeScan(), false); fixture.api.dispose();
});

test('pagehide and account-change cancel active feedback and ignore stale callbacks', () => {
  const fixture = installed(); fixture.api.report('saved_execute', { id: 'leaving-1' });
  const stale = fixture.audios[0]; dispatch(fixture.root, 'pagehide'); event(stale, 'playing');
  assert.equal(fixture.api.state().speaking, false);
  dispatch(fixture.doc, 'patrol:voice-owner-changed');
  assert.equal(fixture.api.state().lastResult, null);
  event(stale, 'ended'); assert.equal(fixture.api.state().lastResult, null); fixture.api.dispose();
});

test('logout clears result and pending scan or cross-page arrival before response', () => {
  const fixture = installed(); fixture.api.report('saved_inspect', { id: 'logout-1' });
  fixture.api.armScan('/c/point-a'); fixture.api.armResult('offline_stored', 'local-logout', '/offline', 'actor-a');
  dispatch(fixture.doc, 'submit', { target: { action: 'https://patrol.test/logout' } });
  assert.equal(fixture.api.state().lastResult, null);
  assert.equal(fixture.sessionStorage.getItem('patrol-voice-scan-v1'), null);
  assert.equal(fixture.sessionStorage.getItem('patrol-voice-arrival-v1'), null); fixture.api.dispose();
});

test('cross-page offline result waits for identity and cannot cross account or destination', () => {
  const fixture = installed({ path: '/offline', shell: true, actor: '' });
  fixture.api.armResult('offline_stored', 'local-1', '/offline', 'actor-a');
  assert.equal(fixture.api.takeResult(''), null);
  assert(fixture.sessionStorage.getItem('patrol-voice-arrival-v1'));
  assert.equal(fixture.api.takeResult('actor-b'), null);
  fixture.api.armResult('offline_stored', 'local-2', '/offline', 'actor-a');
  assert.equal(fixture.api.takeResult('actor-a').id, 'local-2');
  assert.equal(fixture.api.takeResult('actor-a'), null);
  fixture.api.armResult('offline_stored', 'local-3', '/offline?point=other', 'actor-a');
  assert.equal(fixture.api.takeResult('actor-a'), null); fixture.api.dispose();
});

test('explicitly clearing a pending arrival prevents later playback after an account change', () => {
  const fixture = installed({ path: '/offline', shell: true });
  fixture.api.armResult('offline_stored', 'local-before-owner-change', '/offline', 'actor-a');
  assert(fixture.sessionStorage.getItem('patrol-voice-arrival-v1'));
  fixture.api.clearResult();
  assert.equal(fixture.sessionStorage.getItem('patrol-voice-arrival-v1'), null);
  assert.equal(fixture.api.takeResult('actor-a'), null); assert.equal(fixture.audios.length, 0); fixture.api.dispose();
});

test('cross-tab mute applies without replaying prior speech when enabled again', () => {
  const fixture = installed(); fixture.api.report('saved_visit', { id: 'tab-mute' });
  dispatch(fixture.root, 'storage', { key: 'patrol-voice-enabled-v1', newValue: 'off' });
  assert.equal(fixture.api.state().enabled, false); assert.equal(fixture.api.state().speaking, false);
  dispatch(fixture.root, 'storage', { key: 'patrol-voice-enabled-v1', newValue: 'on' });
  assert.equal(fixture.audios.length, 1); fixture.api.dispose();
});

test('partial sync, local storage and confirmed sync retain distinct result meanings', () => {
  const fixture = setup();
  for (const [kind, id] of [['offline_stored', 'local:one'], ['sync_partial', 'partial:one'], ['sync_confirmed', 'ack:one']]) {
    fixture.api.report(kind, { id }); assert.equal(fixture.api.state().lastResult.kind, kind);
  }
  assert.equal(fixture.audios.length, 1);
  assert.equal(new Set(fixture.audios[0].playedSources).size, 3); fixture.api.dispose();
});

test('confirm intent can cover its own validation page but not another point', () => {
  const storage = new MemoryStorage();
  let fixture = installed({ sessionStorage: storage, path: '/c/point-a' });
  fixture.api.armScan('/c/point-a/confirm', 'confirm'); fixture.api.dispose();
  fixture = installed({ sessionStorage: storage, path: '/c/point-a', result: { voiceResult: 'not_saved', voiceResultId: 'validation-a', voiceAuto: 'scan' } });
  assert.equal(fixture.audios.length, 1); fixture.api.dispose();
  fixture = installed({ sessionStorage: storage, path: '/c/point-a' });
  fixture.api.armScan('/c/point-a/confirm', 'confirm'); fixture.api.dispose();
  fixture = installed({ sessionStorage: storage, path: '/c/point-b', result: { voiceResult: 'not_saved', voiceResultId: 'validation-b', voiceAuto: 'scan' } });
  assert.equal(fixture.audios.length, 0); fixture.api.dispose();
});

test('consumed result storage is bounded and contains no spoken/private text', () => {
  const fixture = setup(); fixture.api.setEnabled(false);
  for (let i = 0; i < 55; i++) fixture.api.report('saved_inspect', { id: 'receipt-' + i });
  const values = JSON.parse(fixture.sessionStorage.getItem('patrol-voice-seen-v1'));
  assert.equal(values.length, 50); assert.equal(values[0], 'receipt-5');
  assert(values.every(value => /^receipt-\d+$/.test(value))); fixture.api.dispose();
});


test('installed native Audio sets anonymous CORS before src and never passes src to constructor', () => {
  const f = installed({ strictCORS: true }); f.api.report('saved_execute', { id: 'cors-media' });
  assert.deepEqual(f.root.audioConstruction, [[]]);
  assert.equal(f.audios[0].crossOrigin, 'anonymous');
  assert.equal(f.audios[0].originalSrc, '/static/audio/patrol-v1/vi/saved_execute.mp3?rev=natural-female-1');
  assert.equal(f.audios[0].playCalls, 1); f.api.dispose();
});

test('gesture preparation silently unlocks one element for a later asynchronous result', async () => {
  let gesture = true;
  const f = setup({ primeSource: 'blob:zero-pcm', play(audio) {
    if (!gesture && !audio.unlocked) throw Object.assign(Error('gesture required'), { name: 'NotAllowedError' });
    audio.unlocked = true; return Promise.resolve();
  } });
  assert.equal(f.api.prepare(), true); assert.equal(f.audios[0].playCalls, 1);
  assert.equal(f.audios[0].muted, false); assert.equal(f.api.state().lastResult, null);
  assert.equal(f.api.state().speaking, false); assert.equal(f.api.state().status, 'ready');
  assert.equal(f.sessionStorage.getItem('patrol-voice-seen-v1'), null);
  gesture = false; await Promise.resolve(); event(f.audios[0], 'ended');
  await Promise.resolve(); f.api.report('saved_execute', { id: 'actual-server-ack' }); await Promise.resolve();
  assert.equal(f.audios.length, 1); assert.equal(f.api.state().status, 'playing');
  assert.deepEqual(f.audios[0].playedSources, ['blob:zero-pcm', '/static/audio/patrol-v1/vi/saved_execute.mp3?rev=natural-female-1']);
  f.api.dispose();
});

test('late silent preparation callbacks and promise failure cannot interrupt confirmed audio', async () => {
  const priming = deferred(), f = setup({ primeSource: 'blob:zero-pcm', play: audio => audio.src === 'blob:zero-pcm' ? priming.promise : undefined });
  f.api.prepare(); const audio = f.audios[0], ended = audio.onended, failed = audio.onerror;
  f.api.report('saved_inspect', { id: 'confirmed-after-prime' }); event(audio, 'playing');
  const pauseCalls = audio.pauseCalls; ended(); failed(); priming.reject(new Error('old request aborted')); await Promise.resolve();
  assert.equal(f.api.state().status, 'playing'); assert.equal(audio.pauseCalls, pauseCalls);
  assert.equal(f.api.state().lastResult.id, 'confirmed-after-prime');
  f.clock.advance(3000); assert.equal(f.api.state().status, 'playing'); f.api.dispose();
});

test('failed, muted, hidden or unsupported preparation never claims a result or throws', async () => {
  for (const options of [{ factoryThrows: true }, { unsupported: true }, { primeSource: () => { throw Error('blob denied'); } },
    { play: () => Promise.reject(Object.assign(Error('no gesture'), { name: 'NotAllowedError' })) }]) {
    const f = setup({ primeSource: 'blob:zero-pcm', ...options });
    assert.doesNotThrow(() => f.api.prepare()); await Promise.resolve();
    assert.equal(f.api.state().lastResult, null); assert.equal(f.api.state().speaking, false); f.api.dispose();
  }
  const f = setup({ primeSource: 'blob:zero-pcm' }); f.api.setEnabled(false); assert.equal(f.api.prepare(), false);
  f.api.setEnabled(true); f.setVisible(false); assert.equal(f.api.prepare(), false);
  f.setVisible(true); f.api.dispose(); assert.equal(f.api.prepare(), false); assert.equal(f.audios.length, 0);
});

test('idle waiting is bounded independently of the loading and playback watchdogs', async () => {
  const f = setup(); f.api.report('saved_inspect', { id: 'idle-bound' });
  let done = false; f.api.waitForIdle(4500).then(() => { done = true; });
  assert.equal(f.clock.jobs.size, 2); f.clock.advance(4499); await Promise.resolve(); assert.equal(done, false);
  f.clock.advance(1); await Promise.resolve(); assert.equal(done, true); assert.equal(f.api.state().status, 'waiting');
  assert.equal(f.clock.jobs.size, 1); f.clock.advance(500); assert.equal(f.api.state().status, 'audio_missing'); f.api.dispose();
});

test('idle waiting resolves on ended, rejected, cancelled, muted, hidden and disposed playback', async () => {
  for (const finish of [f => event(f.audios[0], 'ended'), f => event(f.audios[0], 'error'),
    f => f.api.cancel(true), f => f.api.setEnabled(false), f => { f.setVisible(false); f.api.cancel(); }, f => f.api.dispose()]) {
    const f = setup(); f.api.report('saved_inspect', { id: 'idle-terminal' }); event(f.audios[0], 'playing');
    let done = false; f.api.waitForIdle().then(() => { done = true; }); finish(f); await Promise.resolve();
    assert.equal(done, true); assert.equal(f.clock.jobs.size, 0); assert.equal(f.audios[0].playCalls, 1); f.api.dispose();
  }
  const f = setup(); await f.api.waitForIdle(); assert.equal(f.audios.length, 0); assert.equal(f.clock.jobs.size, 0); f.api.dispose();
});

test('installed submit and sync hooks prepare actual silent PCM without reporting attendance', async () => {
  const f = installed({ strictCORS: true });
  dispatch(f.doc, 'submit', { target: { id: 'inspection-form', action: '/c/point-a/confirm' } });
  assert.equal(f.audios.length, 1); assert.equal(f.audios[0].src, 'blob:patrol-prime'); assert.equal(f.api.state().lastResult, null);
  dispatch(f.doc, 'submit', { target: { id: 'offline-checkin', action: '/offline' } });
  const button = { hasAttribute: key => key === 'data-offline-sync' };
  dispatch(f.doc, 'click', { target: { closest: () => button } });
  assert.equal(f.audios[0].playCalls, 3); assert.equal(f.audios.length, 1); assert.equal(f.root.primeBlobs.length, 1);
  const bytes = await f.root.primeBlobs[0].arrayBuffer(), view = new DataView(bytes);
  assert.equal(f.root.primeBlobs[0].type, 'audio/wav'); assert.equal(bytes.byteLength, 1644);
  assert.equal(new TextDecoder().decode(new Uint8Array(bytes, 0, 4)), 'RIFF');
  assert.equal(view.getUint32(24, true), 8000); assert.equal(view.getUint32(40, true), 1600);
  assert(new Uint8Array(bytes, 44).every(value => value === 0));
  f.api.dispose(); assert.deepEqual(f.root.revokedURLs, ['blob:patrol-prime']);
});

test('only enabling the local toggle prepares audio; cross-tab enable does not play', () => {
  const f = installed(); f.api.setEnabled(false);
  const button = { hasAttribute: key => key === 'data-voice-toggle' };
  dispatch(f.doc, 'click', { target: { closest: () => button } });
  assert.equal(f.audios[0].playCalls, 1); assert.equal(f.api.state().lastResult, null);
  dispatch(f.root, 'storage', { key: 'patrol-voice-enabled-v1', newValue: 'off' });
  dispatch(f.root, 'storage', { key: 'patrol-voice-enabled-v1', newValue: 'on' });
  assert.equal(f.audios[0].playCalls, 1); f.api.dispose();
});

test('blocked panels expose a visible manual playback action and restore normal replay wording', async () => {
  const label = { dataset: {} }, replay = { querySelector: selector => selector === '.patrol-voice-label' ? label : null }, status = {};
  const panel = { dataset: {}, querySelector: selector => ({ '[data-voice-replay]': replay, '[data-voice-status]': status })[selector] || null };
  let blocked = true;
  const f = installed({ panels: [panel], play: () => blocked ? Promise.reject(Object.assign(Error('gesture required'), { name: 'NotAllowedError' })) : undefined });
  f.api.report('saved_inspect', { id: 'blocked-panel' }); await Promise.resolve();
  assert.equal(panel.hidden, false); assert.equal(panel.dataset.voiceStatus, 'blocked');
  assert.equal(replay.hidden, false); assert.equal(replay.disabled, false);
  assert.equal(label.dataset.i18n, '點一下播放結果'); assert.equal(label.textContent, '點一下播放結果');
  assert.equal(status.textContent, '瀏覽器限制自動播放，請點一下播放結果。');
  blocked = false; f.api.replay(); event(f.audios[0], 'playing');
  assert.equal(panel.dataset.voiceStatus, 'playing'); assert.equal(label.dataset.i18n, '重播結果'); assert.equal(label.textContent, '重播結果');
  event(f.audios[0], 'ended'); assert.equal(panel.dataset.voiceStatus, 'played'); f.api.dispose();
});
