'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createFeedback, install } = require('../static/patrol-voice.js');

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
class Utterance extends EventTarget { constructor(text) { super(); this.text = text; } }
function event(utterance, type, error) {
  const value = new Event(type); if (error) Object.defineProperty(value, 'error', { value: error });
  utterance.dispatchEvent(value); utterance['on' + type]?.(value);
}
const voice = (lang, localService = true) => ({ lang, localService, name: 'QA ' + lang, voiceURI: 'qa:' + lang });
function setup(options = {}) {
  const clock = new Clock(), spoken = [], states = [];
  let voices = options.voices ?? [voice('vi-VN')], locale = options.locale || 'vi', online = true, visible = true;
  const synth = new EventTarget();
  synth.getVoices = () => voices;
  synth.speak = utterance => { spoken.push(utterance); options.onSpeak?.(utterance); };
  synth.cancel = () => { options.onCancel?.(spoken.at(-1)); };
  const localStorage = options.localStorage || new MemoryStorage(), sessionStorage = options.sessionStorage || new MemoryStorage();
  const api = createFeedback({ synth: options.unsupported ? undefined : synth, Utterance: options.unsupported ? undefined : Utterance,
    localStorage, sessionStorage, getLocale: () => locale, t: text => text,
    isVisible: () => visible, isOnline: () => online, onState: state => states.push(state),
    now: () => clock.time, setTimeout: (fn, ms) => clock.setTimeout(fn, ms), clearTimeout: id => clock.clearTimeout(id) });
  return { api, synth, spoken, states, clock, localStorage, sessionStorage,
    setLocale: value => { locale = value; }, setOnline: value => { online = value; }, setVisible: value => { visible = value; },
    setVoices: value => { voices = value; synth.dispatchEvent(new Event('voiceschanged')); } };
}

test('confirmed fixed result has start/end lifecycle and a fresh utterance for manual replay', () => {
  const { api, spoken } = setup(); api.setEnabled(true);
  api.report('saved_execute', { id: 'execute-1' });
  assert.equal(spoken.length, 1); assert.match(spoken[0].lang, /^vi(?:-|$)/i);
  event(spoken[0], 'start'); assert.equal(api.state().status, 'playing');
  event(spoken[0], 'end'); assert.equal(api.state().status, 'played');
  api.replay(); assert.equal(spoken.length, 2); assert.notEqual(spoken[0], spoken[1]);
});

test('unknown kinds cannot fabricate a spoken success result', () => {
  const { api, spoken } = setup(); api.setEnabled(true);
  api.report('arbitrary success text', { id: 'untrusted-1' });
  assert.equal(spoken.length, 0);
});

test('muted reports and enabling sound do not replay old results automatically', () => {
  const { api, spoken, localStorage } = setup();
  api.setEnabled(false); api.report('offline_stored', { id: 'local-1' });
  assert.equal(spoken.length, 0); assert.equal(api.state().status, 'off');
  assert.equal(localStorage.getItem('patrol-voice-enabled-v1'), 'off');
  api.setEnabled(true); assert.equal(spoken.length, 0);
  api.replay(); assert.equal(spoken.length, 1);
});

test('a result id is auto-consumed once per tab, including a newly loaded module', () => {
  const first = setup(); first.api.setEnabled(true);
  first.api.report('saved_inspect', { id: 'receipt-1' });
  first.api.report('saved_inspect', { id: 'receipt-1' });
  assert.equal(first.spoken.length, 1); first.api.dispose();
  const next = setup({ localStorage: first.localStorage, sessionStorage: first.sessionStorage });
  next.api.report('saved_inspect', { id: 'receipt-1' });
  assert.equal(next.spoken.length, 0);
  next.api.replay(); assert.equal(next.spoken.length, 1);
});

test('history receipt auto=false needs explicit replay', () => {
  const { api, spoken } = setup(); api.setEnabled(true);
  api.report('receipt_confirmed', { id: 'old-receipt-1', auto: false });
  assert.equal(spoken.length, 0); api.replay(); assert.equal(spoken.length, 1);
});

for (const locale of ['id', 'vi']) {
  test(locale + ' without an installed matching voice never falls back to Chinese speech', () => {
    const { api, spoken, clock } = setup({ locale, voices: [voice('zh-TW')] }); api.setEnabled(true);
    api.report('saved_visit', { id: 'missing-' + locale }); clock.advance(2000);
    assert.equal(spoken.length, 0); assert.equal(api.state().status, 'no_voice');
    assert(api.state().lastResult);
  });
}

test('asynchronous voice availability can speak once before the bounded wait expires', () => {
  const fixture = setup({ voices: [] }); fixture.api.setEnabled(true);
  fixture.api.report('saved_execute', { id: 'loading-1' });
  assert.equal(fixture.spoken.length, 0);
  fixture.clock.advance(300); fixture.setVoices([voice('vi-VN')]);
  assert.equal(fixture.spoken.length, 1);
  fixture.setVoices([voice('vi-VN')]); assert.equal(fixture.spoken.length, 1);
});

test('a late voiceschanged after cancel or mute cannot speak a stale result', () => {
  for (const cancel of [fixture => fixture.api.cancel(true), fixture => fixture.api.setEnabled(false)]) {
    const fixture = setup({ voices: [] }); fixture.api.setEnabled(true);
    fixture.api.report('saved_execute', { id: 'pending-1' }); cancel(fixture);
    fixture.setVoices([voice('vi-VN')]); fixture.clock.advance(3000);
    assert.equal(fixture.spoken.length, 0);
  }
});

test('offline speech requires an available local voice', () => {
  const fixture = setup({ voices: [voice('vi-VN', false)] }); fixture.api.setEnabled(true); fixture.setOnline(false);
  fixture.api.report('offline_stored', { id: 'offline-remote' });
  assert.equal(fixture.spoken.length, 0); assert.equal(fixture.api.state().status, 'offline_voice');
  fixture.setVoices([voice('vi-VN', false), voice('vi-VN', true)]); fixture.api.replay();
  assert.equal(fixture.spoken.length, 1); assert.equal(fixture.spoken[0].voice.localService, true);
});

test('silent browser refusal reaches a bounded blocked state and allows manual retry', () => {
  const { api, spoken, clock } = setup(); api.setEnabled(true);
  api.report('saved_inspect', { id: 'silent-1' }); clock.advance(1201);
  assert.equal(api.state().status, 'blocked');
  api.replay(); assert.equal(spoken.length, 2);
});

test('intentional cancellation ignores stale speech callbacks', () => {
  const fixture = setup({ onCancel: utterance => { if (utterance) event(utterance, 'error', 'canceled'); } });
  fixture.api.setEnabled(true); fixture.api.report('saved_inspect', { id: 'cancel-1' });
  const stale = fixture.spoken[0]; fixture.api.cancel(true);
  const after = fixture.api.state(); event(stale, 'start'); event(stale, 'end'); event(stale, 'error', 'not-allowed');
  fixture.clock.advance(3000);
  assert.equal(fixture.api.state().status, after.status); assert.equal(fixture.api.state().lastResult, null);
});

test('hidden result and disposed module cannot speak after delayed browser events', () => {
  const fixture = setup(); fixture.api.setEnabled(true); fixture.setVisible(false);
  fixture.api.report('saved_execute', { id: 'hidden-1' }); assert.equal(fixture.spoken.length, 0);
  fixture.api.dispose(); fixture.setVoices([voice('vi-VN')]); fixture.clock.advance(3000);
  assert.equal(fixture.spoken.length, 0);
});

test('missing speech API and denied storage remain nonfatal to check-in callers', () => {
  const storage = { getItem() { throw Error('denied'); }, setItem() { throw Error('denied'); }, removeItem() { throw Error('denied'); } };
  const { api } = setup({ unsupported: true, localStorage: storage, sessionStorage: storage });
  assert.doesNotThrow(() => { api.setEnabled(true); api.report('offline_stored', { id: 'without-api' }); api.replay(); api.cancel(true); api.dispose(); });
  assert.equal(api.state().supported, false);
});

test('older browsers without Object.hasOwn can report optional feedback', () => {
  const original = Object.hasOwn;
  try {
    Object.hasOwn = undefined;
    const { api, spoken } = setup();
    assert.doesNotThrow(() => api.report('saved_visit', { id: 'old-browser' }));
    assert.equal(spoken.length, 1);
  } finally { Object.hasOwn = original; }
});

function installed(options = {}) {
  const fixture = setup(options), root = new EventTarget(), doc = new EventTarget();
  fixture.api.dispose();
  doc.visibilityState = 'visible'; doc.documentElement = { lang: 'vi' };
  doc.body = { dataset: { offlineUser: options.actor || 'actor-a' }, hasAttribute: () => Boolean(options.shell) };
  doc.querySelectorAll = () => [];
  doc.querySelector = selector => selector === '[data-voice-result]' && options.result ? { dataset: options.result } : null;
  root.document = doc; root.localStorage = fixture.localStorage; root.sessionStorage = fixture.sessionStorage;
  root.location = new URL(options.path || '/c/point-a?round=2', 'https://patrol.test');
  root.navigator = { onLine: true }; root.speechSynthesis = fixture.synth; root.SpeechSynthesisUtterance = Utterance;
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
    assert.equal(fixture.spoken.length, 0); fixture.api.dispose();
  }
});

test('a scan outcome speaks only when it consumes the exact scanner intent', () => {
  const storage = new MemoryStorage();
  storage.setItem('patrol-voice-scan-v1', JSON.stringify({ path: '/c/point-a?round=2', at: Date.now() }));
  const fixture = installed({ sessionStorage: storage, result: { voiceResult: 'waiting_execution', voiceResultId: 'scan-wait', voiceAuto: 'scan' } });
  assert.equal(fixture.spoken.length, 1); assert.equal(fixture.api.takeScan(), false); fixture.api.dispose();
});

test('pagehide and account-change cancel active feedback and ignore stale callbacks', () => {
  const fixture = installed(); fixture.api.report('saved_execute', { id: 'leaving-1' });
  const stale = fixture.spoken[0]; dispatch(fixture.root, 'pagehide'); event(stale, 'start');
  assert.equal(fixture.api.state().speaking, false);
  dispatch(fixture.doc, 'patrol:voice-owner-changed');
  assert.equal(fixture.api.state().lastResult, null);
  event(stale, 'end'); assert.equal(fixture.api.state().lastResult, null); fixture.api.dispose();
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

test('cross-tab mute applies without replaying prior speech when enabled again', () => {
  const fixture = installed(); fixture.api.report('saved_visit', { id: 'tab-mute' });
  dispatch(fixture.root, 'storage', { key: 'patrol-voice-enabled-v1', newValue: 'off' });
  assert.equal(fixture.api.state().enabled, false); assert.equal(fixture.api.state().speaking, false);
  dispatch(fixture.root, 'storage', { key: 'patrol-voice-enabled-v1', newValue: 'on' });
  assert.equal(fixture.spoken.length, 1); fixture.api.dispose();
});

test('partial sync, local storage and confirmed sync retain distinct result meanings', () => {
  const fixture = setup();
  for (const [kind, id] of [['offline_stored', 'local:one'], ['sync_partial', 'partial:one'], ['sync_confirmed', 'ack:one']]) {
    fixture.api.report(kind, { id }); assert.equal(fixture.api.state().lastResult.kind, kind);
  }
  assert.equal(fixture.spoken.length, 3);
  assert.equal(new Set(fixture.spoken.map(value => value.text)).size, 3); fixture.api.dispose();
});

test('confirm intent can cover its own validation page but not another point', () => {
  const storage = new MemoryStorage();
  let fixture = installed({ sessionStorage: storage, path: '/c/point-a' });
  fixture.api.armScan('/c/point-a/confirm', 'confirm'); fixture.api.dispose();
  fixture = installed({ sessionStorage: storage, path: '/c/point-a', result: { voiceResult: 'not_saved', voiceResultId: 'validation-a', voiceAuto: 'scan' } });
  assert.equal(fixture.spoken.length, 1); fixture.api.dispose();
  fixture = installed({ sessionStorage: storage, path: '/c/point-a' });
  fixture.api.armScan('/c/point-a/confirm', 'confirm'); fixture.api.dispose();
  fixture = installed({ sessionStorage: storage, path: '/c/point-b', result: { voiceResult: 'not_saved', voiceResultId: 'validation-b', voiceAuto: 'scan' } });
  assert.equal(fixture.spoken.length, 0); fixture.api.dispose();
});

test('consumed result storage is bounded and contains no spoken/private text', () => {
  const fixture = setup(); fixture.api.setEnabled(false);
  for (let i = 0; i < 55; i++) fixture.api.report('saved_inspect', { id: 'receipt-' + i });
  const values = JSON.parse(fixture.sessionStorage.getItem('patrol-voice-seen-v1'));
  assert.equal(values.length, 50); assert.equal(values[0], 'receipt-5');
  assert(values.every(value => /^receipt-\d+$/.test(value))); fixture.api.dispose();
});
