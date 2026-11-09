/* Real DOM event propagation; only the browser's media device is controlled. */
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');
const { install } = require('../static/patrol-voice.js');

function setup(t, options = {}) {
  const dom = new JSDOM('<body data-offline-user="12"><button data-offline-sync>Sync</button><form id="inspection-form" action="/c/a/confirm"><button>OK</button></form></body>',
    { url: 'https://patrol.test/c/a', pretendToBeVisual: true });
  const win = dom.window, audios = [];
  win.URL.createObjectURL = () => 'blob:https://patrol.test/prime'; win.URL.revokeObjectURL = () => {};
  win.Audio = function () {
    const audio = win.document.createElement('audio');
    const media = { src: '', currentSrc: '', paused: true, ended: false, error: null };
    for (const key of Object.keys(media)) Object.defineProperty(audio, key, { configurable: true, get: () => media[key],
      ...(key === 'src' ? { set: value => { media.src = new URL(value, win.location.href).href; } } : {}) });
    audio.playCalls = 0; audio.pauseCalls = 0;
    audio.setMedia = value => Object.assign(media, value);
    audio.play = () => { audio.playCalls++; if (options.play) return options.play(audio);
      audio.setMedia({ currentSrc: audio.src, paused: false, ended: false, error: null }); return Promise.resolve(); };
    audio.pause = () => { audio.pauseCalls++; media.paused = true; };
    audio.load = () => {};
    audios.push(audio); return audio;
  };
  const api = install(win);
  t.after(() => { api.dispose(); win.close(); });
  return { win, doc: win.document, api, audios, mediaEvent: (audio, name) => audio.dispatchEvent(new win.Event(name)) };
}

test('sync gesture is prepared before its target disables the button and stops propagation', async t => {
  let gesture = false;
  const ui = setup(t, { play(audio) {
    if (!gesture && !audio.unlocked) return Promise.reject(Object.assign(Error('gesture required'), { name: 'NotAllowedError' }));
    audio.unlocked = true; audio.setMedia({ currentSrc: audio.src, paused: false, ended: false, error: null }); return Promise.resolve();
  } });
  const button = ui.doc.querySelector('[data-offline-sync]'); let handlers = 0;
  button.addEventListener('click', event => {
    handlers++; button.disabled = true; event.stopPropagation();
    assert.equal(ui.audios.length, 1, 'capture must prime before the sync controller claims the action');
    Promise.resolve().then(() => ui.api.report('sync_confirmed', { id: 'ack:sync' }));
  });
  gesture = true; button.click(); gesture = false;
  await Promise.resolve(); await Promise.resolve();
  assert.equal(handlers, 1); assert.equal(ui.api.state().status, 'playing'); assert.equal(ui.audios[0].playCalls, 2);
  button.click(); assert.equal(handlers, 1); assert.equal(ui.audios[0].playCalls, 2, 'disabled repeat must not replace confirmed audio with silence');
});

test('a repeated busy submit preserves the accepted result and its pending playback wait', async t => {
  const ui = setup(t), form = ui.doc.querySelector('form');
  form.addEventListener('submit', event => event.preventDefault());
  form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true }));
  ui.api.report('saved_execute', { id: 'ack:accepted' }); await Promise.resolve();
  form.dataset.submitting = 'true'; form.dataset.offlineSaving = 'true';
  const plays = ui.audios[0].playCalls; let finished = false;
  ui.api.waitForIdle().then(() => { finished = true; });
  form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true })); await Promise.resolve();
  assert.deepEqual(ui.api.state().lastResult, { kind: 'saved_execute', id: 'ack:accepted' }); assert.equal(ui.api.state().status, 'playing');
  assert.equal(ui.audios[0].playCalls, plays); assert.equal(finished, false);
  Object.defineProperty(ui.doc, 'visibilityState', { configurable: true, value: 'hidden' });
  ui.doc.dispatchEvent(new ui.win.Event('visibilitychange')); await Promise.resolve();
  assert.equal(finished, true); assert.equal(ui.api.state().speaking, false);
});

test('a saved form restored after navigation keeps its result until explicitly replaced with a draft', async t => {
  const ui = setup(t), form = ui.doc.querySelector('form');
  form.addEventListener('submit', event => event.preventDefault());
  ui.api.report('saved_execute', { id: 'ack:saved-form' }); await Promise.resolve();
  form.dataset.offlineStored = 'true'; form.querySelector('button').disabled = true;
  const plays = ui.audios[0].playCalls;
  form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true }));
  assert.deepEqual(ui.api.state().lastResult, { kind: 'saved_execute', id: 'ack:saved-form' });
  assert.equal(ui.audios[0].playCalls, plays);
  // The existing input/change draft controller owns clearing this marker.
  delete form.dataset.offlineStored; form.querySelector('button').disabled = false;
  form.dispatchEvent(new ui.win.Event('submit', { bubbles: true, cancelable: true }));
  assert.equal(ui.api.state().lastResult, null); assert.equal(ui.audios[0].playCalls, plays + 1);
});

test('reused audio events must match its current source and actual ended or error state', async t => {
  const ui = setup(t, { play: () => new Promise(() => {}) });
  ui.api.report('saved_execute', { id: 'first' }); const audio = ui.audios[0];
  audio.setMedia({ currentSrc: audio.src, paused: false }); ui.mediaEvent(audio, 'playing');
  const previousSource = audio.src;
  ui.api.report('offline_stored', { id: 'second' });
  audio.setMedia({ currentSrc: previousSource, paused: false, ended: true, error: { code: 3 } });
  for (const name of ['playing', 'ended', 'error']) ui.mediaEvent(audio, name);
  assert.equal(ui.api.state().status, 'waiting'); assert.equal(ui.api.state().lastResult.id, 'second');
  audio.setMedia({ currentSrc: audio.src, paused: false, ended: false, error: null }); ui.mediaEvent(audio, 'playing');
  ui.mediaEvent(audio, 'ended'); ui.mediaEvent(audio, 'error');
  assert.equal(ui.api.state().status, 'playing', 'a queued event must not override the native current media state');
  audio.setMedia({ ended: true, paused: true }); ui.mediaEvent(audio, 'ended');
  assert.equal(ui.api.state().status, 'played'); assert.equal(ui.audios.length, 1);
});
