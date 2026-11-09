/* Optional audible feedback. Never authorizes or delays attendance writes. */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (!root.document) return;
  const ready = () => api.install(root);
  if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', ready);
  else ready();
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';
  const MESSAGES = Object.freeze({
    saved_execute: '執行簽到完成。', saved_inspect: '巡檢完成。', saved_visit: '簽到完成。',
    already_recorded: '本次已有紀錄，沒有新增打卡。', waiting_execution: '尚未執行，請先由執行人員簽到。',
    device_required: '請先完成手機綁定核准。', point_unavailable: '此點無法簽到，請確認點位。',
    offline_stored: '已暫存在手機，尚未同步。', sync_confirmed: '同步完成。', sync_partial: '部分已同步，仍有紀錄待處理。',
    not_saved: '尚未完成，請查看畫面提示。', login_required: '請先登入帳號。',
    receipt_confirmed: '這是已確認的打卡紀錄。'
  });
  const PREF = 'patrol-voice-enabled-v1', SEEN = 'patrol-voice-seen-v1', SCAN = 'patrol-voice-scan-v1';
  const AUDIO_REVISION = 'natural-female-1';
  function createFeedback(options) {
    const o = options || {};
    const later = o.setTimeout || setTimeout, clearTimer = o.clearTimeout || clearTimeout;
    const supported = typeof o.createAudio === 'function';
    const read = (store, key) => { try { return store?.getItem(key); } catch (_) { return null; } };
    const write = (store, key, value) => { try { store?.setItem(key, value); } catch (_) { /* Cosmetic preference only. */ } };
    let enabled = read(o.localStorage, PREF) !== 'off', status = supported ? 'ready' : 'unavailable';
    let lastResult = null, speaking = false, epoch = 0, timer = null, active = null, player = null, disposed = false;
    const idleWaiters = new Set();
    let seen = [];
    try { const value = JSON.parse(read(o.sessionStorage, SEEN) || '[]'); if (Array.isArray(value)) seen = value.filter(x => typeof x === 'string' && x.length <= 180).slice(-50); } catch (_) { /* Storage may be blocked. */ }
    const state = () => ({ enabled, supported, status, lastResult: lastResult && { ...lastResult }, speaking });
    const emit = () => {
      if (disposed || !['waiting', 'playing'].includes(status)) for (const finish of [...idleWaiters]) finish();
      try { o.onState?.(state()); } catch (_) { /* Feedback cannot break a save. */ }
    };
    const locale = () => { const value = o.getLocale?.(); return value === 'id' || value === 'vi' ? value : 'zh-Hant'; };
    const visible = () => o.isVisible?.() !== false;
    function stop() {
      epoch++; if (timer !== null) clearTimer(timer); timer = null;
      const previous = active; active = null; speaking = false;
      if (previous) {
        previous.onplaying = previous.onended = previous.onerror = null;
        // Keep the element and its source alive: Safari grants playback access
        // to the element used during the gesture, not to every new Audio().
        try { previous.pause(); } catch (_) { /* Cosmetic only. */ }
      }
    }
    function audioFor(source) {
      if (!player) player = o.createAudio(source);
      if (!player || typeof player.play !== 'function' || typeof player.pause !== 'function') throw new Error('Audio unavailable');
      player.preload = 'auto'; player.playsInline = true; player.volume = 1; player.muted = false;
      player.src = source;
      return player;
    }
    // A reused element can receive a queued event after its source changes.
    // Inspect the element's current media state as well as the run token;
    // the event's handler itself may already belong to the new source.
    const currentMedia = audio => typeof audio.currentSrc !== 'string' || audio.currentSrc === audio.src;
    function cancel(clear = false) { stop(); if (clear) lastResult = null; status = !enabled ? 'off' : supported ? 'ready' : 'unavailable'; emit(); }
    function prepare() {
      if (disposed || !enabled || !supported || !visible()) return false;
      let source;
      try { source = typeof o.primeSource === 'function' ? o.primeSource() : o.primeSource; } catch (_) { return false; }
      if (typeof source !== 'string' || !source) return false;
      stop(); status = 'ready'; emit();
      const run = epoch; let audio;
      try { audio = audioFor(source); } catch (_) { return false; }
      active = audio;
      const current = () => !disposed && run === epoch && enabled && active === audio;
      const finish = () => { if (current()) { stop(); emit(); } };
      // No attendance message, lastResult or success state is created here.
      // play() must run synchronously inside the real click/submit handler.
      audio.onplaying = null;
      audio.onended = () => { if (currentMedia(audio) && audio.ended !== false) finish(); };
      audio.onerror = () => { if (currentMedia(audio) && (!('error' in audio) || audio.error)) finish(); };
      try {
        const promise = audio.play();
        if (promise && typeof promise.then === 'function') promise.then(() => {}, finish);
      } catch (_) { finish(); return false; }
      if (current()) timer = later(finish, 3000);
      return true;
    }
    function start(run) {
      if (disposed || run !== epoch || !enabled || !visible() || !lastResult) return;
      // Fixed public assets only: no device TTS, remote synthesis or private text.
      let audio;
      try {
        // A fixed public revision avoids the browser's decoded-media cache
        // reusing an older voice after the service-worker cache has updated.
        audio = audioFor('/static/audio/patrol-v1/' + locale() + '/' + lastResult.kind + '.mp3?rev=' + AUDIO_REVISION);
      } catch (_) { status = 'unavailable'; emit(); return; }
      active = audio; let started = false;
      const current = () => !disposed && run === epoch && enabled && active === audio;
      const failed = error => {
        if (!current()) return;
        stop(); status = error?.name === 'NotAllowedError' ? 'blocked' : o.isOnline?.() === false ? 'offline_audio' : 'audio_missing'; emit();
      };
      const playing = () => {
        if (!current() || started) return;
        started = true; speaking = true; status = 'playing';
        if (timer !== null) clearTimer(timer);
        timer = later(() => failed(), 20000);
        emit();
      };
      audio.onplaying = () => { if (currentMedia(audio) && audio.paused !== true) playing(); };
      audio.onended = () => {
        if (!current() || !currentMedia(audio) || audio.ended === false) return;
        if (!started) { failed(); return; }
        stop(); status = 'played'; emit();
      };
      audio.onerror = () => { if (currentMedia(audio) && (!('error' in audio) || audio.error)) failed(); };
      status = 'waiting'; emit();
      // Preserve the manual replay gesture; never await fetch before play().
      try {
        const promise = audio.play();
        if (promise && typeof promise.then === 'function') promise.then(playing, failed);
      } catch (error) { failed(error); return; }
      if (current() && !started) timer = later(() => failed(), 5000);
    }
    function replay() {
      if (disposed || !lastResult || !enabled || !supported || !visible()) { emit(); return false; }
      stop(); start(epoch); return true;
    }
    function report(kind, details = {}) {
      if (disposed || !Object.prototype.hasOwnProperty.call(MESSAGES, kind) || typeof details.id !== 'string' || !details.id || details.id.length > 180) return false;
      if (lastResult?.id === details.id && lastResult?.kind === kind) return true;
      stop(); lastResult = { kind, id: details.id }; status = !enabled ? 'off' : supported ? 'ready' : 'unavailable'; emit();
      if (details.auto !== false && !seen.includes(details.id)) {
        seen.push(details.id); seen = seen.slice(-50); write(o.sessionStorage, SEEN, JSON.stringify(seen)); replay();
      }
      return true;
    }
    function setEnabled(value) { enabled = Boolean(value); write(o.localStorage, PREF, enabled ? 'on' : 'off'); cancel(); }
    function refresh() { cancel(); }
    function waitForIdle(maxMs = 4500) {
      if (disposed || !['waiting', 'playing'].includes(status)) return Promise.resolve();
      const delay = Number.isFinite(maxMs) ? Math.max(0, Math.min(maxMs, 4500)) : 4500;
      return new Promise(resolve => {
        let timeout = null;
        const finish = () => { if (timeout !== null) clearTimer(timeout); idleWaiters.delete(finish); resolve(); };
        idleWaiters.add(finish); timeout = later(finish, delay);
      });
    }
    function dispose() {
      if (disposed) return;
      stop(); disposed = true;
      try { player?.removeAttribute?.('src'); player?.load?.(); } catch (_) { /* Cosmetic only. */ }
      player = null;
      try { o.releasePrimeSource?.(); } catch (_) { /* Cosmetic only. */ }
      emit();
    }
    if (!enabled) status = 'off';
    return { report, replay, prepare, waitForIdle, setEnabled, cancel, refresh, state, dispose };
  }
  function install(root) {
    const doc = root.document, t = value => root.PatrolI18n?.t(value) || value;
    const storage = name => { try { return root[name]; } catch (_) { return null; } };
    const session = storage('sessionStorage');
    let primeURL = null;
    const primeSource = () => {
      if (primeURL) return primeURL;
      if (!root.Blob || !root.URL?.createObjectURL) return null;
      // 100 ms of actual zero-valued PCM: this cannot announce a successful
      // save before the local store or server has confirmed anything.
      const samples = 800, bytes = new ArrayBuffer(44 + samples * 2), view = new DataView(bytes);
      const label = (offset, value) => { for (let i = 0; i < value.length; i++) view.setUint8(offset + i, value.charCodeAt(i)); };
      label(0, 'RIFF'); view.setUint32(4, bytes.byteLength - 8, true); label(8, 'WAVE'); label(12, 'fmt ');
      view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true);
      view.setUint32(24, 8000, true); view.setUint32(28, 16000, true); view.setUint16(32, 2, true); view.setUint16(34, 16, true);
      label(36, 'data'); view.setUint32(40, samples * 2, true);
      primeURL = root.URL.createObjectURL(new root.Blob([bytes], { type: 'audio/wav' })); return primeURL;
    };
    const statusText = {
      off: '語音已關閉。', unavailable: '此瀏覽器無法播放提示音，請以畫面結果為準。',
      audio_missing: '提示音未能載入，請重播或重新整理；打卡結果不受影響。',
      offline_audio: '離線提示音尚未備妥，連線後請重新準備離線資料。', waiting: '正在載入提示音…',
      playing: '正在播報…', played: '播報結束，可按重播再聽一次。', blocked: '瀏覽器限制自動播放，請點一下播放結果。'
    };
    const core = createFeedback({ createAudio: typeof root.Audio === 'function' ? src => {
      // Media must opt into CORS before src, even on the same origin, so
      // Safari routes its range requests through the offline service worker.
      const audio = new root.Audio(); audio.crossOrigin = 'anonymous'; audio.src = src; return audio;
    } : null,
      primeSource, releasePrimeSource: () => { if (primeURL) { root.URL.revokeObjectURL?.(primeURL); primeURL = null; } },
      localStorage: storage('localStorage'), sessionStorage: session,
      getLocale: () => root.PatrolI18n?.getLocale() || doc.documentElement.lang, t,
      isVisible: () => doc.visibilityState !== 'hidden', isOnline: () => root.navigator.onLine !== false,
      onState: state => {
        for (const panel of doc.querySelectorAll('[data-voice-controls]')) {
          panel.hidden = false;
          panel.dataset.voiceStatus = state.status;
          const toggle = panel.querySelector('[data-voice-toggle]'), label = panel.querySelector('[data-voice-state]');
          if (toggle) { toggle.disabled = !state.supported; toggle.setAttribute('aria-checked', String(state.enabled)); }
          if (label) { label.dataset.i18n = state.enabled ? '開啟' : '關閉'; label.textContent = t(label.dataset.i18n); }
          const replay = panel.querySelector('[data-voice-replay]');
          if (replay) {
            replay.hidden = !state.lastResult; replay.disabled = !state.enabled || !state.supported || !state.lastResult;
            const label = replay.querySelector('.patrol-voice-label');
            if (label) { label.dataset.i18n = state.status === 'blocked' ? '點一下播放結果' : '重播結果'; label.textContent = t(label.dataset.i18n); }
          }
          const status = panel.querySelector('[data-voice-status]');
          if (status) status.textContent = t(statusText[state.status] || (state.lastResult ? '未聽到提示時可重播；請以畫面結果為準。' : '依帳號語言播放內建提示音；請以畫面結果為準。'));
        }
      }
    });
    const clearScan = () => { try { session?.removeItem(SCAN); } catch (_) {} };
    const armScan = (path, kind = 'scan') => {
      try { const url = new URL(path, root.location.origin); if (url.origin !== root.location.origin) return;
        session?.setItem(SCAN, JSON.stringify({ path: url.pathname + url.search, kind, at: Date.now() })); } catch (_) {}
    };
    const takeScan = () => {
      try { const item = JSON.parse(session?.getItem(SCAN) || 'null'); clearScan();
        const target = root.location.pathname + root.location.search;
        return Boolean(item && (item.path === target || item.kind === 'confirm' && item.path.replace(/\/confirm$/, '') === target) && Date.now() - item.at >= 0 && Date.now() - item.at < 90000); } catch (_) { clearScan(); return false; }
    };
    const RESULT = 'patrol-voice-arrival-v1';
    const clearResult = () => { try { session?.removeItem(RESULT); } catch (_) {} };
    const armResult = (kind, id, path, actor) => {
      try {
        const url = new URL(path, root.location.origin);
        if (url.origin !== root.location.origin || !Object.prototype.hasOwnProperty.call(MESSAGES, kind) || !actor) return;
        session?.setItem(RESULT, JSON.stringify({ kind, id, path: url.pathname + url.search, actor: String(actor), at: Date.now() }));
      } catch (_) {}
    };
    const takeResult = actor => {
      try {
        const value = JSON.parse(session?.getItem(RESULT) || 'null');
        if (!value) return null;
        if (!actor) return null;
        clearResult();
        if (value.actor !== String(actor) || value.path !== root.location.pathname + root.location.search ||
            Date.now() - value.at < 0 || Date.now() - value.at >= 90000) return null;
        return Object.prototype.hasOwnProperty.call(MESSAGES, value.kind) ? value : null;
      } catch (_) { clearResult(); return null; }
    };
    let scanArrival = takeScan();
    root.PatrolVoice = { ...core, armScan, clearScan, armResult, clearResult, takeResult, takeScan: () => { const value = scanArrival; scanArrival = false; return value; } };
    doc.addEventListener('click', event => {
      // Capture the gesture before a sync handler disables its busy button or
      // stops bubbling. Never prepare from an already-disabled action.
      const button = event.target.closest?.('button');
      if (!event.defaultPrevented && button?.hasAttribute('data-offline-sync') && !button.disabled) core.prepare();
    }, true);
    doc.addEventListener('click', event => {
      const button = event.target.closest?.('button'); if (!button) return;
      if (button.hasAttribute('data-voice-toggle')) { core.setEnabled(!core.state().enabled); if (core.state().enabled) core.prepare(); }
      if (button.hasAttribute('data-voice-replay')) core.replay();
      if (button.hasAttribute('data-qr-start')) { core.cancel(true); clearScan(); }
    });
    doc.addEventListener('submit', event => {
      // A repeated submit may still reach this capture listener before the
      // save controller rejects it. Keep the accepted result/voice intact.
      if (event.defaultPrevented || event.target.dataset?.submitting === 'true' || event.target.dataset?.offlineSaving === 'true') return;
      if (event.target.id === 'inspection-form' && event.target.dataset?.offlineStored === 'true') return;
      if (event.target.id === 'inspection-form') { core.cancel(true); core.prepare(); armScan(event.target.action, 'confirm'); }
      if (event.target.id === 'offline-checkin') { core.cancel(true); core.prepare(); }
      if (new URL(event.target.action || '/', root.location.origin).pathname === '/logout') { core.cancel(true); clearScan(); clearResult(); }
    }, true);
    doc.addEventListener('visibilitychange', () => { if (doc.visibilityState === 'hidden') core.cancel(); });
    root.addEventListener('pagehide', () => core.cancel());
    root.addEventListener('storage', event => { if (event.key === PREF) core.setEnabled(event.newValue !== 'off'); });
    doc.addEventListener('patrol:locale-changed', () => core.refresh());
    doc.addEventListener('patrol:voice-owner-changed', () => { core.cancel(true); clearScan(); clearResult(); scanArrival = false; });
    core.refresh();
    const result = doc.querySelector('[data-voice-result]');
    const arrival = takeResult(doc.body.dataset.offlineUser);
    if (arrival && result) core.report(arrival.kind, { id: arrival.id });
    else if (result) {
      const automatic = result.dataset.voiceAuto === 'true' || result.dataset.voiceAuto === 'scan' && root.PatrolVoice.takeScan();
      core.report(result.dataset.voiceResult, { id: result.dataset.voiceResultId, auto: automatic });
    } else if (!doc.body.hasAttribute('data-offline-shell')) scanArrival = false;
    return root.PatrolVoice;
  }
  return { createFeedback, install, MESSAGES };
});
