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
  function createFeedback(options) {
    const o = options || {}, synth = o.synth, Utterance = o.Utterance;
    const later = o.setTimeout || setTimeout, clearTimer = o.clearTimeout || clearTimeout;
    const supported = Boolean(synth && Utterance && typeof synth.speak === 'function' && typeof synth.cancel === 'function');
    const read = (store, key) => { try { return store?.getItem(key); } catch (_) { return null; } };
    const write = (store, key, value) => { try { store?.setItem(key, value); } catch (_) { /* Cosmetic preference only. */ } };
    let enabled = read(o.localStorage, PREF) !== 'off', status = supported ? 'ready' : 'unavailable';
    let lastResult = null, speaking = false, epoch = 0, timer = null, voiceWait = null, active = null, disposed = false;
    let seen = [];
    try { const value = JSON.parse(read(o.sessionStorage, SEEN) || '[]'); if (Array.isArray(value)) seen = value.filter(x => typeof x === 'string' && x.length <= 180).slice(-50); } catch (_) { /* Storage may be blocked. */ }
    const state = () => ({ enabled, supported, status, lastResult: lastResult && { ...lastResult }, speaking });
    const emit = () => { try { o.onState?.(state()); } catch (_) { /* Feedback cannot break a save. */ } };
    const locale = () => ({ id: 'id-ID', vi: 'vi-VN' })[o.getLocale?.()] || 'zh-TW';
    const visible = () => o.isVisible?.() !== false;
    function stop() {
      epoch++; if (timer !== null) clearTimer(timer); timer = null; voiceWait = null; active = null; speaking = false;
      try { if (supported) synth.cancel(); } catch (_) { /* Browser may have shut down speech. */ }
    }
    function cancel(clear = false) { stop(); if (clear) lastResult = null; status = !enabled ? 'off' : supported ? 'ready' : 'unavailable'; emit(); }
    function available() { try { return Array.from(synth.getVoices?.() || []); } catch (_) { return []; } }
    function start(voices, run) {
      if (disposed || run !== epoch || !enabled || !visible() || !lastResult) return;
      const lang = locale(), base = lang.split('-')[0];
      const matches = voices.filter(v => typeof v.lang === 'string' && v.lang.toLowerCase().replace('_', '-').split('-')[0] === base);
      const online = o.isOnline?.() !== false;
      const candidates = matches.filter(v => online || v.localService === true).sort((a, b) =>
        (Number(b.localService === true) * 2 + Number(b.lang.toLowerCase() === lang.toLowerCase())) -
        (Number(a.localService === true) * 2 + Number(a.lang.toLowerCase() === lang.toLowerCase())));
      if (!candidates.length) { status = !online && matches.length ? 'offline_voice' : 'no_voice'; emit(); return; }
      let utterance;
      try {
        utterance = new Utterance(o.t ? o.t(MESSAGES[lastResult.kind]) : MESSAGES[lastResult.kind]);
        utterance.lang = lang; utterance.voice = candidates[0]; utterance.rate = 1; utterance.volume = 1;
      } catch (_) { status = 'unavailable'; emit(); return; }
      active = utterance; let started = false;
      const current = () => !disposed && run === epoch && enabled && active === utterance;
      utterance.onstart = () => {
        if (!current()) return;
        started = true; speaking = true; status = 'playing';
        if (timer !== null) clearTimer(timer);
        timer = later(() => { if (!current()) return; stop(); status = 'blocked'; emit(); }, 15000);
        emit();
      };
      utterance.onend = () => { if (!current()) return; if (timer !== null) clearTimer(timer); timer = null; active = null; speaking = false; status = 'played'; emit(); };
      utterance.onerror = event => {
        if (!current()) return;
        stop(); status = event?.error === 'language-unavailable' || event?.error === 'voice-unavailable' ? 'no_voice' : 'blocked'; emit();
      };
      status = 'waiting'; emit();
      try { synth.speak(utterance); } catch (_) { if (current()) { stop(); status = 'blocked'; emit(); } return; }
      // Some mobile browsers silently refuse non-gesture speech without onerror.
      if (current() && !started) timer = later(() => { if (!current()) return; stop(); status = 'blocked'; emit(); }, 1200);
    }
    function replay() {
      if (disposed || !lastResult || !enabled || !supported || !visible()) { emit(); return false; }
      stop(); const run = epoch, voices = available();
      if (voices.length) start(voices, run);
      else {
        status = 'waiting'; voiceWait = run; emit();
        timer = later(() => { if (voiceWait !== run || run !== epoch) return; voiceWait = null; timer = null; start(available(), run); }, 600);
      }
      return true;
    }
    function voicesChanged() {
      if (voiceWait === null || voiceWait !== epoch || !available().length) return;
      const run = voiceWait; voiceWait = null; if (timer !== null) clearTimer(timer); timer = null; start(available(), run);
    }
    synth?.addEventListener?.('voiceschanged', voicesChanged);
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
    function dispose() { stop(); disposed = true; synth?.removeEventListener?.('voiceschanged', voicesChanged); }
    if (!enabled) status = 'off';
    return { report, replay, setEnabled, cancel, refresh, state, dispose };
  }
  function install(root) {
    const doc = root.document, t = value => root.PatrolI18n?.t(value) || value;
    const storage = name => { try { return root[name]; } catch (_) { return null; } };
    const session = storage('sessionStorage');
    const statusText = {
      off: '語音已關閉。', unavailable: '此瀏覽器不支援語音，請以畫面結果為準。',
      no_voice: '此裝置未提供此語言的語音，請以畫面結果為準。',
      offline_voice: '目前離線，沒有可離線播放的此語言語音。', waiting: '正在準備語音…',
      playing: '正在播報…', played: '播報結束，可按重播再聽一次。', blocked: '未能自動播報，請按「重播結果」。'
    };
    const core = createFeedback({ synth: root.speechSynthesis, Utterance: root.SpeechSynthesisUtterance,
      localStorage: storage('localStorage'), sessionStorage: session,
      getLocale: () => root.PatrolI18n?.getLocale() || doc.documentElement.lang, t,
      isVisible: () => doc.visibilityState !== 'hidden', isOnline: () => root.navigator.onLine !== false,
      onState: state => {
        for (const panel of doc.querySelectorAll('[data-voice-controls]')) {
          panel.hidden = false;
          const toggle = panel.querySelector('[data-voice-toggle]'), label = panel.querySelector('[data-voice-state]');
          if (toggle) { toggle.disabled = !state.supported; toggle.setAttribute('aria-checked', String(state.enabled)); }
          if (label) { label.dataset.i18n = state.enabled ? '開啟' : '關閉'; label.textContent = t(label.dataset.i18n); }
          const replay = panel.querySelector('[data-voice-replay]');
          if (replay) { replay.hidden = !state.lastResult; replay.disabled = !state.enabled || !state.supported || !state.lastResult; }
          const status = panel.querySelector('[data-voice-status]');
          if (status) status.textContent = t(statusText[state.status] || (state.lastResult ? '未聽到提示時可重播；請以畫面結果為準。' : '確認後依帳號語言播報；請以畫面結果為準。'));
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
    root.PatrolVoice = { ...core, armScan, clearScan, armResult, takeResult, takeScan: () => { const value = scanArrival; scanArrival = false; return value; } };
    doc.addEventListener('click', event => {
      const button = event.target.closest?.('button'); if (!button) return;
      if (button.hasAttribute('data-voice-toggle')) core.setEnabled(!core.state().enabled);
      if (button.hasAttribute('data-voice-replay')) core.replay();
      if (button.hasAttribute('data-qr-start')) { core.cancel(true); clearScan(); }
    });
    doc.addEventListener('submit', event => {
      if (event.target.id === 'inspection-form') { core.cancel(true); armScan(event.target.action, 'confirm'); }
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
