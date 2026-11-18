/* Local check-ins remain pending until the server acknowledges their immutable ID. */
(function (root) {
  'use strict';
  const t = (source, params = {}) => root.PatrolI18n?.t(source, params) ?? String(source).replace(/\{(\w+)\}/g, (match, key) => Object.prototype.hasOwnProperty.call(params, key) ? String(params[key]) : match);
  const pointName = (source, names) => names?.[root.PatrolI18n?.getLocale()] || source;
  const frequencyLabel = frequency => t({ daily: '每日一次', daily2: '每日兩次', three_day: '每3日一次',
    weekly: '每週一次', weekly_wed: '每週三', weekly_fri: '每週五', monthly: '每月一次', irregular: '不定期' }[frequency] || '每日一次');
  const DB_NAME = 'patrol-offline-v1';
  const STORES = ['meta', 'manifests', 'queue', 'receipts'];
  const MAX_QUEUE_BYTES = 256 * 1024 * 1024;
  const MAX_QUEUE_ITEMS = 200;
  const PHOTO_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/pjpeg', 'image/png', 'image/x-png', 'image/webp', 'image/heic', 'image/heif']);
  const isToken = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(value);
  const fault = (code, message) => Object.assign(new Error(message), { code });
  const CHECKLIST_UPDATE_MESSAGE = '離線點檢資料需要更新。請連線按「更新離線資料」；原有待補傳紀錄仍保留並可同步。';
  const owns = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
  const checklistLabel = labels => labels?.[root.PatrolI18n?.getLocale() || 'zh-Hant'] || labels?.['zh-Hant'] || '';
  function validChecklistDefinition(value) {
    if (value === null) return true;
    const labels = text => text && ['zh-Hant', 'id', 'vi'].every(locale => typeof text[locale] === 'string' && text[locale].trim().length > 0 && text[locale].length <= 1000);
    return Boolean(value && value.version === 1 && typeof value.key === 'string' && /^[A-Za-z0-9_.-]{1,100}$/.test(value.key) &&
      labels(value.title) && Array.isArray(value.items) && value.items.length > 0 && value.items.length <= 100 &&
      value.items.every(item => item && typeof item.id === 'string' && /^[A-Za-z0-9_.-]{1,100}$/.test(item.id) && labels(item.label) &&
        (item.source_code === undefined || typeof item.source_code === 'string' && item.source_code.length <= 100)) &&
      new Set(value.items.map(item => item.id)).size === value.items.length);
  }
  function validateChecklist(definition, selected = []) {
    if (!validChecklistDefinition(definition)) throw fault('checklist_update', CHECKLIST_UPDATE_MESSAGE);
    if (!Array.isArray(selected) || selected.some(id => typeof id !== 'string') || new Set(selected).size !== selected.length) {
      throw fault('checklist', '點檢項目資料不正確，請重新確認。');
    }
    if (!definition) {
      if (selected.length) throw fault('checklist', '此巡檢點沒有適用的點檢項目，請重新開啟此點。');
      return [];
    }
    const allowed = new Set(definition.items.map(item => item.id));
    if (selected.some(id => !allowed.has(id))) throw fault('checklist', '點檢項目資料不正確，請重新確認。');
    if (!selected.length) throw fault('checklist', '請至少勾選 1 項已完成的點檢項目。');
    const chosen = new Set(selected);
    return definition.items.filter(item => chosen.has(item.id)).map(item => item.id);
  }
  const checklistCapable = manifest => manifest?.checklist_version === 1 && Array.isArray(manifest.points) && manifest.points.every(point => point && validChecklistDefinition(point.checklist));
  function executionStatus(point, slot) {
    if (!slot || point?.stage !== 'inspect' || point.workflow_mode !== 'two_stage') return null;
    if (Array.isArray(point.own_execution_slots) && point.own_execution_slots.includes(slot)) return 'same_account';
    return Array.isArray(point.executed_slots) && point.executed_slots.includes(slot) ? 'signed' : 'unconfirmed';
  }
  // Preserve absence on pre-checklist rows: adding [] changes their receipt hash.
  const savedChecklist = row => owns(row, 'checklist') ? { checklist: row.checklist, checklist_snapshot: row.checklist_snapshot } : {};
  const formChecklist = target => target ? Array.from(target.querySelectorAll('input[type="checkbox"][name="checklist"]')).filter(choice => choice.checked).map(choice => choice.value) : [];
  const photoAllowed = file => PHOTO_TYPES.has((file.type || '').toLowerCase()) ||
    ((!file.type || file.type === 'application/octet-stream') && /\.(jpe?g|png|webp|heic|heif)$/i.test(file.name || ''));
  function validatePhotos(photos) {
    if (photos.length > 3) throw fault('photos', '最多可附 3 張照片。');
    for (const file of photos) {
      if (!file || typeof file.size !== 'number' || file.size <= 0 || file.size > 8 * 1024 * 1024 || !photoAllowed(file)) {
        throw fault('photos', '照片須為 JPG、PNG、WebP 或 HEIC，每張大於 0 且不超過 8 MB。');
      }
    }
  }
  function safePath(value) {
    if (typeof value !== 'string' || !/^(?:https?:\/\/[A-Za-z0-9.:\[\]-]+)?\/c\/[A-Za-z0-9_-]{1,100}$/.test(value)) return null;
    try { const url = new URL(value, root.location?.origin || 'https://offline.invalid'); return url.origin === (root.location?.origin || 'https://offline.invalid') ? url.pathname : null; } catch { return null; }
  }
  function secureUUID(source) {
    try { if (typeof source?.randomUUID === 'function') return source.randomUUID(); } catch (_) { /* Older WebKit can expose an unavailable method. */ }
    try {
      if (typeof source?.getRandomValues === 'function') {
        const bytes = new Uint8Array(16); source.getRandomValues(bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40; bytes[8] = (bytes[8] & 0x3f) | 0x80;
        const hex = Array.from(bytes, byte => byte.toString(16).padStart(2, '0'));
        return hex.slice(0, 4).join('') + '-' + hex.slice(4, 6).join('') + '-' + hex.slice(6, 8).join('') + '-' + hex.slice(8, 10).join('') + '-' + hex.slice(10).join('');
      }
    } catch (_) { /* Never substitute timestamps or Math.random for secure IDs. */ }
    throw fault('support', '此瀏覽器無法建立安全的離線編號，目前僅支援線上打卡；請連線操作或更新瀏覽器。');
  }
  function requestPersistence(navigator) {
    try { Promise.resolve(navigator.storage?.persist?.()).catch(() => {}); }
    catch (_) { /* Persistence permission is optional; IndexedDB writes remain authoritative. */ }
  }
  function createCore(options = {}) {
    const env = options.env || root;
    const idb = options.indexedDB || env.indexedDB;
    const now = options.now || (() => Date.now());
    const uuid = () => secureUUID(options.crypto || env.crypto);
    const fetcher = options.fetch || env.fetch?.bind(env);
    const timers = options.timers || env;
    const navigator = options.navigator || env.navigator || {};
    const connectTimeout = options.connectTimeout || 5000;
    const uploadTimeout = options.uploadTimeout || 30000;
    const photoReadTimeout = options.photoReadTimeout || 10000;
    const listeners = new Set();
    let tabId, capabilityError;
    try {
      if (env.isSecureContext === false) throw fault('support', '離線暫存需要 HTTPS 安全連線，目前僅支援線上打卡；請使用正式網站網址。');
      tabId = uuid();
    } catch (error) { capabilityError = error?.code === 'support' ? error : fault('support', '此瀏覽器無法啟用安全離線暫存，目前僅支援線上打卡；請連線操作或更新瀏覽器。'); }
    const requireSupport = () => { if (capabilityError) throw capabilityError; };
    async function copyPhotos(photos, saved = false) {
      if (!Array.isArray(photos) || photos.length > 3) throw fault('photos', '最多可附 3 張照片。');
      const copies = [];
      for (let index = 0; index < photos.length; index++) {
        const item = photos[index], blob = saved ? item?.blob : item;
        const message = saved ? `第 ${index + 1} 張暫存照片無法完整讀取；資料仍保留，請稍後重試或聯絡管理員，請勿清除瀏覽器資料。` :
          `第 ${index + 1} 張照片無法完整讀取，尚未暫存；請重新選擇照片後再按 OK。`;
        let timeout, fallback, reader, finished = false;
        try {
          if (!blob || !Number.isInteger(blob.size) || blob.size <= 0 || blob.size > 8 * 1024 * 1024 ||
              (saved && blob.size !== item.size)) throw new Error('Invalid stored photo size');
          const readers = [];
          if (typeof blob.arrayBuffer === 'function') readers.push(() => blob.arrayBuffer());
          if (typeof env.FileReader === 'function') readers.push(() => new Promise((resolve, reject) => {
              reader = new env.FileReader(); reader.onload = () => resolve(reader.result);
              reader.onerror = reader.onabort = () => reject(new Error('Photo read failed'));
              reader.readAsArrayBuffer(blob);
            }));
          if (typeof env.Response === 'function') readers.push(() => new env.Response(blob).arrayBuffer());
          // A camera reader can hang without rejecting. Start the next reader
          // within the same deadline and accept the first complete byte copy.
          const buffer = await new Promise((resolve, reject) => {
            if (!readers.length) return reject(new Error('Photo reading unavailable'));
            let next = 0, failed = 0;
            const startNext = () => {
              if (finished || next === readers.length) return;
              timers.clearTimeout(fallback);
              const attempt = readers[next++];
              if (next < readers.length) fallback = timers.setTimeout(startNext, Math.ceil(photoReadTimeout / readers.length));
              Promise.resolve().then(attempt).then(bytes => {
                if (Object.prototype.toString.call(bytes) !== '[object ArrayBuffer]' || bytes.byteLength !== blob.size) throw new Error('Incomplete photo bytes');
                resolve(bytes);
              }).catch(() => {
                if (++failed === readers.length) reject(new Error('Photo reading unavailable'));
                else startNext();
              });
            };
            timeout = timers.setTimeout(() => reject(new Error('Photo read timed out')), photoReadTimeout);
            startNext();
          });
          // Materialize phone camera Files before clearing the form. A File's
          // advertised size alone does not prove its backing bytes can be read.
          const copied = new env.Blob([buffer], { type: blob.type || item.type || '' });
          if (copied.size !== blob.size) throw new Error('Incomplete photo copy');
          copies.push({ blob: copied, name: item.name || 'photo.jpg', type: copied.type, size: copied.size });
        } catch (_) { throw fault('photo_read', message); }
        finally {
          finished = true; timers.clearTimeout(timeout); timers.clearTimeout(fallback);
          try { if (reader?.readyState === 1) reader.abort(); } catch (_) {}
        }
      }
      return copies;
    }
    let dbPromise, state = { locked: true, prepared: false, queue: [], receipts: [], pending: 0, blocked: 0, online: navigator.onLine !== false,
      supported: !capabilityError, supportMessage: capabilityError?.message || '' };
    let epoch = 0, syncController, syncing = false, repairing = false, cancelled = false, syncState = {}, message = '', messageSource = null, privacyHold = false;
    const setMessage = (value, source = null) => { message = value; messageSource = source; };
    const requests = new Set();
    const abortRequests = () => { for (const controller of requests) controller.abort(); };
    let channel;
    try {
      if (options.broadcast !== false && env.BroadcastChannel) {
        channel = new env.BroadcastChannel('patrol-offline-state-v1');
        channel.onmessage = event => { if (event.data?.type === 'lock') { epoch++; abortRequests(); hidePrivateState(); } refresh().catch(() => {}); };
      }
    } catch (_) { channel = null; /* IndexedDB transactions still enforce ownership and synchronization leases. */ }
    function announce() {
      for (const fn of listeners) { try { fn(state); } catch (_) { /* One UI subscriber cannot interrupt persistence. */ } }
      if (env.dispatchEvent && env.CustomEvent) env.dispatchEvent(new env.CustomEvent('patrol:offline-state', { detail: state }));
    }
    function broadcast(type = 'change') { try { channel?.postMessage({ type }); } catch (_) { /* A closed tab cannot undo a durable write. */ } }
    function storageError(error) {
      return typeof error?.code === 'string' ? error : fault('storage', error?.name === 'QuotaExceededError' ?
        '手機儲存空間不足，這筆尚未保存。請先補傳既有紀錄；原表單與照片仍保留。' :
        '手機離線儲存暫時無法使用；已保存的資料不會刪除，請重試。');
    }
    function hidePrivateState(storageUnavailable = false) {
      state = { ...state, locked: true, prepared: false, identity: null, owner: null, queue: [], receipts: [], pending: 0, blocked: 0,
        day: '', captureUntil: '', syncUntil: '', storageUnavailable: Boolean(storageUnavailable && !privacyHold),
        sync: { ...syncState, current: '', running: syncing || repairing }, message };
      announce();
    }
    function database() {
      if (!idb) return Promise.reject(fault('storage', '此瀏覽器無法使用離線儲存，請在線上打卡。'));
      if (!dbPromise) dbPromise = new Promise((resolve, reject) => {
        const request = idb.open(options.databaseName || DB_NAME, 1);
        request.onupgradeneeded = () => {
          const db = request.result;
          for (const name of STORES) db.createObjectStore(name, { keyPath: name === 'meta' ? 'key' : name === 'manifests' ? 'owner' : 'client_id' });
        };
        request.onsuccess = () => { const db = request.result; db.onversionchange = () => { db.close(); dbPromise = null; }; resolve(db); };
        request.onerror = () => { dbPromise = null; reject(fault('storage', '無法開啟手機儲存空間，請檢查瀏覽器設定或改用線上打卡。')); };
        request.onblocked = () => { dbPromise = null; reject(fault('storage', '請關閉其他舊版巡檢分頁，再重試。')); };
      });
      return dbPromise;
    }
    async function transaction(names, mode, work) {
      const db = await database();
      return new Promise((resolve, reject) => {
        let tx, result, failure;
        try { tx = db.transaction(names, mode); } catch (error) { reject(storageError(error)); return; }
        tx.oncomplete = () => resolve(result);
        tx.onabort = () => reject(storageError(failure || tx.error));
        tx.onerror = () => { /* onabort is authoritative; partial writes are never reported saved. */ };
        const done = value => { result = value; };
        const fail = error => { failure = error; tx.abort(); };
        try { work(tx, done, fail); } catch (error) { fail(error); }
      });
    }
    const photoSyncKey = id => 'photo-sync:' + id;
    const storedAttempts = Symbol('storedAttempts');
    const photoRevision = row => row?.photo_revision || 0;
    function applyPhotoSyncState(tx, data) {
      const photos = new Map();
      for (const row of data.queue) if (row.photos?.length) {
        row[storedAttempts] = row.attempts || 0;
        photos.set(photoSyncKey(row.client_id), row);
      }
      for (const saved of data.meta) if (typeof saved.key === 'string' && saved.key.startsWith('photo-sync:')) {
        const row = photos.get(saved.key);
        if (row && saved.progress && saved.owner === row.owner && saved.photo_revision === photoRevision(row) && saved.base_attempts === row[storedAttempts]) {
          const { status, error, retryable, attempts } = saved.progress;
          Object.assign(row, { status, error, retryable, attempts });
        } else if (tx.mode === 'readwrite') {
          // Older tabs may already have removed the row or replaced its photos.
          tx.objectStore('meta').delete(saved.key);
        }
      }
    }
    function saveSyncState(tx, row) {
      if (!row.photos?.length) { tx.objectStore('queue').put(row); return; }
      // WebKit can invalidate a persisted Blob when a metadata-only update
      // puts the same IndexedDB record back. Leave its evidence untouched.
      const { status, error, retryable, attempts } = row;
      tx.objectStore('meta').put({ key: photoSyncKey(row.client_id), owner: row.owner,
        photo_revision: photoRevision(row), base_attempts: row[storedAttempts], progress: { status, error, retryable, attempts } });
    }
    function deleteQueuedEntry(tx, id) {
      tx.objectStore('queue').delete(id);
      tx.objectStore('meta').delete(photoSyncKey(id));
    }
    function readAll(tx, callback) {
      const result = {}, names = STORES; let remaining = names.length;
      for (const name of names) {
        const request = tx.objectStore(name).getAll();
        request.onsuccess = () => { result[name] = request.result; if (!--remaining) {
          try { applyPhotoSyncState(tx, result); callback(result); } catch (_) { tx.abort(); }
        } };
      }
    }
    function current(data) {
      const active = data.meta.find(item => item.key === 'active');
      const manifest = active && !active.locked && !privacyHold ? data.manifests.find(item => item.owner === active.owner) : null;
      return { active, manifest };
    }
    const fresh = manifest => Boolean(manifest && checklistCapable(manifest) && now() + manifest.offset_ms < Date.parse(manifest.capture_until) &&
      now() + manifest.offset_ms >= Date.parse(manifest.server_time) - 60000);
    function usedSlots(manifest, point, data) {
      return new Set([...(point.used_slots || []), ...data.queue, ...data.receipts]
        .filter(item => typeof item === 'string' || (item.owner === manifest.owner && item.day === manifest.day && item.token === point.token))
        .map(item => typeof item === 'string' ? item : item.slot));
    }
    const summary = row => ({ client_id: row.client_id, token: row.token, code: row.code, name: row.name, name_i18n: row.name_i18n, stage: row.stage, slot: row.slot,
      day: row.day, observed_at: row.observed_at, status: row.status, error: row.error || '', retryable: row.retryable,
      note: row.note, is_abnormal: row.is_abnormal, photo_count: row.photos?.length || 0, attempts: row.attempts || 0,
      execution_unconfirmed: row.execution_unconfirmed === true, ...savedChecklist(row) });
    async function refresh() {
      if (capabilityError) { setMessage(capabilityError.message); state.online = navigator.onLine !== false; hidePrivateState(); return state; }
      let snapshot;
      try { snapshot = await transaction(STORES, 'readonly', (tx, done) => readAll(tx, done)); }
      catch (error) { hidePrivateState(true); throw error; }
      const { active, manifest } = current(snapshot);
      const owned = manifest ? snapshot.queue.filter(row => row.owner === manifest.owner || row.user_id === manifest.identity.id)
        .sort((a, b) => a.created_ms - b.created_ms || (a.sequence || 0) - (b.sequence || 0) || a.client_id.localeCompare(b.client_id)) : [];
      const queue = owned.map(row => row.owner === manifest.owner ? { ...summary(row),
        checklist_review_required: Boolean(manifest.points.find(point => point.token === row.token)?.checklist && (!Array.isArray(row.checklist) || !row.checklist.length)) } : { ...summary(row), stale_owner: true, status: 'blocked', retryable: false,
        error: '原登入版本或手機綁定已變更。此筆保留供處理，不會使用新授權補傳；請聯絡管理員。' });
      const receipts = manifest ? snapshot.receipts.filter(row => row.owner === manifest.owner).map(row => ({ ...row, photos: undefined })) : [];
      // Only the pending notice created for this local UUID may advance when
      // another tab confirms it. Auth, preparation and error notices win.
      if (messageSource?.kind === 'local-save' && receipts.some(row => row.client_id === messageSource.client_id)) setMessage('已同步完成');
      if (messageSource?.kind === 'photo-repair') {
        const accepted = receipts.find(row => row.client_id === messageSource.client_id);
        if (accepted) setMessage(photoRevision(accepted) === messageSource.photo_revision ? '已同步完成' : EXISTING_PHOTO_RECEIPT);
      }
      state = { locked: !manifest || Boolean(active?.locked), prepared: fresh(manifest), supported: true, supportMessage: '', storageUnavailable: false, identity: manifest?.identity || null,
        owner: manifest?.owner || null, revision: active?.revision || 0, day: manifest?.day || '', captureUntil: manifest?.capture_until || '', syncUntil: manifest?.sync_until || '',
        needsChecklistUpdate: Boolean(manifest && !checklistCapable(manifest)),
        online: navigator.onLine !== false, pending: queue.length, blocked: queue.filter(row => row.status === 'blocked').length,
        queue, receipts,
        sync: { ...syncState, current: manifest ? syncState.current : '', running: syncing || repairing }, message };
      announce(); return state;
    }
    async function lock(reason = '', expected = null) {
      const hideAndStop = () => { privacyHold = true; epoch++; cancelled = true; abortRequests(); hidePrivateState(); };
      // An explicit logout hides data and cancels requests before waiting on
      // storage. A failed lock remains private in this tab until preparation.
      if (!expected) hideAndStop();
      let applied;
      try { applied = await transaction(['meta', 'manifests'], 'readwrite', (tx, done, fail) => {
        const store = tx.objectStore('meta'), request = store.get('active');
        request.onsuccess = () => { try {
          if ((expected?.owner && request.result?.owner !== expected.owner) ||
              (expected?.revision !== undefined && (request.result?.revision || 0) !== expected.revision)) return done(false);
          store.put({ key: 'active', locked: true, owner: null, revision: (request.result?.revision || 0) + 1 });
          tx.objectStore('manifests').clear(); done(true); } catch (error) { fail(error); } };
      }); } catch (error) { if (expected) hideAndStop(); throw error; }
      if (applied) { setMessage(reason); if (expected) hideAndStop(); else hidePrivateState(); broadcast('lock'); }
      return refresh();
    }
    async function network(url, init = {}, timeout = connectTimeout) {
      if (navigator.onLine === false) throw fault('offline', '目前沒有網路，資料仍保留在此手機。');
      const aborter = new env.AbortController(), isSync = url !== '/api/offline/prepare';
      requests.add(aborter); if (isSync) syncController = aborter;
      let timer, abortTimer, stopWaiting;
      const readResponse = async () => {
        const response = await fetcher(url, { ...init, signal: aborter.signal, credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
        let json;
        try { json = await response.json(); } catch (error) {
          if (error.name === 'AbortError') throw error;
          if (!response.ok) return { response, json: null };
          throw fault('response', '伺服器回應無法確認，資料仍保留，請重試。');
        }
        return { response, json };
      };
      try {
        // Some mobile requests or response readers do not settle on abort.
        // Release the UI at the deadline; any late commit retains the same UUID.
        const deadline = new Promise((_, reject) => {
          const end = () => reject(fault('timeout', '連線逾時，資料仍保留，請重試。'));
          // Accept a complete ACK already being delivered on this event loop turn.
          // A reader that ignores cancellation cannot keep the queue busy.
          stopWaiting = () => { abortTimer = timers.setTimeout(end, 0); };
          aborter.signal.addEventListener('abort', stopWaiting, { once: true });
          timer = timers.setTimeout(() => { aborter.abort(); end(); }, timeout);
        });
        return await Promise.race([readResponse(), deadline]);
      } catch (error) {
        if (aborter.signal.aborted || error.name === 'AbortError') throw fault(isSync && cancelled ? 'cancelled' : 'timeout', isSync && cancelled ? '已停止補傳，尚未確認的資料仍保留。' : '連線逾時，資料仍保留，請重試。');
        if (error.name === 'TypeError') throw fault('network', '無法連線，待補傳資料仍保留。');
        throw error;
      } finally {
        timers.clearTimeout(timer); timers.clearTimeout(abortTimer); aborter.signal.removeEventListener('abort', stopWaiting);
        requests.delete(aborter); if (syncController === aborter) syncController = null;
      }
    }
    function validManifest(value) {
      return value?.ok === true && value.version === 1 && checklistCapable(value) && typeof value.owner === 'string' && value.owner.length <= 300 && value.identity &&
        Number.isInteger(value.identity.id) && Number.isInteger(value.identity.auth_version) && Number.isInteger(value.identity.binding_id) &&
        /^\d{4}-\d{2}-\d{2}$/.test(value.day) && Number.isFinite(Date.parse(value.server_time)) && Number.isFinite(Date.parse(value.capture_until)) &&
        Number.isFinite(Date.parse(value.sync_until)) && typeof value.csrf_token === 'string' && Array.isArray(value.points) &&
        value.points.every(p => isToken(p.token) && typeof p.grant === 'string' && typeof p.revision === 'string' && ['execute', 'inspect', 'visit'].includes(p.stage) &&
          Array.isArray(p.slots) && p.slots.length > 0 && p.slots.every(slot => ['any', 'am', 'pm'].includes(slot)) && Array.isArray(p.used_slots));
    }
    async function prepare(expectedIdentity) {
      requireSupport();
      const startEpoch = epoch;
      const revision = await transaction(['meta'], 'readonly', (tx, done) => {
        const request = tx.objectStore('meta').get('active'); request.onsuccess = () => done(request.result?.revision || 0);
      });
      const { response, json } = await network('/api/offline/prepare');
      // Cache installation may take several seconds. It must not shift the
      // phone's calibrated clock backwards by that preparation duration.
      const receivedMs = now(), offsetMs = Date.parse(json?.server_time) - receivedMs;
      if (!response.ok || !validManifest(json)) {
        if ([401, 403].includes(response.status)) await lock('請先登入並使用已核准的綁定手機。', { revision });
        if (response.ok && json?.ok === true && !checklistCapable(json)) throw fault('checklist_update', CHECKLIST_UPDATE_MESSAGE);
        throw fault(json?.code || 'prepare', json?.message_source || json?.message || '無法準備離線資料，請先確認登入與手機綁定。');
      }
      if (expectedIdentity && (String(json.identity.id) !== String(expectedIdentity.id) || String(json.identity.auth_version) !== String(expectedIdentity.version))) {
        await lock('帳號已變更，請重新載入頁面。', { revision }); throw fault('owner', '帳號已變更，請重新載入頁面。');
      }
      if (startEpoch !== epoch) throw fault('owner', '帳號狀態已變更，請重試。');
      if (options.ensureShell) await options.ensureShell();
      if (startEpoch !== epoch) throw fault('owner', '帳號狀態已變更，請重試。');
      const manifest = { ...json, offset_ms: offsetMs, prepared_ms: receivedMs };
      await transaction(['meta', 'manifests'], 'readwrite', (tx, done, fail) => {
        const store = tx.objectStore('meta'), request = store.get('active');
        request.onsuccess = () => { try {
          if ((request.result?.revision || 0) !== revision) return fail(fault('owner', '帳號狀態已變更，請重新準備。'));
          tx.objectStore('manifests').put(manifest);
          store.put({ key: 'active', owner: manifest.owner, locked: false, revision: revision + 1 }); done(true);
        } catch (error) { fail(error); } };
      });
      // Logout can begin after this write transaction starts. Its memory
      // privacy hold must survive even if the following lock write fails.
      if (startEpoch !== epoch) throw fault('owner', '帳號狀態已變更，請重新登入後準備離線資料。');
      privacyHold = false;
      setMessage('今日離線資料已備妥。未上傳的紀錄只保留在這支手機。');
      if (!syncing) syncState = {};
      broadcast(); return refresh();
    }
    async function getPoint(token, { includeManagementOnly = false } = {}) {
      if (capabilityError) return null;
      return transaction(STORES, 'readonly', (tx, done) => readAll(tx, data => {
        const { manifest } = current(data), point = manifest?.points.find(item => item.token === token);
        if (!point) {
          const label = includeManagementOnly && manifest?.identity.role === 'admin' && fresh(manifest) &&
            Array.isArray(manifest.management_only_points) && manifest.management_only_points.find(item => item?.token === token);
          return done(label ? { ...label, owner: manifest.owner, managementOnly: true } : null);
        }
        const used = usedSlots(manifest, point, data);
        const availableSlots = point.slots.filter(slot => !used.has(slot) && !used.has('any'));
        done({ ...point, owner: manifest.owner, identity: manifest.identity, availableSlots, prepared: fresh(manifest), day: manifest.day,
          executionCheckedAt: manifest.server_time, waitingExecution: executionStatus(point, availableSlots[0]) === 'unconfirmed' });
      }));
    }
    async function enqueue(input) {
      requireSupport();
      const startEpoch = epoch, capturedMs = now();
      const photos = Array.from(input.photos || []); validatePhotos(photos);
      const note = String(input.note || '').replace(/\r\n?/g, '\n').trim();
      if (Array.from(note).length > 2000) throw fault('note', '巡檢備註最多 2,000 字。');
      if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\ud800-\udfff]/u.test(note)) throw fault('note', '巡檢備註含無法儲存的字元，請移除特殊控制字元後重試。');
      const photoOwner = photos.length ? await transaction(['meta'], 'readonly', (tx, done) => {
        const request = tx.objectStore('meta').get('active'); request.onsuccess = () => done(request.result?.owner);
      }) : null;
      const savedPhotos = await copyPhotos(photos);
      if (epoch !== startEpoch) throw fault('owner', '帳號狀態已變更，請重新開啟點位。');
      const client_id = uuid(), captured_device_at = new Date(capturedMs).toISOString();
      const saved = await transaction(STORES, 'readwrite', (tx, done, fail) => readAll(tx, data => {
        if (epoch !== startEpoch) return fail(fault('owner', '帳號狀態已變更，請重新開啟點位。'));
        const { manifest } = current(data);
        if (!manifest) return fail(fault('locked', '請先連線登入，準備今日離線資料。'));
        if (photos.length && photoOwner !== manifest.owner) return fail(fault('owner', '帳號狀態已變更，請重新開啟點位。'));
        if (input.owner && input.owner !== manifest.owner) return fail(fault('owner', '帳號或手機綁定已變更，請重新開啟點位。'));
        if (!checklistCapable(manifest)) return fail(fault('checklist_update', CHECKLIST_UPDATE_MESSAGE));
        if (!fresh(manifest)) return fail(fault('expired', '今日離線資料已到期，請連線重新準備。原有待補傳資料仍保留。'));
        const point = manifest.points.find(item => item.token === input.token);
        if (!point) return fail(fault('point', '此點不在本帳號的離線清單中，請連線更新。'));
        if (input.expected && (String(input.expected.user_id) !== String(manifest.identity.id) || String(input.expected.auth_version) !== String(manifest.identity.auth_version) ||
          input.expected.day !== manifest.day || input.expected.stage !== point.stage ||
          input.expected.frequency !== point.frequency || input.expected.workflow_mode !== point.workflow_mode ||
          input.expected.period_key !== point.period_key || input.expected.revision !== point.revision || !point.slots.includes(input.expected.slot))) {
          return fail(fault('stale', '這份打卡表單的日期、階段或點位設定已變更，請重新掃描。原內容尚未送出。'));
        }
        if (point.stage !== 'inspect' && (note || input.is_abnormal || photos.length)) return fail(fault('stage', '執行與直接簽到不接受備註或照片。'));
        let checklist;
        try { checklist = validateChecklist(point.checklist, input.checklist); } catch (error) { return fail(error); }
        const checklist_snapshot = point.checklist ? { ...JSON.parse(JSON.stringify(point.checklist)), selected: checklist.slice() } : null;
        const used = usedSlots(manifest, point, data);
        const slot = point.slots.find(item => !used.has(item) && !used.has('any'));
        if (!slot) return fail(fault('quota', '此點今日可登記的次數已完成或已暫存。'));
        if (input.expected && input.expected.slot !== slot) return fail(fault('stale', '這份表單的次數已完成或已暫存，請重新掃描下一次；不會自動改成另一個次數。'));
        const execution = executionStatus(point, slot);
        if (execution === 'same_account') return fail(fault('forbidden', '執行與巡檢必須由不同帳號完成。'));
        const usedBytes = data.queue.reduce((total, item) => total + (item.photos || []).reduce((size, photo) => size + photo.size, 0), 0);
        if (data.queue.length >= MAX_QUEUE_ITEMS || usedBytes + photos.reduce((total, photo) => total + photo.size, 0) > MAX_QUEUE_BYTES) {
          return fail(fault('storage', '待補傳資料已達本機上限（200 筆或 256 MB 照片），請先補傳既有紀錄。這筆原表單與照片仍保留。'));
        }
        const sequence = (data.meta.find(item => item.key === 'sequence')?.value || 0) + 1;
        const row = { client_id, sequence, owner: manifest.owner, user_id: manifest.identity.id, auth_version: manifest.identity.auth_version,
          binding_id: manifest.identity.binding_id, token: point.token, grant: point.grant, slot,
          observed_at: new Date(capturedMs + manifest.offset_ms).toISOString(), captured_device_at, note, is_abnormal: Boolean(input.is_abnormal),
          photos: savedPhotos,
          day: manifest.day, sync_until: manifest.sync_until, created_ms: now(), code: point.code, name: point.name, name_i18n: point.name_i18n,
          stage: point.stage, frequency: point.frequency, period_key: point.period_key, status: 'pending', retryable: true, attempts: 0,
          checklist, checklist_snapshot };
        if (execution === 'unconfirmed') row.execution_unconfirmed = true;
        tx.objectStore('meta').put({ key: 'sequence', value: sequence }); tx.objectStore('queue').add(row); done(summary(row));
      }));
      setMessage('已暫存此手機，尚未收到伺服器確認。', { kind: 'local-save', client_id: saved.client_id });
      if (!syncing) syncState = {};
      broadcast();
      // The transaction has committed. A later display read must not turn a
      // durable save into a reported failure or encourage a duplicate retry.
      try { await refresh(); } catch (_) { /* refresh already hides unreadable private state. */ }
      return saved;
    }
    async function remove(client_id, confirmation) {
      if (confirmation !== true) throw fault('confirm', '刪除本機紀錄需要明確確認。');
      if (syncing || repairing) throw fault('busy', '請先停止補傳，再刪除本機紀錄。');
      await transaction(STORES, 'readwrite', (tx, done, fail) => readAll(tx, data => {
        const { manifest } = current(data), row = data.queue.find(item => item.client_id === client_id);
        const lease = data.meta.find(item => item.key === 'sync');
        if (lease?.until > now()) return fail(fault('busy', '其他分頁正在補傳，請稍後再刪除。'));
        if (!manifest || !row || (row.owner !== manifest.owner && row.user_id !== manifest.identity.id)) return fail(fault('owner', '無法操作其他帳號的本機資料。'));
        deleteQueuedEntry(tx, client_id); done(true);
      }));
      setMessage('已刪除這筆尚未確認的本機資料。'); syncState = {}; broadcast(); return refresh();
    }
    async function lease(owner, release = false, requestTimeout = uploadTimeout) {
      return transaction(['meta'], 'readwrite', (tx, done, fail) => {
        const store = tx.objectStore('meta'), request = store.get('sync');
        request.onsuccess = () => { try {
          const previous = request.result;
          if (release) { if (previous?.tab === tabId) store.delete('sync'); done(true); }
          else if (!previous || previous.until < now() || previous.tab === tabId) { store.put({ key: 'sync', tab: tabId, owner, until: now() + requestTimeout + 15000 }); done(true); }
          else done(false);
        } catch (error) { fail(error); } };
      });
    }
    async function ownedEntry(client_id, owner, mutation) {
      return transaction(STORES, 'readwrite', (tx, done, fail) => readAll(tx, data => {
        const { manifest } = current(data), row = data.queue.find(item => item.client_id === client_id);
        if (!manifest || manifest.owner !== owner || (row && row.owner !== owner)) return fail(fault('owner', '帳號已變更，已停止補傳。'));
        // A suspended tab may resume after another tab acquired its expired
        // lease and acknowledged this UUID. A missing row is not an auth loss.
        if (!row) return done(null);
        if (mutation) mutation(tx, row); done(row);
      }));
    }
    const EXISTING_PHOTO_RECEIPT = '伺服器已有這筆紀錄，已確認收件；新選的照片未覆蓋原紀錄。';
    async function inspectReceipt(client_id, owner, revision) {
      const { response, json } = await network('/api/offline/receipt/' + encodeURIComponent(client_id) + '?owner=' + encodeURIComponent(owner));
      if ([401, 403].includes(response.status) || (response.ok && json?.ok === true && json.owner !== owner)) {
        await lock('登入或手機綁定已變更，請用原帳號重新登入後補傳。', { owner, revision });
        throw fault('owner', '登入或手機綁定已變更，待補傳資料仍保留。');
      }
      if (!response.ok || json?.ok !== true || json.owner !== owner || json.client_id !== client_id ||
          !['not_received', 'already_synced'].includes(json.status)) {
        throw fault('response', json?.message_source || json?.message || '無法確認伺服器收件狀態；原照片與暫存仍保留，請稍後重試。');
      }
      return json;
    }
    async function settleKnownReceipt(row, owner, json, startEpoch, revision) {
      return transaction(STORES, 'readwrite', (tx, done, fail) => readAll(tx, data => {
        const { active, manifest } = current(data), currentRow = data.queue.find(item => item.client_id === row.client_id);
        if (epoch !== startEpoch || cancelled || !manifest || manifest.owner !== owner || active.revision !== revision || currentRow?.owner !== owner) {
          if (!currentRow && manifest?.owner === owner && active.revision === revision && epoch === startEpoch && !cancelled) return done(false);
          return fail(fault('owner', '帳號已變更，已停止補傳。'));
        }
        tx.objectStore('receipts').put({ client_id: row.client_id, owner, token: row.token, slot: row.slot, day: row.day,
          code: row.code, name: row.name, name_i18n: row.name_i18n, stage: row.stage, observed_at: row.observed_at,
          ack: json, received_ms: now(), ...savedChecklist(row) });
        deleteQueuedEntry(tx, row.client_id); done(true);
      }));
    }
    async function repairPhotos(client_id, files, confirmation) {
      requireSupport();
      if (confirmation !== true) throw fault('confirm', '重新選照片需要確認；原照片與暫存仍保留。');
      if (syncing || repairing) throw fault('busy', '另一項補傳或照片處理尚未完成，請稍候。');
      if (navigator.onLine === false) throw fault('offline', '重新選照片前需連網確認收件狀態；原照片與暫存仍保留。');
      const selected = Array.from(files || []); validatePhotos(selected);
      if (!selected.length) throw fault('photos', '請至少選擇 1 張照片；原照片與暫存仍保留。');
      repairing = true; cancelled = false;
      const startEpoch = epoch; let owner, revision, leaseHeld = false;
      const checkActive = () => {
        if (epoch !== startEpoch) throw fault('owner', '帳號已變更，已停止補傳。');
        if (cancelled) throw fault('cancelled', '已停止補傳，尚未確認的資料仍保留。');
      };
      syncState = { phase: 'checking', current: '', elapsed: 0, total: 1, processed: 0, saved: 0, failed: 0 };
      try {
        await refresh(); checkActive(); owner = state.owner; revision = state.revision;
        if (!owner || state.locked) throw fault('locked', '請先連線登入原帳號，再補傳。');
        leaseHeld = await lease(owner);
        if (!leaseHeld) throw fault('busy', '另一個分頁正在補傳，請稍候。');
        const row = await ownedEntry(client_id, owner); checkActive();
        // A cancelled/interrupted upload can leave a retained row as pending.
        // Its temporary display status is not evidence of server acceptance;
        // receipt lookup below remains authoritative before replacing photos.
        if (!row || row.stage !== 'inspect' || !row.photos?.length) {
          throw fault('stale', '這筆目前不需要重選照片，請重新確認待傳清單。');
        }
        syncState.current = row.code; await refresh();
        const receipt = await inspectReceipt(client_id, owner, revision); checkActive();
        if (receipt.status === 'already_synced') {
          await settleKnownReceipt(row, owner, receipt, startEpoch, revision);
          setMessage(EXISTING_PHOTO_RECEIPT); syncState.saved = 1;
          return { status: 'already_synced', client_id };
        }
        const copies = await copyPhotos(selected); checkActive();
        if (!await lease(owner)) throw fault('busy', '另一個分頁正在補傳，請稍候。');
        checkActive();
        await transaction(STORES, 'readwrite', (tx, done, fail) => readAll(tx, data => {
          const { active, manifest } = current(data), item = data.queue.find(value => value.client_id === client_id);
          const held = data.meta.find(value => value.key === 'sync');
          if (epoch !== startEpoch || cancelled || !manifest || manifest.owner !== owner || active.revision !== revision || item?.owner !== owner) {
            return fail(fault('owner', '帳號狀態已變更，請重新開啟點位。'));
          }
          if (held?.tab !== tabId || held.until <= now()) return fail(fault('busy', '另一個分頁正在補傳，請稍候。'));
          if (photoRevision(item) !== photoRevision(row)) return fail(fault('stale', '照片已在其他分頁更新，請重新確認待傳清單。'));
          const otherBytes = data.queue.filter(value => value.client_id !== client_id).reduce((sum, value) =>
            sum + (value.photos || []).reduce((total, photo) => total + (photo.size || 0), 0), 0);
          if (otherBytes + copies.reduce((sum, photo) => sum + photo.size, 0) > MAX_QUEUE_BYTES) {
            return fail(fault('storage', '手機儲存空間不足，這筆尚未保存。請先補傳既有紀錄；原表單與照片仍保留。'));
          }
          // The immutable capture identity and all inspection evidence remain.
          // Only an explicit, server-checked photo reselection changes bytes.
          item.photos = copies; item.photo_revision = photoRevision(item) + 1;
          item.status = 'pending'; item.error = ''; item.retryable = true;
          tx.objectStore('queue').put(item); tx.objectStore('meta').delete(photoSyncKey(client_id)); done(true);
        }));
        setMessage('照片已重新保存，原巡檢時間、備註與異常內容保留；請按「同步待傳紀錄」。',
          { kind: 'photo-repair', client_id, photo_revision: photoRevision(row) + 1 });
        return { status: 'repaired', client_id };
      } finally {
        repairing = false; syncState.phase = 'idle';
        try { if (leaseHeld) await lease(owner, true); } catch (_) { /* A future lease expires; never erase a preserved draft. */ }
        broadcast(); try { await refresh(); } catch (_) { hidePrivateState(true); }
      }
    }
    async function synchronize(selection = {}) {
      requireSupport();
      if (syncing || repairing) return state;
      if (navigator.onLine === false) { setMessage('目前沒有網路，資料仍保留在此手機。'); return refresh(); }
      // Claim synchronously: two clicks can otherwise both pass the guard
      // while their first IndexedDB reads are still in flight.
      syncing = true; cancelled = false; const started = now();
      let owner, revision, firstFailure, leaseHeld = false; const startEpoch = epoch;
      syncState = { total: state.pending, processed: 0, saved: 0, failed: 0, elapsed: 0, current: '', phase: 'checking', cancelled: false };
      const checkActive = () => {
        if (epoch !== startEpoch) throw fault('owner', '帳號已變更，已停止補傳。');
        if (cancelled) throw fault('cancelled', '已停止補傳，尚未確認的資料仍保留。');
      };
      const retryTransient = async (request, retry) => {
        try {
          const result = await request();
          if (!result || ![408, 500, 502, 503, 504].includes(result.response.status) || result.json?.retryable === false) return result;
        } catch (error) {
          if (!['network', 'timeout', 'response'].includes(error.code)) throw error;
        }
        checkActive();
        syncState.phase = 'retrying'; await refresh();
        const delay = options.retryDelay ?? 750;
        if (delay) await new Promise(resolve => timers.setTimeout(resolve, delay));
        checkActive();
        return retry();
      };
      const ticker = timers.setInterval(() => { syncState.elapsed = Math.floor((now() - started) / 1000); state = { ...state, sync: { ...syncState, current: state.locked ? '' : syncState.current, running: syncing } }; announce(); }, 1000);
      try {
        await refresh();
        owner = state.owner; revision = state.revision;
        if (selection.expectedOwner && selection.expectedOwner !== owner) return state;
        if (!owner || state.locked) throw fault('locked', '請先連線登入原帳號，再補傳。');
        leaseHeld = await lease(owner);
        if (!leaseHeld) throw fault('busy', '另一個分頁正在補傳，請稍候。');
        if (cancelled || epoch !== startEpoch) throw fault('cancelled', '已停止補傳，尚未確認的資料仍保留。');
        const checkServer = () => network('/api/offline/status');
        const status = await retryTransient(checkServer, async () => {
          syncState.phase = 'checking'; await refresh(); checkActive();
          return checkServer();
        });
        if (!status.response.ok || status.json?.ok !== true || status.json.owner !== owner || typeof status.json.csrf_token !== 'string') {
          if ([401, 403].includes(status.response.status) || (status.response.ok && status.json?.ok === true && status.json.owner !== owner)) {
            await lock('登入或手機綁定已變更，請用原帳號重新登入後補傳。', { owner, revision });
            throw fault('owner', '登入或手機綁定已變更，待補傳資料仍保留。');
          }
          throw fault('response', '目前無法確認伺服器連線，暫存與離線準備仍保留；請稍後重試。');
        }
        const eligible = row => !selection.retryableOnly || (row.status !== 'blocked' && row.retryable !== false);
        const ids = state.queue.filter(row => !row.stale_owner && eligible(row) && (!selection.client_id || row.client_id === selection.client_id)).map(row => row.client_id);
        syncState.total = ids.length;
        for (const id of ids) {
          if (cancelled || epoch !== startEpoch) break;
          if (!await lease(owner)) throw fault('busy', '另一個分頁正在補傳，請稍候。');
          const row = await ownedEntry(id, owner, (tx, item) => {
            if (!eligible(item)) return;
            item.status = 'pending'; item.attempts = (item.attempts || 0) + 1; saveSyncState(tx, item);
          });
          if (!row || !eligible(row)) { syncState.processed++; continue; }
          // Allow larger camera payloads time to transfer over a weak connection.
          const bytes = (row.photos || []).reduce((sum, photo) => sum + (Number(photo?.size) || 0), 0);
          const rowTimeout = options.uploadTimeout || Math.min(180000, uploadTimeout + Math.floor(bytes / 131072) * 1000);
          syncState.current = row.code; syncState.uploadTimeoutSeconds = Math.ceil(rowTimeout / 1000);
          syncState.phase = 'uploading'; await refresh();
          if (cancelled || epoch !== startEpoch) break;
          try {
            // A previous upload may have committed while the phone lost the
            // response. Verify that UUID before touching its original photos.
            const reconcile = async (beforeUpload) => {
              const known = await inspectReceipt(id, owner, revision);
              checkActive();
              if (known.status === 'not_received') return false;
              await settleKnownReceipt(row, owner, known, startEpoch, revision);
              syncState.saved++;
              if (beforeUpload && photoRevision(row)) syncState.existingPhotoReceipt = true;
              return true;
            };
            if ((photoRevision(row) || row.attempts > 1) && await reconcile(true)) {
              syncState.processed++; broadcast(); await refresh(); continue;
            }
            const photos = await copyPhotos(row.photos, true);
            if (cancelled || epoch !== startEpoch) break;
            const Form = options.FormData || env.FormData, body = new Form();
            const entry = { client_id: row.client_id, owner: row.owner, token: row.token, grant: row.grant, slot: row.slot,
              observed_at: row.observed_at, note: row.note, is_abnormal: row.is_abnormal };
            if (owns(row, 'checklist')) entry.checklist = row.checklist;
            body.append('entry', JSON.stringify(entry));
            for (let index = 0; index < photos.length; index++) {
              const photo = photos[index];
              try { body.append('photos', photo.blob, photo.name); }
              catch (_) { throw fault('photo_read', `第 ${index + 1} 張暫存照片無法完整讀取；資料仍保留，請稍後重試或聯絡管理員，請勿清除瀏覽器資料。`); }
            }
            // Recheck after every asynchronous read or receipt query. A
            // suspended tab may resume after another rewrote a photo or signed out.
            const upload = async () => {
              if (!await lease(owner, false, rowTimeout)) throw fault('busy', '另一個分頁正在補傳，請稍候。');
              const latestRow = await ownedEntry(id, owner); checkActive();
              if (!latestRow || photoRevision(latestRow) !== photoRevision(row)) return null;
              syncState.phase = 'uploading';
              return network('/api/offline/sync', { method: 'POST', headers: { 'X-CSRF-Token': status.json.csrf_token }, body }, rowTimeout);
            };
            const result = await retryTransient(upload, async () => await reconcile(false) ? null : upload());
            if (!result) { syncState.processed++; broadcast(); await refresh(); continue; }
            const { response, json } = result;
            const acknowledged = response.ok && json?.ok === true && ['saved', 'already_synced'].includes(json.status) && json.client_id === id;
            if (acknowledged) {
              // ACK is durable together with removal. Losing this transaction safely retries the same UUID.
              const photoChanged = await transaction(['queue', 'receipts', 'meta'], 'readwrite', (tx, done, fail) => {
                const request = tx.objectStore('queue').get(id);
                request.onsuccess = () => { try {
                  if (request.result?.owner === owner) {
                    tx.objectStore('receipts').put({ client_id: id, owner, token: row.token, slot: row.slot, day: row.day,
                      code: row.code, name: row.name, name_i18n: row.name_i18n, stage: row.stage, observed_at: row.observed_at,
                      photo_revision: photoRevision(row), ack: json, received_ms: now(), ...savedChecklist(row) });
                    deleteQueuedEntry(tx, id);
                    return done(photoRevision(request.result) !== photoRevision(row));
                  }
                  done(false);
                } catch (error) { fail(error); } };
              });
              if (photoChanged) syncState.existingPhotoReceipt = true;
              syncState.saved++;
            } else {
              const reason = json?.message_source || json?.message || '伺服器未確認這筆紀錄，資料仍保留，請重試。';
              // A single point can reject an otherwise authorized inspector
              // (for example, reviewing their own earlier execution). Keep
              // other points available instead of discarding the manifest.
              if (response.status === 401 || (response.status === 403 && json?.code !== 'forbidden')) {
                await lock(reason, { owner, revision }); throw fault('owner', reason);
              }
              const retryable = response.status >= 500 || json?.retryable !== false || json?.ok === true;
              await ownedEntry(id, owner, (tx, item) => { if (photoRevision(item) !== photoRevision(row)) return;
                item.status = retryable ? 'retry' : 'blocked'; item.error = reason; item.retryable = retryable; saveSyncState(tx, item); });
              if (!firstFailure) firstFailure = reason;
              syncState.failed++;
            }
          } catch (error) {
            if (epoch !== startEpoch || error.code === 'owner' || error.code === 'busy') throw error;
            const reason = error.message || '連線失敗，資料仍保留。';
            await ownedEntry(id, owner, (tx, item) => { if (photoRevision(item) !== photoRevision(row)) return;
              item.status = 'retry'; item.error = reason; item.retryable = true; saveSyncState(tx, item); });
            if (!firstFailure) firstFailure = reason;
            syncState.failed++;
            if (['timeout', 'cancelled', 'offline', 'network'].includes(error.code)) { syncState.processed++; break; }
          }
          syncState.processed++; broadcast(); await refresh();
        }
        setMessage(cancelled ? '已停止補傳，尚未確認的資料仍保留。' : syncState.existingPhotoReceipt ?
          EXISTING_PHOTO_RECEIPT : !syncState.saved && firstFailure ? firstFailure :
          `已確認 ${syncState.saved} 筆；其餘未確認資料仍保留在此手機。`);
      } catch (error) {
        setMessage(error.message || '無法連線，待補傳資料仍保留。');
        if (!cancelled && !['cancelled', 'busy'].includes(error.code)) syncState.errorCode = error.code || 'network';
      }
      finally {
        syncing = false; syncState.cancelled = cancelled; syncState.phase = 'idle'; timers.clearInterval(ticker);
        try { if (leaseHeld) await lease(owner, true); }
        catch (_) { setMessage('補傳已停止，但手機儲存狀態暫時無法讀取；請重試。未收到確認的資料仍保留。'); syncState.errorCode = 'storage'; }
        broadcast();
        try { await refresh(); }
        catch (_) { syncState.errorCode = 'storage'; hidePrivateState(true); }
      }
      return state;
    }
    function cancelSync() { cancelled = true; syncController?.abort(); }
    async function route(value) {
      const path = safePath(value); if (!path) throw fault('point', '這不是本站的巡檢點網址。');
      if (navigator.onLine === false) requireSupport();
      return navigator.onLine === false ? '/offline?point=' + encodeURIComponent(path.slice(3)) : path;
    }
    return { prepare, getState: refresh, getPoint, enqueue, sync: synchronize, repairPhotos, lock, remove, route, cancelSync,
      subscribe(fn) { listeners.add(fn); fn(state); return () => listeners.delete(fn); },
      async close() { try { channel?.close(); } catch (_) {} const db = await dbPromise; db?.close(); },
      async matchIdentity(id, version) { await refresh(); if (state.identity && (String(state.identity.id) !== String(id) || String(state.identity.auth_version) !== String(version))) await lock('帳號已變更，請重新準備離線資料。'); return state; } };
  }
  function createShellReadiness(env) {
    const e = env || root, nav = e.navigator, schedule = e.setTimeout || setTimeout, unschedule = e.clearTimeout || clearTimeout;
    let pending;
    return function ensureShell() {
      if (!e.isSecureContext || !nav?.serviceWorker || !e.MessageChannel) return Promise.reject(fault('support', '此瀏覽器無法啟用離線頁面，請使用 HTTPS 網址與支援的瀏覽器。'));
      if (pending) return pending;
      let cancelled = false, deadline;
      const probes = new Set();
      // Older workers may have every file but fail to serve the versioned URLs
      // referenced by their cached HTML. Require the corrected asset contract
      // before today's manifest can be reported prepared.
      const currentShell = value => value?.assetVersion === 1 && value.audioVersion === 'patrol-v1' && value.audioRevision === 'natural-female-1' && value.checklistVersion === 1 && value.calendarVersion === 1;
      const ready = value => value?.ready === true && value.audioReady === true && currentShell(value);
      const probe = (worker, type, timeout) => new Promise((resolve, reject) => {
        const channel = new e.MessageChannel(); let finished = false;
        const finish = (error, value) => {
          if (finished) return; finished = true; unschedule(timer);
          probes.delete(cancelProbe); channel.port1.close(); channel.port2.close(); error ? reject(error) : resolve(value);
        };
        const cancelProbe = () => finish(fault('shell', '離線頁面準備逾時，請連線後再試。'));
        const timer = schedule(() => finish(fault('shell', '離線頁面尚未備妥，請重試。')), timeout);
        probes.add(cancelProbe);
        channel.port1.onmessage = event => finish(null, event.data);
        try { worker.postMessage({ type }, [channel.port2]); } catch (error) { finish(error); }
      });
      const install = async () => {
        const registration = await nav.serviceWorker.register('/offline-sw.js', { scope: '/', updateViaCache: 'none' });
        let checked, updated = false;
        while (!cancelled) {
          const worker = registration.active;
          if (worker && worker !== checked) {
            checked = worker;
            let reply = await probe(worker, 'PATROL_OFFLINE_READY', e.probeTimeout || 3000);
            if (cancelled) break;
            if (currentShell(reply)) {
              if (!ready(reply) && nav.onLine !== false) reply = await probe(worker, 'PATROL_OFFLINE_PREPARE', e.repairTimeout || 28000);
              if (cancelled) break;
              if (!ready(reply)) throw fault('shell', '離線頁面與提示音尚未備妥，請連線後重試。');
              requestPersistence(nav); return;
            }
          }
          // An older worker may be controlling this page while the new public
          // assets install. Its old ready:true response cannot prove that the
          // cached shell can load all of its scripts and styles while offline.
          if (!updated && !registration.installing && !registration.waiting && nav.onLine !== false) {
            updated = true; await registration.update();
          }
          if (nav.onLine === false && !registration.installing && !registration.waiting) throw fault('shell', '離線頁面與提示音尚未備妥，請連線後重試。');
          await new Promise(resolve => schedule(resolve, e.pollInterval || 100));
        }
      };
      pending = Promise.race([install(), new Promise((_, reject) => {
        deadline = schedule(() => reject(fault('shell', '離線頁面準備逾時，請連線後再試。')), e.deadline || 35000);
      })]).finally(() => { cancelled = true; unschedule(deadline); for (const cancel of probes) cancel(); pending = null; });
      return pending;
    };
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { createCore, validatePhotos, validateChecklist, validChecklistDefinition, formChecklist, safePath, requestPersistence, createShellReadiness, frequencyLabel };
  if (!root.document) return;
  const ensureShell = createShellReadiness(root);
  const core = createCore({ ensureShell }); root.PatrolOffline = core;
  function ready() {
    const body = document.body, shell = body.hasAttribute('data-offline-shell');
    const all = hook => [...document.querySelectorAll(`[data-offline-${hook}]`)];
    const one = hook => document.querySelector(`[data-offline-${hook}]`);
    const text = (hook, value) => all(hook).forEach(el => { if (el.textContent !== value) el.textContent = value; });
    const query = new URLSearchParams(location.search);
    let selectedToken = query.get('point') || safePath(location.pathname)?.slice(3), savedClientId = query.get('queued'),
      pointGeneration = 0, previewURLs = [], selectedOwner, viewOwner, selectedSnapshot, normalProgress,
      navigationAllowed = false, pageActive = true, pageEpoch = 0, selectedPhotos = [], canEditPhotos = false, latestState, preparing = false, uiSyncing = false, updatingLocale = false,
      checklistUIKey = '', checklistLocale = '';
    let uiRequest = null, uiRequestEpoch = 0, uiSessionKnown = null, localNotice = null, queueSignature = '', lastManifestUIKey = null,
      photoReselection = null, queueNotice = null;
    const savedResultPanels = new Map();
    const uiIdentityKey = state => JSON.stringify([state?.owner, state?.revision, state?.identity?.ui_language, state?.identity?.simple_executor_ui]);
    const uiPreferencesFromIdentity = identity => ({ ui_language: identity.ui_language,
      simple_executor_ui: identity.role === 'executor' && identity.simple_executor_ui === true });
    function cancelUIPreferences() { uiRequestEpoch++; uiRequest?.abort(); uiRequest = null; }
    async function refreshUIPreferences() {
      if (!shell || navigator.onLine === false || !root.fetch || !root.AbortController) return;
      cancelUIPreferences();
      const epoch = uiRequestEpoch, identityKey = uiIdentityKey(latestState), controller = new root.AbortController();
      uiRequest = controller;
      const timer = setTimeout(() => controller.abort(), 5000);
      try {
        const response = await root.fetch('/api/ui-preferences', { credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal });
        const value = await response.json();
        if (epoch !== uiRequestEpoch || identityKey !== uiIdentityKey(latestState)) return;
        if (response.status === 401) { uiSessionKnown = false; if (latestState) render(latestState); return; }
        if (!response.ok || value?.ok !== true) return;
        const previousLocale = root.PatrolI18n?.getLocale();
        updatingLocale = true;
        try { if (root.PatrolI18n?.acceptPreferences(value)) uiSessionKnown = true; } finally { updatingLocale = false; }
        if (latestState) { render(latestState); if (root.PatrolI18n?.getLocale() !== previousLocale) renderPhotos(); }
      } catch (_) { /* A presentation lookup must never block capture, sync or local recovery. */ }
      finally { clearTimeout(timer); if (uiRequest === controller) uiRequest = null; }
    }
    const form = one('checkin'), photosInput = form?.elements.namedItem('photos');
    core.allowNavigation = () => { navigationAllowed = true; };
    const draftPresent = target => target && !target.hasAttribute('data-offline-stored') && (
      target.elements.namedItem('note')?.value || target.elements.namedItem('is_abnormal')?.checked ||
      target.elements.namedItem('photos')?.files.length || formChecklist(target).length || target.dataset.offlineSaving === 'true' ||
      target === form && target.dataset.submitting === 'true');
    const hasDraft = () => draftPresent(form) || draftPresent(document.getElementById('inspection-form'));
    for (const event of ['input', 'change']) document.getElementById('inspection-form')?.addEventListener(event, event => { delete event.currentTarget.dataset.offlineStored; });
    window.addEventListener('beforeunload', event => {
      const normal = document.getElementById('inspection-form');
      if (navigationAllowed || normal?.dataset.submitting === 'true' && normal.dataset.offlineSaving !== 'true' || !hasDraft()) return;
      event.preventDefault(); event.returnValue = '';
    });
    const slotText = slot => slot === 'am' ? t('第 1 次') : slot === 'pm' ? t('第 2 次') : t('本次');
    const stageText = stage => ({ execute: t('執行簽到'), inspect: t('巡檢'), visit: t('直接簽到') }[stage] || t('巡檢'));
    const timeText = iso => { try { return new Date(iso).toLocaleString(({ id: 'id-ID', vi: 'vi-VN' })[root.PatrolI18n?.getLocale()] || 'zh-TW', { timeZone: 'Asia/Taipei', hour12: false }); } catch { return iso; } };
    const pendingExecutionHint = '巡檢已暫存。若執行人員也離線簽到，請對方先同步，再補傳本筆巡檢。';
    function pendingSaveMessage(row) {
      if (row.error || row.execution_unconfirmed) return `${row.code} · ${slotText(row.slot)} · ${t(row.error || pendingExecutionHint)}`;
      return t('{code} · {slot} 已暫存此手機，尚未收到伺服器確認。連線後請按「同步待傳紀錄」。', { code: row.code, slot: slotText(row.slot) });
    }
    function showNotice(source, tone = 'error') {
      localNotice = { source, tone };
      text('status', t(source));
      if (one('status')) one('status').dataset.state = tone;
      one('status')?.focus();
    }
    const reportError = error => showNotice(error.message || '操作未完成，原有資料仍保留。');
    function syncPhaseText(sync) {
      if (sync.phase === 'retrying') return t('正在重試，請稍候…');
      if (sync.phase === 'uploading') return t('正在處理本筆紀錄，送出後最多等 {seconds} 秒', { seconds: sync.uploadTimeoutSeconds || 30 });
      return t('正在檢查連線（最多 5 秒）');
    }
    function updateQueueFeedback(state) {
      let notice = queueNotice;
      if (state.locked && !notice?.public) notice = null;
      if (!state.locked && state.sync?.running) {
        const repairing = photoReselection?.owner === state.owner;
        const progressText = repairing ? t('正在確認收件並讀取新照片…') : syncPhaseText(state.sync);
        notice = { progressText, clientId: repairing ? photoReselection.clientId : notice?.clientId };
      } else if (notice?.clientId && !uiSyncing && !state.queue.some(row => row.client_id === notice.clientId)) {
        // A peer can acknowledge or remove a draft after a local failure.
        queueNotice = notice = state.receipts.some(row => row.client_id === notice.clientId) ? { source: '已同步完成' } : null;
      } else if (notice?.error && !state.locked && !state.pending) {
        queueNotice = notice = null;
      }
      // Report a card action where it was taken. Once acknowledged, the card
      // disappears and its result stays next to the queue's sync control.
      const rows = all('row-feedback'), queue = one('queue-feedback');
      const row = notice?.clientId && rows.find(el => el.dataset.offlineRowFeedback === notice.clientId);
      const target = row || queue;
      let message = notice ? notice.progressText || t(notice.source) : '';
      if (notice?.savedPhotos) message = t('新照片已存到此手機。{reason}', { reason: message });
      for (const el of [queue, ...rows]) {
        if (!el) continue;
        const value = el === target ? message : '';
        el.hidden = !value;
        if (el.textContent !== value) el.textContent = value;
        el.dataset.state = notice?.error ? 'error' : 'info';
      }
    }
    let voiceSequence = 0, scanVoicePending = root.PatrolVoice?.takeScan?.() === true;
    const voice = (kind, id, auto = true) => { try { root.PatrolVoice?.report(kind, { id, auto }); } catch (_) { /* Optional feedback never interrupts capture. */ } };
    const voiceFailure = () => voice('not_saved', `failure:${Date.now()}:${++voiceSequence}`);
    const isBlocked = row => row?.status === 'blocked' || row?.retryable === false;
    const voiceArrival = async (kind, id, destination, owner, skip) => {
      // Feedback starts only after a durable local save / server ACK. Keep the
      // current document alive briefly so iOS can use its prepared audio player.
      // Optional media failures must never enter the save/retry error path.
      let deadline;
      try {
        if (latestState?.owner !== owner || latestState?.locked) return;
        const feedback = root.PatrolVoice;
        feedback?.armResult?.(kind, id, destination, latestState?.identity?.id);
        feedback?.report?.(kind, { id });
        if (typeof feedback?.waitForIdle !== 'function') return;
        await Promise.race([Promise.resolve(feedback.waitForIdle(4500)), skip,
          new Promise(resolve => { deadline = setTimeout(resolve, 4500); })]);
      } catch (_) { /* Confirmed records remain confirmed even without audio. */ }
      finally { clearTimeout(deadline); }
    };
    // Home pages require a live session and are deliberately never cached.
    // Keep the current draft/queue in place when the device knows it is offline.
    for (const home of all('home')) home.addEventListener('click', event => {
      if (navigator.onLine !== false) return;
      event.preventDefault();
      showNotice('目前沒有網路，請連線後再返回首頁；此手機的暫存仍保留。', 'offline');
    });
    one('login')?.addEventListener('click', event => {
      if (navigator.onLine !== false) return;
      event.preventDefault(); showNotice('目前沒有網路，資料仍保留在此手機。', 'offline');
    });
    function showChecklist(point, expected) {
      const group = one('checklist'), options = one('checklist-options');
      if (!group || !options) return false;
      const definition = point?.checklist;
      const valid = validChecklistDefinition(definition);
      group.hidden = !definition || !valid;
      const key = JSON.stringify([point?.owner, point?.token, point?.day, point?.revision, point?.stage, point?.period_key, expected?.slot, definition]);
      const locale = root.PatrolI18n?.getLocale() || 'zh-Hant';
      if (key !== checklistUIKey || locale !== checklistLocale) {
        const selected = new Set(key === checklistUIKey ? formChecklist(form) : []);
        checklistUIKey = key; checklistLocale = locale;
        options.replaceChildren(); group.classList.remove('is-invalid');
        if (definition && valid) {
          for (const item of definition.items) {
            const label = document.createElement('label'); label.className = 'checklist-option';
            const choice = document.createElement('input'); choice.type = 'checkbox'; choice.name = 'checklist'; choice.value = item.id;
            choice.autocomplete = 'off'; choice.checked = selected.has(item.id);
            const span = document.createElement('span');
            if (item.source_code) { const code = document.createElement('small'); code.className = 'checklist-source-code'; code.textContent = item.source_code; span.append(code); }
            span.append(document.createTextNode(checklistLabel(item.label))); label.append(choice, span); options.append(label);
          }
        }
      }
      const chosen = formChecklist(form);
      text('checklist-title', definition && valid ? checklistLabel(definition.title) : '');
      text('checklist-count', definition && valid ? t('已勾選 {count} / {total} 項', { count: chosen.length, total: definition.items.length }) : '');
      for (const choice of options.querySelectorAll('input')) choice.closest('.checklist-option')?.classList.toggle('is-checked', choice.checked);
      if (chosen.length) group.classList.remove('is-invalid');
      try { validateChecklist(definition, chosen); return true; } catch (_) { return false; }
    }
    async function showPoint() {
      const run = ++pointGeneration, section = one('point'); if (!section) return;
      if (latestState?.storageUnavailable) { section.hidden = true; if (one('save')) one('save').disabled = true; return; }
      if (body.hasAttribute('data-offline-hydrating') && latestState?.supported && latestState.revision === undefined) return;
      const point = selectedToken ? await core.getPoint(selectedToken, { includeManagementOnly: true }) : null;
      if (run !== pointGeneration) return;
      section.hidden = !selectedToken || Boolean(point && point.owner !== latestState?.owner);
      if (section.hidden) return;
      selectedOwner = point?.owner;
      const actionable = point && !point.managementOnly;
      if (actionable && !selectedSnapshot) selectedSnapshot = { point, expected: { user_id: point.identity.id, auth_version: point.identity.auth_version,
        day: point.day, slot: point.availableSlots[0], stage: point.stage, frequency: point.frequency, workflow_mode: point.workflow_mode,
        period_key: point.period_key, revision: point.revision } };
      const displayed = point?.managementOnly ? point : selectedSnapshot?.point || point;
      const expected = selectedSnapshot?.expected;
      const unchanged = actionable && expected && point.owner === selectedSnapshot.point.owner && point.revision === expected.revision && point.day === expected.day;
      const roundAvailable = point?.prepared && unchanged && point.availableSlots.includes(expected.slot);
      const handoff = roundAvailable ? executionStatus(point, expected.slot) : null;
      const eligible = roundAvailable && handoff !== 'same_account';
      const saving = form?.dataset.submitting === 'true';
      let reason = '';
      if (point?.managementOnly) reason = '由總務執行人員先簽到，再由{inspector}或總務管理員巡檢。系統管理員可在此查看點位。';
      else if (latestState?.supported === false) reason = latestState.supportMessage;
      else if (latestState?.locked) reason = '請連線登入並準備今日離線資料。';
      else if (latestState?.needsChecklistUpdate) reason = CHECKLIST_UPDATE_MESSAGE;
      else if (!latestState?.prepared || (actionable && !point.prepared)) reason = '今日離線資料已到期，請連線重新準備。原有待補傳資料仍保留。';
      else if (!point) reason = '此點不在本帳號的離線清單中，請連線更新。';
      else if (!unchanged) reason = '點位或日期已變更，請重新掃描';
      else if (handoff === 'same_account') reason = '執行與巡檢必須由不同帳號完成。';
      else if (!eligible && !saving) {
        if (point.availableSlots.length) reason = '這份表單的次數已完成或已暫存，請重新掃描下一次；不會自動改成另一個次數。';
        else if (latestState.queue.some(row => !row.stale_owner && row.token === point.token && row.day === point.day))
          reason = '這支手機已有此點的暫存紀錄，請查看「待傳紀錄」。';
        else reason = '本次{stage}已完成，可繼續掃描下一點。';
      }
      if (scanVoicePending && latestState && !body.hasAttribute('data-offline-hydrating')) {
        scanVoicePending = false;
        if (!eligible) voice('point_unavailable', `scan:${Date.now()}:${++voiceSequence}`);
      }
      text('point-code', displayed?.code || '');
      text('point-name', displayed ? pointName(displayed.name, displayed.name_i18n) : t('無法離線打卡'));
      const labels = point?.managementOnly ? { inspector: t(point.inspection_team === 'engineering' ? '工務巡檢員' : '總務巡檢員') } :
        { stage: actionable ? stageText(point.stage) : '' };
      text('point-meta', reason ? t(reason, labels) : `${point.floor} · ${frequencyLabel(point.frequency)}`);
      text('point-stage', actionable ? stageText(point.stage) : '');
      const roundLabel = (eligible || saving) && expected?.slot ? `${slotText(expected.slot)} · ${expected.day}` : '';
      text('point-round', roundLabel);
      text('stage', actionable ? stageText(point.stage) : '');
      text('round', roundLabel);
      const execution = one('execution');
      if (execution) {
        execution.hidden = !eligible || !handoff;
        execution.dataset.state = handoff || '';
        text('execution-title', handoff === 'signed' ? t('執行人員已簽到，可以巡檢') : handoff === 'unconfirmed' ? t('尚未查到本次執行簽到') : '');
        text('execution-help', handoff === 'unconfirmed' ? t('請先確認執行人員已簽到。若對方已離線簽到，可先暫存巡檢，連線後請對方先同步。') : '');
        text('execution-time', handoff ? t('離線資料更新於 {time}', { time: timeText(point.executionCheckedAt) }) : '');
      }
      if (form) {
        form.dataset.pointPath = '/c/' + selectedToken;
        form.hidden = !actionable || (!eligible && !draftPresent(form));
      }
      if (one('fields')) one('fields').disabled = !eligible || saving;
      const checklistValid = showChecklist(displayed, expected);
      if (one('save')) one('save').disabled = !eligible || saving || !checklistValid;
      if (one('report-fields')) { one('report-fields').hidden = !point || point.stage !== 'inspect'; for (const field of one('report-fields').querySelectorAll('input,textarea')) field.disabled = point?.stage !== 'inspect'; }
    }
    function render(state) {
      for (const [panel, owner] of savedResultPanels) {
        if (state.locked || state.owner !== owner) { panel.remove(); savedResultPanels.delete(panel); }
      }
      const oldIdentity = latestState?.identity;
      if (latestState && latestState.owner !== state.owner) {
        if (latestState.owner) { document.dispatchEvent(new CustomEvent('patrol:voice-owner-changed')); scanVoicePending = false; }
        localNotice = null; queueNotice = null;
        if (oldIdentity) uiSessionKnown = null;
      }
      const manifestUIKey = state.identity ? uiIdentityKey(state) : null;
      if (shell && state.identity && ((lastManifestUIKey && manifestUIKey !== lastManifestUIKey) || preparing)) {
        // A freshly prepared manifest supersedes older display hints. This
        // only changes labels; capture still requires the manifest's grants.
        cancelUIPreferences();
        updatingLocale = true;
        try { root.PatrolI18n?.acceptPreferences(uiPreferencesFromIdentity(state.identity)); } finally { updatingLocale = false; }
      }
      // A cross-tab login can lock the old identity before the new manifest
      // arrives. Retain only this comparison key through that transition so
      // the new account's language replaces the old confirmed display hint.
      if (manifestUIKey) lastManifestUIKey = manifestUIKey;
      latestState = state;
      if (shell) {
        // The cached document is public. Display preferences also work on an
        // unbound desktop and never authorize access to the private manifest.
        const preferences = root.PatrolI18n?.getPreferences(state.identity);
        const locale = preferences?.ui_language || state.identity?.ui_language || 'zh-Hant';
        updatingLocale = true;
        try { root.PatrolI18n?.setLocale(locale); } finally { updatingLocale = false; }
        const simple = Boolean(preferences?.simple_executor_ui);
        body.classList.toggle('simple-executor-ui', simple); body.dataset.uiLanguage = locale;
        for (const home of all('home')) {
          home.href = simple ? '/ready' : '/dashboard';
          const source = simple ? '返回今日待簽到' : '返回巡檢總覽';
          home.dataset.i18nAriaLabel = source; home.setAttribute('aria-label', t(source));
          const label = home.querySelector('[data-offline-home-label]');
          if (label) { label.dataset.i18n = source; label.textContent = t(source); }
        }
      }
      text('count', state.pending ? String(state.pending) : '');
      text('network', state.supported === false ? t('僅限線上') : !state.online ? t('離線') : state.sync?.running ? t('補傳中') : state.pending ? t('待補傳') : state.prepared ? t('已備妥') : t('準備離線'));
      for (const link of all('open')) { if (state.supported === false) link.title = t(state.supportMessage); }
      if (normalProgress && !normalProgress.saving && !normalProgress.result) {
        normalProgress.status.textContent = state.sync?.running ?
          t('{phase} · 已等 {seconds} 秒', { phase: syncPhaseText(state.sync), seconds: state.sync.elapsed || 0 }) :
          t('已保存在手機，正在開啟收據或待傳紀錄…');
        normalProgress.cancel.disabled = !state.sync?.running;
      }
      if (!shell) return;
      if (!state.storageUnavailable) {
        if (viewOwner && viewOwner !== state.owner) { selectedToken = null; selectedOwner = null; selectedSnapshot = null; form?.reset(); resetPhotos(); if (one('saved')) one('saved').hidden = true; }
        viewOwner = state.owner;
      }
      const signedIn = state.online && uiSessionKnown === true;
      text('account', state.identity ? `${state.identity.name} · ${state.identity.role_label ? t(state.identity.role_label) : stageText(state.identity.role === 'executor' ? 'execute' : 'inspect')}` : t(signedIn ? '已登入・尚未準備' : '尚未解鎖離線資料'));
      text('validity', state.prepared ? t('可暫存至 {captureUntil}；補傳期限 {syncUntil}', { captureUntil: timeText(state.captureUntil), syncUntil: timeText(state.syncUntil) }) : state.locked ? t(signedIn ? '請使用已核准的綁定瀏覽器更新離線資料。' : '請先連線登入原帳號，並準備今日資料。') : state.needsChecklistUpdate ? t(CHECKLIST_UPDATE_MESSAGE) : t('今日資料已到期。待補傳紀錄仍保留，請連線補傳。'));
      text('status', preparing ? t('正在準備離線資料與三語提示音，請稍候…') : localNotice ? t(localNotice.source) : state.message ? t(state.message) : (!state.online ? t('目前離線。暫存不等於打卡完成，請連線後補傳。') : state.prepared ? t('今日離線資料已備妥。') : t('請先準備今日離線資料。')));
      if (one('status')) one('status').dataset.state = localNotice?.tone || (!state.online ? 'offline' : state.blocked ? 'blocked' :
        !state.sync?.running && (state.sync?.errorCode || state.sync?.failed > 0) ? 'error' : 'online');
      text('queue-summary', state.sync?.running ? t('正在處理 {processed}/{total} 筆 · 已確認 {saved} 筆 · {seconds} 秒', { processed: state.sync.processed, total: state.sync.total, saved: state.sync.saved, seconds: state.sync.elapsed }) :
        state.blocked ? t('{pending} 筆待補傳，其中 {blocked} 筆需處理', { pending: state.pending, blocked: state.blocked }) : t('{pending} 筆待補傳', { pending: state.pending }));
      if (one('sync')) one('sync').disabled = uiSyncing || state.locked || !state.pending || state.sync?.running;
      if (one('cancel-sync')) one('cancel-sync').hidden = !state.sync?.running;
      if (one('prepare')) one('prepare').disabled = state.supported === false || preparing || !state.online || state.sync?.running;
      if (one('login')) {
        const action = one('login'), label = action.querySelector('[data-offline-account-action-label]');
        const source = signedIn ? '查看綁定狀態' : '登入帳號';
        action.hidden = !state.locked;
        action.href = signedIn ? '/devices' : '/login?next=/offline';
        action.setAttribute('aria-label', t(source));
        if (label) { label.dataset.i18n = source; if (label.textContent !== t(source)) label.textContent = t(source); }
      }
      if (one('empty')) one('empty').hidden = state.pending > 0;
      if (state.identity && !state.locked) {
        const arrival = root.PatrolVoice?.takeResult?.(state.identity.id);
        if (arrival) {
          const key = arrival.id.replace(/^(local|ack|blocked):/, '');
          const queued = state.queue.find(row => row.client_id === key && !row.stale_owner);
          const receipt = state.receipts.find(row => row.client_id === key);
          // The queue can be rejected or acknowledged by another tab between
          // leaving the form and opening this shell. Speak its current outcome.
          if (receipt) voice(['offline_stored', 'not_saved'].includes(arrival.kind) ? 'sync_confirmed' : arrival.kind, `ack:${key}`);
          else if (queued) voice(isBlocked(queued) ? 'not_saved' : 'offline_stored', `${isBlocked(queued) ? 'blocked' : 'local'}:${key}`);
        }
      }
      if (savedClientId && one('saved')) {
        const queued = state.queue.find(row => row.client_id === savedClientId && !row.stale_owner);
        const receipt = state.receipts.find(row => row.client_id === savedClientId);
        one('saved').hidden = !queued && !receipt;
        if (queued || receipt) {
          const blocked = !receipt && isBlocked(queued);
          one('saved').dataset.resultState = receipt ? 'saved' : blocked ? 'blocked' : 'pending';
          const previousVoice = root.PatrolVoice?.state().lastResult;
          // Another tab can acknowledge this UUID without a local sync click.
          // Keep replay consistent with its receipt, without auto-speaking or
          // replacing a newer result belonging to another point/action.
          if (!previousVoice || ['local', 'ack', 'blocked'].some(prefix => previousVoice.id === `${prefix}:${savedClientId}`)) {
            voice(receipt ? 'sync_confirmed' : blocked ? 'not_saved' : 'offline_stored', `${receipt ? 'ack' : blocked ? 'blocked' : 'local'}:${savedClientId}`, false);
          }
          const record = queued || receipt;
          const title = document.getElementById('offline-saved-title');
          if (title) title.textContent = receipt ? t('已同步完成') : blocked ? t('本筆未完成') : t('已暫存在這支手機');
          text('saved-message', receipt ? t('{code} · {slot} 已收到伺服器確認，可以繼續下一點。', { code: record.code, slot: slotText(record.slot) }) :
            blocked ? `${record.code} · ${slotText(record.slot)} · ${t(record.error || '本筆未完成')}` : pendingSaveMessage(record));
        }
      }
      const list = one('queue');
      const nextQueueSignature = JSON.stringify([state.queue, Boolean(state.sync?.running), root.PatrolI18n?.getLocale()]);
      // Keep a camera File's owning input attached while its bytes are being
      // verified and copied. Busy-state rendering must not replace that node.
      // Account locking/change takes priority over preserving private UI.
      const keepPhotoInput = list && photoReselection && list.contains(photoReselection.input) &&
        !state.locked && state.owner === photoReselection.owner;
      if (keepPhotoInput) {
        for (const action of list.querySelectorAll('button, input[type=file]')) action.disabled = Boolean(state.sync?.running) && action !== photoReselection.input;
      } else if (list && queueSignature !== nextQueueSignature) {
        queueSignature = nextQueueSignature;
        list.replaceChildren();
        for (const row of state.queue) {
          const item = document.createElement('li'); item.className = 'offline-queue-item';
          const heading = document.createElement('strong'); heading.textContent = `${row.code} · ${pointName(row.name, row.name_i18n)}`;
          const info = document.createElement('p'); info.textContent = `${stageText(row.stage)} · ${slotText(row.slot)} · ${timeText(row.observed_at)}`;
          const status = document.createElement('p'); status.className = row.error || row.status === 'blocked' ? 'offline-item-error' : 'offline-item-status';
          status.textContent = t(row.error || (row.checklist_review_required ? '這筆舊版暫存未記錄點檢勾選。可先同步核對是否已有收據；若被拒絕，請核對後明確刪除，再到現場重新掃描。' :
            row.execution_unconfirmed ? pendingExecutionHint : '已暫存此手機，尚未收到伺服器確認。'));
          const details = document.createElement('small'); details.textContent = `${row.is_abnormal ? t('異常回報') + ' · ' : ''}${t('{count} 張照片', { count: row.photo_count })}${row.note ? ' · ' + row.note : ''}`;
          const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button button-secondary button-small'; remove.disabled = state.sync?.running;
          remove.textContent = t('刪除本機紀錄'); remove.addEventListener('click', async () => {
            if (confirm(t('確定刪除 {code} 這筆本機資料與照片？\n若伺服器尚未收到，刪除後將無法補傳；已存在伺服器的紀錄不會被刪除。', { code: row.code }))) try { localNotice = null; await core.remove(row.client_id, true); } catch (error) { reportError(error); }
          });
          item.append(heading, info, status, details);
          if (row.checklist_snapshot && Array.isArray(row.checklist)) {
            const selected = new Set(row.checklist), snapshot = row.checklist_snapshot;
            const checklist = document.createElement('p'); checklist.className = 'offline-help';
            checklist.textContent = checklistLabel(snapshot.title) + ' · ' + (snapshot.items || []).filter(choice => selected.has(choice.id)).map(choice => checklistLabel(choice.label)).join('、');
            item.append(checklist);
          }
          const actions = document.createElement('div'); actions.className = 'offline-queue-actions';
          if (!row.stale_owner && row.stage === 'inspect' && row.photo_count > 0) {
            const repair = document.createElement('label'); repair.className = 'button button-secondary button-small offline-photo-repair';
            repair.textContent = t('重新選照片');
            const choose = document.createElement('input'); choose.type = 'file'; choose.multiple = true; choose.disabled = Boolean(state.sync?.running);
            choose.accept = 'image/jpeg,image/png,image/webp,image/heic,image/heif,.heic,.heif';
            choose.setAttribute('aria-label', t('為 {code} 重新選照片', { code: row.code }));
            choose.addEventListener('click', event => { if (photoReselection || uiSyncing || latestState?.sync?.running) event.preventDefault(); });
            choose.addEventListener('change', async () => {
              if (photoReselection || uiSyncing || latestState?.sync?.running || latestState?.owner !== state.owner) return;
              const files = Array.from(choose.files || []);
              if (!files.length) return;
              const repairPageEpoch = pageEpoch;
              const stillActive = () => pageActive && pageEpoch === repairPageEpoch && !latestState?.locked && latestState?.owner === state.owner;
              let repaired = false;
              try {
                validatePhotos(files);
                if (!confirm(t('為 {code} 更換 {count} 張照片並立即補傳這筆巡檢？\n原巡檢時間、備註、異常及點檢內容都會保留。若已有收據，會直接顯示結果。', { code: row.code, count: files.length }))) return;
                photoReselection = { input: choose, owner: state.owner, clientId: row.client_id };
                localNotice = null; queueNotice = null;
                const result = await core.repairPhotos(row.client_id, files, true);
                if (stillActive()) {
                  repaired = result.status === 'repaired';
                  if (!repaired) queueNotice = { source: latestState.message || '已同步完成' };
                }
              } catch (error) {
                if (stillActive()) queueNotice = { source: error.message || '操作未完成，原有資料仍保留。', clientId: row.client_id, error: true };
                else if (pageActive && pageEpoch === repairPageEpoch && latestState?.locked) queueNotice = { source: '請先連線登入原帳號，再補傳。', public: true, error: true };
              }
              finally {
                choose.value = '';
                if (photoReselection?.input === choose) photoReselection = null;
                if (latestState) render(latestState);
              }
              if (repaired && stillActive()) await syncQueue(row.client_id);
            });
            repair.append(choose); actions.append(repair);
          }
          const feedback = document.createElement('p'); feedback.className = 'offline-queue-feedback';
          feedback.dataset.offlineRowFeedback = row.client_id; feedback.setAttribute('role', 'status'); feedback.hidden = true;
          actions.append(remove); item.append(actions, feedback); list.append(item);
        }
      }
      updateQueueFeedback(state);
      showPoint().catch(reportError);
    }
    core.subscribe(render);
    function releasePreviews() { previewURLs.forEach(url => URL.revokeObjectURL(url)); previewURLs = []; one('photo-previews')?.replaceChildren(); }
    function resetPhotos() {
      releasePreviews(); selectedPhotos = []; photosInput?.setCustomValidity('');
      photosInput?.setAttribute('aria-invalid', 'false'); text('photo-status', '');
      if (one('clear-photos')) one('clear-photos').hidden = true;
    }
    function setPhotos(files) {
      const transfer = new DataTransfer(); files.forEach(file => transfer.items.add(file)); photosInput.files = transfer.files;
      if (photosInput.files.length !== files.length) throw new Error('File selection was not updated');
    }
    if (photosInput) {
      try {
        const probe = photosInput.cloneNode(false), transfer = new DataTransfer();
        transfer.items.add(new File(['x'], 'probe.jpg', { type: 'image/jpeg' })); probe.files = transfer.files;
        canEditPhotos = probe.files.length === 1;
      } catch { /* The native picker remains available on older mobile browsers. */ }
    }
    function renderPhotos() {
      if (!photosInput) return;
      releasePreviews(); const files = Array.from(photosInput.files); selectedPhotos = files;
      let error = '';
      try { validatePhotos(files); } catch (failure) { error = failure.message; }
      photosInput.setCustomValidity(t(error)); photosInput.setAttribute('aria-invalid', String(Boolean(error)));
      text('photo-status', error ? t(error) : (files.length ? t('已選 {count} 張，按 OK 後才會暫存。{hint}', { count: files.length, hint: canEditPhotos ? t('可繼續加入或移除照片。') : t('重新選取會取代目前照片。') }) : ''));
      if (one('clear-photos')) one('clear-photos').hidden = !files.length;
      files.slice(0, 6).forEach((file, index) => {
        const figure = document.createElement('figure'), caption = document.createElement('figcaption'); caption.textContent = file.name; caption.title = file.name;
        const placeholder = document.createElement('small'); placeholder.className = 'offline-photo-placeholder'; placeholder.textContent = t('無法預覽，請核對照片檔案');
        figure.append(placeholder);
        if (photoAllowed(file) && file.size > 0 && file.size <= 8 * 1024 * 1024) {
          const image = document.createElement('img'), url = URL.createObjectURL(file); previewURLs.push(url);
          image.alt = t('已選照片 {number}', { number: index + 1 }); image.onload = () => { placeholder.hidden = true; };
          image.onerror = () => { image.remove(); placeholder.hidden = false; };
          image.src = url; figure.prepend(image);
        }
        figure.append(caption);
        if (canEditPhotos) {
          const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button button-secondary button-small';
          remove.textContent = t('移除'); remove.setAttribute('aria-label', t('移除照片 {number}：{name}', { number: index + 1, name: file.name }));
          remove.addEventListener('click', () => {
            try { setPhotos(files.filter((_, current) => current !== index)); renderPhotos(); photosInput.focus(); }
            catch { canEditPhotos = false; renderPhotos(); text('photo-status', t('此瀏覽器不支援逐張移除，請清空後重新選擇。')); }
          }); figure.append(remove);
        }
        one('photo-previews')?.append(figure);
      });
    }
    photosInput?.addEventListener('change', () => {
      if (canEditPhotos && selectedPhotos.length) {
        try { setPhotos([...selectedPhotos, ...photosInput.files]); }
        catch { canEditPhotos = false; }
      }
      renderPhotos();
    });
    one('clear-photos')?.addEventListener('click', () => { photosInput.value = ''; renderPhotos(); photosInput.focus(); });
    form?.addEventListener('change', event => {
      if (event.target.name !== 'checklist' || !selectedSnapshot || form.hidden) return;
      const valid = showChecklist(selectedSnapshot.point, selectedSnapshot.expected);
      one('save').disabled = one('fields').disabled || !valid;
    });
    form?.addEventListener('reset', () => { resetPhotos(); setTimeout(() => showPoint().catch(reportError), 0); });
    form?.addEventListener('submit', async event => {
      event.preventDefault(); if (form.dataset.submitting === 'true' || form.hidden || !selectedSnapshot) return;
      localNotice = null;
      const checklist = new FormData(form).getAll('checklist');
      form.dataset.submitting = 'true'; const submit = one('save'); if (submit) submit.disabled = true;
      form.setAttribute('aria-busy', 'true');
      const caption = submit?.querySelector('[data-i18n]'), mark = submit?.querySelector('strong');
      if (caption) { caption.dataset.i18n = '正在暫存到這支手機…'; caption.textContent = t(caption.dataset.i18n); }
      if (mark) mark.hidden = true;
      const scanButtons = document.querySelectorAll('[data-qr-start]:enabled');
      for (const button of scanButtons) button.disabled = true;
      if (one('fields')) one('fields').disabled = true;
      const captureOwner = selectedSnapshot?.point.owner || selectedOwner;
      try {
        const row = await core.enqueue({ token: selectedToken, owner: captureOwner, expected: selectedSnapshot?.expected, checklist,
          note: form.elements.namedItem('note')?.disabled ? '' : form.elements.namedItem('note')?.value,
          is_abnormal: !form.elements.namedItem('is_abnormal')?.disabled && form.elements.namedItem('is_abnormal')?.checked,
          photos: photosInput?.disabled ? [] : photosInput?.files || [] });
        form.reset(); resetPhotos(); text('photo-status', ''); selectedToken = null; selectedSnapshot = null; savedClientId = row.client_id;
        if (latestState?.owner !== captureOwner) {
          if (one('saved')) one('saved').hidden = true;
          showNotice('本筆已暫存在手機。請連線登入原帳號後，到同步查看。', 'offline');
          return;
        }
        if (one('saved')) { one('saved').hidden = false; one('saved').dataset.resultState = 'pending'; }
        const savedTitle = document.getElementById('offline-saved-title');
        if (savedTitle) savedTitle.textContent = t('已暫存在這支手機');
        voice('offline_stored', `local:${row.client_id}`);
        text('saved-message', pendingSaveMessage(row));
        await showPoint(); one('saved')?.scrollIntoView({ block: 'nearest' });
      } catch (error) {
        if (error.code === 'checklist') { one('checklist')?.classList.add('is-invalid'); one('checklist-options')?.querySelector('input')?.focus(); }
        reportError(error); voiceFailure();
      }
      finally {
        delete form.dataset.submitting; form.removeAttribute('aria-busy');
        if (caption) { caption.dataset.i18n = '確認暫存打卡'; caption.textContent = t(caption.dataset.i18n); }
        if (mark) mark.hidden = false;
        for (const button of scanButtons) button.disabled = false;
        await showPoint().catch(reportError);
      }
    }, true);
    one('prepare')?.addEventListener('click', async () => {
      if (preparing) return;
      localNotice = null;
      preparing = true; const button = one('prepare'); button.disabled = true; button.setAttribute('aria-busy', 'true');
      try { if (latestState) render(latestState); await core.prepare(); } catch (error) { reportError(error); }
      finally { preparing = false; if (latestState) render(latestState); button.removeAttribute('aria-busy'); button.disabled = !latestState?.online || latestState?.sync?.running; if (!latestState?.prepared) refreshUIPreferences(); }
    });
    async function syncQueue(clientId, retryableOnly = false) {
      // Claim before the first await; a second click must not narrate the
      // core's still-running snapshot as a completed synchronization.
      if (uiSyncing || latestState?.sync?.running) return;
      uiSyncing = true; if (one('sync')) one('sync').disabled = true;
      queueNotice = { source: '正在檢查連線（最多 5 秒）', clientId };
      if (latestState) updateQueueFeedback(latestState);
      localNotice = null; const owner = latestState?.owner, syncPageEpoch = pageEpoch, before = new Set((latestState?.receipts || []).map(row => row.client_id));
      try {
        const state = await core.sync(retryableOnly ? { retryableOnly: true, expectedOwner: owner } : clientId ? { client_id: clientId } : {});
        if (!pageActive || syncPageEpoch !== pageEpoch) return;
        if (state.locked) {
          queueNotice = { source: state.storageUnavailable ? '手機離線儲存暫時無法使用；已保存的資料不會刪除，請重試。' : '請先連線登入原帳號，再補傳。', error: true, public: true };
          return;
        }
        if (state.owner !== owner || latestState?.owner !== owner) return;
        const row = clientId && state.queue.find(row => row.client_id === clientId);
        queueNotice = { source: (state.sync?.failed && row?.error) || state.message || '操作未完成，原有資料仍保留。',
          clientId: row ? clientId : null, savedPhotos: Boolean(row),
          error: Boolean(state.sync?.failed || state.sync?.errorCode || state.sync?.cancelled || !state.online || (state.pending && !state.sync?.saved)) };
        const fresh = state.receipts.filter(row => !before.has(row.client_id));
        if (fresh.length) voice(state.pending ? 'sync_partial' : 'sync_confirmed', `sync:${fresh.map(row => row.client_id).join(',').slice(0,145)}`);
        else if (state.pending && !retryableOnly) voice(!state.online || state.blocked || state.sync?.cancelled || state.sync?.failed || state.sync?.errorCode ? 'not_saved' : 'offline_stored', `retry:${Date.now()}:${++voiceSequence}`);
      } catch (error) {
        if (pageActive && syncPageEpoch === pageEpoch && latestState?.owner === owner) {
          queueNotice = { source: error.message || '操作未完成，原有資料仍保留。', clientId, savedPhotos: Boolean(clientId), error: true };
          if (!retryableOnly) voiceFailure();
        }
      }
      finally {
        uiSyncing = false;
        if (syncPageEpoch !== pageEpoch) queueNotice = null;
        if (latestState) render(latestState);
      }
    }
    let reconnectOwner = null, reconnectTimer, reconnectPaused = false;
    function clearReconnect() {
      clearTimeout(reconnectTimer);
      reconnectOwner = null;
    }
    function scheduleReconnect() {
      clearTimeout(reconnectTimer);
      if (!reconnectOwner || document.visibilityState === 'hidden' || !pageActive) return;
      reconnectTimer = setTimeout(() => {
        const owner = reconnectOwner;
        clearReconnect();
        if (!owner || reconnectPaused || !pageActive || document.visibilityState === 'hidden' || navigator.onLine === false ||
            latestState?.owner !== owner || latestState.locked || latestState.sync?.running || uiSyncing ||
            photoReselection || preparing || hasDraft()) return;
        if (latestState.queue.some(row => !row.stale_owner && !isBlocked(row))) syncQueue(undefined, true);
      }, 750);
    }
    one('sync')?.addEventListener('click', () => { clearReconnect(); reconnectPaused = false; syncQueue(); });
    one('cancel-sync')?.addEventListener('click', () => { clearReconnect(); reconnectPaused = true; core.cancelSync(); });
    one('close-point')?.addEventListener('click', () => {
      if (form?.dataset.submitting === 'true') return;
      if (draftPresent(form) && !confirm(t('離開點位會放棄尚未暫存的內容，確定離開？'))) return;
      localNotice = null; selectedToken = null; selectedSnapshot = null;
      root.PatrolVoice?.cancel(true);
      form?.reset(); resetPhotos();
      if (latestState) render(latestState); else showPoint().catch(reportError);
    });
    document.addEventListener('submit', async event => {
      const logout = event.target; if (!(logout instanceof HTMLFormElement) || new URL(logout.action, location.origin).pathname !== '/logout') return;
      event.preventDefault(); event.stopImmediatePropagation();
      if (logout.dataset.offlineLoggingOut === 'true') return;
      if (hasDraft() && !confirm(t('目前有尚未保存的內容，確定放棄並登出？'))) return;
      const buttons = [...logout.elements].filter(el => el instanceof HTMLButtonElement);
      const original = buttons.map(button => ({ button, disabled: button.disabled }));
      logout.dataset.offlineLoggingOut = 'true'; for (const button of buttons) button.disabled = true;
      try { await core.lock(); core.allowNavigation(); HTMLFormElement.prototype.submit.call(logout); }
      catch {
        let notice = document.querySelector('[data-offline-logout-error]');
        if (!notice) { notice = document.createElement('p'); notice.dataset.offlineLogoutError = ''; notice.className = 'flash flash-error'; notice.setAttribute('role', 'alert'); notice.tabIndex = -1; (document.querySelector('main') || body).prepend(notice); }
        notice.textContent = t('尚未登出：無法鎖定本機暫存，請重試登出。'); notice.focus();
      } finally { delete logout.dataset.offlineLoggingOut; for (const item of original) item.button.disabled = item.disabled; }
    }, true);
    document.addEventListener('submit', async event => {
      const normal = event.target;
      if (!(normal instanceof HTMLFormElement) || normal.id !== 'inspection-form') return;
      // A confirmed/local-saved form may remain visible after blocked
      // navigation or BFCache restore. Only its result link remains actionable.
      if (normal.dataset.offlineStored === 'true') { event.preventDefault(); event.stopImmediatePropagation(); return; }
      // Unprepared online forms retain the original server-rendered submission.
      if (!latestState?.prepared && navigator.onLine !== false) return;
      event.preventDefault(); event.stopImmediatePropagation();
      if (normal.dataset.offlineSaving === 'true') return;
      const value = name => normal.elements.namedItem(name)?.value || '';
      const target = new URL(normal.action, location.origin).pathname.replace(/\/confirm$/, '');
      const token = safePath(target)?.slice(3);
      const buttons = Array.from(normal.elements).filter(el => el instanceof HTMLButtonElement && el.type === 'submit');
      const saved = buttons.map(button => ({ button, disabled: button.disabled, content: button.innerHTML }));
      const controls = [...normal.elements].filter(el => ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName) && el.type !== 'hidden');
      const originalControls = controls.map(control => ({ control, disabled: control.disabled }));
      const captureOwner = latestState?.owner, capturePageEpoch = pageEpoch;
      let durableEntry, confirmedState, resultDestination, resultSkip, navigationAttempted = false, resultAbandoned = false;
      delete normal.dataset.offlineStored;
      normal.dataset.offlineSaving = 'true'; normal.dataset.submitting = 'true'; normal.setAttribute('aria-busy', 'true');
      for (const button of buttons) { button.disabled = true; button.textContent = t('正在保存／送出…'); }
      const panel = document.createElement('div'), progress = document.createElement('p'), cancel = document.createElement('button');
      panel.className = 'offline-submit-progress'; panel.tabIndex = -1;
      progress.dataset.offlineFormProgress = ''; progress.setAttribute('role', 'status'); progress.setAttribute('aria-live', 'polite');
      progress.textContent = t('正在保存到手機；請稍候…');
      cancel.type = 'button'; cancel.className = 'button button-secondary button-small'; cancel.dataset.offlineCancelSubmit = '';
      cancel.textContent = t('取消上傳，保留待傳'); cancel.disabled = true;
      cancel.addEventListener('click', () => {
        if (normal.dataset.offlineStored === 'true' && normal.dataset.offlineSaving !== 'true') {
          const sameOwner = latestState?.owner === captureOwner && !latestState?.locked;
          core.allowNavigation();
          try { location.assign(sameOwner && resultDestination ? resultDestination : '/offline'); } catch (_) {}
          return;
        }
        if (resultSkip) {
          try { root.PatrolVoice?.cancel?.(); } catch (_) {}
          resultSkip(); return;
        }
        cancel.disabled = true; core.cancelSync(); progress.textContent = t('正在停止上傳，紀錄仍保留在手機…');
      });
      panel.append(progress, cancel);
      const quickAction = normal.closest('.checkin-card')?.querySelector('.checkin-quick-action');
      if (quickAction) quickAction.after(panel); else normal.before(panel);
      normalProgress = { panel, status: progress, cancel, saving: true }; panel.scrollIntoView({ block: 'nearest' });
      normalProgress.abandon = () => {
        resultAbandoned = true;
        try { root.PatrolVoice?.cancel?.(); root.PatrolVoice?.clearResult?.(); } catch (_) {}
        resultSkip?.();
      };
      const finishSaved = async (kind, id, destination, reason = '') => {
        if (navigationAttempted) return;
        resultDestination = destination;
        normalProgress.result = true;
        panel.dataset.resultState = kind === 'not_saved' ? 'blocked' : kind === 'offline_stored' ? 'pending' : 'saved';
        progress.textContent = kind === 'not_saved' ? `${t('本筆未完成')}${reason ? ' · ' + t(reason) : ''}` : t(kind === 'offline_stored' ? '已暫存在這支手機' : '已同步完成');
        cancel.textContent = t('查看結果'); cancel.disabled = false;
        if (resultAbandoned || !pageActive || pageEpoch !== capturePageEpoch) { navigationAttempted = true; return; }
        const skip = new Promise(resolve => { resultSkip = resolve; });
        try { await voiceArrival(kind, id, destination, captureOwner, skip); }
        finally {
          resultSkip = null; navigationAttempted = true;
          const sameOwner = latestState?.owner === captureOwner && !latestState?.locked;
          if (!sameOwner) {
            try { root.PatrolVoice?.cancel?.(true); root.PatrolVoice?.clearResult?.(); } catch (_) {}
          }
          if (resultAbandoned || !pageActive || pageEpoch !== capturePageEpoch) return;
          core.allowNavigation();
          // A browser navigation failure is not a failed save. Do not fall into
          // the durable-save catch and route or announce the same record twice.
          try { location.assign(sameOwner ? destination : '/offline'); } catch (_) {}
        }
      };
      const showSavedOutcome = (entry, state) => {
        const fallback = '/offline?queued=' + encodeURIComponent(entry.client_id);
        const receipt = state?.owner === captureOwner && state.receipts.find(item => item.client_id === entry.client_id);
        const row = state?.owner === captureOwner && state.queue.find(item => item.client_id === entry.client_id);
        if (receipt) {
          const url = receipt.ack?.receipt_url;
          const destination = typeof url === 'string' && /^\/(?:checkins|executions)\/[0-9]+(?:\/success)?(?:\?[^#]*)?$/.test(url) ? url : fallback;
          return finishSaved(receipt.stage === 'execute' ? 'saved_execute' : receipt.stage === 'visit' ? 'saved_visit' : 'saved_inspect', `ack:${entry.client_id}`, destination);
        }
        return finishSaved(isBlocked(row) ? 'not_saved' : 'offline_stored', `${isBlocked(row) ? 'blocked' : 'local'}:${entry.client_id}`, fallback, row?.error);
      };
      try {
        const input = { token, note: value('note'), is_abnormal: Boolean(normal.elements.namedItem('is_abnormal')?.checked), checklist: new FormData(normal).getAll('checklist'),
          photos: normal.elements.namedItem('photos')?.files || [], expected: { user_id: body.dataset.offlineUser, auth_version: body.dataset.offlineVersion,
            day: value('personal_day'), slot: value('slot'), stage: value('stage'),
            frequency: value('frequency'), workflow_mode: value('workflow_mode'), period_key: value('period_key'), revision: value('point_revision') } };
        for (const control of controls) control.disabled = true;
        const entry = durableEntry = await core.enqueue(input);
        // Files are cleared only after the atomic local write has completed.
        normal.dataset.offlineStored = 'true'; normal.reset();
        // A server-returned validation draft can have defaultChecked=true.
        // Native reset restores those defaults, but a saved round must not
        // leave its previous selection ready to submit again.
        normal.querySelectorAll('input[type="checkbox"][name="checklist"]').forEach(choice => { choice.checked = false; });
        normalProgress.saving = false;
        if (latestState?.owner !== captureOwner) { await finishSaved('offline_stored', `local:${entry.client_id}`, '/offline'); return; }
        if (navigator.onLine !== false) confirmedState = await core.sync({ client_id: entry.client_id });
        const updated = confirmedState = await core.getState();
        if (updated.owner !== captureOwner) { await finishSaved('offline_stored', `local:${entry.client_id}`, '/offline'); return; }
        await showSavedOutcome(entry, updated);
      } catch (error) {
        if (durableEntry) { await showSavedOutcome(durableEntry, confirmedState || latestState); return; }
        let notice = normal.parentElement.querySelector('[data-offline-form-error]');
        if (!notice) { notice = document.createElement('p'); notice.dataset.offlineFormError = ''; notice.className = 'flash flash-error'; notice.setAttribute('role', 'alert'); notice.tabIndex = -1; normal.before(notice); }
        notice.textContent = t(error.message || '無法保存，原本的備註與照片仍保留在表單中。'); notice.focus();
        voiceFailure();
      } finally {
        normalProgress = null;
        if (!durableEntry || latestState?.owner !== captureOwner || latestState?.locked) panel.remove();
        else savedResultPanels.set(panel, captureOwner);
        delete normal.dataset.offlineSaving; delete normal.dataset.submitting; normal.removeAttribute('aria-busy');
        for (const item of saved) { item.button.disabled = item.disabled; item.button.innerHTML = item.content; }
        for (const item of originalControls) item.control.disabled = item.disabled;
        // A durable save resets the form before attempting navigation. If the
        // browser keeps this page open, restore checklist gating after the
        // busy-state controls so an empty selection never looks ready again.
        root.PatrolChecklist?.refresh(normal);
        if (durableEntry) {
          // The old form represents an immutable saved UUID. Retain a visible
          // result entry if navigation failed; SCAN remains available because
          // submitting/offlineSaving have both been cleared above.
          for (const item of saved) item.button.disabled = true;
          for (const item of originalControls) item.control.disabled = true;
        }
      }
    }, true);
    document.addEventListener('click', event => {
      if (!normalProgress?.result || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
      const link = event.target.closest?.('a[href]');
      if (!link || link.hasAttribute('download') || link.target && link.target !== '_self') return;
      const target = new URL(link.href, location.href);
      if (target.origin === location.origin && target.pathname === location.pathname && target.search === location.search && target.hash) return;
      // The record is already safe. Respect a deliberate Home/other-page click
      // instead of replacing that navigation with a delayed receipt redirect.
      normalProgress.abandon?.();
    });
    window.addEventListener('online', () => {
      if (localNotice?.tone === 'offline') localNotice = null;
      if (shell && !reconnectPaused) {
        reconnectOwner = latestState?.owner;
        scheduleReconnect();
      }
      core.getState().then(refreshUIPreferences).catch(reportError);
    });
    document.addEventListener('visibilitychange', scheduleReconnect);
    window.addEventListener('offline', () => { clearReconnect(); uiSessionKnown = null; cancelUIPreferences(); core.cancelSync(); core.getState().catch(reportError); });
    window.addEventListener('pageshow', event => {
      pageActive = true; navigationAllowed = false; renderPhotos();
      core.getState().then(() => { if (event.persisted) refreshUIPreferences(); }).catch(() => {});
    });
    window.addEventListener('pagehide', () => {
      clearReconnect(); pageActive = false; ++pageEpoch; normalProgress?.abandon?.();
      uiSessionKnown = null; cancelUIPreferences(); releasePreviews();
    });
    document.addEventListener('patrol:locale-changed', () => { if (!updatingLocale && latestState) { render(latestState); renderPhotos(); } });
    (async () => {
      try {
        if (shell) { await core.getState(); await showPoint(); refreshUIPreferences(); return; }
        if (body.dataset.offlineWorkspace !== 'true' || !body.dataset.offlineUser) { await core.lock(); return; }
        await core.matchIdentity(body.dataset.offlineUser, body.dataset.offlineVersion);
      } finally { delete body.dataset.offlineHydrating; if (shell && scanVoicePending) showPoint().catch(reportError); }
      if (navigator.onLine !== false) await core.prepare({ id: body.dataset.offlineUser, version: body.dataset.offlineVersion });
    })().catch(error => { if (shell) reportError(error); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready); else ready();
})(typeof window !== 'undefined' ? window : globalThis);
