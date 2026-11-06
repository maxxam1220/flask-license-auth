/* Local check-ins remain pending until the server acknowledges their immutable ID. */
(function (root) {
  'use strict';
  const DB_NAME = 'patrol-offline-v1';
  const STORES = ['meta', 'manifests', 'queue', 'receipts'];
  const MAX_QUEUE_BYTES = 256 * 1024 * 1024;
  const MAX_QUEUE_ITEMS = 200;
  const PHOTO_TYPES = new Set(['image/jpeg', 'image/jpg', 'image/pjpeg', 'image/png', 'image/x-png', 'image/webp', 'image/heic', 'image/heif']);
  const isToken = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(value);
  const fault = (code, message) => Object.assign(new Error(message), { code });
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
  function createCore(options = {}) {
    const env = options.env || root;
    const idb = options.indexedDB || env.indexedDB;
    const now = options.now || (() => Date.now());
    const uuid = () => (options.crypto || env.crypto).randomUUID();
    const fetcher = options.fetch || env.fetch?.bind(env);
    const timers = options.timers || env;
    const navigator = options.navigator || env.navigator || {};
    const connectTimeout = options.connectTimeout || 5000;
    const uploadTimeout = options.uploadTimeout || 30000;
    const listeners = new Set();
    const tabId = uuid();
    let dbPromise, state = { locked: true, prepared: false, queue: [], receipts: [], pending: 0, blocked: 0, online: navigator.onLine !== false };
    let epoch = 0, syncController, syncing = false, cancelled = false, syncState = {}, message = '';
    const requests = new Set();
    const abortRequests = () => { for (const controller of requests) controller.abort(); };
    let channel;
    if (options.broadcast !== false && env.BroadcastChannel) {
      channel = new env.BroadcastChannel('patrol-offline-state-v1');
      channel.onmessage = event => { if (event.data?.type === 'lock') { epoch++; abortRequests(); } refresh().catch(() => {}); };
    }
    function announce() {
      for (const fn of listeners) { try { fn(state); } catch (_) { /* One UI subscriber cannot interrupt persistence. */ } }
      if (env.dispatchEvent && env.CustomEvent) env.dispatchEvent(new env.CustomEvent('patrol:offline-state', { detail: state }));
    }
    function broadcast(type = 'change') { channel?.postMessage({ type }); }
    function database() {
      if (!idb) return Promise.reject(fault('storage', '此瀏覽器無法使用離線儲存，請在線上打卡。'));
      if (!dbPromise) dbPromise = new Promise((resolve, reject) => {
        const request = idb.open(options.databaseName || DB_NAME, 1);
        request.onupgradeneeded = () => {
          const db = request.result;
          for (const name of STORES) db.createObjectStore(name, { keyPath: name === 'meta' ? 'key' : name === 'manifests' ? 'owner' : 'client_id' });
        };
        request.onsuccess = () => { const db = request.result; db.onversionchange = () => db.close(); resolve(db); };
        request.onerror = () => { dbPromise = null; reject(fault('storage', '無法開啟手機儲存空間，請檢查瀏覽器設定或改用線上打卡。')); };
        request.onblocked = () => { dbPromise = null; reject(fault('storage', '請關閉其他舊版巡檢分頁，再重試。')); };
      });
      return dbPromise;
    }
    async function transaction(names, mode, work) {
      const db = await database();
      return new Promise((resolve, reject) => {
        const tx = db.transaction(names, mode); let result, failure;
        tx.oncomplete = () => resolve(result);
        tx.onabort = () => reject(failure || fault('storage', tx.error?.name === 'QuotaExceededError' ?
          '手機儲存空間不足，這筆尚未保存。請先補傳既有紀錄；原表單與照片仍保留。' : '離線資料未能保存，原表單與照片仍保留，請重試。'));
        tx.onerror = () => { /* onabort is authoritative; partial writes are never reported saved. */ };
        const done = value => { result = value; };
        const fail = error => { failure = error; tx.abort(); };
        try { work(tx, done, fail); } catch (error) { fail(error); }
      });
    }
    function readAll(tx, callback) {
      const result = {}, names = STORES; let remaining = names.length;
      for (const name of names) {
        const request = tx.objectStore(name).getAll();
        request.onsuccess = () => { result[name] = request.result; if (!--remaining) {
          try { callback(result); } catch (_) { tx.abort(); }
        } };
      }
    }
    function current(data) {
      const active = data.meta.find(item => item.key === 'active');
      const manifest = active && !active.locked ? data.manifests.find(item => item.owner === active.owner) : null;
      return { active, manifest };
    }
    const fresh = manifest => Boolean(manifest && now() + manifest.offset_ms < Date.parse(manifest.capture_until) &&
      now() + manifest.offset_ms >= Date.parse(manifest.server_time) - 60000);
    function usedSlots(manifest, point, data) {
      return new Set([...(point.used_slots || []), ...data.queue, ...data.receipts]
        .filter(item => typeof item === 'string' || (item.owner === manifest.owner && item.day === manifest.day && item.token === point.token))
        .map(item => typeof item === 'string' ? item : item.slot));
    }
    const summary = row => ({ client_id: row.client_id, token: row.token, code: row.code, name: row.name, stage: row.stage, slot: row.slot,
      day: row.day, observed_at: row.observed_at, status: row.status, error: row.error || '', retryable: row.retryable,
      note: row.note, is_abnormal: row.is_abnormal, photo_count: row.photos?.length || 0, attempts: row.attempts || 0 });
    async function refresh() {
      const snapshot = await transaction(STORES, 'readonly', (tx, done) => readAll(tx, done));
      const { active, manifest } = current(snapshot);
      const owned = manifest ? snapshot.queue.filter(row => row.owner === manifest.owner || row.user_id === manifest.identity.id)
        .sort((a, b) => a.created_ms - b.created_ms || (a.sequence || 0) - (b.sequence || 0) || a.client_id.localeCompare(b.client_id)) : [];
      const queue = owned.map(row => row.owner === manifest.owner ? summary(row) : { ...summary(row), stale_owner: true, status: 'blocked', retryable: false,
        error: '原登入版本或手機綁定已變更。此筆保留供處理，不會使用新授權補傳；請聯絡管理員。' });
      state = { locked: !manifest || Boolean(active?.locked), prepared: fresh(manifest), identity: manifest?.identity || null,
        owner: manifest?.owner || null, revision: active?.revision || 0, day: manifest?.day || '', captureUntil: manifest?.capture_until || '', syncUntil: manifest?.sync_until || '',
        online: navigator.onLine !== false, pending: queue.length, blocked: queue.filter(row => row.status === 'blocked').length,
        queue, receipts: manifest ? snapshot.receipts.filter(row => row.owner === manifest.owner).map(row => ({ ...row, photos: undefined })) : [],
        sync: { ...syncState, running: syncing }, message };
      announce(); return state;
    }
    async function lock(reason = '', expected = null) {
      const applied = await transaction(['meta', 'manifests'], 'readwrite', (tx, done) => {
        const store = tx.objectStore('meta'), request = store.get('active');
        request.onsuccess = () => {
          if ((expected?.owner && request.result?.owner !== expected.owner) ||
              (expected?.revision !== undefined && (request.result?.revision || 0) !== expected.revision)) return done(false);
          store.put({ key: 'active', locked: true, owner: null, revision: (request.result?.revision || 0) + 1 });
          tx.objectStore('manifests').clear(); done(true); };
      });
      if (applied) { epoch++; abortRequests(); message = reason; cancelled = true; broadcast('lock'); }
      return refresh();
    }
    async function network(url, init = {}, timeout = connectTimeout) {
      if (navigator.onLine === false) throw fault('offline', '目前沒有網路，資料仍保留在此手機。');
      const aborter = new env.AbortController(), isSync = url !== '/api/offline/prepare';
      requests.add(aborter); if (isSync) syncController = aborter;
      const timer = timers.setTimeout(() => aborter.abort(), timeout);
      try {
        const response = await fetcher(url, { ...init, signal: aborter.signal, credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
        let json;
        try { json = await response.json(); } catch (error) {
          if (error.name === 'AbortError') throw error;
          throw fault('response', '伺服器回應無法確認，資料仍保留，請重試。');
        }
        return { response, json };
      } catch (error) {
        if (error.name === 'AbortError') throw fault(isSync && cancelled ? 'cancelled' : 'timeout', isSync && cancelled ? '已停止補傳，尚未確認的資料仍保留。' : '連線逾時，資料仍保留，請重試。');
        throw error;
      } finally { timers.clearTimeout(timer); requests.delete(aborter); if (syncController === aborter) syncController = null; }
    }
    function validManifest(value) {
      return value?.ok === true && value.version === 1 && typeof value.owner === 'string' && value.owner.length <= 300 && value.identity &&
        Number.isInteger(value.identity.id) && Number.isInteger(value.identity.auth_version) && Number.isInteger(value.identity.binding_id) &&
        /^\d{4}-\d{2}-\d{2}$/.test(value.day) && Number.isFinite(Date.parse(value.server_time)) && Number.isFinite(Date.parse(value.capture_until)) &&
        Number.isFinite(Date.parse(value.sync_until)) && typeof value.csrf_token === 'string' && Array.isArray(value.points) &&
        value.points.every(p => isToken(p.token) && typeof p.grant === 'string' && typeof p.revision === 'string' && ['execute', 'inspect', 'visit'].includes(p.stage) &&
          Array.isArray(p.slots) && p.slots.length > 0 && p.slots.every(slot => ['any', 'am', 'pm'].includes(slot)) && Array.isArray(p.used_slots));
    }
    async function prepare(expectedIdentity) {
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
        throw fault(json?.code || 'prepare', json?.message || '無法準備離線資料，請先確認登入與手機綁定。');
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
        request.onsuccess = () => {
          if ((request.result?.revision || 0) !== revision) return fail(fault('owner', '帳號狀態已變更，請重新準備。'));
          tx.objectStore('manifests').put(manifest);
          store.put({ key: 'active', owner: manifest.owner, locked: false, revision: revision + 1 }); done(true);
        };
      });
      message = '今日離線資料已備妥。未上傳的紀錄只保留在這支手機。';
      if (!syncing) syncState = {};
      broadcast(); return refresh();
    }
    async function getPoint(token) {
      return transaction(STORES, 'readonly', (tx, done) => readAll(tx, data => {
        const { manifest } = current(data), point = manifest?.points.find(item => item.token === token);
        if (!point) return done(null);
        const used = usedSlots(manifest, point, data);
        done({ ...point, owner: manifest.owner, identity: manifest.identity, availableSlots: point.slots.filter(slot => !used.has(slot) && !used.has('any')), prepared: fresh(manifest), day: manifest.day,
          waitingExecution: point.stage === 'inspect' && point.workflow_mode === 'two_stage' });
      }));
    }
    async function enqueue(input) {
      const photos = Array.from(input.photos || []); validatePhotos(photos);
      const note = String(input.note || '').replace(/\r\n?/g, '\n').trim();
      if (note.length > 2000) throw fault('note', '巡檢備註最多 2,000 字。');
      const client_id = uuid(), captured_device_at = new Date(now()).toISOString();
      const saved = await transaction(STORES, 'readwrite', (tx, done, fail) => readAll(tx, data => {
        const { manifest } = current(data);
        if (!manifest) return fail(fault('locked', '請先連線登入，準備今日離線資料。'));
        if (input.owner && input.owner !== manifest.owner) return fail(fault('owner', '帳號或手機綁定已變更，請重新開啟點位。'));
        if (!fresh(manifest)) return fail(fault('expired', '今日離線資料已到期，請連線重新準備。原有待補傳資料仍保留。'));
        const point = manifest.points.find(item => item.token === input.token);
        if (!point) return fail(fault('point', '此點不在本帳號的離線清單中，請連線更新。'));
        if (input.expected && (String(input.expected.user_id) !== String(manifest.identity.id) || String(input.expected.auth_version) !== String(manifest.identity.auth_version) ||
          input.expected.day !== manifest.day || input.expected.stage !== point.stage ||
          input.expected.frequency !== point.frequency || input.expected.workflow_mode !== point.workflow_mode ||
          input.expected.period_key !== point.period_key || input.expected.revision !== point.revision || !point.slots.includes(input.expected.slot))) {
          return fail(fault('stale', '這份打卡表單的日期、階段或點位設定已變更，請重新掃描。原內容尚未送出。'));
        }
        if (point.stage !== 'inspect' && (note || input.is_abnormal || photos.length)) return fail(fault('stage', '執行與直接簽到只記錄人員、點位與時間。'));
        const used = usedSlots(manifest, point, data);
        const slot = point.slots.find(item => !used.has(item) && !used.has('any'));
        if (!slot) return fail(fault('quota', '此點今日可登記的次數已完成或已暫存。'));
        if (input.expected && input.expected.slot !== slot) return fail(fault('stale', '這份表單的次數已完成或已暫存，請重新掃描下一次；不會自動改成另一個次數。'));
        const usedBytes = data.queue.reduce((total, item) => total + (item.photos || []).reduce((size, photo) => size + photo.size, 0), 0);
        if (data.queue.length >= MAX_QUEUE_ITEMS || usedBytes + photos.reduce((total, photo) => total + photo.size, 0) > MAX_QUEUE_BYTES) {
          return fail(fault('storage', '待補傳資料已達本機上限（200 筆或 256 MB 照片），請先補傳既有紀錄。這筆原表單與照片仍保留。'));
        }
        const sequence = (data.meta.find(item => item.key === 'sequence')?.value || 0) + 1;
        const row = { client_id, sequence, owner: manifest.owner, user_id: manifest.identity.id, auth_version: manifest.identity.auth_version,
          binding_id: manifest.identity.binding_id, token: point.token, grant: point.grant, slot,
          observed_at: new Date(now() + manifest.offset_ms).toISOString(), captured_device_at, note, is_abnormal: Boolean(input.is_abnormal),
          photos: photos.map(file => ({ blob: file, name: file.name || 'photo.jpg', type: file.type, size: file.size })),
          day: manifest.day, sync_until: manifest.sync_until, created_ms: now(), code: point.code, name: point.name,
          stage: point.stage, frequency: point.frequency, period_key: point.period_key, status: 'pending', retryable: true, attempts: 0 };
        tx.objectStore('meta').put({ key: 'sequence', value: sequence }); tx.objectStore('queue').add(row); done(summary(row));
      }));
      message = '已暫存此手機，尚未上傳。請保持頁面開啟，連線後按「同步待傳紀錄」。';
      if (!syncing) syncState = {};
      broadcast(); await refresh(); return saved;
    }
    async function remove(client_id, confirmation) {
      if (confirmation !== true) throw fault('confirm', '刪除本機紀錄需要明確確認。');
      if (syncing) throw fault('busy', '請先停止補傳，再刪除本機紀錄。');
      await transaction(STORES, 'readwrite', (tx, done, fail) => readAll(tx, data => {
        const { manifest } = current(data), row = data.queue.find(item => item.client_id === client_id);
        const lease = data.meta.find(item => item.key === 'sync');
        if (lease?.until > now()) return fail(fault('busy', '其他分頁正在補傳，請稍後再刪除。'));
        if (!manifest || !row || (row.owner !== manifest.owner && row.user_id !== manifest.identity.id)) return fail(fault('owner', '無法操作其他帳號的本機資料。'));
        tx.objectStore('queue').delete(client_id); done(true);
      }));
      message = '已刪除這筆尚未確認的本機資料。'; syncState = {}; broadcast(); return refresh();
    }
    async function lease(owner, release = false) {
      return transaction(['meta'], 'readwrite', (tx, done) => {
        const store = tx.objectStore('meta'), request = store.get('sync');
        request.onsuccess = () => {
          const previous = request.result;
          if (release) { if (previous?.tab === tabId) store.delete('sync'); done(true); }
          else if (!previous || previous.until < now() || previous.tab === tabId) { store.put({ key: 'sync', tab: tabId, owner, until: now() + uploadTimeout + 15000 }); done(true); }
          else done(false);
        };
      });
    }
    async function ownedEntry(client_id, owner, mutation) {
      return transaction(STORES, 'readwrite', (tx, done, fail) => readAll(tx, data => {
        const { manifest } = current(data), row = data.queue.find(item => item.client_id === client_id);
        if (!manifest || manifest.owner !== owner || row?.owner !== owner) return fail(fault('owner', '帳號已變更，已停止補傳。'));
        if (mutation) mutation(tx, row); done(row);
      }));
    }
    async function synchronize(selection = {}) {
      if (syncing) return state;
      if (navigator.onLine === false) { message = '目前沒有網路，資料仍保留在此手機。'; return refresh(); }
      // Claim synchronously: two clicks can otherwise both pass the guard
      // while their first IndexedDB reads are still in flight.
      syncing = true; cancelled = false; const started = now();
      let owner, revision, leaseHeld = false; const startEpoch = epoch;
      syncState = { total: state.pending, processed: 0, saved: 0, failed: 0, elapsed: 0, current: '', phase: 'checking', cancelled: false };
      const ticker = timers.setInterval(() => { syncState.elapsed = Math.floor((now() - started) / 1000); state = { ...state, sync: { ...syncState, running: syncing } }; announce(); }, 1000);
      try {
        await refresh();
        owner = state.owner; revision = state.revision;
        if (!owner || state.locked) throw fault('locked', '請先連線登入原帳號，再補傳。');
        leaseHeld = await lease(owner);
        if (!leaseHeld) throw fault('busy', '另一個分頁正在補傳，請稍候。');
        if (cancelled || epoch !== startEpoch) throw fault('cancelled', '已停止補傳，尚未確認的資料仍保留。');
        const status = await network('/api/offline/status');
        if (!status.response.ok || status.json?.ok !== true || status.json.owner !== owner || typeof status.json.csrf_token !== 'string') {
          if ([401, 403].includes(status.response.status) || (status.response.ok && status.json?.ok === true && status.json.owner !== owner)) {
            await lock('登入或手機綁定已變更，請用原帳號重新登入後補傳。', { owner, revision });
            throw fault('owner', '登入或手機綁定已變更，待補傳資料仍保留。');
          }
          throw fault('response', '目前無法確認伺服器連線，暫存與離線準備仍保留；請稍後重試。');
        }
        const ids = state.queue.filter(row => !row.stale_owner && (!selection.client_id || row.client_id === selection.client_id)).map(row => row.client_id);
        syncState.total = ids.length;
        for (const id of ids) {
          if (cancelled || epoch !== startEpoch) break;
          if (!await lease(owner)) break;
          const row = await ownedEntry(id, owner, (tx, item) => { item.status = 'pending'; item.attempts++; tx.objectStore('queue').put(item); });
          syncState.current = row.code; syncState.phase = 'uploading'; await refresh();
          if (cancelled || epoch !== startEpoch) break;
          const Form = options.FormData || env.FormData, body = new Form();
          body.append('entry', JSON.stringify({ client_id: row.client_id, owner: row.owner, token: row.token, grant: row.grant, slot: row.slot,
            observed_at: row.observed_at, note: row.note, is_abnormal: row.is_abnormal }));
          for (const photo of row.photos) body.append('photos', photo.blob, photo.name);
          try {
            const { response, json } = await network('/api/offline/sync', { method: 'POST', headers: { 'X-CSRF-Token': status.json.csrf_token }, body }, uploadTimeout);
            const acknowledged = response.ok && json?.ok === true && ['saved', 'already_synced'].includes(json.status) && json.client_id === id;
            if (acknowledged) {
              // ACK is durable together with removal. Losing this transaction safely retries the same UUID.
              await transaction(['queue', 'receipts'], 'readwrite', (tx, done) => {
                const request = tx.objectStore('queue').get(id);
                request.onsuccess = () => {
                  if (request.result?.owner === owner) {
                    tx.objectStore('receipts').put({ client_id: id, owner, token: row.token, slot: row.slot, day: row.day,
                      code: row.code, name: row.name, stage: row.stage, observed_at: row.observed_at, ack: json, received_ms: now() });
                    tx.objectStore('queue').delete(id);
                  }
                  done(true);
                };
              });
              syncState.saved++;
            } else {
              const reason = json?.message || '伺服器未確認這筆紀錄，資料仍保留，請重試。';
              // A single point can reject an otherwise authorized inspector
              // (for example, reviewing their own earlier execution). Keep
              // other points available instead of discarding the manifest.
              if (response.status === 401 || (response.status === 403 && json?.code !== 'forbidden')) {
                await lock(reason, { owner, revision }); throw fault('owner', reason);
              }
              const retryable = response.status >= 500 || json?.retryable !== false || json?.ok === true;
              await ownedEntry(id, owner, (tx, item) => { item.status = retryable ? 'retry' : 'blocked'; item.error = reason; item.retryable = retryable; tx.objectStore('queue').put(item); });
              syncState.failed++;
            }
          } catch (error) {
            if (epoch !== startEpoch || error.code === 'owner') throw error;
            await ownedEntry(id, owner, (tx, item) => { item.status = 'retry'; item.error = error.message || '連線失敗，資料仍保留。'; item.retryable = true; tx.objectStore('queue').put(item); });
            syncState.failed++;
            if (['timeout', 'cancelled', 'offline'].includes(error.code) || error instanceof TypeError) { syncState.processed++; break; }
          }
          syncState.processed++; broadcast(); await refresh();
        }
        message = cancelled ? '已停止補傳，尚未確認的資料仍保留。' : `已確認 ${syncState.saved} 筆；其餘未確認資料仍保留在此手機。`;
      } catch (error) {
        message = error.message || '無法連線，待補傳資料仍保留。';
        if (!cancelled && !['cancelled', 'busy'].includes(error.code)) syncState.errorCode = error.code || 'network';
      }
      finally {
        syncing = false; syncState.cancelled = cancelled; syncState.phase = 'idle'; timers.clearInterval(ticker);
        if (leaseHeld) await lease(owner, true);
        broadcast(); await refresh();
      }
      return state;
    }
    function cancelSync() { cancelled = true; syncController?.abort(); }
    async function route(value) {
      const path = safePath(value); if (!path) throw fault('point', '這不是本站的巡檢點網址。');
      return navigator.onLine === false ? '/offline?point=' + encodeURIComponent(path.slice(3)) : path;
    }
    return { prepare, getState: refresh, getPoint, enqueue, sync: synchronize, lock, remove, route, cancelSync,
      subscribe(fn) { listeners.add(fn); fn(state); return () => listeners.delete(fn); },
      async close() { channel?.close(); const db = await dbPromise; db?.close(); },
      async matchIdentity(id, version) { await refresh(); if (state.identity && (String(state.identity.id) !== String(id) || String(state.identity.auth_version) !== String(version))) await lock('帳號已變更，請重新準備離線資料。'); return state; } };
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { createCore, validatePhotos, safePath };
  if (!root.document) return;

  let shellPromise;
  async function ensureShell() {
    if (!root.isSecureContext || !navigator.serviceWorker) throw fault('support', '此瀏覽器無法啟用離線頁面，請使用 HTTPS 網址與支援的瀏覽器。');
    if (!shellPromise) shellPromise = (async () => {
      const registration = await navigator.serviceWorker.register('/offline-sw.js', { scope: '/', updateViaCache: 'none' });
      let readyTimer;
      try { await Promise.race([navigator.serviceWorker.ready, new Promise((_, reject) => { readyTimer = setTimeout(() => reject(fault('shell', '離線頁面準備逾時，請連線後再試。')), 15000); })]); }
      finally { clearTimeout(readyTimer); }
      const worker = registration.active || (await navigator.serviceWorker.ready).active;
      await new Promise((resolve, reject) => {
        const channel = new MessageChannel(), timer = setTimeout(() => reject(fault('shell', '離線頁面尚未備妥，請重試。')), 5000);
        channel.port1.onmessage = event => { clearTimeout(timer); channel.port1.close(); event.data?.ready ? resolve() : reject(fault('shell', '離線頁面檔案不完整，請重試。')); };
        worker.postMessage({ type: 'PATROL_OFFLINE_READY' }, [channel.port2]);
      });
      navigator.storage?.persist?.().catch(() => {});
    })().catch(error => { shellPromise = null; throw error; });
    return shellPromise;
  }
  const core = createCore({ ensureShell }); root.PatrolOffline = core;
  function ready() {
    const body = document.body, shell = body.hasAttribute('data-offline-shell');
    const all = hook => [...document.querySelectorAll(`[data-offline-${hook}]`)];
    const one = hook => document.querySelector(`[data-offline-${hook}]`);
    const text = (hook, value) => all(hook).forEach(el => { el.textContent = value; });
    const query = new URLSearchParams(location.search);
    let selectedToken = query.get('point') || safePath(location.pathname)?.slice(3), savedClientId = query.get('queued'),
      pointGeneration = 0, previewURLs = [], selectedOwner, viewOwner, selectedSnapshot, normalProgress;
    const form = one('checkin'), photosInput = form?.elements.namedItem('photos');
    const slotText = slot => slot === 'am' ? '第 1 次' : slot === 'pm' ? '第 2 次' : '本次';
    const stageText = stage => ({ execute: '執行簽到', inspect: '巡檢', visit: '直接簽到' }[stage] || '巡檢');
    const timeText = iso => { try { return new Date(iso).toLocaleString('zh-TW', { timeZone: 'Asia/Taipei', hour12: false }); } catch { return iso; } };
    const reportError = error => { text('status', error.message || '操作未完成，原有資料仍保留。'); if (one('status')) one('status').dataset.state = 'error'; one('status')?.focus(); };
    async function showPoint() {
      const run = ++pointGeneration, section = one('point'); if (!section) return;
      const point = selectedToken ? await core.getPoint(selectedToken) : null;
      if (run !== pointGeneration) return;
      section.hidden = !selectedToken;
      if (!selectedToken) return;
      selectedOwner = point?.owner;
      if (point && !selectedSnapshot) selectedSnapshot = { point, expected: { user_id: point.identity.id, auth_version: point.identity.auth_version,
        day: point.day, slot: point.availableSlots[0], stage: point.stage, frequency: point.frequency, workflow_mode: point.workflow_mode,
        period_key: point.period_key, revision: point.revision } };
      const displayed = selectedSnapshot?.point || point;
      const expected = selectedSnapshot?.expected;
      const unchanged = point && expected && point.owner === selectedSnapshot.point.owner && point.revision === expected.revision && point.day === expected.day;
      const eligible = point?.prepared && unchanged && point.availableSlots.includes(expected.slot);
      text('point-code', displayed?.code || '尚未取得點位'); text('point-name', displayed?.name || '請連線登入並準備今日離線資料。');
      text('point-meta', point ? `${point.floor} · ${point.frequency === 'daily2' ? '每日兩次' : point.frequency === 'weekly' ? '每週一次' : point.frequency === 'monthly' ? '每月一次' : point.frequency === 'irregular' ? '不定期' : '每日一次'}` : '');
      text('point-stage', point ? stageText(point.stage) : '');
      const roundLabel = displayed ? eligible ? `${slotText(expected.slot)} · ${expected.day}` : !unchanged ? '點位或日期已變更，請重新掃描' : '本次已完成、已暫存或已到期，請重新掃描確認' : '';
      text('point-round', roundLabel);
      text('stage', point ? stageText(point.stage) : '');
      text('round', roundLabel);
      if (form) form.dataset.pointPath = '/c/' + selectedToken;
      if (one('fields')) one('fields').disabled = !eligible;
      if (one('save')) one('save').disabled = !eligible;
      if (one('report-fields')) { one('report-fields').hidden = !point || point.stage !== 'inspect'; for (const field of one('report-fields').querySelectorAll('input,textarea')) field.disabled = point?.stage !== 'inspect'; }
    }
    function render(state) {
      text('count', state.pending ? String(state.pending) : '');
      text('network', !state.online ? '離線' : state.sync?.running ? '補傳中' : state.pending ? '待補傳' : state.prepared ? '已備妥' : '離線準備');
      if (normalProgress && !normalProgress.saving) {
        normalProgress.status.textContent = state.sync?.running ?
          `${state.sync.phase === 'uploading' ? '正在上傳本筆紀錄（最多 30 秒）' : '正在檢查連線（最多 5 秒）'} · 已等 ${state.sync.elapsed || 0} 秒` :
          '已保存在手機，正在開啟收據或待傳紀錄…';
        normalProgress.cancel.disabled = !state.sync?.running;
      }
      if (!shell) return;
      if (viewOwner && viewOwner !== state.owner) { selectedToken = null; selectedOwner = null; selectedSnapshot = null; form?.reset(); resetPhotos(); if (one('saved')) one('saved').hidden = true; }
      viewOwner = state.owner;
      text('account', state.identity ? `${state.identity.name} · ${state.identity.role_label || stageText(state.identity.role === 'executor' ? 'execute' : 'inspect')}` : '尚未解鎖離線資料');
      text('validity', state.prepared ? `可暫存至 ${timeText(state.captureUntil)}；補傳期限 ${timeText(state.syncUntil)}` : state.locked ? '請先連線登入原帳號，並準備今日資料。' : '今日資料已到期。待補傳紀錄仍保留，請連線補傳。');
      text('status', state.message || (!state.online ? '目前離線。暫存不等於打卡完成，請連線後補傳。' : state.prepared ? '今日離線資料已備妥。' : '請先準備今日離線資料。'));
      if (one('status')) one('status').dataset.state = !state.online ? 'offline' : state.blocked ? 'blocked' :
        !state.sync?.running && (state.sync?.errorCode || state.sync?.failed > 0) ? 'error' : 'online';
      text('queue-summary', state.sync?.running ? `正在處理 ${state.sync.processed}/${state.sync.total} 筆 · 已確認 ${state.sync.saved} 筆 · ${state.sync.elapsed} 秒` : `${state.pending} 筆待補傳${state.blocked ? `，其中 ${state.blocked} 筆需處理` : ''}`);
      if (one('sync')) one('sync').disabled = state.locked || !state.pending || state.sync?.running;
      if (one('cancel-sync')) one('cancel-sync').hidden = !state.sync?.running;
      if (one('prepare')) one('prepare').disabled = !state.online || state.sync?.running;
      if (one('login')) one('login').hidden = !state.locked;
      if (one('empty')) one('empty').hidden = state.pending > 0;
      if (savedClientId && one('saved')) {
        const queued = state.queue.find(row => row.client_id === savedClientId && !row.stale_owner);
        const receipt = state.receipts.find(row => row.client_id === savedClientId);
        one('saved').hidden = !queued && !receipt;
        if (queued || receipt) {
          const record = queued || receipt;
          const title = document.getElementById('offline-saved-title');
          if (title) title.textContent = receipt ? '已同步完成' : '已暫存在這支手機';
          text('saved-message', receipt ? `${record.code} · ${slotText(record.slot)} 已收到伺服器確認，可以繼續下一點。` :
            `${record.code} · ${slotText(record.slot)} 已暫存此手機，尚未上傳。連線後請按「同步待傳紀錄」。`);
        }
      }
      const list = one('queue');
      if (list) {
        list.replaceChildren();
        for (const row of state.queue) {
          const item = document.createElement('li'); item.className = 'offline-queue-item';
          const heading = document.createElement('strong'); heading.textContent = `${row.code} · ${row.name}`;
          const info = document.createElement('p'); info.textContent = `${stageText(row.stage)} · ${slotText(row.slot)} · ${timeText(row.observed_at)}`;
          const status = document.createElement('p'); status.className = row.status === 'blocked' ? 'offline-item-error' : 'offline-item-status';
          status.textContent = row.error || '已暫存此手機，尚未收到伺服器確認。';
          const details = document.createElement('small'); details.textContent = `${row.is_abnormal ? '異常回報 · ' : ''}${row.photo_count} 張照片${row.note ? ' · ' + row.note : ''}`;
          const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'button button-secondary button-small'; remove.disabled = state.sync?.running;
          remove.textContent = '刪除本機紀錄'; remove.addEventListener('click', async () => {
            if (confirm(`確定刪除 ${row.code} 這筆本機資料與照片？\n若伺服器尚未收到，刪除後將無法補傳；已存在伺服器的紀錄不會被刪除。`)) try { await core.remove(row.client_id, true); } catch (error) { reportError(error); }
          });
          item.append(heading, info, status, details, remove); list.append(item);
        }
      }
      showPoint().catch(reportError);
    }
    core.subscribe(render);
    function resetPhotos() { previewURLs.forEach(url => URL.revokeObjectURL(url)); previewURLs = []; one('photo-previews')?.replaceChildren(); }
    photosInput?.addEventListener('change', () => {
      resetPhotos(); const files = Array.from(photosInput.files);
      try {
        validatePhotos(files); photosInput.setCustomValidity(''); text('photo-status', files.length ? `已選 ${files.length} 張，按 OK 後才會暫存。` : '');
        for (const file of files) {
          const image = document.createElement('img'), url = URL.createObjectURL(file); previewURLs.push(url); image.src = url; image.alt = file.name; one('photo-previews')?.append(image);
        }
      } catch (error) { photosInput.setCustomValidity(error.message); text('photo-status', error.message); }
    });
    form?.addEventListener('submit', async event => {
      event.preventDefault(); if (form.dataset.submitting === 'true') return;
      form.dataset.submitting = 'true'; const submit = one('save'); if (submit) submit.disabled = true;
      try {
        const row = await core.enqueue({ token: selectedToken, owner: selectedSnapshot?.point.owner || selectedOwner, expected: selectedSnapshot?.expected,
          note: form.elements.namedItem('note')?.disabled ? '' : form.elements.namedItem('note')?.value,
          is_abnormal: !form.elements.namedItem('is_abnormal')?.disabled && form.elements.namedItem('is_abnormal')?.checked,
          photos: photosInput?.disabled ? [] : photosInput?.files || [] });
        form.reset(); resetPhotos(); text('photo-status', ''); selectedToken = null; selectedSnapshot = null; savedClientId = row.client_id;
        if (one('saved')) one('saved').hidden = false;
        text('saved-message', `${row.code} · ${slotText(row.slot)} 已暫存此手機，尚未上傳。連線後請按「同步待傳紀錄」。`);
        await showPoint(); one('saved')?.scrollIntoView({ block: 'nearest' });
      } catch (error) { reportError(error); }
      finally { delete form.dataset.submitting; await showPoint(); }
    }, true);
    one('prepare')?.addEventListener('click', () => core.prepare().catch(reportError));
    one('sync')?.addEventListener('click', () => core.sync().catch(reportError));
    one('cancel-sync')?.addEventListener('click', () => core.cancelSync());
    one('close-point')?.addEventListener('click', () => { if (form && (form.elements.namedItem('note')?.value || form.elements.namedItem('is_abnormal')?.checked || photosInput?.files.length) && !confirm('離開點位會放棄尚未暫存的內容，確定離開？')) return; selectedToken = null; selectedSnapshot = null; form?.reset(); resetPhotos(); showPoint(); });
    document.addEventListener('submit', event => {
      const logout = event.target; if (!(logout instanceof HTMLFormElement) || new URL(logout.action, location.origin).pathname !== '/logout') return;
      event.preventDefault(); event.stopImmediatePropagation(); core.lock().finally(() => HTMLFormElement.prototype.submit.call(logout));
    }, true);
    let latestState;
    core.subscribe(value => { latestState = value; });
    document.addEventListener('submit', async event => {
      const normal = event.target;
      if (!(normal instanceof HTMLFormElement) || normal.id !== 'inspection-form') return;
      // Unprepared online forms retain the original server-rendered submission.
      if (!latestState?.prepared && navigator.onLine !== false) return;
      event.preventDefault(); event.stopImmediatePropagation();
      if (normal.dataset.offlineSaving === 'true') return;
      const value = name => normal.elements.namedItem(name)?.value || '';
      const target = new URL(normal.action, location.origin).pathname.replace(/\/confirm$/, '');
      const token = safePath(target)?.slice(3);
      const buttons = Array.from(normal.elements).filter(el => el instanceof HTMLButtonElement && el.type === 'submit');
      const saved = buttons.map(button => ({ button, disabled: button.disabled, content: button.innerHTML }));
      normal.dataset.offlineSaving = 'true'; normal.dataset.submitting = 'true'; normal.setAttribute('aria-busy', 'true');
      for (const button of buttons) { button.disabled = true; button.textContent = '正在保存／送出…'; }
      const panel = document.createElement('div'), progress = document.createElement('p'), cancel = document.createElement('button');
      panel.className = 'offline-submit-progress'; panel.tabIndex = -1;
      progress.dataset.offlineFormProgress = ''; progress.setAttribute('role', 'status'); progress.setAttribute('aria-live', 'polite');
      progress.textContent = '正在保存到手機；請稍候…';
      cancel.type = 'button'; cancel.className = 'button button-secondary button-small'; cancel.dataset.offlineCancelSubmit = '';
      cancel.textContent = '取消上傳，保留待傳'; cancel.disabled = true;
      cancel.addEventListener('click', () => { cancel.disabled = true; core.cancelSync(); progress.textContent = '正在停止上傳，紀錄仍保留在手機…'; });
      panel.append(progress, cancel);
      const quickAction = normal.closest('.checkin-card')?.querySelector('.checkin-quick-action');
      if (quickAction) quickAction.after(panel); else normal.before(panel);
      normalProgress = { panel, status: progress, cancel, saving: true }; panel.scrollIntoView({ block: 'nearest' });
      try {
        const entry = await core.enqueue({ token, note: value('note'), is_abnormal: Boolean(normal.elements.namedItem('is_abnormal')?.checked),
          photos: normal.elements.namedItem('photos')?.files || [], expected: { user_id: body.dataset.offlineUser, auth_version: body.dataset.offlineVersion,
            day: value('personal_day'), slot: value('slot'), stage: value('stage'),
            frequency: value('frequency'), workflow_mode: value('workflow_mode'), period_key: value('period_key'), revision: value('point_revision') } });
        // Files are cleared only after the atomic local write has completed.
        normal.reset();
        normalProgress.saving = false;
        if (navigator.onLine !== false) await core.sync({ client_id: entry.client_id });
        const updated = await core.getState(), receipt = updated.receipts.find(item => item.client_id === entry.client_id);
        const receiptURL = receipt?.ack?.receipt_url;
        if (typeof receiptURL === 'string' && /^\/(?:checkins|executions)\/[0-9]+(?:\/success)?(?:\?[^#]*)?$/.test(receiptURL)) location.assign(receiptURL);
        else location.assign('/offline?queued=' + encodeURIComponent(entry.client_id));
      } catch (error) {
        let notice = normal.parentElement.querySelector('[data-offline-form-error]');
        if (!notice) { notice = document.createElement('p'); notice.dataset.offlineFormError = ''; notice.className = 'flash flash-error'; notice.setAttribute('role', 'alert'); notice.tabIndex = -1; normal.before(notice); }
        notice.textContent = error.message || '無法保存，原本的備註與照片仍保留在表單中。'; notice.focus();
      } finally {
        normalProgress = null; panel.remove();
        delete normal.dataset.offlineSaving; delete normal.dataset.submitting; normal.removeAttribute('aria-busy');
        for (const item of saved) { item.button.disabled = item.disabled; item.button.innerHTML = item.content; }
      }
    }, true);
    window.addEventListener('online', () => core.getState().catch(reportError));
    window.addEventListener('offline', () => { core.cancelSync(); core.getState().catch(reportError); });
    window.addEventListener('pageshow', () => core.getState().catch(() => {}));
    window.addEventListener('pagehide', resetPhotos);
    (async () => {
      if (shell) { await core.getState(); await showPoint(); return; }
      if (body.dataset.offlineWorkspace !== 'true' || !body.dataset.offlineUser) { await core.lock(); return; }
      await core.matchIdentity(body.dataset.offlineUser, body.dataset.offlineVersion);
      if (navigator.onLine !== false) await core.prepare({ id: body.dataset.offlineUser, version: body.dataset.offlineVersion });
    })().catch(error => { if (shell) reportError(error); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready); else ready();
})(typeof window !== 'undefined' ? window : globalThis);
