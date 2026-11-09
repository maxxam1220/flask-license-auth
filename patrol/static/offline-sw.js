/* Never cache account pages, API responses, records, or uploaded photos. */
'use strict';
// Bump this release key whenever the shell or a required asset changes.
const CACHE = 'patrol-offline-shell-20261109-v17';
const AUDIO_VERSION = 'patrol-v1', AUDIO_ROOT = '/static/audio/' + AUDIO_VERSION + '/';
// Keep the fixed paths compatible with already-open pages and pending drafts.
// A new revision still requires a complete, verified download before activation.
const AUDIO_REVISION = 'natural-female-1';
const AUDIO_KINDS = ['saved_execute', 'saved_inspect', 'saved_visit', 'already_recorded', 'waiting_execution', 'device_required', 'point_unavailable',
  'offline_stored', 'sync_confirmed', 'sync_partial', 'not_saved', 'login_required', 'receipt_confirmed'];
const AUDIO_PATHS = ['zh-Hant', 'id', 'vi'].flatMap(locale => AUDIO_KINDS.map(kind => AUDIO_ROOT + locale + '/' + kind + '.mp3'));
const AUDIO_MANIFEST = AUDIO_ROOT + 'manifest.json', audioAllowed = new Set(AUDIO_PATHS);
const REQUIRED = ['/offline', '/static/app.css', '/static/offline.css', '/static/checklist.css', '/static/executor-locale.css', '/static/i18n.js', '/static/patrol-voice.js', '/static/patrol-voice.css', '/static/offline.js', '/static/offline-update.js', '/static/patrol-scanner.js', '/static/vendor/jsqr-1.4.0.js', '/static/logo.ico', AUDIO_MANIFEST, ...AUDIO_PATHS];
const allowed = new Set(REQUIRED);
const completeResponse = response => response && response.status === 200 && response.type !== 'opaque' && !response.redirected;
function audioManifest(value) {
  if (!value || value.version !== AUDIO_VERSION || value.revision !== AUDIO_REVISION || !Array.isArray(value.files) || value.files.length !== AUDIO_PATHS.length) throw new Error('Incomplete audio manifest');
  const entries = new Map();
  for (const item of value.files) {
    if (!item || !audioAllowed.has(item.path) || entries.has(item.path) ||
        item.path !== AUDIO_ROOT + item.locale + '/' + item.kind + '.mp3' ||
        !Number.isSafeInteger(item.bytes) || item.bytes < 1 || item.bytes > 2 * 1024 * 1024 || !/^[a-f0-9]{64}$/.test(item.sha256)) throw new Error('Invalid audio manifest');
    entries.set(item.path, item);
  }
  return entries;
}
const audioType = response => /^audio\/(?:mpeg|mp3)(?:\s*;|$)/i.test(response.headers.get('Content-Type') || '');
async function cacheReady(cache) {
  try {
    const responses = await Promise.all(REQUIRED.map(path => cache.match(path)));
    if (!responses.every(completeResponse)) return false;
    const manifest = audioManifest(await responses[REQUIRED.indexOf(AUDIO_MANIFEST)].json());
    return AUDIO_PATHS.every(path => {
      const response = responses[REQUIRED.indexOf(path)], item = manifest.get(path);
      // Cache.put commits complete bodies. These headers are written only
      // after the downloaded bytes passed the manifest's SHA-256 check.
      return audioType(response) && response.headers.get('Content-Length') === String(item.bytes) &&
        response.headers.get('X-Patrol-Audio-SHA256') === item.sha256 && !response.headers.has('Content-Range');
    });
  } catch (_) { return false; }
}
async function audioRange(response, request) {
  const range = request.headers?.get('Range');
  // Ignoring unsupported/multiple ranges or conditional ranges returns the
  // complete representation. Never turn them into an incorrect single range.
  if (!range || request.headers?.has('If-Range')) return response;
  const match = /^bytes=(\d*)-(\d*)$/i.exec(range.trim());
  if (!match || !match[1] && !match[2]) return response;
  const bytes = await response.arrayBuffer(), size = bytes.byteLength;
  let first = match[1] ? Number(match[1]) : null, last = match[2] ? Number(match[2]) : null;
  if (first === null) { first = Math.max(0, size - last); last = size - 1; }
  else last = last === null ? size - 1 : Math.min(last, size - 1);
  const headers = new Headers(response.headers);
  headers.delete('Content-Encoding'); headers.set('Accept-Ranges', 'bytes');
  if (first >= size || first > last) {
    headers.set('Content-Range', 'bytes */' + size); headers.set('Content-Length', '0');
    return new Response(null, { status: 416, statusText: 'Range Not Satisfiable', headers });
  }
  headers.set('Content-Range', 'bytes ' + first + '-' + last + '/' + size);
  headers.set('Content-Length', String(last - first + 1));
  return new Response(bytes.slice(first, last + 1), { status: 206, statusText: 'Partial Content', headers });
}
// Without a cached shell no account language is available. Offer neutral
// recovery instructions in every supported language without reading identity.
const unavailable = () => new Response('離線頁面尚未備妥。請連線後重新開啟巡檢網站。' + '\n\n' +
  'Halaman offline belum siap. Hubungkan internet lalu buka kembali situs inspeksi.' + '\n\n' +
  'Trang ngoại tuyến chưa sẵn sàng. Kết nối mạng rồi mở lại trang kiểm tra.',
  { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
let preparation = null;
function prepareCache() {
  if (!preparation) preparation = downloadCache().finally(() => { preparation = null; });
  return preparation;
}
async function downloadCache() {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 25000);
    const responses = [];
    try {
      const download = async path => {
        const response = await fetch(new Request(path, { cache: 'reload', credentials: 'omit', redirect: 'error', signal: controller.signal }));
        if (!completeResponse(response)) throw new Error('Incomplete offline shell');
        const bytes = await response.clone().arrayBuffer();
        if (!bytes.byteLength) throw new Error('Empty offline asset');
        return { path, response, bytes };
      };
      const manifestDownload = await download(AUDIO_MANIFEST);
      const manifest = audioManifest(await manifestDownload.response.clone().json());
      responses.push([AUDIO_MANIFEST, manifestDownload.response]);
      let index = 0;
      const pending = REQUIRED.filter(path => path !== AUDIO_MANIFEST);
      // Bound requests so preparing a phone does not monopolize the server.
      await Promise.all(Array.from({ length: 4 }, async () => {
        while (index < pending.length) {
          const { path, response, bytes } = await download(pending[index++]);
          if (!audioAllowed.has(path)) { responses.push([path, response]); continue; }
          const item = manifest.get(path);
          if (!audioType(response) || bytes.byteLength !== item.bytes) throw new Error('Incomplete offline audio');
          const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), value => value.toString(16).padStart(2, '0')).join('');
          if (digest !== item.sha256) throw new Error('Offline audio integrity mismatch');
          const headers = new Headers(response.headers);
          headers.delete('Content-Encoding'); headers.delete('Content-Range');
          headers.set('Content-Length', String(bytes.byteLength)); headers.set('Accept-Ranges', 'bytes');
          headers.set('X-Patrol-Audio-SHA256', digest);
          responses.push([path, new Response(bytes, { status: 200, headers })]);
        }
      }));
    } catch (error) { controller.abort(); throw error; }
    finally { clearTimeout(timeout); }
    // No cache is touched until every public asset and audio file is complete.
    const cache = await caches.open(CACHE);
    await Promise.all(responses.map(([path, response]) => cache.put(path, response)));
    if (!await cacheReady(cache)) throw new Error('Incomplete offline cache');
}
self.addEventListener('install', event => {
  event.waitUntil((async () => { await prepareCache(); await self.skipWaiting(); })());
});
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    if (!await cacheReady(await caches.open(CACHE))) return;
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith('patrol-offline-shell-') && key !== CACHE).map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});
self.addEventListener('message', event => {
  if (!['PATROL_OFFLINE_READY', 'PATROL_OFFLINE_PREPARE'].includes(event.data?.type)) return;
  event.waitUntil((async () => {
    let ready = false;
    try {
      ready = await cacheReady(await caches.open(CACHE));
      if (!ready && event.data.type === 'PATROL_OFFLINE_PREPARE' && self.navigator?.onLine !== false) {
        await prepareCache(); ready = await cacheReady(await caches.open(CACHE));
      }
    } catch (_) { /* Leave existing entries and private IndexedDB data intact. */ }
    event.ports[0]?.postMessage({ ready, audioReady: ready, checklistVersion: 1, audioVersion: AUDIO_VERSION, audioRevision: AUDIO_REVISION });
  })());
});
self.addEventListener('fetch', event => {
  const request = event.request, url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  // Static requests are immutable shell assets, not arbitrary /static paths.
  const versionedAudio = audioAllowed.has(url.pathname) && url.search === '?rev=' + AUDIO_REVISION;
  const versionedChecklist = url.pathname === '/static/offline.js' && url.search === '?v=checklist-1';
  if (allowed.has(url.pathname) && url.pathname !== '/offline' && (!url.search || versionedAudio || versionedChecklist)) {
    event.respondWith(caches.open(CACHE).then(async cache => {
      const cached = await cache.match(url.pathname);
      if (!completeResponse(cached)) return fetch(request);
      return audioAllowed.has(url.pathname) ? audioRange(cached, request) : cached;
    })); return;
  }
  if (request.mode !== 'navigate' || !(url.pathname === '/offline' || /^\/c\/[A-Za-z0-9_-]{1,100}$/.test(url.pathname))) return;
  event.respondWith((async () => {
    const fallback = async () => (await caches.open(CACHE)).match('/offline');
    if (self.navigator?.onLine === false) return (await fallback()) || unavailable();
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(request, { signal: controller.signal });
      if (response.status >= 500) return (await fallback()) || response;
      // Headers alone do not make a usable check-in page. Keep the deadline
      // active through the body, but return the original Response so its URL,
      // redirect state and security headers remain unchanged. Never cache it.
      await response.clone().arrayBuffer();
      return response;
    } catch (_) {
      return (await fallback()) || unavailable();
    } finally { clearTimeout(timeout); }
  })());
});
