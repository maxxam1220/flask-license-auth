/* Never cache account pages, API responses, records, or uploaded photos. */
'use strict';
// Bump this release key whenever the shell or a required asset changes.
const CACHE = 'patrol-offline-shell-20261106-v8';
const REQUIRED = ['/offline', '/static/app.css', '/static/offline.css', '/static/executor-locale.css', '/static/i18n.js', '/static/offline.js', '/static/patrol-scanner.js', '/static/vendor/jsqr-1.4.0.js', '/static/logo.ico'];
const allowed = new Set(REQUIRED);
// Without a cached shell no account language is available. Offer neutral
// recovery instructions in every supported language without reading identity.
const unavailable = () => new Response('離線頁面尚未備妥。請連線後重新開啟巡檢網站。' + '\n\n' +
  'Halaman offline belum siap. Hubungkan internet lalu buka kembali situs inspeksi.' + '\n\n' +
  'Trang ngoại tuyến chưa sẵn sàng. Kết nối mạng rồi mở lại trang kiểm tra.',
  { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const responses = await Promise.all(REQUIRED.map(async path => {
      const response = await fetch(new Request(path, { cache: 'reload', credentials: 'omit', redirect: 'error' }));
      if (!response.ok || response.type === 'opaque') throw new Error('Incomplete offline shell');
      return [path, response];
    }));
    const cache = await caches.open(CACHE);
    await Promise.all(responses.map(([path, response]) => cache.put(path, response)));
    await self.skipWaiting();
  })());
});
self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith('patrol-offline-shell-') && key !== CACHE).map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});
self.addEventListener('message', event => {
  if (event.data?.type !== 'PATROL_OFFLINE_READY') return;
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE), responses = await Promise.all(REQUIRED.map(path => cache.match(path)));
    event.ports[0]?.postMessage({ ready: responses.every(Boolean) });
  })());
});
self.addEventListener('fetch', event => {
  const request = event.request, url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== self.location.origin) return;
  // Static requests are immutable shell assets, not arbitrary /static paths.
  if (allowed.has(url.pathname) && url.pathname !== '/offline' && !url.search) {
    event.respondWith(caches.open(CACHE).then(async cache => (await cache.match(url.pathname)) || fetch(request))); return;
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
