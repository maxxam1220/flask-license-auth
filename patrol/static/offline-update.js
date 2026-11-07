/* Public asset maintenance only. Never authorizes capture, reads private
   storage, creates a registration, or reloads an open form. */
(function (root, factory) {
  'use strict';
  const createUpdater = factory();
  if (typeof module === 'object' && module.exports) module.exports = createUpdater;
  if (!root.document) return;
  const update = createUpdater(root);
  update();
  root.addEventListener('online', update);
  root.addEventListener('pageshow', event => { if (event.persisted) update(); });
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';
  return function createUpdater(env) {
    let pending = null;
    return function update() {
      const nav = env.navigator;
      if (!env.isSecureContext || !nav?.serviceWorker?.getRegistration || nav.onLine === false) return Promise.resolve(false);
      if (pending) return pending;
      const attempt = (async () => {
        try {
          const origin = env.location.origin;
          const registration = await nav.serviceWorker.getRegistration(origin + '/');
          if (!registration || nav.onLine === false || registration.scope !== origin + '/') return false;
          const workers = [registration.active, registration.waiting, registration.installing].filter(Boolean);
          // A different worker or nested scope must not be adopted or changed.
          if (!workers.length || workers.some(worker => worker.scriptURL !== origin + '/offline-sw.js')) return false;
          // Installation already verifies the entire public pack before activation.
          // Leave it alone; a later natural navigation will load the fresh assets.
          if (registration.installing || registration.waiting) return false;
          await registration.update();
          return true;
        } catch (_) { return false; } // Offline/rejected updates cannot interrupt page use.
      })();
      pending = attempt.finally(() => { pending = null; });
      return pending;
    };
  };
});
