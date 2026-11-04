/* Refresh the current shift without changing the dashboard date or scrolling the page. */
(() => {
  let panel = document.querySelector('[data-ready-panel]');
  if (!panel || !window.fetch || !window.AbortController) return;
  let busy = false;
  let lastAttempt = Date.now();
  let shiftTimer;
  const more = p => p.querySelector('[data-ready-more]');
  const updateLink = p => p.querySelector('[data-ready-refresh]');
  function refreshIfVisible(minAge = 60000) {
    const rect = panel.getBoundingClientRect();
    if (!document.hidden && rect.bottom > 0 && rect.top < innerHeight &&
        !document.querySelector('dialog[open]') && Date.now() - lastAttempt >= minAge) refresh(false);
  }
  function scheduleShiftChange() {
    clearTimeout(shiftTimer);
    const stamp = Date.parse(panel.querySelector('.ready-asof time')?.dateTime);
    if (!Number.isFinite(stamp)) return;
    // Base the boundary on server Taipei time, independent of the phone's clock or zone.
    const halfDay = 12 * 3600000;
    const remaining = halfDay - ((stamp + 8 * 3600000) % halfDay);
    shiftTimer = setTimeout(() => refreshIfVisible(0), remaining + 250);
  }
  async function refresh(manual) {
    if (busy) return;
    busy = true;
    lastAttempt = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    panel.setAttribute('aria-busy', 'true');
    try {
      const res = await fetch(panel.dataset.readyUrl, {cache: 'no-store', credentials: 'same-origin', signal: controller.signal});
      if (res.redirected || res.status === 401 || res.status === 403) {
        // Re-enter through the full page so sign-in never returns a bare fragment.
        panel.hidden = true;
        location.reload();
        return;
      }
      if (!res.ok) throw Error('Unavailable');
      const fragment = new DOMParser().parseFromString(await res.text(), 'text/html');
      const next = fragment.querySelector('section#today-ready[data-ready-panel]');
      if (!next || !updateLink(next)) throw Error('Missing list');
      const active = document.activeElement;
      const focus = active === panel ? 'panel' : active === updateLink(panel) ? 'link'
        : more(panel)?.contains(active) ? 'more' : null;
      updateLink(next).href = updateLink(panel).href;
      if (more(next) && more(panel)) more(next).open = more(panel).open;
      const feedback = next.querySelector('[data-ready-feedback]');
      if (manual && feedback) feedback.textContent = '已更新列表。';
      panel.replaceWith(next);
      panel = next;
      scheduleShiftChange();
      if (focus) {
        const target = focus === 'panel' ? panel : focus === 'more' ? more(panel)?.querySelector('summary') : updateLink(panel);
        (target || updateLink(panel)).focus({preventScroll: true});
      }
    } catch {
      const feedback = panel.querySelector('[data-ready-feedback]');
      if (feedback) feedback.textContent = '暫時無法更新，目前顯示上次查詢結果。請稍後再按「更新列表」。';
    } finally {
      clearTimeout(timeout);
      panel.removeAttribute('aria-busy');
      busy = false;
    }
  }
  document.addEventListener('click', event => {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    if (event.target.closest('[data-ready-refresh]')) {
      event.preventDefault();
      refresh(true);
    } else if (event.target.closest('[data-ready-jump]') && Date.now() - lastAttempt >= 60000) refresh(false);
  });
  window.addEventListener('pageshow', event => { if (event.persisted) refresh(false); });
  document.addEventListener('visibilitychange', () => refreshIfVisible(0));
  setInterval(() => refreshIfVisible(0), 60000);
  scheduleShiftChange();
})();
