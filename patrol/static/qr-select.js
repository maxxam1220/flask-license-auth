/* Checkbox selection only. The server owns filtering and the final printable IDs. */
(() => {
  'use strict';
  const start = () => {
    const form = document.querySelector('[data-qr-selection-form]');
    if (!form || form.dataset.qrSelectionReady) return;
    form.dataset.qrSelectionReady = 'true';
    const boxes = Array.from(form.querySelectorAll('input[type="checkbox"][name="ids"]'));
    const counters = Array.from(form.querySelectorAll('[data-qr-selected-count]'));
    const previews = Array.from(form.querySelectorAll('[data-qr-preview]'));
    const hint = form.querySelector('[data-qr-empty-selection]');
    const all = form.querySelector('[data-qr-select-all]');
    const clear = form.querySelector('[data-qr-select-clear]');
    const update = () => {
      let count = 0;
      for (const box of boxes) {
        if (box.checked) count += 1;
        const card = box.closest('.qr-choice');
        if (card) card.classList.toggle('is-selected', box.checked);
      }
      for (const counter of counters) counter.textContent = String(count);
      for (const preview of previews) preview.disabled = count === 0;
      if (hint) hint.hidden = count > 0;
      if (all) all.disabled = boxes.length === 0 || count === boxes.length;
      if (clear) clear.disabled = count === 0;
      return count;
    };
    const choose = checked => {
      for (const box of boxes) box.checked = checked;
      update();
    };
    form.addEventListener('change', update);
    if (all) all.addEventListener('click', () => choose(true));
    if (clear) clear.addEventListener('click', () => choose(false));
    form.addEventListener('submit', event => {
      if (update() === 0) {
        event.preventDefault();
        if (boxes[0]) boxes[0].focus();
      }
    });
    const tools = form.querySelector('[data-qr-selection-tools]');
    if (tools) tools.hidden = false;
    window.addEventListener('pageshow', update);
    update();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
