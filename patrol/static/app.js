/* Progressive enhancements; all core forms work without JavaScript. */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', event => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
  document.querySelectorAll('form[data-submit-once]').forEach(form => {
    form.addEventListener('submit', event => {
      if (event.defaultPrevented) return;
      if (form.dataset.submitting === 'true') { event.preventDefault(); return; }
      form.dataset.submitting = 'true';
      form.querySelectorAll('button[type="submit"],button:not([type])').forEach(button => {
        button.disabled = true;
        button.dataset.originalText = button.textContent;
        button.textContent = button.dataset.loadingText || '處理中…';
      });
    });
  });
  document.querySelectorAll('[data-print]').forEach(button => button.addEventListener('click', () => window.print()));
});
window.addEventListener('pageshow', () => {
  document.querySelectorAll('form[data-submitting="true"]').forEach(form => {
    delete form.dataset.submitting;
    form.querySelectorAll('button[data-original-text]').forEach(button => {
      button.disabled = false;
      button.textContent = button.dataset.originalText;
    });
  });
});
