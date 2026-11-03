/* Progressive enhancements. Core navigation and forms remain server-rendered. */
(() => {
  const savedButtons = new WeakMap();
  let pendingConfirmation = null;

  function announce(message) {
    const feedback = document.getElementById('page-feedback');
    if (feedback) feedback.textContent = message;
  }

  function restoreForms() {
    document.querySelectorAll('form[data-submitting="true"]').forEach(form => {
      delete form.dataset.submitting;
      form.removeAttribute('aria-busy');
      form.querySelectorAll('button[data-busy-button]').forEach(button => {
        const saved = savedButtons.get(button);
        if (saved) {
          button.replaceChildren(...saved.children);
          button.disabled = saved.disabled;
          savedButtons.delete(button);
        }
        delete button.dataset.busyButton;
      });
    });
    announce('');
  }

  document.addEventListener('DOMContentLoaded', () => {
    const dialog = document.getElementById('confirm-dialog');
    const dialogTitle = document.getElementById('confirm-title');
    const dialogMessage = document.getElementById('confirm-message');
    const dialogConfirm = dialog?.querySelector('[data-dialog-confirm]');
    const dialogCancel = dialog?.querySelector('[data-dialog-cancel]');

    function dismissConfirmation() {
      pendingConfirmation = null;
      if (dialog?.open) dialog.close();
    }

    dialogCancel?.addEventListener('click', dismissConfirmation);
    dialog?.addEventListener('cancel', () => { pendingConfirmation = null; });
    dialog?.addEventListener('close', () => {
      pendingConfirmation = null;
      document.body.classList.remove('dialog-open');
    });
    dialogConfirm?.addEventListener('click', () => {
      const action = pendingConfirmation;
      if (!action) return;
      pendingConfirmation = null;
      dialog.close();
      action.form.dataset.confirmed = 'true';
      // requestSubmit preserves constraint validation, submit handlers, and submitter.
      action.form.requestSubmit(action.submitter || undefined);
      delete action.form.dataset.confirmed;
    });

    document.querySelectorAll('form').forEach(form => {
      form.addEventListener('submit', event => {
        if (event.defaultPrevented) return;
        if (form.dataset.submitting === 'true') {
          event.preventDefault();
          return;
        }
        if (form.dataset.confirm && form.dataset.confirmed !== 'true' && dialog?.showModal) {
          event.preventDefault();
          pendingConfirmation = { form, submitter: event.submitter };
          dialogTitle.textContent = form.dataset.confirmTitle || '確認這項操作';
          dialogMessage.textContent = form.dataset.confirm;
          dialogConfirm.textContent = form.dataset.confirmLabel || '確認繼續';
          dialogConfirm.classList.toggle('button-danger', form.dataset.confirmDanger === 'true');
          dialogConfirm.classList.toggle('button-primary', form.dataset.confirmDanger !== 'true');
          dialog.showModal();
          document.body.classList.add('dialog-open');
          dialogCancel.focus();
          return;
        }
        if (form.method.toLowerCase() !== 'post') return;
        delete form.dataset.confirmed;
        form.dataset.submitting = 'true';
        form.setAttribute('aria-busy', 'true');
        const submitter = event.submitter;
        form.querySelectorAll('button[type="submit"],button:not([type])').forEach(button => {
          if (button.disabled) return;
          savedButtons.set(button, { children: [...button.childNodes].map(node => node.cloneNode(true)), disabled: button.disabled });
          button.dataset.busyButton = 'true';
          // Avoid dropping a named submitter's value from native form submission.
          if (!button.name) button.disabled = true;
          if (button === submitter || !submitter) button.textContent = button.dataset.loadingText || '正在送出…';
        });
        announce('正在送出，請稍候。請勿重複提交。');
      });
    });

    document.querySelectorAll('[data-print]').forEach(button => {
      button.addEventListener('click', () => window.print());
    });

    // Validate related fields without discarding input on a separate error page.
    document.querySelectorAll('form[data-date-range]').forEach(form => {
      const begin = form.elements.namedItem('date_from');
      const end = form.elements.namedItem('date_to');
      if (!begin || !end) return;
      const validateRange = () => {
        end.setCustomValidity('');
        if (!begin.value || !end.value) return;
        if (begin.value > end.value) end.setCustomValidity('結束日期不能早於開始日期。');
        else if (end.valueAsNumber - begin.valueAsNumber > 366 * 86400000) end.setCustomValidity('一次最多查詢 367 天，請縮小日期範圍。');
      };
      begin.addEventListener('input', validateRange);
      end.addEventListener('input', validateRange);
      validateRange();
    });

    document.querySelectorAll('form[data-point-form]').forEach(form => {
      const floor = form.elements.namedItem('floor');
      const code = form.elements.namedItem('code');
      if (!floor || !code) return;
      const validatePoint = () => {
        code.setCustomValidity('');
        const value = code.value.trim().toUpperCase();
        if (value && /^[1-5]F-[A-Z0-9]{2,20}$/.test(value) && !value.startsWith(`${floor.value}F-`)) {
          code.setCustomValidity(`點位編號需與樓層一致，請使用 ${floor.value}F- 開頭。`);
        }
      };
      code.addEventListener('input', validatePoint);
      floor.addEventListener('change', validatePoint);
      code.addEventListener('blur', () => { code.value = code.value.trim().toUpperCase(); validatePoint(); });
      validatePoint();
    });

    const mobileMenu = document.querySelector('.mobile-menu');
    document.addEventListener('click', event => {
      if (mobileMenu?.open && !mobileMenu.contains(event.target)) mobileMenu.open = false;
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && mobileMenu?.open) {
        mobileMenu.open = false;
        mobileMenu.querySelector('summary')?.focus();
      }
    });
  });

  window.addEventListener('pageshow', restoreForms);
})();
