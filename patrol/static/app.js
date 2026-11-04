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
      [...form.elements].filter(element => element instanceof HTMLButtonElement && element.hasAttribute('data-busy-button')).forEach(button => {
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
    // Bookmarks from when the work list was part of the overview.
    const formerReadyEntry = document.querySelector('a[data-today-ready-entry]');
    if (formerReadyEntry) {
      const redirectOldBookmark = () => {
        if (location.hash !== '#today-ready') return false;
        location.replace(formerReadyEntry.href);
        return true;
      };
      if (redirectOldBookmark()) return;
      window.addEventListener('hashchange', redirectOldBookmark);
    }
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
        [...form.elements].filter(element => element instanceof HTMLButtonElement && element.type === 'submit').forEach(button => {
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

    // Keep the selected floor visible when the horizontal row is rebuilt after a query.
    const floorNav = document.querySelector('[data-floor-navigation]');
    if (floorNav) {
      const target = floorNav.querySelector('[aria-current=page]') || floorNav.querySelector('[data-has-visits]');
      if (target && floorNav.scrollWidth > floorNav.clientWidth) {
        const row = floorNav.getBoundingClientRect();
        const item = target.getBoundingClientRect();
        if (item.left < row.left || item.right > row.right) floorNav.scrollLeft += item.left - row.left;
      }
    }

    // Keep the full search form usable without JavaScript; collapse only on phones.
    document.querySelectorAll('[data-records-query]').forEach(panel => {
      const toggle = panel.querySelector('[data-query-toggle]');
      const fields = panel.querySelector('[data-query-fields]');
      const action = panel.querySelector('[data-query-action]');
      if (!toggle || !fields || !action) return;
      const mobile = window.matchMedia('(max-width: 720px)');
      let expandedOnMobile = false;
      const render = () => {
        const expanded = !mobile.matches || expandedOnMobile;
        toggle.hidden = !mobile.matches;
        if (!expanded && fields.contains(document.activeElement)) toggle.focus();
        fields.hidden = !expanded;
        toggle.setAttribute('aria-expanded', String(expanded));
        action.textContent = expanded ? '收合查詢' : '調整查詢';
      };
      toggle.addEventListener('click', () => {
        expandedOnMobile = !expandedOnMobile;
        render();
      });
      if (mobile.addEventListener) mobile.addEventListener('change', render);
      else mobile.addListener(render);
      render();
    });

    // Keep long point summaries available while prioritising detail rows on phones.
    document.querySelectorAll('details[data-responsive-summary]').forEach(details => {
      const mobile = window.matchMedia('(max-width: 720px)');
      const render = () => {
        if (mobile.matches && details.contains(document.activeElement)) details.querySelector('summary')?.focus();
        details.open = !mobile.matches;
      };
      if (mobile.addEventListener) mobile.addEventListener('change', render);
      else mobile.addListener(render);
      render();
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

    const officialCodes = JSON.parse(document.querySelector('#official-general-codes')?.dataset.codes || '{}');
    const catalogCodes = new Map(Object.entries(officialCodes).map(([code, floor]) => [code.toLowerCase(), {code, floor}]));
    document.querySelectorAll('form[data-point-form]').forEach(form => {
      const workflow = form.querySelector('[data-workflow-control]');
      if (workflow) {
        const categoryInputs = form.querySelectorAll('input[name=category]');
        const select = workflow.querySelector('select');
        const updateWorkflow = () => {
          const general = form.elements.namedItem('category')?.value === 'general';
          workflow.hidden = !general;
          select.disabled = !general;
          const frequency = form.elements.namedItem('frequency');
          for (const option of frequency.querySelectorAll('[data-general-frequency]')) {
            option.hidden = option.disabled = !general;
            if (!general && option.selected) frequency.value = 'daily';
          }
          if (general && !select.value) select.value = 'spot';
        };
        categoryInputs.forEach(input => input.addEventListener('change', updateWorkflow));
        updateWorkflow();
      }
      const floor = form.elements.namedItem('floor');
      const code = form.elements.namedItem('code');
      if (!floor || !code) return;
      const registeredCode = value => {
        const official = catalogCodes.get(value.toLowerCase());
        if (official) return official;
        const original = form.dataset.originalCode;
        if (original && value === original && form.elements.namedItem('category')?.value === 'general'
            && form.dataset.originalFloor === floor.value) return {code: original, floor: floor.value};
      };
      const validatePoint = () => {
        code.setCustomValidity('');
        const value = code.value.trim();
        if (!value) return;
        const registered = registeredCode(value);
        if (registered) {
          if (String(registered.floor) !== floor.value || form.elements.namedItem('category')?.value !== 'general') {
            code.setCustomValidity('清冊原始編號須對應總務分類與原樓層。');
          }
          return;
        }
        const prefix = floor.selectedOptions[0]?.textContent.trim().toUpperCase();
        if (!/^[A-Z0-9]+-[A-Z0-9]{2,20}$/i.test(value) || !value.toUpperCase().startsWith(`${prefix}-`)) {
          code.setCustomValidity(`點位編號需與樓層一致，請使用 ${prefix}- 開頭。`);
        }
      };
      code.addEventListener('input', validatePoint);
      floor.addEventListener('change', validatePoint);
      form.querySelectorAll('input[name=category]').forEach(input => input.addEventListener('change', validatePoint));
      code.addEventListener('blur', () => {
        const value = code.value.trim();
        code.value = registeredCode(value)?.code || value.toUpperCase();
        validatePoint();
      });
      validatePoint();
    });

    document.querySelectorAll('textarea[data-character-count]').forEach(input => {
      const counter = document.getElementById(input.dataset.characterCount);
      const update = () => {
        if (counter) counter.textContent = `${input.value.length.toLocaleString()} / ${input.maxLength.toLocaleString()}`;
      };
      input.addEventListener('input', update);
      update();
    });

    document.querySelectorAll('textarea[data-nonblank]').forEach(input => {
      const validate = () => input.setCustomValidity(input.value && !input.value.trim() ? '請填寫說明，不能只輸入空白。' : '');
      input.addEventListener('input', validate);
      validate();
    });
    document.querySelector('[data-error-focus]')?.focus();

    document.querySelectorAll('[data-photo-upload]').forEach(container => {
      const input = container.querySelector('[data-photo-input]');
      const feedback = container.querySelector('[data-photo-feedback]');
      const previewList = container.querySelector('[data-photo-previews]');
      if (!input || !feedback || !previewList) return;
      const supportedTypes = new Set(['image/jpeg', 'image/jpg', 'image/pjpeg', 'image/png', 'image/x-png', 'image/webp', 'image/heic', 'image/heif']);
      const maxSize = 8 * 1024 * 1024;
      let previewUrls = [];
      let canRemove = typeof DataTransfer === 'function';

      function supportsPhoto(file) {
        const type = file.type.toLowerCase();
        return supportedTypes.has(type) || ((!type || type === 'application/octet-stream') && /\.(jpe?g|png|webp|heic|heif)$/i.test(file.name));
      }

      function validatePhotos(files) {
        let message = '';
        if (files.length > 3) message = `目前選了 ${files.length} 張照片，最多只能附 3 張，請移除多餘照片或重新選擇。`;
        else if (files.some(file => file.size === 0)) message = '有照片是空白檔案，請移除並重新選擇。';
        else if (files.some(file => file.size > maxSize)) message = '有照片超過 8 MB，請移除或更換較小的照片。';
        else if (files.some(file => !supportsPhoto(file))) message = '請選擇 JPG、PNG、WebP 或 HEIC 照片。';
        input.setCustomValidity(message);
        input.setAttribute('aria-invalid', message ? 'true' : 'false');
        feedback.textContent = message || (files.length ? `已選 ${files.length} 張，確認打卡時才會上傳。` : '');
        feedback.classList.toggle('is-error', !!message);
      }

      function renderPhotos() {
        previewUrls.forEach(url => URL.revokeObjectURL(url));
        previewUrls = [];
        previewList.replaceChildren();
        const files = Array.from(input.files || []);
        validatePhotos(files);
        files.slice(0, 6).forEach((file, index) => {
          const figure = document.createElement('figure');
          figure.className = 'photo-preview';
          const imageContainer = document.createElement('div');
          imageContainer.className = 'photo-preview-image';
          const placeholder = document.createElement('span');
          placeholder.className = 'photo-preview-placeholder';
          placeholder.textContent = '照片預覽';
          imageContainer.append(placeholder);
          // Preview only recognised image formats; the server validates actual file contents.
          if (file.size > maxSize) placeholder.textContent = '超過 8 MB，請更換照片';
          else if (file.size === 0) placeholder.textContent = '空白檔案，請重新選擇';
          else if (supportsPhoto(file)) {
            const image = document.createElement('img');
            const url = URL.createObjectURL(file);
            previewUrls.push(url);
            image.alt = `已選照片 ${index + 1}`;
            image.onload = () => { placeholder.hidden = true; };
            image.onerror = () => { image.remove(); placeholder.hidden = false; placeholder.textContent = '此格式無法預覽，仍可上傳'; };
            image.src = url;
            imageContainer.append(image);
          } else placeholder.textContent = '不支援的檔案格式';
          figure.append(imageContainer);
          const caption = document.createElement('figcaption');
          const name = document.createElement('span');
          name.textContent = file.name;
          const size = document.createElement('small');
          size.textContent = `${(file.size / 1024 / 1024).toFixed(1)} MB`;
          caption.append(name, size);
          figure.append(caption);
          if (canRemove) {
            const remove = document.createElement('button');
            remove.type = 'button';
            remove.className = 'button button-secondary button-small photo-remove';
            remove.textContent = '移除';
            remove.setAttribute('aria-label', `移除照片 ${index + 1}：${file.name}`);
            remove.addEventListener('click', () => {
              try {
                const transfer = new DataTransfer();
                files.forEach((item, itemIndex) => { if (itemIndex !== index) transfer.items.add(item); });
                input.files = transfer.files;
                if (input.files.length !== files.length - 1) throw new Error('File selection was not updated');
                renderPhotos();
                input.focus();
              } catch (_) {
                canRemove = false;
                renderPhotos();
                feedback.textContent = '此瀏覽器不支援逐張移除，請使用檔案選擇按鈕重新選擇照片。';
              }
            });
            figure.append(remove);
          }
          previewList.append(figure);
        });
      }

      input.addEventListener('change', renderPhotos);
      renderPhotos();
      container.classList.add('photo-picker-ready');
    });

    const mobileMenu = document.querySelector('.mobile-menu');
    document.addEventListener('click', event => {
      if (mobileMenu?.open && (!mobileMenu.contains(event.target) || event.target.closest('a[href]'))) mobileMenu.open = false;
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
