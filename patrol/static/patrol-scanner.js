/* Scan locally. A successful read only opens the existing confirmation page. */
(() => {
  const starts = document.querySelectorAll('[data-qr-start]');
  const dialog = document.querySelector('[data-qr-dialog]');
  if (!starts.length || !dialog) return;

  const video = dialog.querySelector('[data-qr-video]');
  const status = dialog.querySelector('[data-qr-status-zh]') || dialog.querySelector('[data-qr-status]');
  const englishStatus = dialog.querySelector('[data-qr-status-en]');
  const retry = dialog.querySelector('[data-qr-retry]');
  const close = dialog.querySelector('[data-qr-close]');
  const draftActions = dialog.querySelector('[data-qr-draft-actions]');
  const keep = dialog.querySelector('[data-qr-keep]');
  const discard = dialog.querySelector('[data-qr-discard]');
  // Deferred scripts and embedded browsers do not always expose currentScript.
  // The template supplies the same-origin decoder path independently of it.
  let vendorURL = new URL('/static/vendor/jsqr-1.4.0.js', location.origin);
  try {
    const declared = new URL(dialog.getAttribute('data-qr-decoder') || vendorURL.href, location.origin);
    if (declared.origin === location.origin) vendorURL = declared;
  } catch { /* The bundled default remains usable if a path is malformed. */ }
  let opener;
  let pendingPath;
  let vendorLoad;
  let generation = 0;
  let dismissedGeneration;
  let stream;
  let timer;
  let onTrackEnd;
  let fallbackOpen = false;
  let backdrop;
  let background = [];
  const isOpen = () => fallbackOpen || Boolean(dialog.open);

  function openDialog() {
    if (isOpen()) return;
    if (typeof dialog.showModal === 'function' && typeof dialog.close === 'function') {
      try { dialog.showModal(); return; } catch { /* Use the accessible fallback below. */ }
    }
    fallbackOpen = true;
    dialog.setAttribute('open', '');
    dialog.setAttribute('data-qr-fallback-open', 'true');
    dialog.setAttribute('aria-modal', 'true');
    backdrop = document.createElement('div');
    backdrop.className = 'scanner-fallback-backdrop';
    backdrop.setAttribute('aria-hidden', 'true');
    dialog.parentElement.insertBefore(backdrop, dialog);
    document.body.classList.add('scanner-fallback-open');
    // Match native modal isolation, including browsers without inert support.
    let branch = dialog;
    for (let parent = dialog.parentElement; parent && parent !== document.documentElement; parent = parent.parentElement) {
      for (const sibling of parent.children) {
        if (sibling === branch || sibling === backdrop || ['SCRIPT', 'STYLE', 'LINK'].includes(sibling.tagName)) continue;
        background.push({ element: sibling, ariaHidden: sibling.getAttribute('aria-hidden'), inert: sibling.inert });
        sibling.setAttribute('aria-hidden', 'true');
        if ('inert' in sibling) sibling.inert = true;
      }
      branch = parent;
    }
    close.focus({ preventScroll: true });
  }

  function closeFallback() {
    fallbackOpen = false;
    dialog.removeAttribute('open');
    dialog.removeAttribute('data-qr-fallback-open');
    dialog.removeAttribute('aria-modal');
    backdrop?.remove(); backdrop = null;
    document.body.classList.remove('scanner-fallback-open');
    for (const saved of background) {
      if (saved.ariaHidden === null) saved.element.removeAttribute('aria-hidden');
      else saved.element.setAttribute('aria-hidden', saved.ariaHidden);
      if ('inert' in saved.element) saved.element.inert = saved.inert;
    }
    background = [];
  }

  function fallbackKeys(event) {
    if (!fallbackOpen) return;
    if (event.key === 'Escape') { event.preventDefault(); dismiss(); return; }
    if (event.key !== 'Tab') return;
    const controls = Array.from(dialog.querySelectorAll('button, a[href], input, select, textarea, [tabindex]'))
      .filter(control => !control.disabled && control.tabIndex !== -1 && !control.closest('[hidden]'));
    const first = controls[0] || close, last = controls[controls.length - 1] || close;
    const outside = !dialog.contains(document.activeElement);
    if ((event.shiftKey && (document.activeElement === first || outside)) ||
        (!event.shiftKey && (document.activeElement === last || outside))) {
      event.preventDefault(); (event.shiftKey ? last : first).focus();
    }
  }

  function confirmationPath(value) {
    // Check the original text before URL resolution can normalize dot segments or escapes.
    if (typeof value !== 'string' ||
        !/^(?:https?:\/\/[A-Za-z0-9.:\[\]-]+)?\/c\/[A-Za-z0-9_-]{1,100}$/.test(value)) return null;
    try {
      const url = new URL(value, location.origin);
      return url.origin === location.origin ? url.pathname : null;
    } catch {
      return null;
    }
  }

  function loadJsQR() {
    if (typeof window.jsQR === 'function') return Promise.resolve(window.jsQR);
    if (!vendorLoad) {
      vendorLoad = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = vendorURL.href;
        script.onload = () => typeof window.jsQR === 'function' ? resolve(window.jsQR) : reject();
        script.onerror = () => reject();
        document.head.append(script);
      }).catch(() => {
        vendorLoad = null;
        throw new Error('decoder');
      });
    }
    return vendorLoad;
  }

  async function canvasReader() {
    const decode = await loadJsQR();
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d', { willReadFrequently: true });
    if (!context) throw new Error('canvas');
    return () => {
      const scale = Math.min(1, 960 / Math.max(video.videoWidth, video.videoHeight));
      const width = Math.max(1, Math.round(video.videoWidth * scale));
      const height = Math.max(1, Math.round(video.videoHeight * scale));
      if (canvas.width !== width) canvas.width = width;
      if (canvas.height !== height) canvas.height = height;
      context.drawImage(video, 0, 0, width, height);
      const pixels = context.getImageData(0, 0, width, height);
      const result = decode(pixels.data, width, height);
      return result ? [result.data] : [];
    };
  }

  async function nativeDetector() {
    try {
      const detector = window.BarcodeDetector;
      if (detector && (await detector.getSupportedFormats()).includes('qr_code')) {
        return new detector({ formats: ['qr_code'] });
      }
    } catch { /* Some browsers expose the API without a working QR detector. */ }
    return null;
  }

  function message(text, english) {
    if (englishStatus && englishStatus.textContent !== english) englishStatus.textContent = english;
    if (status.textContent !== text) status.textContent = text;
  }

  function edited(field, form) {
    // A waiting two-stage check-in carries the previous report in hidden inputs.
    if (form.id === 'handoff-recheck' && field.type === 'hidden' && !field.disabled) {
      return (field.name === 'note' && Boolean(field.value)) || (field.name === 'is_abnormal' && field.value === 'on');
    }
    if (!field.name || field.disabled || ['hidden', 'submit', 'button', 'reset', 'image'].includes(field.type)) return false;
    if (field.type === 'file') return field.files.length > 0;
    // Failed check-ins and issue actions can return populated fields as HTML defaults.
    if (field.name === 'note') return Boolean(field.value);
    if (field.name === 'is_abnormal') return field.checked;
    if (field.type === 'checkbox' || field.type === 'radio') return field.checked !== field.defaultChecked;
    if (field.type === 'select-one') {
      const options = Array.from(field.options);
      const initial = options.filter(option => option.defaultSelected).pop() ||
        (field.size <= 1 ? options.find(option => !option.matches(':disabled')) : undefined);
      return options[field.selectedIndex] !== initial;
    }
    if (field.type === 'select-multiple') {
      return Array.from(field.options).some(option => option.selected !== option.defaultSelected);
    }
    return (field.tagName === 'INPUT' || field.tagName === 'TEXTAREA') && field.value !== field.defaultValue;
  }

  function hasDraft() {
    return Array.from(document.forms).some(form => form.method.toLowerCase() === 'post' &&
      Array.from(form.elements).some(field => edited(field, form)));
  }

  async function navigateToPoint(path, discardDraft = false) {
    // The offline helper may route to the generic shell; never follow another origin.
    const navigationGeneration = generation;
    const stillCurrent = () => generation === navigationGeneration && !isOpen() && !document.hidden;
    try {
      const route = window.PatrolOffline?.route;
      const destination = typeof route === 'function' ? await route(path) : path;
      if (!stillCurrent()) return;
      const url = new URL(destination || path, location.origin);
      if (url.origin !== location.origin) return;
      if (discardDraft) window.PatrolOffline?.allowNavigation?.();
      location.assign(url.pathname + url.search + url.hash);
    } catch {
      // Normal confirmation remains available if the optional helper is unavailable.
      if (stillCurrent()) {
        if (discardDraft) window.PatrolOffline?.allowNavigation?.();
        location.assign(path);
      }
    }
  }

  function clearDestination() {
    pendingPath = null;
    if (draftActions) draftActions.hidden = true;
  }

  function stopCamera() {
    ++generation;
    clearTimeout(timer);
    if (stream) {
      for (const track of stream.getTracks()) {
        track.removeEventListener('ended', onTrackEnd);
        track.stop();
      }
      stream = null;
    }
    video.pause();
    video.srcObject = null;
  }

  function dismiss() {
    stopCamera();
    clearDestination();
    if (isOpen()) {
      dismissedGeneration = generation;
      if (fallbackOpen) { closeFallback(); afterClose(); }
      else dialog.close();
    }
  }

  function active(run) {
    return run === generation && isOpen() && !document.hidden;
  }

  function failed(run, text, english) {
    if (!active(run)) return;
    stopCamera();
    message(text, english);
    retry.hidden = false;
  }

  async function begin() {
    stopCamera();
    clearDestination();
    const run = generation;
    openDialog();
    retry.hidden = true;
    if (document.querySelector('form[data-submitting="true"]')) {
      message('資料正在送出。請等候儲存完成後再掃描。', 'Saving. Please wait.');
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      message('此瀏覽器無法開啟相機。請用手機內建相機掃描巡檢點 QR Code。', 'Use your phone’s Camera app to scan.');
      return;
    }
    message('請允許使用相機，並將鏡頭對準巡檢點 QR Code。', 'Tap Allow to use the camera.');
    try {
      const acquired = await navigator.mediaDevices.getUserMedia({
        audio: false, video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }
      });
      if (!active(run)) {
        acquired.getTracks().forEach(track => track.stop());
        return;
      }
      stream = acquired;
      onTrackEnd = () => failed(run, '相機連線已中斷。請重新開啟相機。', 'Camera stopped. Tap Retry.');
      stream.getTracks().forEach(track => track.addEventListener('ended', onTrackEnd));
      video.srcObject = stream;
      await video.play();
      if (!active(run)) return;
    } catch (error) {
      const denied = error.name === 'NotAllowedError' || error.name === 'SecurityError';
      if (denied) {
        failed(run, '相機使用權限未開啟。請在瀏覽器設定中允許使用相機後重試，或改用手機內建相機掃描。',
          'Allow camera access in your browser settings, then tap Retry.');
      } else {
        failed(run, '無法開啟相機。請確認裝置有相機，並關閉其他使用相機的程式後重試。',
          'Close other camera apps, then tap Retry.');
      }
      return;
    }

    let detector = await nativeDetector();
    if (!active(run)) return;
    let fallback;
    message('請對準一張巡檢點 QR Code，掃到後會開啟打卡確認頁。', 'Point the camera at one QR code.');
    async function scan() {
      if (!active(run)) return;
      try {
        if (video.readyState >= 2 && video.videoWidth && video.videoHeight) {
          let values;
          if (detector) {
            try {
              const codes = await detector.detect(video);
              values = codes.filter(code => code.format === 'qr_code').map(code => code.rawValue);
            } catch {
              detector = null;
            }
            if (!active(run)) return;
          }
          if (!values) {
            fallback ||= await canvasReader();
            if (!active(run)) return;
            values = fallback();
          }
          const paths = new Set(values.map(confirmationPath).filter(Boolean));
          if (paths.size === 1) {
            const [path] = paths;
            if (hasDraft()) {
              stopCamera();
              if (draftActions && keep && discard) {
                // Validation errors render the same check-in at its POST URL.
                const samePoint = location.pathname === path || location.pathname === path + '/confirm' ||
                  document.querySelector('[data-offline-checkin]')?.dataset.pointPath === path;
                discard.hidden = samePoint;
                draftActions.hidden = false;
                if (samePoint) {
                  message('這是正在填寫的同一個點位，請返回表單繼續打卡。', 'This point is already open. Keep editing to finish your check-in.');
                } else {
                  pendingPath = path;
                  message('已掃到巡檢點。目前頁面有尚未送出的內容，前往巡檢點會放棄這些內容。',
                    'Leave this page and discard your changes?');
                }
                keep.focus();
              } else {
                message('目前頁面有尚未送出的內容。請關閉掃描視窗，處理完畢後再掃描。',
                  'Close the scanner to finish your changes first.');
              }
              return;
            }
            dismiss();
            await navigateToPoint(path);
            return;
          }
          if (paths.size > 1) message('畫面中有多個巡檢點。請靠近要打卡的點位，一次只掃一張。', 'Scan one QR code at a time.');
          else if (values.length) message('這張 QR Code 不是本站的巡檢點，請對準現場的巡檢點 QR Code。', 'Wrong QR code. Scan a patrol point.');
        }
      } catch {
        failed(run, '無法讀取相機畫面。請重試，或用手機內建相機掃描巡檢點 QR Code。', 'Cannot read the camera. Tap Retry.');
        return;
      }
      if (active(run)) timer = setTimeout(scan, 200);
    }
    scan();
  }

  starts.forEach(button => {
    button.addEventListener('click', () => {
      if (isOpen()) return;
      opener = button;
      begin();
    });
    button.hidden = false;
    button.setAttribute('data-qr-ready', 'true');
  });
  retry.addEventListener('click', begin);
  close.addEventListener('click', dismiss);
  keep?.addEventListener('click', dismiss);
  discard?.addEventListener('click', async () => {
    if (!pendingPath || !isOpen() || document.hidden) return;
    const path = pendingPath;
    dismiss();
    await navigateToPoint(path, true);
  });
  dialog.addEventListener('cancel', event => { event.preventDefault(); dismiss(); });
  function afterClose() {
    if (!isOpen()) {
      // Native dialog close is queued. An explicit dismiss already stopped this
      // scan; invalidating again can cancel its awaited offline destination.
      if (dismissedGeneration !== generation) stopCamera();
      clearDestination();
      if (!document.hidden) opener?.focus({ preventScroll: true });
    }
  }
  dialog.addEventListener('close', afterClose);
  document.addEventListener('keydown', fallbackKeys);
  document.addEventListener('focusin', event => {
    if (fallbackOpen && !dialog.contains(event.target)) close.focus({ preventScroll: true });
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) dismiss(); });
  window.addEventListener('pagehide', dismiss);
})();
