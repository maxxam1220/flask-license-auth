/* Scan locally. A successful read only opens the existing confirmation page. */
(() => {
  const starts = document.querySelectorAll('[data-qr-start]');
  const dialog = document.querySelector('[data-qr-dialog]');
  if (!starts.length || !dialog || typeof dialog.showModal !== 'function') return;

  const video = dialog.querySelector('[data-qr-video]');
  const status = dialog.querySelector('[data-qr-status]');
  const retry = dialog.querySelector('[data-qr-retry]');
  const close = dialog.querySelector('[data-qr-close]');
  const draftActions = dialog.querySelector('[data-qr-draft-actions]');
  const keep = dialog.querySelector('[data-qr-keep]');
  const discard = dialog.querySelector('[data-qr-discard]');
  const vendorURL = new URL('vendor/jsqr-1.4.0.js', document.currentScript.src);
  let opener;
  let pendingPath;
  let vendorLoad;
  let generation = 0;
  let stream;
  let timer;
  let onTrackEnd;

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

  function message(text) {
    if (status.textContent !== text) status.textContent = text;
  }

  function edited(field) {
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
      Array.from(form.elements).some(edited));
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
    if (dialog.open) dialog.close();
  }

  function active(run) {
    return run === generation && dialog.open && !document.hidden;
  }

  function failed(run, text) {
    if (!active(run)) return;
    stopCamera();
    message(text);
    retry.hidden = false;
  }

  async function begin() {
    stopCamera();
    clearDestination();
    const run = generation;
    if (!dialog.open) dialog.showModal();
    retry.hidden = true;
    if (document.querySelector('form[data-submitting="true"]')) {
      message('資料正在送出。請等候儲存完成後再掃描。');
      return;
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      message('此瀏覽器無法開啟相機。請用手機內建相機掃描巡檢點 QR Code。');
      return;
    }
    message('請允許使用相機，並將鏡頭對準巡檢點 QR Code。');
    try {
      const acquired = await navigator.mediaDevices.getUserMedia({
        audio: false, video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } }
      });
      if (!active(run)) {
        acquired.getTracks().forEach(track => track.stop());
        return;
      }
      stream = acquired;
      onTrackEnd = () => failed(run, '相機連線已中斷。請重新開啟相機。');
      stream.getTracks().forEach(track => track.addEventListener('ended', onTrackEnd));
      video.srcObject = stream;
      await video.play();
      if (!active(run)) return;
    } catch (error) {
      const denied = error.name === 'NotAllowedError' || error.name === 'SecurityError';
      failed(run, denied
        ? '相機使用權限未開啟。請在瀏覽器設定中允許使用相機後重試，或改用手機內建相機掃描。'
        : '無法開啟相機。請確認裝置有相機，並關閉其他使用相機的程式後重試。');
      return;
    }

    let detector = await nativeDetector();
    if (!active(run)) return;
    let fallback;
    message('請對準一張巡檢點 QR Code，掃到後會開啟打卡確認頁。');
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
                pendingPath = path;
                draftActions.hidden = false;
                message('已掃到巡檢點。目前頁面有尚未送出的內容，前往巡檢點會放棄這些內容。');
                keep.focus();
              } else {
                message('目前頁面有尚未送出的內容。請關閉掃描視窗，處理完畢後再掃描。');
              }
              return;
            }
            dismiss();
            location.assign(path);
            return;
          }
          if (paths.size > 1) message('畫面中有多個巡檢點。請靠近要打卡的點位，一次只掃一張。');
          else if (values.length) message('這張 QR Code 不是本站的巡檢點，請對準現場的巡檢點 QR Code。');
        }
      } catch {
        failed(run, '無法讀取相機畫面。請重試，或用手機內建相機掃描巡檢點 QR Code。');
        return;
      }
      if (active(run)) timer = setTimeout(scan, 200);
    }
    scan();
  }

  starts.forEach(button => {
    button.addEventListener('click', () => {
      if (dialog.open) return;
      opener = button;
      begin();
    });
    button.hidden = false;
  });
  retry.addEventListener('click', begin);
  close.addEventListener('click', dismiss);
  keep?.addEventListener('click', dismiss);
  discard?.addEventListener('click', () => {
    if (!pendingPath || !dialog.open || document.hidden) return;
    const path = pendingPath;
    dismiss();
    location.assign(path);
  });
  dialog.addEventListener('cancel', event => { event.preventDefault(); dismiss(); });
  dialog.addEventListener('close', () => {
    if (!dialog.open) {
      stopCamera();
      clearDestination();
      if (!document.hidden) opener?.focus({ preventScroll: true });
    }
  });
  document.addEventListener('visibilitychange', () => { if (document.hidden) dismiss(); });
  window.addEventListener('pagehide', dismiss);
})();
