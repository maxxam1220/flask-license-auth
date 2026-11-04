/* Run with node --test tests/patrol-scanner.test.js. All camera and network I/O is simulated. */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const staticDir = path.resolve(__dirname, '../static');
const source = fs.readFileSync(path.join(staticDir, 'patrol-scanner.js'), 'utf8');
const origin = 'https://patrol.example.test';
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
const qr = rawValue => ({ format: 'qr_code', rawValue });

function delayed() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

function simulate(options = {}) {
  function element(props = {}) { return Object.assign(new EventTarget(), props); }
  const button = () => element({ hidden: true, focused: false, focus() { this.focused = true; } });
  const starts = [button(), button(), button()];
  const [start] = starts;
  const close = element();
  const draft = element({ hidden: true });
  const keep = button();
  const discard = button();
  const retry = element({ hidden: true });
  const status = element({ textContent: '' });
  const width = options.width || 1280;
  const video = element({ videoWidth: width, videoHeight: options.height || 720, readyState: 2,
    async play() {}, pause() {} });
  const hooks = { start, close, retry, status, video, keep, discard, 'draft-actions': draft };
  const lookup = selector => hooks[selector.match(/^\[data-qr-([\w-]+)\]$/)[1]];
  const dialog = element({ open: false, querySelector: lookup, showModal() { this.open = true; },
    close() { this.open = false; this.dispatchEvent(new Event('close')); } });
  hooks.dialog = dialog;
  const track = element({ stopped: false, stop() { this.stopped = true; } });
  const stream = { getTracks: () => [track] };
  const timers = new Map();
  const requests = [];
  const constraints = [];
  const destinations = [];
  const frames = [];
  let timerId = 0;
  const document = element({
    hidden: false, currentScript: { src: origin + '/static/patrol-scanner.js?v=1' },
    forms: options.forms || [],
    querySelector: selector => selector === 'form[data-submitting="true"]' ? (options.submitting ? {} : null) : lookup(selector),
    querySelectorAll: selector => { assert.equal(selector, '[data-qr-start]'); return starts; },
    head: { append(script) {
      requests.push(script.src);
      assert.equal(script.src, origin + '/static/vendor/jsqr-1.4.0.js');
      if (options.loadScript) options.loadScript(script, context);
      else { vm.runInContext(fs.readFileSync(path.join(staticDir, 'vendor/jsqr-1.4.0.js'), 'utf8'), context); script.onload(); }
    } },
    createElement(tag) {
      if (tag === 'script') return {};
      assert.equal(tag, 'canvas');
      return { getContext() { return {
        drawImage() {},
        getImageData(x, y, w, h) {
          frames.push([w, h]);
          return { data: options.pixels || new Uint8ClampedArray(w * h * 4) };
        }
      }; } };
    }
  });
  const window = element({
    document, URL, location: { origin, assign(value) { destinations.push(value); } },
    navigator: { mediaDevices: options.unsupported ? undefined : {
      getUserMedia(configuration) {
        constraints.push(configuration);
        return options.acquire ? options.acquire(stream) : Promise.resolve(stream);
      }
    } },
    setTimeout(fn) { timers.set(++timerId, fn); return timerId; },
    clearTimeout(id) { timers.delete(id); }
  });
  if (options.detect) {
    window.BarcodeDetector = class {
      static async getSupportedFormats() { return options.formats || ['qr_code']; }
      constructor(configuration) { assert.deepEqual([...configuration.formats], ['qr_code']); }
      detect() { return options.detect(); }
    };
  }
  window.window = window;
  const context = vm.createContext(window);
  vm.runInContext(source, context);
  function click(button) { button.dispatchEvent(new Event('click')); }
  async function step() {
    assert.equal(timers.size, 1, 'only one frame should be queued');
    const [[key, callback]] = timers;
    timers.delete(key);
    callback();
    await nextTurn();
  }
  return { start, starts, draft, keep, discard, close, retry, status, dialog, video, track, stream, document, window, frames,
    requests, constraints, destinations, timers, click, step };
}

test('opens only after user action, reads rear camera without audio, and navigates once', async () => {
  const s = simulate({ detect: () => [qr(origin + '/c/aB0_-'), qr('/c/aB0_-')] });
  assert.equal(s.start.hidden, false);
  assert.equal(s.constraints.length, 0);
  s.click(s.start);
  await nextTurn();
  assert.equal(s.constraints[0].video.facingMode.ideal, 'environment');
  assert.equal(s.constraints[0].audio, false);
  assert.deepEqual(s.destinations, ['/c/aB0_-']);
  assert.equal(s.track.stopped, true);
  assert.equal(s.video.srcObject, null);
  assert.equal(s.timers.size, 0);
  assert.deepEqual(s.requests, []);
});

test('all entries open the same camera and closing returns focus to the actual entry, even after retry', async () => {
  let attempt = 0;
  const s = simulate({ acquire: stream => {
    if (++attempt === 1) return Promise.reject(new Error('busy'));
    return Promise.resolve(stream);
  }, detect: () => [] });
  assert.ok(s.starts.every(button => button.hidden === false));
  const next = s.starts[2];
  s.click(next);
  await nextTurn();
  assert.equal(s.retry.hidden, false);
  s.click(s.retry);
  await nextTurn();
  s.click(s.close);
  assert.equal(next.focused, true);
  assert.equal(s.start.focused, false);
  s.click(s.starts[1]);
  await nextTurn();
  s.click(s.close);
  assert.equal(s.starts[1].focused, true);
});

const field = (name, value, defaultValue = '') => ({ tagName: 'INPUT', type: 'text', name, value, defaultValue });
const post = (...elements) => ({ method: 'post', elements });
const selectOne = (selectedIndex, explicitDefault = -1) => ({
  name: 'frequency', type: 'select-one', selectedIndex, size: 0, options: [0, 1].map(index => ({
    defaultSelected: index === explicitDefault, matches: () => false
  }))
});

for (const [kind, input] of [
  ['typed note', field('note', '異常')],
  ['restored note after server rejection', field('note', '保留內容', '保留內容')],
  ['restored abnormal flag', { type: 'checkbox', name: 'is_abnormal', checked: true, defaultChecked: true }],
  ['photo without text', { type: 'file', name: 'photos', files: [{}] }],
  ['new device label', field('label', '工作用手機')],
  ['changed admin point name', field('name', '新位置', '原位置')],
  ['changed implicit-default frequency', selectOne(1)],
  ['changed active flag', { type: 'checkbox', name: 'active', checked: false, defaultChecked: true }]
]) {
  test(kind + ' is retained on cancel; explicit discard can navigate exactly once', async () => {
    const s = simulate({ forms: [post(input)], detect: () => [qr('/c/next')] });
    s.click(s.starts[2]);
    await nextTurn();
    assert.equal(s.track.stopped, true);
    assert.equal(s.video.srcObject, null);
    assert.equal(s.draft.hidden, false);
    assert.equal(s.keep.focused, true);
    assert.deepEqual(s.destinations, []);
    s.click(s.keep);
    s.click(s.discard); // Late event after cancellation.
    assert.equal(s.draft.hidden, true);
    assert.equal(s.starts[2].focused, true);
    assert.deepEqual(s.destinations, []);
    s.click(s.starts[1]);
    await nextTurn();
    assert.equal(s.draft.hidden, false, 'the original form still has its draft');
    s.click(s.discard);
    s.click(s.discard);
    assert.deepEqual(s.destinations, ['/c/next']);
  });
}

test('clean or reverted form values, hidden state and GET report filters never interrupt a scan', async () => {
  const forms = [
    { method: 'get', elements: [field('date', '2026-11-04', '2026-11-03')] },
    post(field('name', '原位置', '原位置'), field('note', ''), selectOne(0), selectOne(1, 1),
      { type: 'hidden', name: 'csrf_token', value: 'token', defaultValue: '' },
      { type: 'checkbox', name: 'is_abnormal', checked: false }, { type: 'file', name: 'photos', files: [] })
  ];
  const s = simulate({ forms, detect: () => [qr('/c/already-completed')] });
  s.click(s.starts[2]);
  await nextTurn();
  assert.equal(s.draft.hidden, true);
  assert.deepEqual(s.destinations, ['/c/already-completed']);
});

test('backgrounding while a draft decision is pending prevents a late discard from navigating', async () => {
  const s = simulate({ forms: [post(field('note', '保留'))], detect: () => [qr('/c/other')] });
  s.click(s.start);
  await nextTurn();
  assert.equal(s.draft.hidden, false);
  s.document.hidden = true;
  s.document.dispatchEvent(new Event('visibilitychange'));
  s.document.hidden = false;
  s.click(s.discard);
  assert.equal(s.dialog.open, false);
  assert.deepEqual(s.destinations, []);
});

test('does not start a camera during an in-flight form submission', async () => {
  const s = simulate({ submitting: true, detect: () => [qr('/c/other')] });
  s.click(s.start);
  await nextTurn();
  assert.match(s.status.textContent, /正在送出/);
  assert.equal(s.constraints.length, 0);
  assert.deepEqual(s.destinations, []);
});

test('rejects untrusted, malformed, non-QR and ambiguous readings and keeps scanning', async () => {
  const invalid = ['https://elsewhere.test/c/t', '//patrol.example.test/c/t', 'http://patrol.example.test/c/t',
    origin + ':8443/c/t', 'https://x@patrol.example.test/c/t', 'https://%70atrol.example.test/c/t', origin + '/a/../c/t', '/c/%61',
    '/c/../logout', '/c/t/confirm', '/c/t?next=abc', '/c/t#', ' /c/t', '/c/' + 'a'.repeat(101),
    origin + '\\c\\t', 'javascript:alert(0)', 'data:text/html,hello', '/C/t'];
  const batches = [invalid.map(qr).concat([{ format: 'code_128', rawValue: '/c/bad' }]),
    [qr('/c/one'), qr('/c/two')], [qr('/c/' + 'x'.repeat(100))]];
  const s = simulate({ detect: () => batches.shift() });
  s.click(s.start);
  await nextTurn();
  assert.deepEqual(s.destinations, []);
  assert.match(s.status.textContent, /不是本站/);
  await s.step();
  assert.deepEqual(s.destinations, []);
  assert.match(s.status.textContent, /多個巡檢點/);
  await s.step();
  assert.deepEqual(s.destinations, ['/c/' + 'x'.repeat(100)]);
});

test('late camera permission after closure cannot attach the old stream to a reopened dialog', async () => {
  const permission = delayed();
  let requests = 0;
  const s = simulate({ acquire: stream => ++requests === 1 ? permission.promise : Promise.resolve(stream), detect: () => [] });
  s.click(s.start);
  s.click(s.close);
  s.click(s.start);
  await nextTurn();
  let oldStopped = false;
  permission.resolve({ getTracks: () => [{ stop() { oldStopped = true; } }] });
  await nextTurn();
  assert.equal(oldStopped, true);
  assert.equal(s.video.srcObject, s.stream);
  assert.equal(s.track.stopped, false);
  assert.equal(s.timers.size, 1);
  const cancel = new Event('cancel', { cancelable: true });
  s.dialog.dispatchEvent(cancel);
  assert.equal(cancel.defaultPrevented, true);
  assert.equal(s.track.stopped, true);
  assert.equal(s.start.focused, true);
});

for (const cause of ['visibilitychange', 'pagehide', 'close']) {
  test(cause + ' during native detection discards the result and releases the camera', async () => {
    const reading = delayed();
    const s = simulate({ detect: () => reading.promise });
    s.click(s.start);
    await nextTurn();
    assert.equal(s.timers.size, 0, 'do not decode concurrent frames');
    if (cause === 'visibilitychange') {
      s.document.hidden = true;
      s.document.dispatchEvent(new Event(cause));
    } else if (cause === 'pagehide') s.window.dispatchEvent(new Event(cause));
    else s.click(s.close);
    reading.resolve([qr('/c/expired')]);
    await nextTurn();
    assert.equal(s.track.stopped, true);
    assert.equal(s.video.srcObject, null);
    assert.deepEqual(s.destinations, []);
    assert.equal(s.timers.size, 0);
  });
}

test('permission denial and disconnected cameras explain recovery, no camera API offers system camera', async () => {
  const s = simulate({ acquire: async () => { throw Object.assign(new Error(), { name: 'NotAllowedError' }); } });
  s.click(s.start);
  await nextTurn();
  assert.equal(s.retry.hidden, false);
  assert.match(s.status.textContent, /權限/);
  assert.deepEqual(s.requests, []);
  const t = simulate({ detect: () => [] });
  t.click(t.start);
  await nextTurn();
  t.track.dispatchEvent(new Event('ended'));
  assert.equal(t.retry.hidden, false);
  assert.equal(t.timers.size, 0);
  assert.equal(t.video.srcObject, null);
  const u = simulate({ unsupported: true });
  u.click(u.start);
  assert.match(u.status.textContent, /手機內建相機/);
  assert.equal(u.constraints.length, 0);
});

test('runtime native failure falls back locally and bounds pixel processing', async () => {
  const s = simulate({ width: 4000, height: 3000, detect() { throw new Error('native failure'); },
    loadScript(script, context) { context.jsQR = () => ({ data: '/c/fallback' }); script.onload(); } });
  s.click(s.start);
  await nextTurn();
  assert.deepEqual(s.frames, [[960, 720]]);
  assert.equal(s.requests.length, 1);
  assert.deepEqual(s.destinations, ['/c/fallback']);
});

test('failed local decoder can be retried and loading after close cannot navigate', async () => {
  let loads = 0;
  let finishLoad;
  const s = simulate({ loadScript(script, context) {
    if (++loads === 1) script.onerror();
    else finishLoad = () => { context.jsQR = () => ({ data: '/c/late' }); script.onload(); };
  } });
  s.click(s.start);
  await nextTurn();
  assert.equal(s.retry.hidden, false);
  assert.equal(s.video.srcObject, null);
  s.click(s.retry);
  await nextTurn();
  s.click(s.close);
  finishLoad();
  await nextTurn();
  assert.deepEqual(s.destinations, []);
  assert.equal(loads, 2);
});

test('non-QR native detector falls back to bundled jsQR and decodes a real patrol QR', async () => {
  // Actual QR matrix for /c/QR_42-X, error correction M, with a four-module quiet zone.
  const rows = [
    '111111100000001111111','100000101000101000001','101110100010001011101','101110100111101011101',
    '101110101111101011101','100000100001001000001','111111101010101111111','000000000010000000000',
    '101010100000100010010','011000000011010011011','010110111001000011011','111100001001110101001',
    '111000101111000110010','000000001010001010111','111111100010111011001','100000100000000010011',
    '101110101010111101100','101110100011011001010','101110101101001111101','100000100101110110010',
    '111111101001001011111'
  ];
  const size = (rows.length + 8) * 4;
  const pixels = new Uint8ClampedArray(size * size * 4).fill(255);
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    if (rows[Math.floor(y / 4) - 4]?.[Math.floor(x / 4) - 4] !== '1') continue;
    const index = (y * size + x) * 4;
    pixels.fill(0, index, index + 3);
  }
  const s = simulate({ width: size, height: size, pixels, formats: ['code_128'],
    detect() { assert.fail('unsupported QR native detector was used'); } });
  s.click(s.start);
  await nextTurn();
  assert.equal(s.requests.length, 1);
  assert.deepEqual(s.destinations, ['/c/QR_42-X']);
});
