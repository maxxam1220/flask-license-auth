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
  const englishStatus = options.executor ? element({ textContent: '' }) : null;
  const width = options.width || 1280;
  const video = element({ videoWidth: width, videoHeight: options.height || 720, readyState: 2,
    async play() {}, pause() {} });
  const hooks = { start, close, retry, status, video, keep, discard, 'draft-actions': draft,
    'status-zh': status, 'status-en': englishStatus };
  const lookup = selector => {
    const match = selector.match(/^\[data-qr-([\w-]+)\]$/);
    return match ? hooks[match[1]] || null : null;
  };
  const dialog = element({ open: false, querySelector: lookup, showModal() { this.open = true; },
    close() { this.open = false; if (!options.delayedClose) this.dispatchEvent(new Event('close')); } });
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
    querySelector: selector => selector === 'form[data-submitting="true"]' ? (options.submitting ? {} : null) :
      selector === '[data-offline-checkin]' ? options.offlineForm || null : lookup(selector),
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
    PatrolOffline: options.route ? { route: options.route, allowNavigation: options.allowNavigation } : undefined,
    document, URL, location: { origin, pathname: options.pathname || '/dashboard', assign(value) { destinations.push(value); } },
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
  return { start, starts, draft, keep, discard, close, retry, status, englishStatus, dialog, video, track, stream, document, window, frames,
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

test('offline confirmation keeps same-point notes and photos and asks before routing elsewhere', async () => {
  let scanned = '/c/current';
  const routed = [];
  const offlineForm = post(field('note', '離線草稿'), { type: 'file', name: 'photos', files: [{}] });
  offlineForm.dataset = { pointPath: '/c/current' };
  const s = simulate({ pathname: '/offline', offlineForm, forms: [offlineForm], detect: () => [qr(scanned)],
    route: async path => { routed.push(path); return '/offline?point=' + path.slice(3); } });
  s.click(s.start);
  await nextTurn();
  assert.equal(s.draft.hidden, false);
  assert.equal(s.discard.hidden, true);
  assert.match(s.status.textContent, /同一個點位/);
  s.click(s.discard);
  await nextTurn();
  assert.deepEqual(routed, []);
  s.click(s.keep);
  scanned = '/c/next';
  s.click(s.start);
  await nextTurn();
  assert.equal(s.discard.hidden, false);
  assert.deepEqual(routed, []);
  s.click(s.discard);
  s.click(s.discard);
  await nextTurn();
  assert.deepEqual(routed, ['/c/next']);
  assert.deepEqual(s.destinations, ['/offline?point=next']);
  assert.equal(offlineForm.elements[0].value, '離線草稿');
  assert.equal(offlineForm.elements[1].files.length, 1);
});

test('offline routing waits for its destination after stopping the camera', async () => {
  const routeResult = delayed();
  const routed = [];
  const s = simulate({ detect: () => [qr('/c/next')], route: path => { routed.push(path); return routeResult.promise; } });
  s.click(s.start);
  await nextTurn();
  assert.equal(s.dialog.open, false);
  assert.equal(s.track.stopped, true);
  assert.deepEqual(routed, ['/c/next']);
  assert.deepEqual(s.destinations, []);
  routeResult.resolve('/offline?point=next');
  await nextTurn();
  assert.deepEqual(s.destinations, ['/offline?point=next']);
});

test('the queued native dialog close event preserves a pending offline destination', async () => {
  const routing = delayed();
  const s = simulate({ delayedClose: true, detect: () => [qr('/c/next')], route: () => routing.promise });
  s.click(s.start);
  await nextTurn();
  assert.equal(s.dialog.open, false);
  assert.deepEqual(s.destinations, []);
  s.dialog.dispatchEvent(new Event('close'));
  routing.resolve('/offline?point=next');
  await nextTurn();
  assert.deepEqual(s.destinations, ['/offline?point=next']);
});

test('confirmed discard releases the leave guard only when its destination is ready', async () => {
  const routing = delayed();
  let allowed = 0;
  const s = simulate({ delayedClose: true, forms: [post(field('note', 'draft'))],
    detect: () => [qr('/c/next')], route: () => routing.promise, allowNavigation: () => { allowed++; } });
  s.click(s.start);
  await nextTurn();
  s.click(s.discard);
  s.dialog.dispatchEvent(new Event('close'));
  assert.equal(allowed, 0);
  routing.resolve('/offline?point=next');
  await nextTurn();
  assert.equal(allowed, 1);
  assert.deepEqual(s.destinations, ['/offline?point=next']);
});

test('an interrupted discard route retains the leave guard and its draft', async () => {
  const routing = delayed();
  let allowed = 0;
  const s = simulate({ forms: [post(field('note', 'draft'))], detect: () => [qr('/c/next')],
    route: () => routing.promise, allowNavigation: () => { allowed++; } });
  s.click(s.start);
  await nextTurn();
  s.click(s.discard);
  s.document.hidden = true;
  s.document.dispatchEvent(new Event('visibilitychange'));
  routing.resolve('/offline?point=next');
  await nextTurn();
  assert.equal(allowed, 0);
  assert.deepEqual(s.destinations, []);
});

for (const interruption of ['new scan', 'background', 'pagehide']) {
  test('a delayed offline route cannot navigate after ' + interruption, async () => {
    const routing = delayed();
    let first = true;
    const s = simulate({ detect: () => first ? (first = false, [qr('/c/next')]) : [], route: () => routing.promise });
    s.click(s.start);
    await nextTurn();
    assert.equal(s.dialog.open, false);
    if (interruption === 'new scan') s.click(s.start);
    else if (interruption === 'background') {
      s.document.hidden = true;
      s.document.dispatchEvent(new Event('visibilitychange'));
    } else s.window.dispatchEvent(new Event('pagehide'));
    routing.resolve('/offline?point=next');
    await nextTurn();
    assert.deepEqual(s.destinations, []);
  });
}

test('an unavailable offline helper preserves normal navigation and cannot redirect to another origin', async () => {
  const failed = simulate({ detect: () => [qr('/c/next')], route: async () => { throw new Error('storage'); } });
  failed.click(failed.start);
  await nextTurn();
  assert.deepEqual(failed.destinations, ['/c/next']);
  const untrusted = simulate({ detect: () => [qr('/c/next')], route: async () => 'https://elsewhere.test/offline?point=next' });
  untrusted.click(untrusted.start);
  await nextTurn();
  assert.deepEqual(untrusted.destinations, []);
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

test('rescanning the current report preserves notes and photos, including after a rejected POST', async () => {
  for (const pathname of ['/c/current', '/c/current/confirm']) {
    let scanned = '/c/current';
    const forms = [post(field('note', '等待確認'), { type: 'file', name: 'photos', files: [{}] })];
    const s = simulate({ pathname, forms, detect: () => [qr(scanned)] });
    s.click(s.start);
    await nextTurn();
    assert.equal(s.track.stopped, true);
    assert.equal(s.draft.hidden, false);
    assert.equal(s.discard.hidden, true);
    assert.match(s.status.textContent, /同一個點位/);
    s.click(s.discard);
    assert.deepEqual(s.destinations, []);
    s.click(s.keep);
    scanned = '/c/different';
    s.click(s.start);
    await nextTurn();
    assert.equal(s.discard.hidden, false);
    s.click(s.discard);
    assert.deepEqual(s.destinations, [scanned]);
  }
});

test('does not start a camera during an in-flight form submission', async () => {
  const s = simulate({ submitting: true, detect: () => [qr('/c/other')] });
  s.click(s.start);
  await nextTurn();
  assert.match(s.status.textContent, /正在送出/);
  assert.equal(s.constraints.length, 0);
  assert.deepEqual(s.destinations, []);
});

test('rescanning while waiting for the next execution preserves the carried check-in draft', async () => {
  for (const [name, value] of [['note', '上一時段的現場備註'], ['is_abnormal', 'on']]) {
    let scanned = '/c/point';
    const form = post({ type: 'hidden', name: 'draft_point', value: '12' },
                      { type: 'hidden', name, value });
    form.id = 'handoff-recheck';
    const s = simulate({ forms: [form], pathname: '/c/point/confirm', detect: () => [qr(scanned)] });
    s.click(s.start);
    await nextTurn();
    assert.deepEqual(s.destinations, []);
    assert.equal(s.keep.focused, true);
    assert.equal(s.discard.hidden, true);
    s.click(s.keep);
    scanned = '/c/next';
    s.click(s.start);
    await nextTurn();
    assert.deepEqual(s.destinations, []);
    assert.equal(s.discard.hidden, false);
    s.click(s.discard);
    assert.deepEqual(s.destinations, ['/c/next']);
  }
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
  const s = simulate({ executor: true, acquire: async () => { throw Object.assign(new Error(), { name: 'NotAllowedError' }); } });
  s.click(s.start);
  assert.match(s.englishStatus.textContent, /Allow/);
  await nextTurn();
  assert.equal(s.retry.hidden, false);
  assert.match(s.status.textContent, /權限/);
  assert.match(s.englishStatus.textContent, /browser settings.*Retry/);
  assert.deepEqual(s.requests, []);
  const t = simulate({ executor: true, detect: () => [] });
  t.click(t.start);
  await nextTurn();
  assert.match(t.englishStatus.textContent, /one QR code/);
  t.track.dispatchEvent(new Event('ended'));
  assert.match(t.englishStatus.textContent, /Camera stopped.*Retry/);
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
