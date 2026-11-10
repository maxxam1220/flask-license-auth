/* Isolated IndexedDB exercises; no production data or network. */
const test = require('node:test');
const assert = require('node:assert/strict');
const { indexedDB } = require('fake-indexeddb');
const { createCore, validateChecklist, validChecklistDefinition, formChecklist } = require('../static/offline.js');
const stamp = Date.parse('2026-11-09T02:00:00Z');
const words = text => ({ 'zh-Hant': text, id: 'ID ' + text, vi: 'VI ' + text });
const definition = () => ({ key: 'dining_v1', version: 1, title: words('餐廳點檢'), items: [
  { id: 'dining.a1', label: words('洗手槽'), source_code: 'A1' },
  { id: 'dining.a2', label: words('廚餘箱'), source_code: 'A2' }
] });
const response = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
function fixture(t, stage = 'inspect') {
  const dbName = 'offline-checklist-' + crypto.randomUUID();
  const state = { uploads: [], now: stamp, navigator: { onLine: true }, reply: null, manifest: {
    ok: true, version: 1, checklist_version: 1, owner: 'test-owner', identity: { id: 12, auth_version: 1, binding_id: 8, name: 'Test' },
    server_time: new Date(stamp).toISOString(), day: '2026-11-09', capture_until: '2026-11-09T16:00:00Z', sync_until: '2026-11-10T16:00:00Z', csrf_token: 'csrf',
    points: [{ id: 1, token: 'test-point', code: '4M-G01', name: 'Test dining', floor: '4M', frequency: 'daily2', workflow_mode: 'two_stage', stage,
      period_key: '2026-11-09', slots: ['am', 'pm'], used_slots: [], executed_slots: [], grant: 'original-grant', revision: 'revision-1', checklist: definition() }]
  } };
  const make = () => {
    const core = createCore({ indexedDB, databaseName: dbName, now: () => state.now, navigator: state.navigator, broadcast: false,
      fetch: async (url, init) => {
        if (url.endsWith('/prepare')) return response(state.manifest);
        if (url.endsWith('/status')) return response({ ok: true, owner: state.manifest.owner, csrf_token: 'fresh' });
        const entry = JSON.parse(init.body.get('entry')); state.uploads.push({ entry, photos: init.body.getAll('photos') });
        return state.reply ? state.reply(entry) : response({ ok: true, client_id: entry.client_id, status: 'saved' });
      } });
    t.after(() => core.close()); return core;
  };
  return { state, dbName, make, core: make() };
}
async function storeRows(dbName, name, change) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(dbName); request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result, tx = db.transaction([name], change ? 'readwrite' : 'readonly'), store = tx.objectStore(name), query = store.getAll();
      let values;
      query.onsuccess = () => { values = query.result; if (change) for (const row of values) { change(row); store.put(row); } };
      tx.oncomplete = () => { db.close(); resolve(values); }; tx.onabort = () => { db.close(); reject(tx.error); };
    };
  });
}
const input = { token: 'test-point', checklist: ['dining.a1'] };

for (const stage of ['execute', 'visit', 'inspect']) {
  test(`${stage} requires one checked item and saves a detached catalog snapshot`, async t => {
    const h = fixture(t, stage); await h.core.prepare();
    await assert.rejects(h.core.enqueue({ token: input.token }), { code: 'checklist' });
    await assert.rejects(h.core.enqueue({ ...input, checklist: [] }), { code: 'checklist' });
    assert.deepEqual((await h.core.getPoint(input.token)).availableSlots, ['am', 'pm']);
    const selected = ['dining.a2', 'dining.a1'];
    const saved = await h.core.enqueue({ ...input, checklist: selected }); selected.length = 0;
    const [row] = await storeRows(h.dbName, 'queue');
    assert.deepEqual(row.checklist, ['dining.a1', 'dining.a2']);
    assert.deepEqual(row.checklist_snapshot, { ...definition(), selected: ['dining.a1', 'dining.a2'] });
    assert.equal(saved.client_id, row.client_id); assert.equal(row.slot, 'am');
    await h.core.sync(); const payload = h.state.uploads[0].entry;
    assert.deepEqual(payload.checklist, row.checklist); assert(!Object.hasOwn(payload, 'checklist_snapshot'));
    assert.deepEqual((await h.core.getState()).receipts[0].checklist_snapshot, row.checklist_snapshot);
  });
}

for (const selected of [null, 'dining.a1', {}, [1], ['dining.a1', 'dining.a1'], ['foreign.item'], ['dining.a1', 'foreign.item']]) {
  test(`invalid selection ${JSON.stringify(selected)} never consumes a round`, async t => {
    const h = fixture(t); await h.core.prepare();
    await assert.rejects(h.core.enqueue({ ...input, checklist: selected }), { code: 'checklist' });
    assert.equal((await h.core.getState()).pending, 0);
    assert.equal((await h.core.enqueue(input)).slot, 'am');
  });
}

test('non-checklist point keeps normal capture and rejects fabricated selections', async t => {
  const h = fixture(t); h.state.manifest.points[0].checklist = null; await h.core.prepare();
  await assert.rejects(h.core.enqueue(input), { code: 'checklist' });
  const row = await h.core.enqueue({ token: input.token }); assert.deepEqual(row.checklist, []); assert.equal(row.checklist_snapshot, null);
});

for (const alter of [
  value => { delete value.checklist_version; }, value => { value.checklist_version = 2; },
  value => { delete value.points[0].checklist; }, value => { value.points[0].checklist.version = 2; },
  value => { value.points[0].checklist.items = []; }, value => { value.points[0].checklist.items[0].label.vi = ''; },
  value => { value.points[0].checklist.items[1].id = value.points[0].checklist.items[0].id; },
]) {
  test('incomplete manifest capability fails closed: ' + alter.toString(), async t => {
    const h = fixture(t); alter(h.state.manifest);
    await assert.rejects(h.core.prepare(), { code: 'checklist_update' });
    assert.equal((await h.core.getState()).prepared, false); assert.equal((await h.core.getState()).pending, 0);
  });
}

test('a legacy manifest permits old queue sync but never new capture', async t => {
  const h = fixture(t); await h.core.prepare(); await h.core.enqueue(input);
  await storeRows(h.dbName, 'queue', row => { delete row.checklist; delete row.checklist_snapshot; });
  await storeRows(h.dbName, 'manifests', value => { delete value.checklist_version; delete value.points[0].checklist; });
  const reloaded = h.make(), state = await reloaded.getState();
  assert.equal(state.prepared, false); assert.equal(state.needsChecklistUpdate, true); assert.equal(state.pending, 1); assert.equal(state.locked, false);
  await assert.rejects(reloaded.enqueue(input), { code: 'checklist_update' });
  await reloaded.sync(); assert.equal((await reloaded.getState()).pending, 0);
  assert(!Object.hasOwn(h.state.uploads[0].entry, 'checklist'));
  assert(!Object.hasOwn((await reloaded.getState()).receipts[0], 'checklist'));
});

test('old lost-ACK retry preserves exact original bytes after new preparation', async t => {
  const h = fixture(t); await h.core.prepare();
  const photo = new File(['photo bytes'], 'evidence.jpg', { type: 'image/jpeg' });
  const saved = await h.core.enqueue({ ...input, note: '原備註', photos: [photo] });
  await storeRows(h.dbName, 'queue', row => { delete row.checklist; delete row.checklist_snapshot; });
  let original;
  h.state.reply = entry => { original = JSON.stringify(entry); throw new TypeError('Lost ACK'); };
  await h.core.sync(); assert.equal((await h.core.getState()).pending, 1);
  h.state.manifest.points[0].grant = 'new-grant'; h.state.manifest.points[0].revision = 'revision-2';
  h.state.manifest.points[0].checklist.items[0].label.vi = 'New wording'; await h.core.prepare();
  const pending = (await h.core.getState()).queue[0]; assert.equal(pending.client_id, saved.client_id); assert.equal(pending.checklist_review_required, true);
  assert(!Object.hasOwn(pending, 'checklist'));
  h.state.reply = entry => { assert.equal(JSON.stringify(entry), original); return response({ ok: true, client_id: entry.client_id, status: 'already_synced' }); };
  await h.core.sync(); assert.equal((await h.core.getState()).pending, 0);
  assert.equal(h.state.uploads[1].entry.grant, 'original-grant'); assert.equal(await h.state.uploads[1].photos[0].text(), 'photo bytes');
});

test('old missing checklist rejection retains UUID, grant, notes and photos until explicit removal', async t => {
  const h = fixture(t); await h.core.prepare();
  const saved = await h.core.enqueue({ ...input, note: '保留', is_abnormal: true, photos: [new File(['blob'], 'a.png', { type: 'image/png' })] });
  await storeRows(h.dbName, 'queue', row => { delete row.checklist; delete row.checklist_snapshot; });
  h.state.reply = () => response({ ok: false, code: 'checklist', retryable: false, message: '點檢項目未勾選或已變更，暫存仍保留。' }, 409);
  await h.core.sync(); const state = await h.core.getState(), [row] = await storeRows(h.dbName, 'queue');
  assert.equal(state.locked, false); assert.equal(state.pending, 1); assert.equal(state.blocked, 1);
  assert.equal(row.client_id, saved.client_id); assert.equal(row.grant, 'original-grant'); assert.equal(row.note, '保留');
  assert.equal(await row.photos[0].blob.text(), 'blob'); assert(!Object.hasOwn(row, 'checklist'));
  await assert.rejects(h.core.remove(row.client_id), { code: 'confirm' });
  assert.deepEqual((await h.core.getPoint(input.token)).availableSlots, ['pm']);
  await h.core.remove(row.client_id, true); assert.equal((await h.core.getState()).pending, 0);
});

test('preparation cannot rewrite saved snapshot, selections or signed grant', async t => {
  const h = fixture(t); await h.core.prepare(); await h.core.enqueue(input);
  const [before] = await storeRows(h.dbName, 'queue');
  h.state.manifest.points[0].checklist.items[0].label['zh-Hant'] = 'Updated'; h.state.manifest.points[0].grant = 'new-grant';
  await h.core.prepare(); const [after] = await storeRows(h.dbName, 'queue'); assert.deepEqual(after, before);
  await h.core.sync(); assert.deepEqual(h.state.uploads[0].entry.checklist, ['dining.a1']);
  assert.equal((await h.core.getState()).receipts[0].checklist_snapshot.items[0].label['zh-Hant'], '洗手槽');
});

test('normal old revision cannot silently reinterpret selected item IDs after refresh', async t => {
  const h = fixture(t); await h.core.prepare(); const p = await h.core.getPoint(input.token);
  const expected = { user_id: p.identity.id, auth_version: p.identity.auth_version, day: p.day, stage: p.stage,
    frequency: p.frequency, workflow_mode: p.workflow_mode, period_key: p.period_key, revision: p.revision, slot: 'am' };
  h.state.manifest.points[0].revision = 'new-checklist'; await h.core.prepare();
  await assert.rejects(h.core.enqueue({ ...input, expected }), { code: 'stale' }); assert.equal((await h.core.getState()).pending, 0);
});

test('form draft detection includes checked choices, with no automatic select-all', () => {
  const choices = [{ checked: false, value: 'dining.a1' }, { checked: true, value: 'dining.a2' }];
  assert.deepEqual(formChecklist({ querySelectorAll: () => choices }), ['dining.a2']);
  assert.deepEqual(formChecklist(null), []); assert.equal(choices[0].checked, false);
  assert.deepEqual(validateChecklist(definition(), ['dining.a2']), ['dining.a2']);
  assert.equal(validChecklistDefinition(undefined), false); assert.equal(validChecklistDefinition(null), true);
});

for (const stage of ['execute', 'inspect']) {
  test(`retiring the food checklist preserves pending ${stage} evidence while new capture needs no choices`, async t => {
    const h = fixture(t, stage); await h.core.prepare();
    const first = await h.core.enqueue(input);
    const [original] = await storeRows(h.dbName, 'queue');
    h.state.manifest.points[0].checklist = null;
    h.state.manifest.points[0].revision = 'no-food-checklist';
    h.state.manifest.points[0].grant = 'no-food-checklist-grant';
    await h.core.prepare();
    const [retained] = await storeRows(h.dbName, 'queue');
    assert.deepEqual(retained, original);
    const current = await h.core.getPoint(input.token);
    assert.equal(current.checklist, null);
    assert.deepEqual(current.availableSlots, ['pm']);
    await assert.rejects(h.core.enqueue(input), { code: 'checklist' });
    const next = await h.core.enqueue({ token: input.token });
    assert.equal(next.slot, 'pm');
    const pending = (await storeRows(h.dbName, 'queue')).find(row => row.client_id === next.client_id);
    assert.deepEqual(pending.checklist, []);
    assert.equal(pending.checklist_snapshot, null);
    await h.core.sync();
    const oldUpload = h.state.uploads.find(row => row.entry.client_id === first.client_id);
    const newUpload = h.state.uploads.find(row => row.entry.client_id === next.client_id);
    assert.equal(oldUpload.entry.grant, 'original-grant');
    assert.deepEqual(oldUpload.entry.checklist, ['dining.a1']);
    assert.equal(newUpload.entry.grant, 'no-food-checklist-grant');
    assert.deepEqual(newUpload.entry.checklist, []);
    const receipts = (await h.core.getState()).receipts;
    assert.deepEqual(receipts.find(row => row.client_id === first.client_id).checklist_snapshot, original.checklist_snapshot);
    assert.equal(receipts.find(row => row.client_id === next.client_id).checklist_snapshot, null);
  });
}

test('retiring a food checklist does not silently submit an open form from its previous definition', async t => {
  const h = fixture(t); await h.core.prepare();
  const p = await h.core.getPoint(input.token);
  const expected = { user_id: p.identity.id, auth_version: p.identity.auth_version, day: p.day, stage: p.stage,
    frequency: p.frequency, workflow_mode: p.workflow_mode, period_key: p.period_key, revision: p.revision, slot: 'am' };
  h.state.manifest.points[0].checklist = null;
  h.state.manifest.points[0].revision = 'no-food-checklist';
  await h.core.prepare();
  await assert.rejects(h.core.enqueue({ ...input, expected }), { code: 'stale' });
  assert.equal((await h.core.getState()).pending, 0);
  assert.equal((await h.core.enqueue({ token: input.token })).slot, 'am');
});
