/* Calendar labels and immutable day-scoped drafts, without a live browser/service. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { IDBFactory } = require('fake-indexeddb');
const { createCore } = require('../static/offline.js');
const script = fs.readFileSync(path.join(__dirname, '../static/offline.js'), 'utf8');
const messages = JSON.parse(fs.readFileSync(path.join(__dirname, '../locales/calendar.json'), 'utf8'));

for (const locale of ['zh-Hant', 'id', 'vi']) test('fixed weekday labels remain explicit in ' + locale, () => {
  const module = { exports: {} };
  vm.runInNewContext(script, { module, PatrolI18n: { t: source => locale === 'zh-Hant' ? source : messages[source]?.[locale] || source } });
  const label = module.exports.frequencyLabel;
  assert.equal(label('weekly_wed'), locale === 'zh-Hant' ? '每週三' : messages['每週三'][locale]);
  assert.equal(label('weekly_fri'), locale === 'zh-Hant' ? '每週五' : messages['每週五'][locale]);
  assert.notEqual(label('weekly_fri'), label('daily'));
});

test('fixed weekday draft retains signed period and refresh cannot rewrite it', async t => {
  let now = Date.parse('2026-11-18T02:00:00Z');
  const response = value => new Response(JSON.stringify(value), { headers: { 'Content-Type': 'application/json' } });
  const manifest = { ok: true, version: 1, checklist_version: 1, owner: 'calendar-owner',
    identity: { id: 1, auth_version: 1, binding_id: 2, role: 'inspector' }, csrf_token: 'csrf',
    server_time: new Date(now).toISOString(), day: '2026-11-18', capture_until: '2026-11-18T16:00:00Z', sync_until: '2026-11-19T16:00:00Z',
    points: [{ id: 3, token: 'calendar-point', code: 'AB1-M01', name: 'Point', floor: 'B1', frequency: 'weekly_wed', workflow_mode: 'spot', stage: 'inspect',
      period_key: '2026-11-18', slots: ['any'], used_slots: [], executed_slots: [], grant: 'signed-wednesday', revision: 'revision-a', checklist: null }] };
  const sent = [];
  const core = createCore({ indexedDB: new IDBFactory(), broadcast: false, now: () => now, navigator: { onLine: true }, fetch: async (url, init) => {
    if (url.endsWith('/prepare')) return response(manifest);
    if (url.endsWith('/status')) return response({ ok: true, owner: manifest.owner, identity: manifest.identity, csrf_token: 'csrf', server_time: new Date(now).toISOString() });
    const row = JSON.parse(init.body.get('entry')); sent.push(row);
    return response({ ok: true, client_id: row.client_id, status: 'saved', record_id: 1 });
  } });
  t.after(() => core.close());
  await core.prepare();
  const queued = await core.enqueue({ token: 'calendar-point' });
  await assert.rejects(core.enqueue({ token: 'calendar-point' }), { code: 'quota' });
  now += 86400000;
  Object.assign(manifest, { server_time: new Date(now).toISOString(), day: '2026-11-19', capture_until: '2026-11-19T16:00:00Z', sync_until: '2026-11-20T16:00:00Z' });
  Object.assign(manifest.points[0], { period_key: '2026-11-19', grant: 'signed-thursday' });
  await core.prepare();
  const previous = (await core.getState()).queue.find(row => row.client_id === queued.client_id);
  assert.equal(previous.day, '2026-11-18');
  await core.sync({ client_id: queued.client_id });
  assert.equal(sent[0].grant, 'signed-wednesday');
  assert.equal(sent[0].observed_at, '2026-11-18T02:00:00.000Z');
  assert.equal((await core.getState()).pending, 0);
});
