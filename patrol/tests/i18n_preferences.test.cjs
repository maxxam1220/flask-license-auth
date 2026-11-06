'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const code = fs.readFileSync(require('node:path').join(__dirname, '../static/i18n.js'), 'utf8');

function setup({shell = true, locale = 'zh-Hant', query = '', stored, simple = false, denyStorage = false, loading = false} = {}) {
  const attributes = new Set(shell ? ['data-offline-page'] : []), callbacks = {}, events = [], writes = [];
  const label = {textContent: '同步', hasAttribute: key => key === 'data-i18n', getAttribute: () => '同步'};
  const document = {
    readyState: loading ? 'loading' : 'complete',
    documentElement: {lang: '', hasAttribute: name => attributes.has(name), setAttribute: name => attributes.add(name), removeAttribute: name => attributes.delete(name)},
    body: {classList: {contains: name => name === 'simple-executor-ui' && simple}},
    getElementById: () => null, querySelectorAll: () => [label],
    addEventListener: (name, fn) => {callbacks[name] = fn;}, dispatchEvent: event => events.push(event)
  };
  const window = {location: {search: query}, PATROL_I18N: {locale, messages: {'同步': {id: 'Sinkron', vi: 'Đồng bộ'}}},
    sessionStorage: {getItem() {if (denyStorage) throw Error('denied'); return stored ? JSON.stringify(stored) : null;},
      setItem(key, value) {if (denyStorage) throw Error('denied'); writes.push({key, value: JSON.parse(value)});}}};
  vm.runInNewContext(code, {window, document, URLSearchParams, CustomEvent: function (name, detail) {this.type = name; this.detail = detail.detail;}});
  return {api: window.PatrolI18n, document, attributes, callbacks, events, label, writes};
}
const plain = value => JSON.parse(JSON.stringify(value));

test('unbound shell uses an explicit whitelisted language without private identity', () => {
  const {api, label} = setup({query: '?lang=vi&home=ready'});
  assert.equal(label.textContent, 'Đồng bộ');
  assert.deepEqual(plain(api.getPreferences(null)), {ui_language: 'vi', simple_executor_ui: true, home_url: '/ready'});
});

test('current authenticated preference supersedes query and keeps storage presentation-only', () => {
  const {api, writes} = setup({query: '?lang=id&home=ready'});
  assert(api.acceptPreferences({ui_language: 'vi', simple_executor_ui: false, home_url: 'https://wrong.invalid/', id: 42, name: 'Private name', grant: 'private'}));
  assert.deepEqual(plain(api.getPreferences(null)), {ui_language: 'vi', simple_executor_ui: false, home_url: '/dashboard'});
  assert.deepEqual(writes.at(-1).value, {ui_language: 'vi', simple_executor_ui: false, home_url: '/dashboard'});
  assert.equal(api.getLocale(), 'vi');
});

test('valid manifest beats stale session preference while legacy manifest uses the hint', () => {
  const {api} = setup({stored: {ui_language: 'id', simple_executor_ui: true}});
  assert.equal(api.getPreferences({ui_language: 'vi', role: 'executor', simple_executor_ui: true}).ui_language, 'vi');
  assert.equal(api.getPreferences({role: 'executor'}).ui_language, 'id');
  assert.equal(api.getPreferences({ui_language: 'vi', role: 'inspector', simple_executor_ui: true}).simple_executor_ui, false);
});

test('default Chinese server page replaces an older foreign account hint', () => {
  const {api, writes} = setup({shell: false, locale: 'zh-Hant', stored: {ui_language: 'id', simple_executor_ui: true}});
  assert.equal(api.getPreferences(null).ui_language, 'zh-Hant');
  assert.deepEqual(writes.at(-1).value, {ui_language: 'zh-Hant', simple_executor_ui: false, home_url: '/dashboard'});
});

test('same-language preference update changes home without a false language event', () => {
  const {api, events} = setup({query: '?lang=id'});
  assert(api.acceptPreferences({ui_language: 'id', simple_executor_ui: true}));
  assert.equal(api.getPreferences(null).home_url, '/ready');
  assert.equal(events.length, 0);
});

test('invalid query and response values cannot select an arbitrary locale or route', () => {
  const {api, writes} = setup({query: '?lang=not-supported&home=https://wrong.invalid/', stored: {ui_language: 'vi', simple_executor_ui: false}});
  assert.equal(api.getLocale(), 'vi');
  assert.equal(api.acceptPreferences({ui_language: 'unsupported', simple_executor_ui: true}), false);
  assert.equal(api.getPreferences(null).home_url, '/dashboard');
  assert.equal(writes.length, 0);
});

test('denied session storage does not break online labels or public shell', () => {
  const online = setup({shell: false, locale: 'vi', simple: true, denyStorage: true});
  assert.equal(online.label.textContent, 'Đồng bộ');
  assert.equal(online.api.getPreferences(null).home_url, '/ready');
  const offline = setup({query: '?lang=id', denyStorage: true});
  assert.equal(offline.label.textContent, 'Sinkron');
});

test('early foreign shell stays pending only until DOM labels are translated', () => {
  const {api, attributes, callbacks, label} = setup({query: '?lang=vi', loading: true});
  assert.equal(api.getLocale(), 'vi');
  assert(attributes.has('data-offline-locale-pending'));
  callbacks.DOMContentLoaded();
  assert.equal(label.textContent, 'Đồng bộ');
  assert(!attributes.has('data-offline-locale-pending'));
});
