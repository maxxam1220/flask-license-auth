/* Pure local catalog/runtime validation; no network or production data. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const catalog = JSON.parse(fs.readFileSync(path.join(root, 'locales/client.json'), 'utf8'));
const placeholders = value => [...value.matchAll(/\{([A-Za-z_][A-Za-z_0-9]*)\}/g)].map(match => match[1]).sort();

function runtime(locale) {
  const document = new EventTarget();
  document.readyState = 'complete'; document.documentElement = {};
  document.getElementById = () => null; document.querySelectorAll = () => [];
  class DetailEvent extends Event { constructor(type, options) { super(type); this.detail = options.detail; } }
  const window = { PATROL_I18N: { locale, messages: catalog } };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'static/i18n.js'), 'utf8'), { window, document, CustomEvent: DetailEvent });
  return window.PatrolI18n;
}

test('all client translations are complete and preserve every named parameter', () => {
  assert(Object.keys(catalog).length >= 160);
  for (const [source, translations] of Object.entries(catalog)) {
    for (const locale of ['id', 'vi']) {
      const text = translations[locale];
      assert.equal(typeof text, 'string', source); assert(text.trim(), source);
      assert(!/[\u4e00-\u9fff]/.test(text), source + ': untranslated Chinese');
      assert.deepEqual(placeholders(text), placeholders(source), source + ': lost parameters');
    }
  }
});

test('every static Chinese client source has a translation catalog entry', () => {
  for (const filename of ['offline.js', 'patrol-scanner.js', 'app.js', 'ready-refresh.js', 'offline-sw.js']) {
    const source = fs.readFileSync(path.join(root, 'static', filename), 'utf8');
    for (const match of source.matchAll(/'((?:\\.|[^'\\\r\n])*)'|"((?:\\.|[^"\\\r\n])*)"/g)) {
      const text = match[1] ?? match[2];
      if (!/[\u4e00-\u9fff]/.test(text)) continue;
      const value = vm.runInNewContext(match[0]);
      assert(catalog[value], filename + ': ' + value);
    }
  }
});

for (const locale of ['id', 'vi']) {
  test('dynamic sync/photo messages translate in ' + locale + ' while user values remain exact', () => {
    const i18n = runtime(locale);
    const source = '移除照片 {number}：{name}', name = '現場照片-Budi-Nguyễn.jpg';
    assert.equal(i18n.t(source, { number: 2, name }), catalog[source][locale].replace('{number}', '2').replace('{name}', name));
    const summary = '已確認 {count} 筆；其餘未確認資料仍保留在此手機。';
    assert.equal(i18n.t('已確認 2 筆；其餘未確認資料仍保留在此手機。'), catalog[summary][locale].replace('{count}', '2'));
    assert.equal(i18n.t('Unknown custom point / 原始姓名'), 'Unknown custom point / 原始姓名');
    i18n.setLocale('zh-Hant'); assert.equal(i18n.t('移除'), '移除');
    assert.equal(i18n.t(source, { number: 2, name }), '移除照片 2：' + name);
  });
}
