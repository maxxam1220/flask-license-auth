/* Exercise actual management-form validation, including toilet-specific codes. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

async function page(t, options = {}) {
  const floors = [[-2, 'B2'], [-1, 'B1'], [1, '1F'], [11, '1M'], [2, '2F'],
    [3, '3F'], [4, '4F'], [14, '4M'], [5, '5F'], [15, '5M']];
  const original = options.original || '';
  const dom = new JSDOM(`<div id="official-general-codes" data-codes='${JSON.stringify(options.catalog || {})}'></div>
    <form data-point-form data-original-code="${original}" data-original-floor="${options.floor || -1}">
    <input type="radio" name="category" value="general" checked><input type="radio" name="category" value="safety">
    <select name="floor">${floors.map(([value, label]) => `<option value="${value}" ${value === (options.floor || -1) ? 'selected' : ''}>${label}</option>`).join('')}</select>
    <input name="code" required maxlength="23" pattern="[A-Za-z0-9]+(?:-[A-Za-z0-9]+)?" value="${options.code || original || 'AB1-M01'}">
    <input name="name" required value="${options.name || 'b1男廁所-甲'}"><button>Save</button></form>`,
    { runScripts: 'outside-only', url: 'https://patrol.example.test/admin/points' });
  t.after(() => dom.window.close());
  dom.window.eval(fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8'));
  await new Promise(resolve => dom.window.document.addEventListener('DOMContentLoaded', resolve, { once: true }));
  const form = dom.window.document.querySelector('form');
  const set = (name, value, event = 'input') => {
    const field = form.elements.namedItem(name);
    field.value = value;
    const target = name === 'category' ? form.querySelector(`input[name=category][value="${value}"]`) : field;
    target.dispatchEvent(new dom.window.Event(event, { bubbles: true }));
  };
  return { form, set, code: form.elements.namedItem('code') };
}

for (const code of ['AB1-M01', 'BB1-M02']) {
  test(`${code} can create a general B1 toilet without a literal B1- prefix`, async t => {
    const ui = await page(t, { code });
    assert.equal(ui.code.validationMessage, '');
    assert.equal(ui.form.checkValidity(), true);
  });
}

test('toilet validation recovers as name, floor, and category are corrected', async t => {
  const ui = await page(t, { name: '機房' });
  assert.equal(ui.form.checkValidity(), false);
  assert.match(ui.code.validationMessage, /廁所編號/);
  ui.set('name', 'b1男廁所-甲');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('floor', '-2', 'change');
  assert.equal(ui.form.checkValidity(), false);
  ui.set('floor', '-1', 'change');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('category', 'safety', 'change');
  assert.equal(ui.form.checkValidity(), false);
  ui.set('category', 'general', 'change');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('name', '停車場', 'change');
  assert.equal(ui.form.checkValidity(), false);
});

test('new toilet codes normalize zone/floor/sex while retaining the optional lowercase m', async t => {
  const ui = await page(t, { code: ' ab1-m01 ' });
  ui.set('code', ' ab1-m01 ', 'blur');
  assert.equal(ui.code.value, 'AB1-M01');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('floor', '2', 'change');
  ui.set('code', 'a2fm-m01', 'blur');
  assert.equal(ui.code.value, 'A2Fm-M01');
  assert.equal(ui.form.checkValidity(), true);
});

for (const code of ['AB2-M01', 'AB1-H01', 'AB1-M1', 'AB1-M001', 'AA B1-M01', 'AB3-M01', 'AB1-M01x']) {
  test(`malformed or wrong-floor toilet code ${code} is not accepted`, async t => {
    const ui = await page(t, { code });
    assert.equal(ui.form.checkValidity(), false);
  });
}

test('known catalog casing and nonstandard official codes keep their existing rules', async t => {
  const ui = await page(t, { catalog: { 'AB1m-W01': -1, 'P01': 1 }, code: 'ab1m-w01' });
  ui.set('code', 'ab1m-w01', 'blur');
  assert.equal(ui.code.value, 'AB1m-W01');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('floor', '1', 'change');
  assert.equal(ui.form.checkValidity(), false);
  ui.set('code', 'p01', 'blur');
  assert.equal(ui.code.value, 'P01');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('category', 'safety', 'change');
  assert.equal(ui.form.checkValidity(), false);
});

test('existing general custom codes remain editable without changing their identity', async t => {
  const ui = await page(t, { original: 'CUSTOM-X', name: '原有點位' });
  assert.equal(ui.form.checkValidity(), true);
  ui.set('name', '原有點位新名稱');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('floor', '1', 'change');
  assert.equal(ui.form.checkValidity(), false);
});

test('ordinary point codes still require the selected floor prefix', async t => {
  const ui = await page(t, { code: 'B1-A01', name: '機房' });
  assert.equal(ui.form.checkValidity(), true);
  ui.set('category', 'safety', 'change');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('code', 'B2-A01');
  assert.equal(ui.form.checkValidity(), false);
  ui.set('code', 'b1-a01', 'blur');
  assert.equal(ui.code.value, 'B1-A01');
  assert.equal(ui.form.checkValidity(), true);
});
