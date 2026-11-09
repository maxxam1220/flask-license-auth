/* Exercise the actual progressive enhancement against native date validity. */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { JSDOM } = require('jsdom');

async function page(t, unlimited) {
  const dom = new JSDOM(`<form data-date-range ${unlimited ? 'data-date-range-unlimited' : ''}>
    <input type="date" name="date_from"><input type="date" name="date_to"><button>Query</button>
    </form>`, { runScripts: 'outside-only', url: 'https://patrol.example.test/issues' });
  t.after(() => dom.window.close());
  dom.window.eval(fs.readFileSync(path.join(__dirname, '../static/app.js'), 'utf8'));
  await new Promise(resolve => dom.window.document.addEventListener('DOMContentLoaded', resolve, { once: true }));
  const form = dom.window.document.querySelector('form');
  return { form, end: form.elements.date_to, set(name, value, event = 'change') {
    const field = form.elements.namedItem(name);
    field.value = value;
    field.dispatchEvent(new dom.window.Event(event, { bubbles: true }));
  } };
}

test('issue dates reject reversed ranges on change and recover without losing other input', async t => {
  const ui = await page(t, true);
  ui.set('date_from', '2026-11-10'); ui.set('date_to', '2026-11-09');
  assert.equal(ui.form.checkValidity(), false);
  assert.match(ui.end.validationMessage, /結束日期不能早於開始日期/);
  ui.set('date_to', '2026-11-10', 'input');
  assert.equal(ui.form.checkValidity(), true);
  assert.equal(ui.form.elements.date_from.value, '2026-11-10');
  ui.set('date_from', '2020-01-01');
  assert.equal(ui.form.checkValidity(), true, 'old issues remain queryable across years');
  ui.set('date_to', '');
  assert.equal(ui.form.checkValidity(), true, 'issue searches allow an open end');
});

test('record and missed date ranges retain their 367-day limit', async t => {
  const ui = await page(t, false);
  ui.set('date_from', '2026-01-01'); ui.set('date_to', '2027-01-02');
  assert.equal(ui.form.checkValidity(), true);
  ui.set('date_to', '2027-01-03');
  assert.equal(ui.form.checkValidity(), false);
  assert.match(ui.end.validationMessage, /367 天/);
  ui.set('date_to', '2026-12-31');
  assert.equal(ui.form.checkValidity(), true);
});
