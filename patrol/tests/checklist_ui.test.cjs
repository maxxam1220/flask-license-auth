const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../static/checklist.js'), 'utf8');

function setup(defaults = [false, false]) {
  const docEvents = {}, winEvents = {}, timers = [];
  const classes = () => ({ values: new Set(), add(name) { this.values.add(name); }, remove(name) { this.values.delete(name); }, toggle(name, on) { on ? this.add(name) : this.remove(name); } });
  class Button { constructor() { this.type = 'submit'; this.disabled = !defaults.some(Boolean); this.dataset = this.disabled ? { checklistDisabled: 'true' } : {}; } }
  class Input {
    constructor(index) { this.name = 'checklist'; this.type = 'checkbox'; this.value = `item-${index}`; this.defaultChecked = defaults[index]; this.checked = defaults[index]; this.label = { classList: classes() }; }
    closest(selector) { return selector === '[data-checklist]' ? group : this.label; }
    focus() { this.focused = true; }
  }
  class Form {
    constructor() { this.dataset = {}; }
    querySelector() { return group; }
    closest() { return { querySelectorAll: () => [jump] }; }
  }
  const form = new Form(), choices = defaults.map((_, i) => new Input(i)), buttons = [new Button(), new Button()];
  choices.forEach(choice => { choice.form = form; });
  form.elements = [...choices, ...buttons];
  const status = {}, jump = { dataset: { checklistPrompt: 'Select at least one' } };
  const group = { dataset: { checklistCountFormat: '{count} / {total}' }, classList: classes(), attributes: {},
    setAttribute(name, value) { this.attributes[name] = value; }, removeAttribute(name) { delete this.attributes[name]; },
    querySelectorAll: () => choices, querySelector: selector => selector === '.checklist-count' ? status : choices[0], scrollIntoView() {} };
  const document = { readyState: 'complete', querySelectorAll: () => [form], addEventListener(name, handler) { (docEvents[name] ||= []).push(handler); } };
  const window = { addEventListener(name, handler) { (winEvents[name] ||= []).push(handler); } };
  vm.runInNewContext(source, { document, window, HTMLButtonElement: Button, HTMLInputElement: Input, HTMLFormElement: Form, setTimeout: handler => timers.push(handler) });
  const fire = (collection, name, extra = {}) => {
    const event = { target: form, preventDefault() { this.prevented = true; }, stopImmediatePropagation() { this.stopped = true; }, ...extra };
    for (const handler of collection[name] || []) handler(event);
    return event;
  };
  return { form, group, choices, buttons, status, jump, api: window.PatrolChecklist,
    change: choice => fire(docEvents, 'change', { target: choice }),
    submit: () => fire(docEvents, 'submit'), reset: () => fire(docEvents, 'reset'),
    pagehide: () => fire(winEvents, 'pagehide'), pageshow: persisted => fire(winEvents, 'pageshow', { persisted }),
    flush: () => { while (timers.length) timers.shift()(); } };
}

test('both submit buttons require an explicit item; zero-item submit is stopped before saving', () => {
  const ui = setup();
  assert.ok(ui.buttons.every(button => button.disabled));
  const emptySubmit = ui.submit();
  assert.equal(emptySubmit.prevented, true);
  assert.equal(emptySubmit.stopped, true);
  assert.equal(ui.choices[0].focused, true);
  assert.equal(ui.group.attributes['aria-invalid'], 'true');
  ui.choices[1].checked = true; ui.change(ui.choices[1]);
  assert.ok(ui.buttons.every(button => !button.disabled));
  assert.equal(ui.group.attributes['aria-invalid'], undefined);
  assert.deepEqual(Array.from(ui.api.selected(ui.form)), ['item-1']);
  assert.equal(ui.jump.textContent, '1 / 2');
  assert.equal(ui.submit().prevented, undefined);
  ui.choices[1].checked = false; ui.change(ui.choices[1]);
  assert.ok(ui.buttons.every(button => button.disabled));
});

test('changing selection never unlocks buttons while a save is running', () => {
  const ui = setup();
  ui.form.dataset.offlineSaving = 'true';
  ui.choices[0].checked = true; ui.change(ui.choices[0]);
  assert.ok(ui.buttons.every(button => button.disabled));
  delete ui.form.dataset.offlineSaving; ui.api.refresh(ui.form);
  assert.ok(ui.buttons.every(button => !button.disabled));
});

test('back navigation preserves an unsent draft but cannot reuse a submitted round', () => {
  const ui = setup();
  ui.choices[0].checked = true; ui.change(ui.choices[0]);
  ui.pagehide(); ui.pageshow(true); ui.flush();
  assert.equal(ui.choices[0].checked, true);
  ui.form.dataset.submitting = 'true'; ui.pagehide();
  delete ui.form.dataset.submitting;
  ui.buttons.forEach(button => { button.disabled = false; });
  ui.pageshow(true); ui.flush();
  assert.ok(ui.choices.every(choice => !choice.checked));
  assert.ok(ui.buttons.every(button => button.disabled));
});

test('fresh pages honor server error-draft selection instead of browser restored checkboxes', () => {
  const ui = setup([true, false]);
  ui.choices[0].checked = false; ui.choices[1].checked = true;
  ui.pageshow(false); ui.flush();
  assert.deepEqual(Array.from(ui.api.selected(ui.form)), ['item-0']);
  assert.ok(ui.buttons.every(button => !button.disabled));
});

test('a user selection made before slow page resources finish loading is not erased by pageshow', () => {
  const ui = setup();
  ui.choices[0].checked = true; ui.change(ui.choices[0]);
  ui.pageshow(false); ui.flush();
  assert.deepEqual(Array.from(ui.api.selected(ui.form)), ['item-0']);
  assert.ok(ui.buttons.every(button => !button.disabled));
});

test('unchecking a server-returned draft before pageshow is not silently checked again', () => {
  const ui = setup([true, false]);
  ui.choices[0].checked = false; ui.change(ui.choices[0]);
  ui.pageshow(false); ui.flush();
  assert.deepEqual(Array.from(ui.api.selected(ui.form)), []);
  assert.ok(ui.buttons.every(button => button.disabled));
});

test('reset updates both confirmation buttons after native checkbox reset', () => {
  const ui = setup();
  ui.choices[0].checked = true; ui.change(ui.choices[0]);
  ui.reset(); ui.choices.forEach(choice => { choice.checked = choice.defaultChecked; }); ui.flush();
  assert.ok(ui.buttons.every(button => button.disabled));
  assert.equal(ui.status.textContent, '0 / 2');
});
