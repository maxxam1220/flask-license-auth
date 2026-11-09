(() => {
  'use strict';
  const leavingSubmitted = new WeakSet();
  const checklistFor = form => form?.querySelector('[data-checklist]');
  const choicesFor = group => Array.from(group?.querySelectorAll('input[type="checkbox"][name="checklist"]') || []);
  const submittersFor = form => Array.from(form.elements).filter(item => item instanceof HTMLButtonElement && item.type === 'submit');

  function refresh(form) {
    const group = checklistFor(form);
    if (!group) return;
    const choices = choicesFor(group);
    const count = choices.filter(item => item.checked).length;
    for (const choice of choices) choice.closest('.checklist-option')?.classList.toggle('is-checked', choice.checked);
    const status = group.querySelector('.checklist-count');
    if (status) status.textContent = (group.dataset.checklistCountFormat || '{count} / {total}').replace('{count}', String(count)).replace('{total}', String(choices.length));
    form.closest('.checkin-card')?.querySelectorAll('[data-checklist-prompt]').forEach(link => { link.textContent = count ? status?.textContent || String(count) : link.dataset.checklistPrompt; });
    if (count) group.classList.remove('is-invalid');
    if (form.dataset.submitting !== 'true' && form.dataset.offlineSaving !== 'true') {
      for (const button of submittersFor(form)) {
        if (!count && !button.disabled) { button.dataset.checklistDisabled = 'true'; button.disabled = true; }
        else if (count && button.dataset.checklistDisabled === 'true') { button.disabled = false; delete button.dataset.checklistDisabled; }
      }
    }
  }
  function refreshAll() { document.querySelectorAll('form').forEach(refresh); }
  function onChange(event) {
    const choice = event.target;
    if (choice instanceof HTMLInputElement && choice.name === 'checklist' && choice.closest('[data-checklist]')) refresh(choice.form);
  }
  document.addEventListener('change', onChange);
  document.addEventListener('input', onChange);
  // Capture before the online/offline saving handlers: an empty selection is never a submission.
  document.addEventListener('submit', event => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const group = checklistFor(form);
    if (!group || choicesFor(group).some(item => item.checked)) return;
    event.preventDefault(); event.stopImmediatePropagation();
    group.classList.add('is-invalid');
    group.querySelector('input')?.focus();
    group.scrollIntoView({ block: 'center', behavior: 'smooth' });
    refresh(form);
  }, true);
  document.addEventListener('reset', event => { if (event.target instanceof HTMLFormElement) setTimeout(() => refresh(event.target), 0); });
  window.addEventListener('pagehide', () => {
    document.querySelectorAll('form').forEach(form => {
      if (form.dataset.submitting === 'true' || form.dataset.offlineStored === 'true') leavingSubmitted.add(form);
    });
  });
  window.addEventListener('pageshow', event => {
    document.querySelectorAll('form').forEach(form => {
      const group = checklistFor(form);
      if (!group) return;
      for (const choice of choicesFor(group)) {
        // A restored submission must be reviewed anew; a normal back-navigation keeps an unsent draft.
        if (event.persisted && leavingSubmitted.has(form)) choice.checked = false;
        else if (!event.persisted) choice.checked = choice.defaultChecked;
      }
      leavingSubmitted.delete(form);
    });
    // app.js restores busy buttons on pageshow, so apply the checklist requirement afterwards.
    setTimeout(refreshAll, 0);
  });
  document.addEventListener('patrol:checklist-rendered', refreshAll);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', refreshAll); else refreshAll();
  window.PatrolChecklist = Object.freeze({ refresh, selected: form => choicesFor(checklistFor(form)).filter(item => item.checked).map(item => item.value) });
})();
