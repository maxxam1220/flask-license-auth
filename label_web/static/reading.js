"use strict";
// A local reading preference, independent of inspection and approval state.
(() => {
  const key = "labelcheck-text-size";
  const choices = [...document.querySelectorAll("[data-text-size-choice]")];
  function apply(value) {
    const size = value === "xl" ? "xl" : "large";
    document.documentElement.dataset.textSize = size;
    choices.forEach(button => button.setAttribute("aria-pressed", String(button.dataset.textSizeChoice === size)));
  }
  let saved;
  try { saved = localStorage.getItem(key); } catch { /* Private browsing can deny storage. */ }
  apply(saved);
  choices.forEach(button => button.addEventListener("click", () => {
    apply(button.dataset.textSizeChoice);
    try { localStorage.setItem(key, document.documentElement.dataset.textSize); } catch { /* Keep this page usable. */ }
  }));
})();
