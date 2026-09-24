"use strict";

// Only control visibility. Credentials are never read or stored by this script.
document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  const field = document.getElementById(button.dataset.togglePassword);
  if (!field || field.type !== "password") return;
  button.hidden = false;
  button.addEventListener("click", () => {
    const showPassword = field.type === "password";
    field.type = showPassword ? "text" : "password";
    button.textContent = showPassword ? "隱藏" : "顯示";
    button.setAttribute("aria-pressed", String(showPassword));
    button.setAttribute(
      "aria-label",
      `${showPassword ? "隱藏" : "顯示"}${button.dataset.passwordLabel || "密碼"}`,
    );
  });
});
