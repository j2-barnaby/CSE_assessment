// Secure File Vault - small progressive enhancements. Served as a separate
// file because the Content-Security-Policy blocks all inline JavaScript
// (ASD V-222602, XSS protection). Everything still works with JS disabled.
document.addEventListener("DOMContentLoaded", () => {
  // Copy-key button on the "save your key" page
  document.querySelectorAll("[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const field = document.getElementById(btn.dataset.copy);
      field.select();
      try {
        await navigator.clipboard.writeText(field.value);
      } catch (e) {
        document.execCommand("copy");
      }
      btn.textContent = "Copied";
      setTimeout(() => { btn.textContent = "Copy"; }, 2000);
    });
  });

  // Confirm before deleting a file
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (ev) => {
      if (!window.confirm(form.dataset.confirm)) ev.preventDefault();
    });
  });

  // Show the chosen file name in the upload box
  const fileInput = document.getElementById("file");
  const label = document.querySelector("[data-file-label]");
  if (fileInput && label) {
    fileInput.addEventListener("change", () => {
      label.textContent = fileInput.files.length ? fileInput.files[0].name : "Choose a file";
    });
  }

  // Live password-rule checklist on the registration page
  const pw = document.querySelector("[data-password-rules]");
  if (pw) {
    const min = parseInt(pw.getAttribute("minlength") || "15", 10);
    const tests = {
      length: (v) => v.length >= min,
      upper: (v) => /[A-Z]/.test(v),
      lower: (v) => /[a-z]/.test(v),
      digit: (v) => /[0-9]/.test(v),
      special: (v) => /[^A-Za-z0-9]/.test(v),
    };
    pw.addEventListener("input", () => {
      document.querySelectorAll("#password-rules li").forEach((li) => {
        li.classList.toggle("met", tests[li.dataset.rule](pw.value));
      });
    });
  }
});

// Show/hide toggle for password and key fields.
// ASD V-222554 (passwords must not be displayed in clear text): fields are
// hidden by default, revealed only when the user deliberately presses Show,
// re-hidden automatically after 10 seconds and whenever the form is submitted.
document.addEventListener("DOMContentLoaded", () => {
  const HIDE_AFTER_MS = 10000;
  document.querySelectorAll('input[type="password"]').forEach((input) => {
    const wrap = document.createElement("span");
    wrap.className = "pw-wrap";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pw-toggle";
    btn.textContent = "Show";
    btn.setAttribute("aria-pressed", "false");
    btn.setAttribute("aria-label", "Show " + (input.getAttribute("aria-label") || "password"));
    wrap.appendChild(btn);

    let timer = null;
    const hide = () => {
      input.type = "password";
      btn.textContent = "Show";
      btn.setAttribute("aria-pressed", "false");
      clearTimeout(timer);
    };
    btn.addEventListener("click", () => {
      if (input.type === "password") {
        input.type = "text";
        btn.textContent = "Hide";
        btn.setAttribute("aria-pressed", "true");
        timer = setTimeout(hide, HIDE_AFTER_MS);
      } else {
        hide();
      }
      input.focus();
    });
    if (input.form) input.form.addEventListener("submit", hide);
  });
});
