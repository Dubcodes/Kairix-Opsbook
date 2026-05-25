(function () {
  const savedTheme = localStorage.getItem("opsbook-theme");
  if (savedTheme) {
    document.documentElement.dataset.theme = savedTheme;
  }

  const moonIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 14.5A8.5 8.5 0 0 1 9.5 3a7 7 0 1 0 11.5 11.5Z" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/></svg>';
  const sunIcon = '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';

  function effectiveTheme() {
    const current = document.documentElement.dataset.theme;
    if (current === "dark" || current === "light") return current;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function setThemeButtonLabel() {
    const button = document.querySelector("[data-theme-toggle]");
    if (!button) return;
    const current = document.documentElement.dataset.theme || "auto";
    const effective = effectiveTheme();
    button.innerHTML = effective === "dark" ? sunIcon : moonIcon;
    button.setAttribute("title", `Theme: ${current}. Click to change.`);
    button.setAttribute("aria-label", effective === "dark" ? "Switch theme. Dark mode is active." : "Switch theme. Light mode is active.");
  }

  let tooltipTimer;
  let tooltipTarget;
  let tooltipEl;

  function removeTooltip() {
    clearTimeout(tooltipTimer);
    if (tooltipEl) {
      tooltipEl.remove();
      tooltipEl = null;
    }
    if (tooltipTarget?.dataset.tooltipText) {
      tooltipTarget.setAttribute("title", tooltipTarget.dataset.tooltipText);
      delete tooltipTarget.dataset.tooltipText;
    }
    tooltipTarget = null;
  }

  function scheduleTooltip(target) {
    const text = target.getAttribute("title");
    if (!text) return;
    removeTooltip();
    tooltipTarget = target;
    target.dataset.tooltipText = text;
    target.setAttribute("aria-label", target.getAttribute("aria-label") || text);
    target.removeAttribute("title");
    tooltipTimer = setTimeout(() => {
      if (!tooltipTarget) return;
      tooltipEl = document.createElement("div");
      tooltipEl.className = "delayed-tooltip";
      tooltipEl.textContent = tooltipTarget.dataset.tooltipText || "";
      document.body.appendChild(tooltipEl);
      const rect = tooltipTarget.getBoundingClientRect();
      const tip = tooltipEl.getBoundingClientRect();
      const left = Math.min(window.innerWidth - tip.width - 12, Math.max(12, rect.left + rect.width / 2 - tip.width / 2));
      const top = rect.bottom + 8 < window.innerHeight - tip.height ? rect.bottom + 8 : rect.top - tip.height - 8;
      tooltipEl.style.left = `${left}px`;
      tooltipEl.style.top = `${Math.max(8, top)}px`;
    }, 750);
  }

  function hydrateLocalTimes() {
    document.querySelectorAll("time[data-utc]").forEach((node) => {
      const value = node.getAttribute("data-utc");
      if (!value) return;
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return;
      const format = node.getAttribute("data-format");
      const options = format === "time"
        ? {hour: "2-digit", minute: "2-digit"}
        : {year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit"};
      node.textContent = new Intl.DateTimeFormat(undefined, options).format(date);
      node.setAttribute("title", date.toLocaleString());
    });
  }

  function highlightFocusedField() {
    const focus = new URLSearchParams(window.location.search).get("focus");
    if (!focus || !/^[A-Za-z0-9_-]+$/.test(focus)) return;
    const field = document.querySelector(`[name="${focus}"]`);
    if (!field) return;
    field.classList.add("field-highlight");
    field.scrollIntoView({block: "center", behavior: "smooth"});
    if (typeof field.focus === "function") {
      setTimeout(() => field.focus({preventScroll: true}), 250);
    }
  }

  function findCopySource(button) {
    const mode = button.getAttribute("data-copy-target");
    if (mode === "prev") {
      let node = button.previousElementSibling;
      while (node && node.tagName !== "PRE") node = node.previousElementSibling;
      if (!node) node = button.closest(".command-card")?.querySelector("pre");
      return node ? node.innerText : "";
    }
    if (mode === "next") {
      let node = button.parentElement?.nextElementSibling;
      if (node && node.tagName === "PRE") return node.innerText;
      node = button.closest(".panel")?.querySelector("pre");
      if (node) return node.innerText;
      return "";
    }
    return button.getAttribute("data-copy-text") || "";
  }

  async function copyText(text, button) {
    if (!text) return;
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.left = "-9999px";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    const old = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = old; }, 1200);
  }

  async function revealCredential(button, options = {}) {
    const row = button.closest("[data-credential-row]");
    const output = row?.querySelector("[data-secret-output]");
    const credentialId = button.getAttribute("data-reveal-credential") || button.getAttribute("data-copy-credential") || button.getAttribute("data-copy-go-credential");
    const csrf = document.querySelector("meta[name='csrf-token']")?.getAttribute("content") || "";
    let challenge = "";
    let reason = "";

    async function sendReveal() {
      return fetch(`/credentials/${credentialId}/reveal-json`, {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify({challenge, reason})
      });
    }

    let response = await sendReveal();
    let data = await response.json();
    if (response.status === 403 && data.requires_challenge) {
      challenge = window.prompt(data.message || "Password or reveal PIN") || "";
      if (!challenge) return;
      response = await sendReveal();
      data = await response.json();
    }
    if (!response.ok) {
      if (data.logged_out) {
        window.alert(data.detail || "Too many wrong attempts. You have been logged out.");
        window.location.href = "/login";
        return;
      }
      window.alert(data.detail || "Reveal failed.");
      return;
    }
    if (output && options.show !== false) {
      output.hidden = false;
      output.querySelector("code").textContent = data.secret;
      const copy = output.querySelector("[data-copy-text]");
      if (copy) copy.setAttribute("data-copy-text", data.secret);
    }
    return data;
  }

  document.addEventListener("click", (event) => {
    const quickNoteOpen = event.target.closest("[data-open-quick-note]");
    if (quickNoteOpen) {
      const modal = document.querySelector("[data-quick-note-modal]");
      if (modal) modal.hidden = false;
      return;
    }

    const quickNoteClose = event.target.closest("[data-close-quick-note]");
    if (quickNoteClose) {
      const modal = document.querySelector("[data-quick-note-modal]");
      if (modal) modal.hidden = true;
      return;
    }

    const clickableCard = event.target.closest("[data-card-href]");
    if (clickableCard && !event.target.closest("a, button, input, select, textarea, label, form")) {
      window.location.href = clickableCard.getAttribute("data-card-href");
      return;
    }

    const revealButton = event.target.closest("[data-reveal-credential]");
    if (revealButton) {
      revealCredential(revealButton).catch(() => window.alert("Reveal failed."));
      return;
    }

    const credentialCopyButton = event.target.closest("[data-copy-credential]");
    if (credentialCopyButton) {
      revealCredential(credentialCopyButton, {show: false})
        .then((data) => {
          if (data?.secret) return copyText(data.secret, credentialCopyButton);
        })
        .catch(() => window.alert("Copy failed. You can still open the credential and reveal it manually."));
      return;
    }

    const credentialCopyGoButton = event.target.closest("[data-copy-go-credential]");
    if (credentialCopyGoButton) {
      revealCredential(credentialCopyGoButton, {show: false})
        .then(async (data) => {
          if (!data?.secret) return;
          await copyText(data.secret, credentialCopyGoButton);
          const url = credentialCopyGoButton.getAttribute("data-go-url") || data.login_url;
          if (url) window.open(url, "_blank", "noopener");
        })
        .catch(() => window.alert("Copy and go failed. You can still open the credential and reveal it manually."));
      return;
    }

    const copyButton = event.target.closest("[data-copy-target], [data-copy-text]");
    if (copyButton) {
      copyText(findCopySource(copyButton), copyButton).catch(() => {
        window.alert("Copy failed. The text is still selectable on the page.");
      });
      return;
    }

    const selectAllButton = event.target.closest("[data-select-all]");
    if (selectAllButton) {
      const scopeName = selectAllButton.getAttribute("data-select-all");
      const scope = document.querySelector(`[data-select-scope="${scopeName}"]`);
      const state = selectAllButton.getAttribute("data-select-state");
      if (!scope) return;
      scope.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {
        checkbox.checked = state === "on" ? checkbox.hasAttribute("data-useful") : false;
      });
      return;
    }

    const helpButton = event.target.closest("[data-help-toggle]");
    if (helpButton) {
      const card = helpButton.closest(".command-card");
      const help = card?.querySelector(".help-text");
      if (!help) return;
      const high = help.getAttribute("data-help-high") || "";
      const low = help.getAttribute("data-help-low") || "";
      const showingHigh = helpButton.dataset.mode === "high";
      help.textContent = showingHigh ? (low || "No help text yet.") : (high || low || "No high-detail help yet.");
      helpButton.dataset.mode = showingHigh ? "low" : "high";
      helpButton.textContent = showingHigh ? "High detail" : "Low detail";
      return;
    }

    const themeButton = event.target.closest("[data-theme-toggle]");
    if (themeButton) {
      const current = document.documentElement.dataset.theme || "auto";
      const next = current === "dark" ? "light" : current === "light" ? "auto" : "dark";
      if (next === "auto") {
        delete document.documentElement.dataset.theme;
        localStorage.removeItem("opsbook-theme");
      } else {
        document.documentElement.dataset.theme = next;
        localStorage.setItem("opsbook-theme", next);
      }
      setThemeButtonLabel();
    }
  });
  document.addEventListener("pointerover", (event) => {
    const target = event.target.closest("button[title], a[title], .hint[title], .ping-dot[title], .status-dot[title]");
    if (target) scheduleTooltip(target);
  });
  document.addEventListener("pointerout", (event) => {
    if (tooltipTarget && (event.target === tooltipTarget || tooltipTarget.contains(event.target))) {
      removeTooltip();
    }
  });
  document.addEventListener("scroll", removeTooltip, true);
  document.addEventListener("submit", (event) => {
    const form = event.target.closest("[data-confirm-delete]");
    if (!form) return;
    const message = form.getAttribute("data-confirm-delete") || "Delete this item?";
    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", setThemeButtonLabel);
  }
  setThemeButtonLabel();
  hydrateLocalTimes();
  highlightFocusedField();

  const timeoutMeta = document.querySelector("meta[name='session-timeout-minutes']");
  if (timeoutMeta) {
    const timeoutMinutes = Math.max(1, Math.min(999, Number(timeoutMeta.getAttribute("content") || "20")));
    const warnAfterMs = Math.max(30_000, (timeoutMinutes - 5) * 60_000);
    let warningTimer;
    let logoutTimer;
    let lastKeepalive = 0;
    let warningEl;

    function ensureWarning() {
      if (warningEl) return warningEl;
      warningEl = document.createElement("div");
      warningEl.className = "modal-backdrop session-warning";
      warningEl.hidden = true;
      warningEl.innerHTML = `
        <div class="modal-panel compact-modal">
          <h2>Session timeout soon</h2>
          <p class="muted">You will be logged out in about 5 minutes for security.</p>
          <div class="form-actions">
            <button type="button" data-session-stay>Stay signed in</button>
            <button class="secondary" type="button" data-session-extend>Keep open longer</button>
          </div>
        </div>`;
      document.body.appendChild(warningEl);
      return warningEl;
    }

    async function keepAlive(extend = false) {
      const now = Date.now();
      if (!extend && now - lastKeepalive < 60_000) return;
      lastKeepalive = now;
      const csrf = document.querySelector("meta[name='csrf-token']")?.getAttribute("content") || "";
      await fetch("/session/keepalive", {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify({extend})
      }).catch(() => {});
    }

    function resetSessionTimers(sendKeepalive = true) {
      clearTimeout(warningTimer);
      clearTimeout(logoutTimer);
      if (warningEl) warningEl.hidden = true;
      warningTimer = setTimeout(() => {
        ensureWarning().hidden = false;
      }, warnAfterMs);
      logoutTimer = setTimeout(() => {
        window.location.href = "/login";
      }, timeoutMinutes * 60_000 + 1000);
      if (sendKeepalive) keepAlive(false);
    }

    ["click", "keydown", "pointerdown"].forEach((eventName) => {
      document.addEventListener(eventName, (event) => {
        if (event.target.closest("[data-session-extend]")) {
          keepAlive(true).finally(() => resetSessionTimers(false));
          return;
        }
        if (event.target.closest("[data-session-stay]")) {
          resetSessionTimers(true);
          return;
        }
        if (warningEl && !warningEl.hidden) {
          resetSessionTimers(true);
        }
      }, true);
    });
    resetSessionTimers(false);
  }
})();
