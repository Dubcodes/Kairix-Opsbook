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
    if (mode === "ocr-overlay") {
      return button.closest(".image-card")?.querySelector(".image-ocr-overlay")?.textContent || "";
    }
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

  function escapeHtml(value) {
    return String(value || "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    }[char]));
  }

  function generateRecoveryPhrase() {
    const words = ["Anchor", "backup", "circuit", "docker", "lantern", "matrix", "opsbook", "primary", "signal", "stable", "vault", "warden"];
    const randomValues = new Uint32Array(8);
    if (window.crypto?.getRandomValues) {
      window.crypto.getRandomValues(randomValues);
    } else {
      for (let index = 0; index < randomValues.length; index += 1) randomValues[index] = Math.floor(Math.random() * 1_000_000);
    }
    const chosen = Array.from(randomValues, (value, index) => {
      const word = words[value % words.length];
      return index === 0 ? word : word.toLowerCase();
    });
    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 12);
    const suffix = Array.from(randomValues.slice(0, 2), (value) => value.toString(16).slice(0, 4)).join("");
    return `${chosen.join(" ")} ${stamp}-${suffix}!`;
  }

  function initInlineImageViewers() {
    document.querySelectorAll("[data-inline-image-viewer]").forEach((viewer) => {
      if (viewer.dataset.viewerReady === "true") return;
      const image = viewer.querySelector("img");
      if (!image) return;
      viewer.dataset.viewerReady = "true";

      let scale = 1;
      let offsetX = 0;
      let offsetY = 0;
      let dragging = false;
      let startX = 0;
      let startY = 0;
      let startOffsetX = 0;
      let startOffsetY = 0;

      function clamp(value, min, max) {
        return Math.max(min, Math.min(max, value));
      }

      function apply() {
        image.style.transform = `translate(${offsetX}px, ${offsetY}px) scale(${scale})`;
        viewer.classList.toggle("is-zoomed", scale > 1.01);
      }

      function reset() {
        scale = 1;
        offsetX = 0;
        offsetY = 0;
        apply();
      }

      viewer.addEventListener("wheel", (event) => {
        if (event.target.closest(".image-ocr-overlay")) return;
        event.preventDefault();
        const previousScale = scale;
        const nextScale = clamp(scale + (event.deltaY < 0 ? 0.18 : -0.18), 1, 5);
        if (nextScale === scale) return;
        scale = nextScale;
        if (scale <= 1.01) {
          reset();
          return;
        }
        const rect = viewer.getBoundingClientRect();
        const pointX = event.clientX - rect.left - rect.width / 2;
        const pointY = event.clientY - rect.top - rect.height / 2;
        const ratio = scale / previousScale;
        offsetX = pointX - (pointX - offsetX) * ratio;
        offsetY = pointY - (pointY - offsetY) * ratio;
        apply();
      }, {passive: false});

      viewer.addEventListener("pointerdown", (event) => {
        if (event.button !== 0 || event.target.closest(".image-ocr-overlay") || scale <= 1.01) return;
        dragging = true;
        startX = event.clientX;
        startY = event.clientY;
        startOffsetX = offsetX;
        startOffsetY = offsetY;
        viewer.classList.add("is-dragging");
        viewer.setPointerCapture(event.pointerId);
      });

      viewer.addEventListener("pointermove", (event) => {
        if (!dragging) return;
        offsetX = startOffsetX + event.clientX - startX;
        offsetY = startOffsetY + event.clientY - startY;
        apply();
      });

      ["pointerup", "pointercancel", "lostpointercapture"].forEach((eventName) => {
        viewer.addEventListener(eventName, () => {
          dragging = false;
          viewer.classList.remove("is-dragging");
        });
      });

      viewer.addEventListener("dblclick", (event) => {
        if (!event.target.closest(".image-ocr-overlay")) reset();
      });

      const resetButton = viewer.closest(".image-card")?.querySelector("[data-image-reset]");
      if (resetButton) resetButton.addEventListener("click", reset);
      apply();
    });
  }

  function requestMaskedChallenge(message, options = {}) {
    return new Promise((resolve) => {
      const label = options.label || "Password or reveal PIN";
      const autocomplete = options.autocomplete || "current-password";
      const requireTotp = Boolean(options.requireTotp);
      const backdrop = document.createElement("div");
      backdrop.className = "modal-backdrop";
      backdrop.innerHTML = `
        <form class="modal-panel compact-modal credential-challenge-modal">
          <h2>${escapeHtml(message || label)}</h2>
          <label>${escapeHtml(label)} <input name="challenge" type="password" autocomplete="${escapeHtml(autocomplete)}" required></label>
          ${requireTotp ? '<label>2FA code <input name="totp_code" inputmode="numeric" autocomplete="one-time-code" required></label>' : ''}
          <div class="form-actions">
            <button type="submit">Continue</button>
            <button class="secondary" type="button" data-cancel-challenge>Cancel</button>
          </div>
        </form>`;
      document.body.appendChild(backdrop);
      const form = backdrop.querySelector("form");
      const input = backdrop.querySelector("input");
      const totpInput = backdrop.querySelector('input[name="totp_code"]');

      function finish(value) {
        document.removeEventListener("keydown", onKeydown, true);
        backdrop.remove();
        resolve(value);
      }

      function onKeydown(event) {
        if (event.key === "Escape") finish("");
      }

      form.addEventListener("submit", (event) => {
        event.preventDefault();
        if (requireTotp) {
          finish({challenge: input.value, totp_code: totpInput?.value || ""});
        } else {
          finish(input.value);
        }
      });
      backdrop.addEventListener("click", (event) => {
        if (event.target === backdrop || event.target.closest("[data-cancel-challenge]")) finish("");
      });
      document.addEventListener("keydown", onKeydown, true);
      setTimeout(() => input.focus(), 0);
    });
  }

  async function revealCredential(button, options = {}) {
    const row = button.closest("[data-credential-row]");
    const output = row?.querySelector("[data-secret-output]");
    const credentialId = button.getAttribute("data-reveal-credential") || button.getAttribute("data-copy-credential") || button.getAttribute("data-copy-go-credential");
    const csrf = document.querySelector("meta[name='csrf-token']")?.getAttribute("content") || "";
    let challenge = "";
    let totpCode = "";
    let reason = "";

    async function sendReveal() {
      return fetch(`/credentials/${credentialId}/reveal-json`, {
        method: "POST",
        headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
        body: JSON.stringify({challenge, reason, totp_code: totpCode})
      });
    }

    let response = await sendReveal();
    let data = await response.json();
    if (response.status === 403 && data.requires_challenge) {
      const result = await requestMaskedChallenge(data.message || "Password or reveal PIN", {
        requireTotp: Boolean(data.requires_totp)
      });
      if (typeof result === "object" && result !== null) {
        challenge = result.challenge || "";
        totpCode = result.totp_code || "";
      } else {
        challenge = result || "";
        totpCode = "";
      }
      if (!challenge) return;
      if (data.requires_totp && !totpCode) return;
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

  function initLiveSearch() {
    const inputs = document.querySelectorAll("form.global-search input[type='search'][name='q'], form.filter-bar input[type='search'][name='q']");
    const hosts = [];

    function hide(host) {
      host.dropdown.hidden = true;
      host.input.setAttribute("aria-expanded", "false");
    }

    function render(host, items, query) {
      host.dropdown.replaceChildren();
      if (!items.length) {
        const empty = document.createElement("div");
        empty.className = "live-search-empty";
        empty.textContent = `No quick matches for "${query}". Press Enter for the full search.`;
        host.dropdown.appendChild(empty);
      } else {
        items.forEach((item) => {
          const link = document.createElement("a");
          link.className = "live-search-item";
          link.href = item.url || "/search";
          const badge = document.createElement("small");
          badge.textContent = item.type || "Result";
          const title = document.createElement("strong");
          if (item.type === "Device" && item.device_name) {
            appendDevicePing(title, item.device_name, item.device_ping_state, item.device_ping_label);
          } else {
            title.textContent = item.title || "Result";
          }
          const subtitle = document.createElement("span");
          subtitle.textContent = item.subtitle || "";
          link.append(badge, title, subtitle);
          host.dropdown.appendChild(link);
        });
      }
      host.dropdown.hidden = false;
      host.input.setAttribute("aria-expanded", "true");
    }

    function appendDevicePing(parent, name, state, label) {
      const wrapper = document.createElement("span");
      wrapper.className = "device-with-ping live-search-device";
      wrapper.append(document.createTextNode(name || "Unlinked"));
      if (state) {
        const dot = document.createElement("span");
        dot.className = `ping-dot ping-${state}`;
        dot.setAttribute("title", `Ping: ${label || state}`);
        wrapper.append(dot);
      }
      parent.append(wrapper);
    }

    async function run(host) {
      const query = host.input.value.trim();
      host.requestId += 1;
      const requestId = host.requestId;
      clearTimeout(host.timer);
      if (query.length < 2) {
        hide(host);
        return;
      }
      host.timer = setTimeout(async () => {
        try {
          const response = await fetch(`/search/live?q=${encodeURIComponent(query)}`, {credentials: "same-origin"});
          if (!response.ok || requestId !== host.requestId) return;
          const data = await response.json();
          render(host, Array.isArray(data.items) ? data.items : [], query);
        } catch {
          hide(host);
        }
      }, 160);
    }

    inputs.forEach((input, index) => {
      if (input.closest(".live-search-box")) return;
      const wrapper = document.createElement("div");
      wrapper.className = "live-search-box";
      input.parentNode.insertBefore(wrapper, input);
      wrapper.appendChild(input);

      const dropdown = document.createElement("div");
      dropdown.className = "live-search-results";
      dropdown.hidden = true;
      dropdown.id = `live-search-results-${index}`;
      wrapper.appendChild(dropdown);

      input.setAttribute("autocomplete", "off");
      input.setAttribute("aria-autocomplete", "list");
      input.setAttribute("aria-expanded", "false");
      input.setAttribute("aria-controls", dropdown.id);

      const host = {input, dropdown, wrapper, timer: 0, requestId: 0};
      hosts.push(host);
      input.addEventListener("input", () => run(host));
      input.addEventListener("focus", () => run(host));
      input.addEventListener("keydown", (event) => {
        if (event.key === "Escape") hide(host);
      });
    });

    document.addEventListener("pointerdown", (event) => {
      hosts.forEach((host) => {
        if (!host.wrapper.contains(event.target)) hide(host);
      });
    });
  }

  function initAutoSubmitFilters() {
    document.querySelectorAll("form[data-auto-submit] select").forEach((select) => {
      select.addEventListener("change", () => {
        if (typeof select.form.requestSubmit === "function") {
          select.form.requestSubmit();
        } else {
          select.form.submit();
        }
      });
    });
  }

  function initStatsLive() {
    const roots = document.querySelectorAll("[data-stats-live]");
    if (!roots.length) return;

    function formatLocalDateTime(value) {
      if (!value) return "";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return "";
      return new Intl.DateTimeFormat(undefined, {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
      }).format(date);
    }

    function formatLocalTime(value) {
      if (!value) return "";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return "";
      return new Intl.DateTimeFormat(undefined, {hour: "2-digit", minute: "2-digit"}).format(date);
    }

    function setText(scope, field, value) {
      const node = scope.querySelector(`[data-stat-field="${field}"]`);
      if (node) node.textContent = value || "";
    }

    function setCounter(name, value) {
      document.querySelectorAll(`[data-stats-count="${name}"]`).forEach((node) => {
        node.textContent = value ?? "";
      });
    }

    function drawSparkline(svg, series, metric, startIso, endIso) {
      const line = svg?.querySelector("polyline");
      if (!line) return;
      const values = (Array.isArray(series) ? series : [])
        .map((point) => ({time: new Date(point.created_at).getTime(), value: Number(point[metric])}))
        .filter((point) => Number.isFinite(point.time) && Number.isFinite(point.value));
      if (!values.length) {
        line.setAttribute("points", "");
        svg.classList.add("is-empty");
        return;
      }
      svg.classList.remove("is-empty");
      const start = new Date(startIso).getTime();
      const end = new Date(endIso).getTime();
      const span = Number.isFinite(start) && Number.isFinite(end) && end > start ? end - start : 1;
      const maxValue = metric === "load_1"
        ? Math.max(1, ...values.map((point) => point.value)) * 1.15
        : 100;
      const coords = values.map((point, index) => {
        const rawX = values.length === 1 ? 100 : ((point.time - start) / span) * 100;
        const x = Math.max(0, Math.min(100, rawX));
        const y = 32 - Math.max(0, Math.min(1, point.value / maxValue)) * 30;
        return `${x.toFixed(2)},${y.toFixed(2)}`;
      });
      if (coords.length === 1) coords.unshift("0,32");
      line.setAttribute("points", coords.join(" "));
    }

    function createStatsCard(device, detailMode) {
      const tag = detailMode ? "article" : "a";
      const card = document.createElement(tag);
      card.className = `stats-device-card${detailMode ? " stats-device-card-detail" : ""}`;
      card.dataset.statsDeviceId = String(device.id);
      if (!detailMode) card.href = device.href || `/devices/${device.id}?tab=stats`;
      card.innerHTML = `
        <div class="stats-card-head">
          <div>
            <strong data-stat-field="name"></strong>
            <small data-stat-field="last_report"></small>
          </div>
          <span class="status-dot status-unknown" data-stat-status-dot></span>
        </div>
        <div class="stats-chart-grid">
          <div class="stat-chart stat-chart-cpu">
            <div><strong data-stat-field="cpu_label">n/a</strong><span>CPU</span></div>
            <svg class="stat-sparkline" data-stat-chart="cpu_percent" viewBox="0 0 100 34" preserveAspectRatio="none" aria-hidden="true"><polyline points=""></polyline></svg>
          </div>
          <div class="stat-chart stat-chart-memory">
            <div><strong data-stat-field="memory_label">n/a</strong><span>Memory</span><small data-stat-field="memory_detail"></small></div>
            <svg class="stat-sparkline" data-stat-chart="memory_percent" viewBox="0 0 100 34" preserveAspectRatio="none" aria-hidden="true"><polyline points=""></polyline></svg>
          </div>
          <div class="stat-chart stat-chart-disk">
            <div><strong data-stat-field="disk_label">n/a</strong><span>Root disk</span><small data-stat-field="disk_detail"></small></div>
            <svg class="stat-sparkline" data-stat-chart="root_disk_percent" viewBox="0 0 100 34" preserveAspectRatio="none" aria-hidden="true"><polyline points=""></polyline></svg>
          </div>
          <div class="stat-chart stat-chart-load">
            <div><strong data-stat-field="load_label">n/a</strong><span>Load 1 min</span></div>
            <svg class="stat-sparkline" data-stat-chart="load_1" viewBox="0 0 100 34" preserveAspectRatio="none" aria-hidden="true"><polyline points=""></polyline></svg>
          </div>
        </div>
        <div class="stats-card-foot">
          <span data-stat-field="uptime_label"></span>
          <span data-stat-field="agent_label"></span>
        </div>`;
      return card;
    }

    function updateStatsCard(card, device, payload) {
      const latest = device.latest || {};
      const labels = latest.labels || {};
      const state = device.state || {};
      if (card.tagName === "A") card.href = device.href || `/devices/${device.id}?tab=stats`;
      setText(card, "name", device.name || "Device");
      setText(card, "last_report", latest.created_at ? `Last ${formatLocalDateTime(latest.created_at)}` : "No stats yet");
      setText(card, "cpu_label", labels.cpu || "n/a");
      setText(card, "memory_label", labels.memory || "n/a");
      setText(card, "memory_detail", labels.memory_detail || "");
      setText(card, "disk_label", labels.disk || "n/a");
      setText(card, "disk_detail", labels.disk_detail || "");
      setText(card, "load_label", labels.load || "n/a");
      setText(card, "uptime_label", labels.uptime ? `Uptime ${labels.uptime}` : "");
      setText(card, "agent_label", latest.agent_version ? `Agent ${latest.agent_version}` : "");
      const dot = card.querySelector("[data-stat-status-dot]");
      if (dot) {
        const status = state.state || "unknown";
        dot.className = `status-dot status-${status}`;
        dot.setAttribute("title", state.label || "No agent data yet");
      }
      card.querySelectorAll("[data-stat-chart]").forEach((svg) => {
        drawSparkline(svg, device.series || [], svg.getAttribute("data-stat-chart"), payload.window_start, payload.window_end);
      });
    }

    async function refreshStats(root) {
      const hours = Math.max(1, Math.min(168, Number(root.dataset.statsWindowHours || "8")));
      const params = new URLSearchParams({hours: String(hours)});
      const deviceId = root.dataset.statsDeviceId;
      if (deviceId) params.set("device_id", deviceId);
      const response = await fetch(`/api/stats?${params}`, {credentials: "same-origin"});
      if (!response.ok) return;
      const payload = await response.json();
      const devices = Array.isArray(payload.devices) ? payload.devices : [];
      setCounter("reporting", payload.counts?.reporting ?? devices.length);
      setCounter("stale", payload.counts?.stale ?? 0);
      setCounter("window", payload.window_label || `${hours}h`);
      const refreshed = root.querySelector("[data-stats-refreshed]") || document.querySelector("[data-stats-refreshed]");
      if (refreshed) refreshed.textContent = payload.generated_at ? `Updated ${formatLocalTime(payload.generated_at)}` : "Live";
      const stateLabel = root.querySelector("[data-stats-state-label]");
      if (stateLabel && devices[0]?.state?.label) stateLabel.textContent = devices[0].state.label;

      const grid = root.querySelector("[data-stats-device-grid]");
      const empty = root.querySelector("[data-stats-empty]");
      if (!grid) return;
      const detailMode = Boolean(deviceId);
      const activeIds = new Set();
      devices.forEach((device) => {
        activeIds.add(String(device.id));
        let card = grid.querySelector(`[data-stats-device-id="${device.id}"]`);
        if (!card) {
          card = createStatsCard(device, detailMode);
          grid.appendChild(card);
        }
        updateStatsCard(card, device, payload);
      });
      if (!detailMode) {
        grid.querySelectorAll("[data-stats-device-id]").forEach((card) => {
          if (!activeIds.has(card.dataset.statsDeviceId)) card.remove();
        });
      }
      if (empty) empty.hidden = devices.length > 0;
      const setup = document.getElementById("agent-setup");
      if (setup && detailMode && devices.length > 0) setup.hidden = true;
    }

    roots.forEach((root) => {
      if (root.dataset.statsLiveReady === "true") return;
      root.dataset.statsLiveReady = "true";
      refreshStats(root).catch(() => {});
      window.setInterval(() => refreshStats(root).catch(() => {}), 30_000);
    });
  }

  document.addEventListener("click", (event) => {
    const recoveryGenerator = event.target.closest("[data-generate-recovery]");
    if (recoveryGenerator) {
      const phrase = generateRecoveryPhrase();
      const form = recoveryGenerator.closest("form") || document;
      const input = form.querySelector("[data-recovery-phrase]");
      const confirm = form.querySelector("[data-recovery-confirm]");
      if (input) {
        input.value = phrase;
        input.type = "text";
        input.focus();
      }
      if (confirm) confirm.value = phrase;
      return;
    }

    const ocrToggle = event.target.closest("[data-toggle-ocr]");
    if (ocrToggle) {
      const overlay = ocrToggle.closest(".image-card")?.querySelector(".image-ocr-overlay");
      if (!overlay) return;
      overlay.hidden = !overlay.hidden;
      ocrToggle.textContent = overlay.hidden ? "Show Text" : "Hide Text";
      return;
    }

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
  document.addEventListener("keydown", (event) => {
    if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== "a") return;
    const noteBody = document.querySelector("[data-note-body]");
    if (!noteBody) return;
    const active = document.activeElement;
    if (active && active.closest("input, textarea, select, [contenteditable='true']")) return;
    event.preventDefault();
    noteBody.focus({preventScroll: true});
    const range = document.createRange();
    range.selectNodeContents(noteBody);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
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
  document.addEventListener("submit", async (event) => {
    const favoriteForm = event.target.closest("[data-favorite-form]");
    if (favoriteForm) {
      event.preventDefault();
      const button = favoriteForm.querySelector(".favorite-star");
      const formData = new FormData(favoriteForm);
      const nextActive = formData.get("action") === "show";
      fetch(favoriteForm.action, {
        method: "POST",
        body: formData,
        credentials: "same-origin"
      })
        .then((response) => {
          if (!response.ok) throw new Error("Favorite update failed");
          if (button) {
            button.classList.toggle("active", nextActive);
            button.value = nextActive ? "hide" : "show";
            button.setAttribute("title", nextActive ? "Remove from favorites" : "Add to favorites");
            button.setAttribute("aria-label", nextActive ? "Remove from favorites" : "Add to favorites");
          }
        })
        .catch(() => window.alert("Favorite update failed."));
      return;
    }
    const form = event.target.closest("form");
    if (!form) return;
    const checkedDeleteName = form.getAttribute("data-confirm-checked-name");
    const checkedDeleteMessage = form.getAttribute("data-confirm-checked-delete");
    if (checkedDeleteName && checkedDeleteMessage && form.dataset.confirmedCheckedDelete !== "true") {
      const hasCheckedDelete = Array.from(form.elements).some((element) => (
        element.name === checkedDeleteName && element.checked
      ));
      if (hasCheckedDelete) {
        if (!window.confirm(checkedDeleteMessage)) {
          event.preventDefault();
          return;
        }
        form.dataset.confirmedCheckedDelete = "true";
      }
    }
    const message = form.getAttribute("data-confirm-delete");
    if (message && form.dataset.confirmedDelete !== "true") {
      if (!window.confirm(message || "Delete this item?")) {
        event.preventDefault();
        return;
      }
      form.dataset.confirmedDelete = "true";
    }
    const passwordMessage = form.getAttribute("data-confirm-password");
    if (!passwordMessage || form.dataset.challengeReady === "true") return;
    event.preventDefault();
    const challenge = await requestMaskedChallenge(passwordMessage, {
      label: form.getAttribute("data-confirm-password-label") || "Account password"
    });
    if (!challenge) {
      delete form.dataset.confirmedDelete;
      return;
    }
    let input = form.querySelector('input[name="password"][data-confirm-password-field]');
    if (!input) {
      input = document.createElement("input");
      input.type = "hidden";
      input.name = "password";
      input.setAttribute("data-confirm-password-field", "");
      form.appendChild(input);
    }
    input.value = challenge;
    form.dataset.challengeReady = "true";
    if (typeof form.requestSubmit === "function") {
      form.requestSubmit();
    } else {
      form.submit();
    }
  });
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", setThemeButtonLabel);
  }
  setThemeButtonLabel();
  hydrateLocalTimes();
  highlightFocusedField();
  initLiveSearch();
  initAutoSubmitFilters();
  initInlineImageViewers();
  initStatsLive();

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
