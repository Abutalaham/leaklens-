"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") e.className = v;
    else if (k === "style") e.style.cssText = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c);
  return e;
}

const S = {
  scan: null,
  selected: new Set(),
  showAll: false,
  user: null,
  csrfToken: null,
  activeView: "home",
  uploadExtensions: [],
  maxUploadBytes: 0,
  maxUploadMB: 0,
  uploadConfigLoaded: false,
  scanning: false
};

const LEVEL_COLOR = { high: "var(--high)", medium: "var(--med)", low: "var(--low)" };
const visible = (f) => S.showAll || f.status === "active";

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (S.csrfToken && !headers["X-CSRF-Token"]) {
    headers["X-CSRF-Token"] = S.csrfToken;
  }
  opts.headers = headers;
  
  const r = await fetch(path, opts);
  let body = null;
  try { body = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error((body && body.error) || `Request failed (${r.status})`);
  return body;
}

/* ---------------------------------------------------------------- Theme Toggle */
const storedTheme = localStorage.getItem("leaklens_theme");
const savedTheme = storedTheme === "light" || storedTheme === "dark" ? storedTheme : "dark";
document.documentElement.dataset.theme = savedTheme;

const themeToggle = $("#theme-toggle");
function updateThemeToggle(theme) {
  themeToggle.textContent = theme === "dark" ? "☼" : "☾";
  themeToggle.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} theme`);
  themeToggle.title = `Switch to ${theme === "dark" ? "light" : "dark"} theme`;
}
updateThemeToggle(savedTheme);

themeToggle.addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme;
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("leaklens_theme", next);
  updateThemeToggle(next);
});

const ribbonStage = $(".ribbon-stage");
if (ribbonStage) {
  for (let index = 0; index < 36; index += 1) {
    const slice = document.createElement("span");
    slice.className = "ribbon-slice";
    slice.style.setProperty("--index", index);
    ribbonStage.append(slice);
  }

  const legacyHero = $(".hero");
  if (legacyHero) {
    legacyHero.addEventListener("pointermove", (event) => {
      const bounds = event.currentTarget.getBoundingClientRect();
      const x = ((event.clientX - bounds.left) / bounds.width - .5) * 2;
      const y = ((event.clientY - bounds.top) / bounds.height - .5) * 2;
      ribbonStage.style.setProperty("--mouse-x", x.toFixed(3));
      ribbonStage.style.setProperty("--mouse-y", y.toFixed(3));
    });
    legacyHero.addEventListener("pointerleave", () => {
      ribbonStage.style.setProperty("--mouse-x", "0");
      ribbonStage.style.setProperty("--mouse-y", "0");
    });
  }
}

/* ---------------------------------------------------------------- Navigation */
const mobileNavQuery = window.matchMedia("(max-width: 1080px)");
const primaryMenu = $("#primary-menu");
const mobileNavToggle = $("#mobile-nav-toggle");

function syncNavigationMode() {
  const isMobile = mobileNavQuery.matches;
  mobileNavToggle.setAttribute("aria-hidden", String(!isMobile));
  mobileNavToggle.tabIndex = isMobile ? 0 : -1;
  if (!isMobile) primaryMenu.classList.remove("is-open");
  primaryMenu.setAttribute("aria-hidden", String(isMobile && !primaryMenu.classList.contains("is-open")));
  mobileNavToggle.setAttribute("aria-expanded", String(isMobile && primaryMenu.classList.contains("is-open")));
  mobileNavToggle.setAttribute("aria-label", primaryMenu.classList.contains("is-open")
    ? "Close primary navigation"
    : "Open primary navigation");
}

function closeMobileNavigation(returnFocus = false) {
  primaryMenu.classList.remove("is-open");
  syncNavigationMode();
  if (returnFocus && mobileNavQuery.matches) mobileNavToggle.focus();
}

mobileNavToggle.addEventListener("click", () => {
  const isOpen = primaryMenu.classList.toggle("is-open");
  syncNavigationMode();
  if (isOpen) {
    const firstLink = primaryMenu.querySelector(".tab:not([hidden])");
    if (firstLink) firstLink.focus();
  }
});
mobileNavQuery.addEventListener("change", () => syncNavigationMode());
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && primaryMenu.classList.contains("is-open")) {
    event.preventDefault();
    closeMobileNavigation(true);
  }
});
document.addEventListener("click", (event) => {
  if (mobileNavQuery.matches && primaryMenu.classList.contains("is-open")
      && !primaryMenu.contains(event.target) && !mobileNavToggle.contains(event.target)) {
    closeMobileNavigation();
  }
});
syncNavigationMode();

$$(".tab").forEach((t) => t.addEventListener("click", () => {
  const view = t.dataset.view;
  if (!view) return;
  switchView(view);
}));
$$("[data-go-view]").forEach((button) => button.addEventListener("click", () => {
  switchView(button.dataset.goView);
}));

function switchView(viewName) {
  S.activeView = viewName;
  document.body.classList.toggle("home-active", viewName === "home");
  $$(".tab").forEach((x) => {
    const active = x.dataset.view === viewName;
    x.classList.toggle("active", active);
    if (active) x.setAttribute("aria-current", "page");
    else x.removeAttribute("aria-current");
  });
  $$(".view").forEach((v) => (v.hidden = v.id !== "view-" + viewName));
  if (mobileNavQuery.matches && primaryMenu.classList.contains("is-open")) closeMobileNavigation(true);

  if (viewName === "dashboard") loadDashboard();
  if (viewName === "history") loadHistory();
  if (viewName === "team") loadTeamSetup();
  if (viewName === "eval") loadEval();
  if (viewName === "admin") loadAdminDashboard();
}

switchView("home");

/* ---------------------------------------------------------------- Status & Auth Initialization */
async function initApp() {
  try {
    const s = await api("/api/status");
    S.csrfToken = s.csrf_token;

    S.uploadExtensions = s.extensions;
    S.maxUploadMB = Number(s.max_mb);
    S.maxUploadBytes = Number(s.max_mb) * 1024 * 1024;
    if (!Number.isFinite(S.maxUploadMB) || !S.maxUploadBytes || !Array.isArray(S.uploadExtensions)) {
      throw new Error("Scanner upload configuration is invalid.");
    }
    S.uploadConfigLoaded = true;

    // Status chips
    $("#chips").replaceChildren(
      h("span", { class: "chip " + (s.ml ? "ok" : "warn") }, s.ml ? "ML on" : "ML off"),
      h("span", { class: "chip " + (s.ocr ? "ok" : "warn") }, s.ocr ? "OCR on" : "OCR off")
    );
    $("#file").accept = s.extensions.join(",");
    $("#file").disabled = false;
    $("#scan-browse").disabled = false;
    $$("[data-sample]").forEach((button) => { button.disabled = false; });
    $("#drop-hint").textContent = `Maximum file size: ${s.max_mb} MB. Temporary upload copies are deleted after ${s.ttl_minutes} minutes.`;
    $("#supported-tags").replaceChildren(...s.extensions.map((extension) => h("span", null, extension)));
    $("#scan-status-title").textContent = "Status from this installation";
    $("#scan-ml-state").textContent = s.ml ? "ON" : "OFF";
    $("#scan-ocr-state").textContent = s.ocr ? "ON" : "OFF";
    $("#scan-ml-state").classList.toggle("is-on", s.ml);
    $("#scan-ml-state").classList.toggle("is-off", !s.ml);
    $("#scan-ocr-state").classList.toggle("is-on", s.ocr);
    $("#scan-ocr-state").classList.toggle("is-off", !s.ocr);
    $("#scan-max-size").textContent = `${s.max_mb} MB`;
    $("#scan-ttl").textContent = `${s.ttl_minutes} min`;
  } catch (err) {
    console.warn("Status init error:", err);
    $("#scan-status-title").textContent = "Scanner status unavailable";
    $("#drop-hint").textContent = "Supported formats and upload limits could not be loaded.";
    showError("Scanner configuration could not be loaded. Refresh the page before uploading a file.");
  }

  try {
    const me = await api("/api/auth/me");
    if (me.authenticated) {
      setAuthUser(me.user);
    } else {
      setAuthUser(null);
    }
  } catch (err) {
    console.warn("Auth init error:", err);
  }
}
initApp();

function setAuthUser(user) {
  S.user = user;
  if (user) {
    $("#auth-nav").hidden = true;
    $("#user-menu").hidden = false;
    $("#user-display-name").textContent = user.username + (user.role === "admin" ? " (Admin)" : "");
    if (user.role === "admin") {
      $("#nav-admin").hidden = false;
    } else {
      $("#nav-admin").hidden = true;
    }
  } else {
    $("#auth-nav").hidden = false;
    $("#user-menu").hidden = true;
    $("#nav-admin").hidden = true;
  }
  if (S.activeView === "dashboard") loadDashboard();
  if (S.activeView === "history") loadHistory();
  if (S.activeView === "team") loadTeamSetup();
}

/* ---------------------------------------------------------------- Auth Modals */
function openModal(id) { $(id).hidden = false; }
function closeModal(id) { $(id).hidden = true; }
$$(".modal-close").forEach((btn) => btn.addEventListener("click", (e) => {
  e.target.closest(".modal").hidden = true;
}));

$("#btn-show-login").addEventListener("click", () => openModal("#modal-login"));
$("#btn-show-register").addEventListener("click", () => openModal("#modal-register"));
$("#btn-show-forgot").addEventListener("click", () => {
  closeModal("#modal-login");
  openModal("#modal-forgot");
});
$("#btn-show-profile").addEventListener("click", () => {
  if (!S.user) return;
  $("#prof-user").value = S.user.username;
  $("#prof-email").value = S.user.email || "";
  load2FAStatus();
  loadApiTokens();
  openModal("#modal-profile");
});

// Login Form
$("#form-login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errBox = $("#login-error");
  errBox.hidden = true;
  try {
    const res = await api("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("#login-ident").value,
        password: $("#login-pw").value
      })
    });

    if (res.requires_2fa) {
      closeModal("#modal-login");
      $("#twofa-temp-token").value = res.temp_token;
      $("#twofa-code").value = "";
      $("#twofa-login-error").hidden = true;
      openModal("#modal-2fa-verify");
      return;
    }

    setAuthUser(res.user);
    closeModal("#modal-login");
    $("#form-login").reset();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  }
});

// 2FA Verification Form
$("#form-2fa-verify").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errBox = $("#twofa-login-error");
  errBox.hidden = true;
  try {
    const res = await api("/api/auth/2fa/verify-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        temp_token: $("#twofa-temp-token").value,
        code: $("#twofa-code").value
      })
    });
    setAuthUser(res.user);
    closeModal("#modal-2fa-verify");
    $("#form-login").reset();
    $("#form-2fa-verify").reset();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  }
});

// 2FA Management in Profile Modal
async function load2FAStatus() {
  const statusEl = $("#profile-2fa-status");
  const setupBtn = $("#btn-setup-2fa");
  const disableBtn = $("#btn-disable-2fa");
  const box = $("#profile-2fa-box");
  box.hidden = true;
  try {
    const res = await api("/api/auth/2fa/status");
    if (res.enabled) {
      statusEl.innerHTML = `<span class="badge low">ENABLED</span> Two-factor authentication is active on your account.`;
      setupBtn.hidden = true;
      disableBtn.hidden = false;
    } else {
      statusEl.innerHTML = `<span class="badge st">DISABLED</span> Protect your account with an authenticator app.`;
      setupBtn.hidden = false;
      disableBtn.hidden = true;
    }
  } catch (_) {
    statusEl.textContent = "Unable to load 2FA status.";
  }
}

$("#btn-setup-2fa").addEventListener("click", async () => {
  try {
    const res = await api("/api/auth/2fa/setup", { method: "POST" });
    $("#profile-2fa-key").textContent = res.secret;
    $("#profile-recovery-list").textContent = res.recovery_codes.join("\n");
    $("#profile-2fa-recovery").hidden = false;
    $("#profile-2fa-box").hidden = false;
  } catch (err) {
    alert("2FA setup error: " + err.message);
  }
});

$("#form-confirm-2fa").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("/api/auth/2fa/enable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: $("#confirm-2fa-code").value })
    });
    alert("2FA has been successfully enabled! Be sure to save your recovery codes.");
    load2FAStatus();
  } catch (err) {
    alert("Failed to enable 2FA: " + err.message);
  }
});

$("#btn-disable-2fa").addEventListener("click", async () => {
  const pw = prompt("Please enter your account password to confirm disabling 2FA:");
  if (!pw) return;
  try {
    await api("/api/auth/2fa/disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw })
    });
    alert("2FA has been disabled.");
    load2FAStatus();
  } catch (err) {
    alert("Failed to disable 2FA: " + err.message);
  }
});

// Register Form
$("#form-register").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errBox = $("#register-error");
  errBox.hidden = true;
  try {
    const res = await api("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("#reg-username").value,
        email: $("#reg-email").value,
        password: $("#reg-pw").value
      })
    });
    setAuthUser(res.user);
    closeModal("#modal-register");
    $("#form-register").reset();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  }
});

// Logout
$("#btn-logout").addEventListener("click", async () => {
  try {
    const res = await api("/api/auth/logout", { method: "POST" });
    if (res.csrf_token) S.csrfToken = res.csrf_token;
  } catch (err) {
    console.warn("Logout error:", err);
  }
  setAuthUser(null);
  switchView("home");
});

// Forgot Password & Local Token Reset
$("#form-forgot").addEventListener("submit", async (e) => {
  e.preventDefault();
  const infoBox = $("#forgot-info");
  try {
    const res = await api("/api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email_or_username: $("#forgot-ident").value })
    });
    infoBox.textContent = res.message;
    infoBox.hidden = false;
    if (res.reset_token) {
      $("#reset-token-box").hidden = false;
      $("#reset-token-val").value = res.reset_token;
    }
  } catch (err) {
    infoBox.textContent = err.message;
    infoBox.hidden = false;
  }
});

$("#form-reset-pw").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await api("/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        token: $("#reset-token-val").value,
        new_password: $("#reset-new-pw").value
      })
    });
    alert(res.message);
    closeModal("#modal-forgot");
    openModal("#modal-login");
  } catch (err) {
    alert("Reset failed: " + err.message);
  }
});

// Profile & Password Update
$("#form-profile").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("#profile-msg");
  msg.hidden = true;
  try {
    const res = await api("/api/auth/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: $("#prof-user").value,
        email: $("#prof-email").value
      })
    });
    setAuthUser(res.user);
    msg.textContent = "Profile updated successfully.";
    msg.hidden = false;
  } catch (err) {
    msg.textContent = err.message;
    msg.hidden = false;
  }
});

$("#form-change-pw").addEventListener("submit", async (e) => {
  e.preventDefault();
  const msg = $("#pw-msg");
  msg.hidden = true;
  try {
    await api("/api/auth/password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        current_password: $("#chg-old-pw").value,
        new_password: $("#chg-new-pw").value
      })
    });
    msg.textContent = "Password changed successfully.";
    msg.hidden = false;
    $("#form-change-pw").reset();
  } catch (err) {
    msg.textContent = err.message;
    msg.hidden = false;
  }
});

/* ---------------------------------------------------------------- Personal Access Tokens (PATs) */
async function loadApiTokens() {
  const listEl = $("#pat-list");
  if (!listEl) return;
  listEl.innerHTML = "<p class='muted small'>Loading personal access tokens...</p>";
  try {
    const tokens = await api("/api/tokens");
    if (!tokens || !tokens.length) {
      listEl.innerHTML = "<p class='muted small'>No personal access tokens generated yet.</p>";
      return;
    }
    listEl.replaceChildren(...tokens.map((t) => {
      const exp = t.expires_at ? new Date(t.expires_at * 1000).toLocaleDateString() : "Never";
      const last = t.last_used ? new Date(t.last_used * 1000).toLocaleDateString() : "Never";
      const isRevoked = t.status === "revoked";
      return h("div", { class: "vault-card" },
        h("div", null,
          h("strong", null, t.name),
          h("span", { class: "badge " + (isRevoked ? "high" : "low"), style: "margin-left: .5rem;" }, isRevoked ? "REVOKED" : "ACTIVE"),
          h("div", { class: "muted small", style: "font-family: monospace; margin-top: .2rem;" }, `${t.token_prefix}••••••••${t.token_last4}`),
          h("div", { class: "muted small" }, `Expires: ${exp} · Last used: ${last}`)),
        !isRevoked ? h("button", {
          class: "btn sm text-danger",
          onclick: async () => {
            if (!confirm(`Revoke token "${t.name}"? Applications using this token will lose access.`)) return;
            try {
              await api(`/api/tokens/${t.id}`, { method: "DELETE" });
              loadApiTokens();
            } catch (err) {
              alert("Failed to revoke token: " + err.message);
            }
          }
        }, "Revoke") : null
      );
    }));
  } catch (err) {
    listEl.innerHTML = `<p class='error small'>Error loading tokens: ${err.message}</p>`;
  }
}

$("#form-create-token").addEventListener("submit", async (e) => {
  e.preventDefault();
  const alertBox = $("#new-token-alert");
  const rawInput = $("#new-token-raw");
  alertBox.hidden = true;
  try {
    const res = await api("/api/tokens", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: $("#token-name").value,
        expires_days: parseInt($("#token-expiry").value, 10),
      })
    });
    rawInput.value = res.raw_token;
    alertBox.hidden = false;
    $("#form-create-token").reset();
    loadApiTokens();
  } catch (err) {
    alert("Failed to generate token: " + err.message);
  }
});

$("#btn-copy-token").addEventListener("click", () => {
  const val = $("#new-token-raw").value;
  if (val) {
    navigator.clipboard.writeText(val).then(() => {
      alert("Token copied to clipboard!");
    }).catch(() => {
      $("#new-token-raw").select();
      document.execCommand("copy");
      alert("Token copied to clipboard!");
    });
  }
});

/* ---------------------------------------------------------------- File Upload & Scanning */
const drop = $("#drop"), fileIn = $("#file");
let dragDepth = 0;
drop.addEventListener("click", (event) => {
  if (event.target !== fileIn && !event.target.closest("button")) fileIn.click();
});
drop.addEventListener("keydown", (event) => {
  if (event.target !== drop) return;
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    fileIn.click();
  }
});
$("#scan-browse").addEventListener("click", (event) => {
  event.stopPropagation();
  if (!S.scanning && S.uploadConfigLoaded) fileIn.click();
});
drop.addEventListener("dragenter", (event) => {
  event.preventDefault();
  dragDepth += 1;
  drop.classList.add("over");
});
drop.addEventListener("dragover", (event) => {
  event.preventDefault();
  if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
  drop.classList.add("over");
});
drop.addEventListener("dragleave", (event) => {
  event.preventDefault();
  dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) drop.classList.remove("over");
});
drop.addEventListener("drop", (event) => {
  event.preventDefault();
  dragDepth = 0;
  drop.classList.remove("over");
  const file = event.dataTransfer && event.dataTransfer.files[0];
  if (file) scan(file);
});
fileIn.addEventListener("change", () => {
  const file = fileIn.files[0];
  fileIn.value = "";
  if (file) scan(file);
});

function showError(msg) { const e = $("#error"); e.textContent = msg || ""; e.hidden = !msg; }

function formatUploadSize(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function isSupportedUpload(file) {
  if (!S.uploadConfigLoaded || !S.maxUploadBytes) {
    showError("Scanner configuration is unavailable. Refresh the page before uploading a file.");
    return false;
  }
  const match = file.name.toLowerCase().match(/(\.[^./\\]+)$/);
  const extension = match ? match[1] : "";
  if (!S.uploadExtensions.includes(extension)) {
    showError(`Unsupported file type. This instance supports: ${S.uploadExtensions.join(" ")}`);
    return false;
  }
  if (file.size > S.maxUploadBytes) {
    showError(`File is larger than ${S.maxUploadMB} MB. Choose a smaller file.`);
    return false;
  }
  return true;
}

async function scan(file) {
  if (S.scanning || !file) return;
  showError("");
  const supported = isSupportedUpload(file);
  $("#results").hidden = true;
  drop.classList.add("has-file");
  $("#scan-selected-file").hidden = false;
  $("#scan-selected-file").classList.toggle("is-invalid", !supported);
  $("#scan-selected-mark").textContent = supported ? "✓" : "!";
  $("#scan-selected-name").textContent = file.name;
  $("#scan-selected-size").textContent = formatUploadSize(file.size);
  if (!supported) return;

  S.scanning = true;
  $("#scan-busy-label").textContent = `Scanning ${file.name} with this instance's configured detectors…`;
  $("#busy").hidden = false;
  $("#scan-browse").disabled = true;
  $$("[data-sample]").forEach((button) => { button.disabled = true; });
  const fd = new FormData(); fd.append("file", file);
  try {
    const res = await api("/api/scan", { method: "POST", body: fd });
    S.scan = res; S.showAll = false; $("#show-all").checked = false;
    S.selected = new Set(res.findings.filter((f) => f.status === "active" && !f.metadata && f.level !== "low").map((f) => f.id));
    render();
    $("#results").scrollIntoView({ block: "start" });
  } catch (e) {
    showError(e.message);
  } finally {
    $("#busy").hidden = true;
    S.scanning = false;
    $("#scan-browse").disabled = !S.uploadConfigLoaded;
    $$("[data-sample]").forEach((button) => { button.disabled = !S.uploadConfigLoaded; });
  }
}

const sampleFiles = {
  python: "demo_app.py",
  pdf: "demo_report.pdf",
  screenshot: "demo_screenshot.jpg",
  notes: "demo_notes.txt"
};
$$("[data-sample]").forEach((button) => {
  button.addEventListener("click", async () => {
    if (S.scanning) return;
    const sampleId = button.dataset.sample;
    const filename = sampleFiles[sampleId];
    if (!filename) return;
    button.disabled = true;
    showError("");
    try {
      const response = await fetch(`/api/samples/${encodeURIComponent(sampleId)}`, { credentials: "same-origin" });
      if (!response.ok) throw new Error(`Synthetic sample unavailable (${response.status}).`);
      const blob = await response.blob();
      await scan(new File([blob], filename, { type: blob.type }));
    } catch (error) {
      showError(error.message);
    } finally {
      button.disabled = !S.uploadConfigLoaded;
    }
  });
});

function render() {
  const r = S.scan;
  $("#results").hidden = false; $("#done").hidden = true;
  renderSummary(); renderWarnings(); renderFindings(); renderViewer();
  $("#redact").disabled = false;
}

function renderSummary() {
  const r = S.scan, s = r.summary, o = s.overall;
  const card = (n, l, cls) => h("div", { class: "card" }, h("div", { class: "n " + (cls || "") }, n), h("div", { class: "l" }, l));
  $("#summary").replaceChildren(
    h("div", { class: "card big" },
      h("div", { class: "l" }, `Overall risk · ${r.filename} (${r.kind}, ${(r.size / 1024).toFixed(1)} KB)`),
      h("div", { class: "n " + o.level }, `${o.level.toUpperCase()} · ${o.score}/100`),
      h("div", { class: "gauge" }, h("i", { style: `width:${o.score}%;background:${LEVEL_COLOR[o.level]}` })),
      h("div", { class: "l" }, o.explanation)),
    card(s.high, "high risk", "high"),
    card(s.medium, "medium risk", "medium"),
    card(s.low, "low risk", "low"),
    card(s.placeholder + s.likely_benign, "placeholders / likely benign")
  );
}

function renderWarnings() {
  $("#warnings").replaceChildren(...S.scan.warnings.map((w) => h("div", { class: "warn-box" }, w)));
}

function where(f) {
  if (f.metadata) return "metadata";
  if (S.scan.kind === "pdf") return `page ${f.page || "?"}, line ${f.page_line || "?"}`;
  if (S.scan.kind === "image") return "in image";
  return `line ${f.line}, col ${f.col}`;
}

function renderFindings() {
  const list = S.scan.findings.filter(visible)
    .sort((a, b) => (a.status === "active" ? 0 : 1) - (b.status === "active" ? 0 : 1) || b.score - a.score);
  $("#count").textContent = `(${list.length} shown of ${S.scan.findings.length})`;
  if (!list.length) {
    $("#findings").replaceChildren(h("div", { class: "note" }, "No active findings. This does not guarantee a file is safe: it only means nothing matched current rules and ML model."));
    return;
  }
  $("#findings").replaceChildren(...list.map((f) => {
    const cb = h("input", { type: "checkbox", "aria-label": "Select finding" });
    cb.checked = f.metadata || S.selected.has(f.id); cb.disabled = !!f.metadata;
    cb.addEventListener("change", () => { cb.checked ? S.selected.add(f.id) : S.selected.delete(f.id); });
    const card = h("div", { class: `f ${f.level} ${f.status !== "active" ? "dim" : ""}`, id: "card-" + f.id },
      h("div", { class: "head" }, cb,
        h("span", { class: "badge " + f.level }, `${f.level} ${f.score}`),
        h("span", { class: "title" }, f.label),
        f.provider && f.provider !== "Generic" ? h("span", { class: "badge pro" }, f.provider) : null,
        f.status !== "active" ? h("span", { class: "badge st" }, f.status.replace("_", " ")) : null,
        f.source !== "rule" && f.source !== "metadata" ? h("span", { class: "badge st" }, f.source === "ml" ? "ML only" : "rule + ML") : null,
        h("span", { class: "where", onclick: () => focusFinding(f) }, where(f))),
      h("div", null, h("code", null, f.preview)),
      f.context && !f.metadata ? h("div", { class: "d" }, f.context) : null,
      h("details", null, h("summary", null, "Why was this flagged? What should I do?"),
        h("ul", null, f.reasons.map((x) => h("li", null, x.text, x.delta ? h("span", { class: "d" }, ` (${x.delta > 0 ? "+" : ""}${x.delta})`) : null))),
        h("div", null, h("strong", null, "Risk: "), f.why),
        h("div", null, h("strong", null, "Recommended: "), f.action),
        f.blast_radius ? h("div", null, h("strong", null, "Potential blast radius: "), f.blast_radius) : null,
        f.metadata ? h("div", { class: "muted" }, "Metadata is always stripped from sanitised copy.") : null),
      f.blast_radius ? h("div", { class: "blast" }, h("strong", null, "Potential blast radius: "), f.blast_radius) : null,
      reportFalsePositiveButton(f));
    return card;
  }));
}

function reportFalsePositiveButton(f) {
  const btn = h("button", { type: "button", class: "btn sm outline" }, "Report false positive");
  btn.addEventListener("click", async () => {
    if (!S.user) { openModal("#modal-login"); return; }
    btn.disabled = true;
    try {
      await api("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          kind: "false_positive",
          scan_id: S.scan && S.scan.scan_id,
          finding_id: f.id,
          finding_type: f.type,
          provider: f.provider || "",
          note: "",
        }),
      });
      btn.textContent = "Reported";
    } catch (e) {
      btn.disabled = false;
      showError(e.message);
    }
  });
  return h("div", { class: "fp-row" }, btn);
}

$("#report-missed").addEventListener("click", async () => {
  if (!S.scan) return;
  if (!S.user) { openModal("#modal-login"); return; }
  const note = window.prompt("Describe the missed secret without pasting the raw value (what it is, and where it appears).");
  if (!note) return;
  const btn = $("#report-missed");
  btn.disabled = true;
  try {
    await api("/api/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        kind: "false_negative",
        scan_id: S.scan.scan_id,
        note: note,
      }),
    });
    btn.textContent = "Report saved";
  } catch (e) {
    btn.disabled = false;
    showError(e.message);
  }
});

function lineRows(text) {
  const rows = []; let start = 0, re = /[\n\f]/g, m;
  while ((m = re.exec(text))) { rows.push({ s: start, e: m.index, sep: m[0] }); start = m.index + 1; }
  rows.push({ s: start, e: text.length, sep: "" });
  return rows;
}

function renderViewer() {
  const r = S.scan, v = $("#viewer");
  $("#viewer-title").textContent = r.kind === "image" ? "Image (highlighted regions)" : "Document (secrets masked)";
  if (r.kind === "image") {
    const wrap = h("div", { class: "imgwrap" }, h("img", { src: r.image.url, alt: "Uploaded image" }));
    r.findings.filter((f) => visible(f) && f.boxes_pct).forEach((f) => f.boxes_pct.forEach(([x, y, w, hh]) => {
      const b = h("div", { class: "box " + f.level, "data-fid": f.id, title: f.label });
      b.style.left = x + "%"; b.style.top = y + "%"; b.style.width = w + "%"; b.style.height = hh + "%";
      b.addEventListener("click", () => focusFinding(f, true));
      wrap.append(b);
    }));
    v.replaceChildren(wrap, h("div", { class: "note" }, `OCR read ${r.ocr_text_chars} characters. Metadata findings are listed on the left and stripped from output.`));
    return;
  }
  const t = r.masked_text || "";
  const fs = r.findings.filter((f) => f.start != null && visible(f)).sort((a, b) => a.start - b.start);
  const rows = lineRows(t), out = []; let ln = 0, fi = 0;
  rows.slice(0, 6000).forEach((row, idx) => {
    if (idx === 0 && r.kind === "pdf") out.push(h("div", { class: "ln pg" }, "— page 1 —"));
    ln++;
    const body = h("span", null); let pos = row.s;
    while (fi < fs.length && fs[fi].end <= row.s) fi++;
    for (let k = fi; k < fs.length && fs[k].start < row.e; k++) {
      const f = fs[k], a = Math.max(f.start, row.s), b = Math.min(f.end, row.e);
      if (b <= a) continue;
      if (a > pos) body.append(t.slice(pos, a));
      const mk = h("mark", { class: f.status === "active" ? f.level : "dim", "data-fid": f.id, title: f.label }, t.slice(a, b));
      mk.addEventListener("click", () => focusFinding(f, true));
      body.append(mk); pos = b;
    }
    if (pos < row.e) body.append(t.slice(pos, row.e));
    out.push(h("div", { class: "ln" }, h("i", null, ln), body));
    if (row.sep === "\f") { out.push(h("div", { class: "ln pg" }, "— page break —")); ln = 0; }
  });
  v.replaceChildren(...out);
}

function focusFinding(f, fromViewer) {
  $$(".on").forEach((e) => e.classList.remove("on"));
  $$(".sel").forEach((e) => e.classList.remove("sel"));
  const els = $$(`#viewer [data-fid="${f.id}"]`);
  els.forEach((e) => e.classList.add("on"));
  const card = $("#card-" + f.id);
  if (card) card.classList.add("sel");
  const target = fromViewer ? card : els[0];
  if (target) target.scrollIntoView({ block: "center", behavior: "smooth" });
}

/* ---------------------------------------------------------------- Toolbar / Redaction */
function setSelection(pred) {
  S.selected = new Set(S.scan.findings.filter((f) => f.status === "active" && !f.metadata && pred(f)).map((f) => f.id));
  renderFindings();
}
$("#sel-hm").addEventListener("click", () => setSelection((f) => f.level !== "low"));
$("#sel-all").addEventListener("click", () => setSelection(() => true));
$("#sel-none").addEventListener("click", () => setSelection(() => false));
$("#show-all").addEventListener("change", (e) => { S.showAll = e.target.checked; renderFindings(); renderViewer(); });

$("#redact").addEventListener("click", async () => {
  const btn = $("#redact"); btn.disabled = true; showError("");
  try {
    const res = await api("/api/redact", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: S.scan.scan_id, finding_ids: [...S.selected], style: $("#style").value }),
    });
    const v = res.verification || {};
    const remain = v.error ? h("div", { class: "remain" }, "Rescan failed: " + v.error)
      : h("div", null, "Verification rescan of sanitised file: ",
          h("strong", { class: v.active ? "remain" : "" }, `${v.active} active finding(s) remaining`),
          v.active ? ` (${v.high} high, ${v.medium} medium, ${v.low} low)` : " ✔ CLEAN",
          v.metadata_remaining ? ` · ${v.metadata_remaining} metadata field(s) remain` : "",
          v.active && v.remaining ? h("div", { class: "d" }, "Not redacted: " + v.remaining.map((x) => `${x.label} (${x.level})`).join(", ")) : null);
    const d = res.downloads;
    $("#done").replaceChildren(
      h("div", null, h("strong", null, `Sanitised copy created: ${res.output_file}`), ` · ${res.redacted_count} finding(s) redacted. `),
      remain,
      h("div", { class: "foot-grp grp" },
        h("a", { class: "btn sm primary", href: d.sanitised }, "⬇ Sanitised File"),
        h("a", { class: "btn sm", href: d.report_html, target: "_blank" }, "⬇ Report (HTML)"),
        h("a", { class: "btn sm", href: d.report_json }, "⬇ Report (JSON)"),
        d.sarif ? h("a", { class: "btn sm", href: d.sarif }, "⬇ Report (SARIF)") : null),
      h("div", { class: "muted small", style: "margin-top: .6rem" }, "Redacting a copy does not make an already-exposed secret safe: rotate any real credential.")
    );
    $("#done").hidden = false;
    $("#done").scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (e) { showError(e.message); }
  btn.disabled = false;
});

$("#discard").addEventListener("click", async () => {
  if (!S.scan) return;
  try { await api("/api/scan/" + S.scan.scan_id, { method: "DELETE" }); } catch (_) {}
  S.scan = null; $("#results").hidden = true;
});

$("#btn-create-env-from-scan").addEventListener("click", () => {
  if (!S.scan) return;
  switchView("team");
  generateEnvTemplate(S.scan.scan_id);
});

/* ---------------------------------------------------------------- User Dashboard */
let dashboardDays = 30;

async function loadDashboard() {
  if (!S.user) {
    $("#dashboard-guest").hidden = false;
    $("#dashboard-authenticated").hidden = true;
    return;
  }
  $("#dashboard-guest").hidden = true;
  $("#dashboard-authenticated").hidden = false;
  $("#dashboard-auth-welcome").textContent = `Welcome back, ${S.user.username}!`;
  $("#dashboard-status").replaceChildren(h("span", { class: "dashboard-loading" }, "Loading dashboard…"));
  try {
    const [stats, recent] = await Promise.all([
      api(`/api/user/stats?days=${dashboardDays}`),
      api("/api/user/history?limit=5")
    ]);
    $("#dashboard-status").replaceChildren(h("small", { class: "dashboard-updated" }, `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`));
    const high = stats.period_high ?? stats.high ?? 0;
    const medium = stats.period_medium ?? stats.medium ?? 0;
    const low = stats.period_low ?? stats.low ?? 0;
    const periodFiles = stats.period_files ?? stats.total_files ?? 0;
    const activeFindings = stats.active_findings ?? stats.total_findings ?? 0;
    $("#stat-files").textContent = periodFiles;
    $("#stat-files-detail").textContent = `${dashboardDays}-day period`;
    $("#stat-findings").textContent = activeFindings;
    $("#stat-findings-detail").textContent = activeFindings === 1 ? "Active finding" : "Active findings";
    $("#stat-sanitised").textContent = stats.sanitised;
    $("#stat-sanitised-detail").textContent = stats.sanitised ? "Sanitised outputs available" : "No sanitised files";
    renderTrendsChart(stats.trends || []);
    renderRiskDistribution(high, medium, low);
    renderDashboardRecent(recent);
    renderSecurityInsights(stats, recent);
    renderSparkline(stats.trends || []);
  } catch (e) {
    console.error("Dashboard error:", e);
    $("#dashboard-status").replaceChildren(h("div", { class: "dashboard-error" },
      h("span", null, e.message.includes("Unauthorized") ? "Your session has expired." : "Dashboard analytics could not be loaded."),
      h("button", { class: "btn sm", type: "button", id: "dashboard-retry" }, "Retry")
    ));
    $("#dashboard-retry").addEventListener("click", () => loadDashboard());
  }
}

function renderTrendsChart(trends) {
  const container = $("#chart-trends");
  if (!trends.length) {
    container.replaceChildren(h("p", { class: "chart-empty" }, "No scan activity recorded for this period."));
    return;
  }
  const width = 720, height = 220, left = 38, right = 12, top = 16, bottom = 34;
  const maxValue = Math.max(...trends.map((t) => Math.max(t.files, t.h + t.m + t.l)), 4);
  const step = (width - left - right) / Math.max(trends.length - 1, 1);
  const y = (value) => top + (height - top - bottom) * (1 - value / maxValue);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("class", "trend-svg");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Files scanned and findings detected over time");
  for (let i = 0; i <= 4; i += 1) {
    const yy = y((maxValue / 4) * i);
    const grid = document.createElementNS(svg.namespaceURI, "line");
    grid.setAttribute("x1", left); grid.setAttribute("x2", width - right);
    grid.setAttribute("y1", yy); grid.setAttribute("y2", yy); grid.setAttribute("class", "chart-grid");
    svg.append(grid);
  }
  [["files", "files", (t) => t.files], ["findings", "findings", (t) => t.h + t.m + t.l]].forEach(([kind, cls, getValue]) => {
    const line = document.createElementNS(svg.namespaceURI, "polyline");
    line.setAttribute("points", trends.map((t, i) => `${left + i * step},${y(getValue(t))}`).join(" "));
    line.setAttribute("class", `chart-line ${cls}`);
    svg.append(line);
    trends.forEach((t, i) => {
      const value = getValue(t);
      const dot = document.createElementNS(svg.namespaceURI, "circle");
      dot.setAttribute("cx", left + i * step); dot.setAttribute("cy", y(value));
      dot.setAttribute("r", "4"); dot.setAttribute("class", `chart-dot ${cls}`);
      const title = document.createElementNS(svg.namespaceURI, "title");
      title.textContent = `${t.day}: ${value} ${kind === "files" ? "files scanned" : "findings"}`;
      dot.append(title); svg.append(dot);
    });
  });
  container.replaceChildren(svg, h("div", { class: "chart-legend" },
    h("span", null, h("i", { class: "legend-files" }), "Files Scanned"),
    h("span", null, h("i", { class: "legend-findings" }), "Findings")
  ));
}

function renderRiskDistribution(high, medium, low) {
  const total = high + medium + low;
  const pct = (value) => total ? Math.round((value / total) * 100) : 0;
  $("#risk-total").textContent = total;
  $("#risk-high").textContent = high;
  $("#risk-medium").textContent = medium;
  $("#risk-low").textContent = low;
  $("#risk-high-pct").textContent = `${pct(high)}%`;
  $("#risk-medium-pct").textContent = `${pct(medium)}%`;
  $("#risk-low-pct").textContent = `${pct(low)}%`;
  const highEnd = pct(high) * 3.6;
  const mediumEnd = highEnd + pct(medium) * 3.6;
  $("#risk-donut").style.background = total
    ? `conic-gradient(var(--high) 0deg ${highEnd}deg, var(--med) ${highEnd}deg ${mediumEnd}deg, var(--low) ${mediumEnd}deg 360deg)`
    : "conic-gradient(var(--line) 0deg 360deg)";
  $("#risk-donut").setAttribute("aria-label", `Risk distribution: ${high} high, ${medium} medium, ${low} low`);
}

function renderSparkline(trends) {
  const svg = $("#files-spark");
  svg.replaceChildren();
  if (!trends.length) return;
  const values = trends.map((t) => t.files);
  const max = Math.max(...values, 1);
  const step = 120 / Math.max(values.length - 1, 1);
  const points = values.map((value, index) => `${index * step},${34 - (value / max) * 28}`).join(" ");
  const polyline = document.createElementNS(svg.namespaceURI, "polyline");
  polyline.setAttribute("points", points);
  polyline.setAttribute("class", "spark-line");
  svg.append(polyline);
}

function renderDashboardRecent(rows) {
  const box = $("#dashboard-recent");
  if (!rows.length) {
    box.replaceChildren(h("p", { class: "recent-empty" }, "No scans yet. Scan a file to build your security history."));
    return;
  }
  const table = h("table", { class: "dashboard-table" },
    h("thead", null, h("tr", null,
      ["File Name", "Scan Date", "Risk Level", "Status", "Actions"].map((x) => h("th", null, x))
    )),
    h("tbody", null, rows.slice(0, 5).map((row) => {
      const level = (row.level || "low").toLowerCase();
      const status = row.redacted ? "Sanitised" : "Scanned";
      return h("tr", null,
        h("td", null, h("span", { class: "file-name" }, h("b", null, "▤"), row.filename)),
        h("td", { class: "muted" }, new Date(row.created * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })),
        h("td", null, h("span", { class: `risk-badge ${level}` }, level.charAt(0).toUpperCase() + level.slice(1))),
        h("td", null, h("span", { class: "status-badge" }, status)),
        h("td", null, h("div", { class: "scan-actions" },
          h("a", { class: "action-link", href: `/report/${row.id}`, title: "View report", "aria-label": "View report" }, "◉"),
          h("a", { class: "action-link", href: `/report/${row.id}`, title: "View findings", "aria-label": "View findings" }, "≡"),
          row.redacted ? h("a", { class: "action-link", href: `/api/download/${row.id}/sanitised`, title: "Download sanitised file", "aria-label": "Download sanitised file" }, "↓") : null
        ))
      );
    }))
  );
  box.replaceChildren(table);
}

function renderSecurityInsights(stats, recent) {
  const items = [];
  if (stats.active_findings > 0) {
    items.push("Active findings need review. Rotate exposed credentials and move secrets into environment variables.");
  }
  if (stats.sanitised > 0) {
    items.push("Sanitised files are available. Re-open the latest report and verify the sanitised output.");
  }
  if (!recent.length) {
    items.push("No recent scans: scan a project file before sharing or committing it.");
  } else if (stats.active_findings === 0) {
    items.push("No active findings are recorded in the latest available scan data.");
  }
  const list = $("#dashboard-insights");
  list.replaceChildren(...items.map((text) => h("li", null,
    h("span", { class: "insight-check", "aria-hidden": "true" }, "✓"),
    h("span", null, text)
  )));
}

$$("[data-days]").forEach((button) => button.addEventListener("click", () => {
  $$("[data-days]").forEach((item) => item.classList.toggle("active", item === button));
  dashboardDays = Number(button.dataset.days);
  loadDashboard();
}));
$("#dashboard-refresh").addEventListener("click", () => loadDashboard());
$("#guest-login").addEventListener("click", () => openModal("#modal-login"));
$("#guest-insights-login").addEventListener("click", () => openModal("#modal-login"));
$("#guest-register").addEventListener("click", () => openModal("#modal-register"));

/* ---------------------------------------------------------------- Scan History */
const historyState = { page: 1, total: 0, pages: 1, requestId: 0, selectedId: null };

function historyDate(timestamp) {
  const date = new Date(Number(timestamp) * 1000);
  return Number.isNaN(date.getTime()) ? "Date unavailable" : date.toLocaleString();
}

function setHistoryFormats() {
  const select = $("#history-filter-format");
  if (!select) return;
  const selected = select.value;
  select.replaceChildren(
    h("option", { value: "" }, "All formats"),
    ...S.uploadExtensions.map((ext) => {
      const value = ext.replace(/^\./, "").toLowerCase();
      return h("option", { value }, ext.toUpperCase());
    })
  );
  if ([...select.options].some((option) => option.value === selected)) select.value = selected;
}

function renderHistorySummary(summary) {
  const cards = [
    ["Scans saved", summary.total, "history-summary-total"],
    ["High-risk files", summary.high_risk, "history-summary-high"],
    ["Sanitised files", summary.sanitised, "history-summary-safe"]
  ];
  $("#history-summary").replaceChildren(...cards.map(([label, value, className]) =>
    h("article", { class: `history-summary-card ${className}` },
      h("span", { class: "history-summary-label" }, label),
      h("strong", { class: "history-summary-value" }, String(value)),
      h("span", { class: "history-summary-note" }, "Across your saved scans")
    )
  ));
  $("#history-clear").hidden = !summary.total;
}

function renderHistoryFinding(finding, statusAvailable) {
  const level = String(finding.level || "low").toLowerCase();
  const status = statusAvailable ? String(finding.status || "unclassified").replace(/_/g, " ") : "status unavailable";
  return h("article", { class: "history-finding" },
    h("div", { class: "history-finding-head" },
      h("strong", null, finding.label || finding.type || "Finding"),
      h("span", { class: `history-risk-chip risk-${level}` }, level),
      h("span", { class: "history-finding-status" }, status),
      finding.line != null ? h("span", { class: "muted small" }, `Line ${finding.line}`) : null
    ),
    h("p", { class: "small muted" }, finding.category || "Uncategorized",
      finding.provider ? ` · ${finding.provider}` : ""),
    h("code", { class: "history-masked-preview" }, finding.preview || "Masked preview unavailable")
  );
}

async function showHistoryDetail(scanId) {
  const ownerId = S.user && S.user.id;
  const preview = $("#history-preview");
  preview.hidden = false;
  preview.replaceChildren(h("p", { class: "muted" }, "Loading masked scan details…"));
  historyState.selectedId = scanId;
  try {
    const item = await api(`/api/user/history/${encodeURIComponent(scanId)}`);
    if (!S.user || S.user.id !== ownerId || historyState.selectedId !== scanId) return;
    const findings = Array.isArray(item.findings) ? item.findings : [];
    const counts = item.finding_counts || {};
    const statusAvailable = counts.status_available === true;
    const totalLabel = counts.total == null ? "Total count unavailable" : `${counts.total} total findings`;
    const findingSummary = statusAvailable
      ? [
        totalLabel,
        `${counts.active_high} active high`,
        `${counts.active_medium} active medium`,
        `${counts.active_low} active low`,
        `${counts.redacted} redacted`
      ]
      : [
        totalLabel,
        "Active status unavailable",
        `${counts.redacted} redactions recorded`
      ];
    const detailList = h("div", { class: "history-findings" });
    const disclosure = findings.length
      ? h("details", { class: "history-findings-disclosure" },
        h("summary", null, `View all findings (${findings.length})`),
        detailList)
      : null;
    let findingsRendered = false;
    if (disclosure) disclosure.addEventListener("toggle", () => {
      if (!disclosure.open || findingsRendered) return;
      detailList.replaceChildren(...findings.map((finding) => renderHistoryFinding(finding, statusAvailable)));
      findingsRendered = true;
    });
    const previewContent = [
      h("div", { class: "history-preview-heading" },
        h("div", null,
          h("p", { class: "history-eyebrow" }, "MASKED SCAN PREVIEW"),
          h("h3", null, item.filename),
          h("p", { class: "muted small" }, `${historyDate(item.created)} · ${String(item.kind || "file").toUpperCase()}`)
        ),
        h("button", { class: "btn icon-btn", type: "button", "aria-label": "Close scan details", onclick: () => {
          historyState.selectedId = null;
          preview.hidden = true;
          preview.replaceChildren();
        } }, "×")
      ),
      h("div", { class: "history-detail-stats" },
        h("span", { class: `history-risk-chip risk-${String(item.level || "low").toLowerCase()}` },
          `${String(item.level || "low").toUpperCase()} RISK · ${item.score}`),
        ...findingSummary.map((text) => h("span", null, text))
      )
    ];
    if (!statusAvailable) {
      previewContent.push(h("p", { class: "history-count-status-note" },
        "Per-finding status is unavailable for this scan. The known redaction count is shown without guessing which findings remain active."
      ));
    }
    previewContent.push(disclosure || h("p", { class: "muted" }, counts.total
        ? "Detailed finding data is unavailable for this scan."
        : counts.total === 0 ? "No findings were recorded for this scan."
          : "Finding data is unavailable for this scan."));
    preview.replaceChildren(...previewContent);
  } catch (error) {
    if (S.user && S.user.id === ownerId && historyState.selectedId === scanId) {
      preview.replaceChildren(h("p", { class: "text-danger", role: "alert" }, error.message));
    }
  }
}

function renderHistoryRecord(item) {
  const level = String(item.level || "low").toLowerCase();
  const filename = item.filename || "Unnamed file";
  const counts = item.finding_counts || {};
  const totalLabel = counts.total == null ? "Total unavailable" : `${counts.total} total`;
  const countSummary = counts.status_available
    ? [
      h("span", null, totalLabel),
      h("span", { class: "risk-count-high" }, `${counts.active_high} active high`),
      h("span", { class: "risk-count-medium" }, `${counts.active_medium} active medium`),
      h("span", { class: "risk-count-low" }, `${counts.active_low} active low`),
      h("span", null, `${counts.redacted} redacted`)
    ]
    : [
      h("span", null, counts.total == null ? totalLabel : `${counts.total} findings at scan`),
      h("span", null, `${counts.redacted} redactions recorded`),
      h("span", { class: "muted" }, "Status unavailable")
    ];
  const actions = [
    h("button", { class: "btn sm outline", type: "button", onclick: () => showHistoryDetail(item.id) }, "View masked details")
  ];
  if (item.report_available) {
    actions.push(h("a", {
      class: "btn sm outline", href: `/report/${encodeURIComponent(item.id)}`,
      target: "_blank", rel: "noopener noreferrer"
    }, "View report"));
  }
  if (item.sanitised_available) {
    actions.push(h("a", {
      class: "btn sm outline", href: `/api/download/${encodeURIComponent(item.id)}/sanitised`
    }, "Sanitised copy"));
  }
  actions.push(h("button", {
    class: "btn sm history-delete", type: "button",
    onclick: async () => {
      if (!confirm(`Delete the saved scan for ${filename}?`)) return;
      try {
        await api(`/api/scan/${encodeURIComponent(item.id)}`, { method: "DELETE" });
        if (historyState.selectedId === item.id) {
          historyState.selectedId = null;
          $("#history-preview").hidden = true;
        }
        await loadHistory();
      } catch (error) {
        $("#history-status").textContent = error.message;
      }
    }
  }, "Delete"));

  return h("article", { class: "history-record" },
    h("div", { class: "history-record-main" },
      h("div", { class: "history-file-mark", "aria-hidden": "true" }, (filename.split(".").pop() || "FILE").slice(0, 3).toUpperCase()),
      h("div", { class: "history-file-meta" },
        h("h3", null, filename),
        h("p", { class: "muted small" }, `${historyDate(item.created)} · ${String(item.kind || "file").toUpperCase()}`)
      ),
      h("span", { class: `history-risk-chip risk-${level}` }, `${level} · ${item.score}`)
    ),
    h("div", { class: "history-record-counts" },
      ...countSummary
    ),
    h("div", { class: "history-record-actions" }, actions)
  );
}

function renderHistoryPagination(result) {
  const nav = $("#history-pagination");
  const previous = h("button", {
    class: "btn sm outline", type: "button", disabled: result.page <= 1,
    onclick: () => { historyState.page -= 1; loadHistory(); }
  }, "Previous");
  const next = h("button", {
    class: "btn sm outline", type: "button", disabled: result.page >= result.pages,
    onclick: () => { historyState.page += 1; loadHistory(); }
  }, "Next");
  nav.replaceChildren(previous, h("span", { class: "small muted", "aria-live": "polite" },
    `Page ${result.page} of ${result.pages}`), next);
}

async function loadHistory() {
  const requestId = ++historyState.requestId;
  const guest = $("#history-guest");
  const authenticated = $("#history-authenticated");
  if (!S.user) {
    guest.hidden = false;
    authenticated.hidden = true;
    $("#history-clear").hidden = true;
    return;
  }
  guest.hidden = true;
  authenticated.hidden = false;
  setHistoryFormats();
  const params = new URLSearchParams({
    page: String(historyState.page),
    per_page: $("#history-page-size").value,
    days: $("#history-filter-days").value,
    sort: $("#history-sort").value
  });
  const risk = $("#history-filter-risk").value;
  const fileFormat = $("#history-filter-format").value;
  const query = $("#history-search").value.trim();
  if (risk) params.set("risk", risk);
  if (fileFormat) params.set("format", fileFormat);
  if (query) params.set("q", query);
  $("#history-status").textContent = "Loading your scan history…";

  try {
    const result = await api(`/api/user/history?${params.toString()}`);
    if (requestId !== historyState.requestId || !S.user) return;
    historyState.page = result.page;
    historyState.pages = result.pages;
    historyState.total = result.total;
    historyState.selectedId = null;
    $("#history-preview").hidden = true;
    renderHistorySummary(result.summary);
    const start = result.total ? ((result.page - 1) * result.per_page) + 1 : 0;
    const end = Math.min(result.page * result.per_page, result.total);
    $("#history-status").textContent = result.total
      ? `Showing ${start}–${end} of ${result.total} scans`
      : query || risk || fileFormat || Number(params.get("days"))
        ? "No scans match these filters."
        : "No scans saved yet. Your completed scans will appear here.";
    $("#history-list").replaceChildren(...result.items.map(renderHistoryRecord));
    renderHistoryPagination(result);
  } catch (error) {
    if (requestId !== historyState.requestId) return;
    $("#history-status").textContent = "Could not load scan history.";
    $("#history-list").replaceChildren(h("p", { class: "text-danger", role: "alert" }, error.message));
  }
}

let historySearchTimer;
$("#history-search").addEventListener("input", () => {
  clearTimeout(historySearchTimer);
  historySearchTimer = setTimeout(() => { historyState.page = 1; loadHistory(); }, 250);
});
["history-filter-risk", "history-filter-format", "history-filter-days", "history-sort", "history-page-size"]
  .forEach((id) => $(`#${id}`).addEventListener("change", () => { historyState.page = 1; loadHistory(); }));
$("#history-reset").addEventListener("click", () => {
  $("#history-search").value = "";
  $("#history-filter-risk").value = "";
  $("#history-filter-format").value = "";
  $("#history-filter-days").value = "0";
  $("#history-sort").value = "newest";
  $("#history-page-size").value = "10";
  historyState.page = 1;
  loadHistory();
});
$("#history-guest-login").addEventListener("click", () => openModal("#modal-login"));
$("#history-guest-register").addEventListener("click", () => openModal("#modal-register"));
$("#history-clear").addEventListener("click", async () => {
  if (!confirm("Clear all of your saved scan history? This cannot be undone.")) return;
  try {
    await api("/api/user/history", { method: "DELETE" });
    historyState.page = 1;
    await loadHistory();
  } catch (error) {
    $("#history-status").textContent = error.message;
  }
});

/* ---------------------------------------------------------------- Safe Team Setup */
async function loadTeamSetup() {
  if (!$("#env-preview-code").textContent.trim()) {
    await generateEnvTemplate();
  }
  await loadVaultItems();
}

async function generateEnvTemplate(scanId) {
  const feedback = $("#team-template-feedback");
  feedback.textContent = "Preparing a safe placeholder-only template…";
  feedback.classList.remove("is-error");
  $("#btn-copy-env").disabled = true;
  $("#btn-download-env").disabled = true;
  $("#btn-download-team-zip").disabled = true;
  try {
    const findings = S.scan && Array.isArray(S.scan.findings)
      ? S.scan.findings.map((finding) => ({
          key: typeof finding.key === "string" ? finding.key : null,
          type: typeof finding.type === "string" ? finding.type : null,
          status: typeof finding.status === "string" ? finding.status : null
        }))
      : [];
    const requestBody = scanId && S.user ? { scan_id: scanId } : { findings };
    const res = await api("/api/team/env-example", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody)
    });
    renderTeamTemplate(res.env_example);
    $("#btn-copy-env").disabled = false;
    $("#btn-download-env").disabled = false;
    $("#btn-download-team-zip").disabled = false;
    setTeamIndicator("#team-indicator-safe", "Safe template generated", "is-good");
    setTeamIndicator("#team-indicator-secrets", "Placeholders only", "is-good");
    setTeamIndicator("#team-indicator-ready", res.variables.length
      ? `${res.variables.length} variable${res.variables.length === 1 ? "" : "s"}`
      : "Ready to configure", "is-good");
    feedback.textContent = "Template generated. It contains variable names and placeholders, not submitted secret values.";
  } catch (err) {
    feedback.textContent = `Template could not be generated: ${err.message}`;
    feedback.classList.add("is-error");
    setTeamIndicator("#team-indicator-safe", "Template unavailable", "is-pending");
    setTeamIndicator("#team-indicator-secrets", "No template generated", "is-pending");
    setTeamIndicator("#team-indicator-ready", "Reopen this page to retry", "is-pending");
  }
}

function renderTeamTemplate(template) {
  const code = $("#env-preview-code");
  const lines = String(template || "").replace(/\n$/, "").split("\n");
  code.replaceChildren(...lines.map((line) => {
    const assignment = line.match(/^([A-Za-z_][A-Za-z0-9_]{0,127})(=)(.*)$/);
    if (line.startsWith("#")) {
      return h("span", { class: "team-code-comment" }, line, document.createTextNode("\n"));
    }
    if (assignment) {
      return h("span", { class: "team-code-line" },
        h("span", { class: "team-code-key" }, assignment[1]),
        h("span", { class: "team-code-operator" }, assignment[2]),
        h("span", { class: "team-code-placeholder" }, assignment[3]),
        document.createTextNode("\n")
      );
    }
    return h("span", { class: "team-code-line" }, line, document.createTextNode("\n"));
  }));
}

function setTeamIndicator(selector, text, state) {
  const indicator = $(selector);
  indicator.classList.remove("is-pending", "is-good", "is-error");
  indicator.classList.add(state);
  indicator.lastChild.textContent = text;
}

function showTeamFeedback(selector, message, isError = false) {
  const feedback = $(selector);
  feedback.textContent = message;
  feedback.classList.toggle("is-error", isError);
}

function downloadTeamFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

$("#btn-copy-env").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("#env-preview-code").textContent);
    showTeamFeedback("#team-template-feedback", "Safe environment template copied to the clipboard.");
  } catch (err) {
    showTeamFeedback("#team-template-feedback", `Could not copy the template: ${err.message}`, true);
  }
});

$("#btn-download-env").addEventListener("click", () => {
  const content = $("#env-preview-code").textContent;
  if (!content) return;
  downloadTeamFile(new Blob([content], { type: "text/plain;charset=utf-8" }), ".env.example");
  showTeamFeedback("#team-template-feedback", "Downloaded the placeholder-only .env.example template.");
});

$("#btn-download-team-zip").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  showTeamFeedback("#team-template-feedback", "Preparing the safe team package…");
  try {
    const res = await fetch("/api/team/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": S.csrfToken },
      body: JSON.stringify({ project_name: "LeakLensProject", env_example: $("#env-preview-code").textContent })
    });
    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.error || `Package download failed (${res.status})`);
    }
    const blob = await res.blob();
    downloadTeamFile(blob, "leaklens_team_setup.zip");
    showTeamFeedback("#team-template-feedback", "Downloaded a team package with a sanitized .env.example template.");
  } catch (err) {
    showTeamFeedback("#team-template-feedback", `Team package could not be created: ${err.message}`, true);
  } finally {
    button.disabled = false;
  }
});

// Vault Controller
async function loadVaultItems() {
  const box = $("#vault-items");
  const saveButton = $("#vault-save-button");
  const loginButton = $("#team-login");
  if (!S.user) {
    $("#vault-availability").textContent = "Sign in required";
    $(".team-vault-badge").classList.add("is-locked");
    $("#vault-encryption-status").textContent = "Sign in to access your private vault";
    $("#team-vault-status").classList.add("is-locked");
    $("#vault-item-count").textContent = "Private";
    box.replaceChildren(h("p", { class: "team-vault-empty" }, "Your account-scoped vault is available after you sign in."));
    loginButton.hidden = false;
    saveButton.disabled = true;
    return;
  }
  $("#vault-availability").textContent = "Loading vault";
  $(".team-vault-badge").classList.remove("is-locked");
  $("#team-vault-status").classList.remove("is-locked");
  loginButton.hidden = true;
  saveButton.disabled = true;
  box.replaceChildren(h("p", { class: "team-vault-empty" }, "Loading your private vault…"));
  try {
    const items = await api("/api/vault");
    $("#vault-availability").textContent = "Account protected";
    $(".team-vault-badge").classList.remove("is-locked");
    $("#vault-encryption-status").textContent = "New entries use AES-256-GCM";
    $("#team-vault-status").classList.remove("is-locked");
    $("#vault-item-count").textContent = `${items.length} ${items.length === 1 ? "entry" : "entries"}`;
    saveButton.disabled = false;
    if (!items.length) {
      box.replaceChildren(h("div", { class: "team-vault-empty" },
        h("span", { class: "team-empty-icon", "aria-hidden": "true" }, "⌑"),
        h("strong", null, "Your vault is ready"),
        h("p", null, "Add your first credential above. Secret values are encrypted before storage.")
      ));
      return;
    }
    box.replaceChildren(...items.map((it) => {
      return h("div", { class: "vault-item team-vault-item" },
        h("div", { class: "team-vault-item-main" },
          h("div", { class: "team-vault-item-title" },
            h("code", null, it.key_name),
            h("span", { class: "team-category-badge" }, it.provider || "Generic")
          ),
          h("span", { class: "team-vault-preview", "aria-label": "Masked secret preview" }, it.masked_preview)
        ),
        h("button", {
          class: "team-remove-button",
          type: "button",
          "aria-label": `Remove ${it.key_name} from your vault`,
          onclick: async () => {
            if (!confirm(`Remove ${it.key_name} from your vault?`)) return;
            try {
              await api(`/api/vault/${encodeURIComponent(it.id)}`, { method: "DELETE" });
              showTeamFeedback("#vault-form-feedback", `${it.key_name} was removed from your vault.`);
              await loadVaultItems();
            } catch (err) {
              showTeamFeedback("#vault-form-feedback", `Could not remove this entry: ${err.message}`, true);
            }
          }
        }, "Remove")
      );
    }));
  } catch (e) {
    $("#vault-availability").textContent = "Vault unavailable";
    $(".team-vault-badge").classList.add("is-locked");
    $("#vault-item-count").textContent = "Unavailable";
    saveButton.disabled = true;
    box.replaceChildren(h("p", { class: "team-vault-error", role: "alert" }, `Your vault could not be loaded: ${e.message}`));
  }
}

$("#vault-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!S.user) {
    openModal("#modal-login");
    return;
  }
  if (!e.currentTarget.checkValidity()) {
    e.currentTarget.reportValidity();
    return;
  }
  const saveButton = $("#vault-save-button");
  saveButton.disabled = true;
  showTeamFeedback("#vault-form-feedback", "Encrypting and saving the entry…");
  try {
    await api("/api/vault", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        key_name: $("#vault-key").value,
        provider: $("#vault-provider").value,
        raw_value: $("#vault-val").value
      })
    });
    $("#vault-form").reset();
    showTeamFeedback("#vault-form-feedback", "Credential saved. Only its masked preview is shown.");
    await loadVaultItems();
  } catch (err) {
    showTeamFeedback("#vault-form-feedback", `Vault entry was not saved: ${err.message}`, true);
  } finally {
    saveButton.disabled = !S.user;
  }
});

$("#team-login").addEventListener("click", () => openModal("#modal-login"));
$("#vault-secret-toggle").addEventListener("click", (event) => {
  const button = event.currentTarget;
  const input = $("#vault-val");
  const reveal = input.type === "password";
  input.type = reveal ? "text" : "password";
  button.textContent = reveal ? "Hide" : "Show";
  button.setAttribute("aria-label", reveal ? "Hide secret value" : "Show secret value");
  button.setAttribute("aria-pressed", String(reveal));
});

// Vault Portable Export / Import
$("#btn-show-export-vault").addEventListener("click", () => {
  if (!S.user) { openModal("#modal-login"); return; }
  $("#vault-export-error").hidden = true;
  openModal("#modal-vault-export");
});

$("#form-vault-export").addEventListener("submit", async (e) => {
  e.preventDefault();
  const pw = $("#vault-export-pw").value;
  const errBox = $("#vault-export-error");
  errBox.hidden = true;
  const submitButton = $("#vault-export-submit");
  submitButton.disabled = true;
  try {
    const res = await fetch("/api/vault/export", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": S.csrfToken },
      body: JSON.stringify({ password: pw })
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Export failed (${res.status})`);
    }
    const blob = await res.blob();
    downloadTeamFile(blob, `leaklens_vault_${S.user.username}.leaklens`);
    closeModal("#modal-vault-export");
    $("#form-vault-export").reset();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    submitButton.disabled = false;
  }
});

$("#btn-show-import-vault").addEventListener("click", () => {
  if (!S.user) { openModal("#modal-login"); return; }
  $("#vault-import-error").hidden = true;
  openModal("#modal-vault-import");
});

$("#form-vault-import").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fileInput = $("#vault-import-file");
  const pwInput = $("#vault-import-pw");
  const errBox = $("#vault-import-error");
  const submitButton = $("#vault-import-submit");
  errBox.hidden = true;

  if (!fileInput.files[0]) {
    errBox.textContent = "Please select a file to import.";
    errBox.hidden = false;
    return;
  }
  const maxBytes = S.maxUploadBytes || 10 * 1024 * 1024;
  if (fileInput.files[0].size > maxBytes) {
    errBox.textContent = `Vault file exceeds the ${Math.floor(maxBytes / (1024 * 1024))} MB limit.`;
    errBox.hidden = false;
    return;
  }

  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  fd.append("password", pwInput.value);

  submitButton.disabled = true;
  try {
    const res = await api("/api/vault/import", {
      method: "POST",
      body: fd
    });
    showTeamFeedback("#vault-form-feedback", `${res.imported_count} vault ${res.imported_count === 1 ? "entry was" : "entries were"} imported and encrypted for your account.`);
    closeModal("#modal-vault-import");
    $("#form-vault-import").reset();
    await loadVaultItems();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    submitButton.disabled = false;
  }
});

/* ---------------------------------------------------------------- IDE Guard Simulation */
$("#btn-ide-sim-run").addEventListener("click", async () => {
  const code = $("#ide-sim-code").value;
  const out = $("#ide-sim-results");
  out.innerHTML = `<div class="busy"><span class="spinner"></span> Running in-memory inspection...</div>`;
  try {
    const res = await api("/api/ide/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename: "app.py", content: code })
    });
    if (!res.diagnostics.length) {
      out.innerHTML = `<div class="done">✔ No secrets or sensitive data detected in this code block.</div>`;
      return;
    }
    out.replaceChildren(...res.diagnostics.map((d) => {
      return h("div", { class: "sim-diag" },
        h("div", { class: "head" },
          h("span", { class: "badge " + (d.severity === "error" ? "high" : "medium") }, d.severity.toUpperCase()),
          h("strong", null, `Line ${d.line}: ${d.message}`),
          h("span", { class: "badge pro" }, d.provider)
        ),
        h("div", { class: "small muted", style: "margin: .3rem 0" }, `Masked Value: ${d.preview}`),
        h("div", { class: "small" }, h("strong", null, "QuickFix Suggestion: "), h("code", null, d.suggested_fix))
      );
    }));
  } catch (e) {
    out.innerHTML = `<div class="error">${e.message}</div>`;
  }
});

/* ---------------------------------------------------------------- Evaluation */
async function loadEval() {
  const box = $("#eval");
  try {
    const m = await api("/api/evaluation");
    const names = {
      baseline_regex: "Baseline regex (no context)",
      rules_context: "Rules + context",
      ml_only: "ML only (TF-IDF + LR)",
      hybrid: "Hybrid (rules + context + ML)"
    };
    const f3 = (x) => x.toFixed(3), d = m.dataset;
    box.replaceChildren(
      h("p", { class: "muted" }, `Held-out synthetic test set: ${d.test} snippets (${d.test_sensitive} sensitive, ${d.test_non_sensitive} non-sensitive). Trained on ${d.train}, thresholds tuned on a separate ${d.validation}-snippet validation split. Generated ${m.created}.`),
      h("table", { class: "t" },
        h("thead", null, h("tr", null, ["System", "Precision", "Recall", "F1", "False-positive rate", "TP", "FP", "TN", "FN"].map((x) => h("th", null, x)))),
        h("tbody", null, Object.entries(m.systems).map(([k, v]) => h("tr", null,
          h("td", null, h("strong", null, names[k] || k)),
          h("td", null, f3(v.precision)),
          h("td", null, f3(v.recall)),
          h("td", null, f3(v.f1)),
          h("td", null, f3(v.fpr)),
          h("td", null, v.tp),
          h("td", null, v.fp),
          h("td", null, v.tn),
          h("td", null, v.fn))))
      ),
      h("h3", null, "Read this honestly"),
      h("ul", { class: "clean-list" }, m.notes.map((n) => h("li", null, n))),
      h("details", { style: "margin-top: 1rem;" },
        h("summary", null, "Sample hybrid errors (synthetic snippets)"),
        h("div", null, h("strong", null, "Missed (false negatives)")),
        m.hybrid_errors_sample.false_negatives.map((x) => h("div", { class: "err-list" }, x)),
        h("div", null, h("strong", null, "Wrongly flagged (false positives)")),
        m.hybrid_errors_sample.false_positives.map((x) => h("div", { class: "err-list" }, x))
      )
    );
  } catch (e) { box.replaceChildren(h("p", { class: "muted" }, e.message)); }
}

/* ---------------------------------------------------------------- Admin Dashboard */
async function loadAdminDashboard() {
  if (!S.user || S.user.role !== "admin") {
    $("#view-admin").innerHTML = `<div class="error">Access denied. Administrator privileges required.</div>`;
    return;
  }
  try {
    const stats = await api("/api/admin/stats");
    $("#adm-users").textContent = stats.users.total;
    $("#adm-active").textContent = stats.users.active;
    $("#adm-disabled").textContent = stats.users.disabled;
    $("#adm-scans").textContent = stats.scans.total;
    $("#adm-storage").textContent = `${stats.storage.db_mb + stats.storage.tmp_mb} MB`;

    // Users Table
    const users = await api("/api/admin/users");
    const tbody = $("#admin-users-table tbody");
    tbody.replaceChildren(...users.map((u) => {
      const isSelf = u.id === S.user.id;
      const toggleBtn = isSelf ? null : h("button", {
        class: "btn sm",
        onclick: async () => {
          const next = u.status === "active" ? "disabled" : "active";
          await api(`/api/admin/users/${u.id}/status`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: next })
          });
          loadAdminDashboard();
        }
      }, u.status === "active" ? "Disable" : "Activate");

      const delBtn = isSelf ? null : h("button", {
        class: "btn sm text-danger",
        onclick: async () => {
          if (confirm(`Permanently delete account for ${u.username}?`)) {
            await api(`/api/admin/users/${u.id}`, { method: "DELETE" });
            loadAdminDashboard();
          }
        }
      }, "Delete");

      return h("tr", null,
        h("td", null, h("strong", null, u.username)),
        h("td", null, u.email),
        h("td", null, h("span", { class: "badge " + (u.role === "admin" ? "pro" : "st") }, u.role)),
        h("td", null, h("span", { class: "badge " + (u.status === "active" ? "low" : "high") }, u.status)),
        h("td", { class: "small muted" }, new Date(u.created_at * 1000).toLocaleDateString()),
        h("td", null, h("div", { class: "grp" }, toggleBtn, delBtn))
      );
    }));

    // Audit Logs
    const auditLogs = await api("/api/admin/audit");
    $("#admin-audit-logs").replaceChildren(...auditLogs.slice(0, 30).map((a) => {
      return h("div", { class: "audit-entry" },
        h("span", { class: "time" }, new Date(a.timestamp * 1000).toLocaleTimeString()),
        h("span", { class: "act" }, a.action),
        h("span", { class: "muted" }, ` by ${a.username || a.ip_address || "anonymous"}`),
        a.details ? h("span", { class: "d" }, ` · ${a.details}`) : null
      );
    }));

    // Policy Config
    const policies = stats.system.scoring_policy || {};
    const policyGrid = $("#admin-policy-list");
    policyGrid.replaceChildren(...Object.entries(policies).map(([type, val]) => {
      return h("div", { class: "policy-item" },
        h("span", null, type),
        h("input", { type: "number", min: "0", max: "100", value: val, "data-type": type })
      );
    }));
  } catch (err) {
    console.error("Admin dashboard error:", err);
  }
}

$("#btn-save-policies").addEventListener("click", async () => {
  const updates = {};
  $$("#admin-policy-list input").forEach((inp) => {
    updates[inp.dataset.type] = parseInt(inp.value, 10);
  });
  try {
    await api("/api/admin/policies", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updates)
    });
    alert("Scoring policies saved successfully!");
  } catch (err) {
    alert("Failed to save policies: " + err.message);
  }
});
