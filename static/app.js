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
  activeView: "scan"
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
const savedTheme = localStorage.getItem("leaklens_theme") || "dark";
document.documentElement.dataset.theme = savedTheme;

$("#theme-toggle").addEventListener("click", () => {
  const cur = document.documentElement.dataset.theme;
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("leaklens_theme", next);
});

/* ---------------------------------------------------------------- Navigation */
$$(".tab").forEach((t) => t.addEventListener("click", () => {
  const view = t.dataset.view;
  if (!view) return;
  switchView(view);
}));

function switchView(viewName) {
  S.activeView = viewName;
  $$(".tab").forEach((x) => x.classList.toggle("active", x.dataset.view === viewName));
  $$(".view").forEach((v) => (v.hidden = v.id !== "view-" + viewName));

  if (viewName === "dashboard") loadDashboard();
  if (viewName === "history") loadHistory();
  if (viewName === "team") loadTeamSetup();
  if (viewName === "eval") loadEval();
  if (viewName === "admin") loadAdminDashboard();
}

/* ---------------------------------------------------------------- Status & Auth Initialization */
async function initApp() {
  try {
    const s = await api("/api/status");
    S.csrfToken = s.csrf_token;
    
    // Status chips
    $("#chips").replaceChildren(
      h("span", { class: "chip " + (s.ml ? "ok" : "warn") }, s.ml ? "ML on" : "ML off"),
      h("span", { class: "chip " + (s.ocr ? "ok" : "warn") }, s.ocr ? "OCR on" : "OCR off")
    );
    $("#file").accept = s.extensions.join(",");
    $("#drop-hint").textContent = `Up to ${s.max_mb} MB. Supported: ${s.extensions.join(" ")}. Temp copies deleted after ${s.ttl_minutes} min.`;

    // Auth check
    const me = await api("/api/auth/me");
    if (me.authenticated) {
      setAuthUser(me.user);
    } else {
      setAuthUser(null);
    }
  } catch (err) {
    console.warn("Init error:", err);
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
  try { await api("/api/auth/logout", { method: "POST" }); } catch (_) {}
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
drop.addEventListener("click", () => fileIn.click());
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") fileIn.click(); });
["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) scan(e.dataTransfer.files[0]); });
fileIn.addEventListener("change", () => { if (fileIn.files[0]) scan(fileIn.files[0]); fileIn.value = ""; });

function showError(msg) { const e = $("#error"); e.textContent = msg || ""; e.hidden = !msg; }

async function scan(file) {
  showError(""); $("#results").hidden = true; $("#busy").hidden = false;
  const fd = new FormData(); fd.append("file", file);
  try {
    const res = await api("/api/scan", { method: "POST", body: fd });
    S.scan = res; S.showAll = false; $("#show-all").checked = false;
    S.selected = new Set(res.findings.filter((f) => f.status === "active" && !f.metadata && f.level !== "low").map((f) => f.id));
    render();
  } catch (e) { showError(e.message); }
  $("#busy").hidden = true;
}

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
async function loadDashboard() {
  if (!S.user) {
    $("#dash-cards").innerHTML = `<div class="warn-box">Please <button class="link" onclick="openModal('#modal-login')">log in</button> to view your personal dashboard metrics.</div>`;
    $("#chart-trends").innerHTML = `<p class="muted center">Login required to view personal scan trends.</p>`;
    $("#chart-providers").replaceChildren(h("p", { class: "muted center" }, "Log in to see findings by provider."));
    return;
  }
  try {
    const stats = await api("/api/user/stats");
    $("#stat-files").textContent = stats.total_files;
    $("#stat-findings").textContent = stats.total_findings;
    $("#stat-high").textContent = stats.high;
    $("#stat-med").textContent = stats.medium;
    $("#stat-low").textContent = stats.low;
    $("#stat-sanitised").textContent = stats.sanitised;

    renderTrendsChart(stats.trends || []);
    renderProviderChart(stats.providers || []);
  } catch (e) {
    console.error("Dashboard error:", e);
  }
}

function renderTrendsChart(trends) {
  const container = $("#chart-trends");
  if (!trends.length) {
    container.innerHTML = `<p class="muted center">No scan data recorded yet. Upload files to see trends.</p>`;
    return;
  }
  // Lightweight responsive SVG chart
  const maxFindings = Math.max(...trends.map((t) => t.h + t.m + t.l), 5);
  const bars = trends.map((t, idx) => {
    const tot = t.h + t.m + t.l;
    const hPct = (t.h / maxFindings) * 100;
    const mPct = (t.m / maxFindings) * 100;
    const lPct = (t.l / maxFindings) * 100;
    return `
      <div style="flex:1; display:flex; flex-direction:column; align-items:center; height:180px; justify-content:flex-end;">
        <div style="font-size:.7rem; color:var(--muted); margin-bottom:4px;">${tot}</div>
        <div style="width:100%; max-width:28px; display:flex; flex-direction:column; justify-content:flex-end;">
          <div style="height:${hPct}px; background:var(--high); border-radius:3px 3px 0 0;" title="High: ${t.h}"></div>
          <div style="height:${mPct}px; background:var(--med);" title="Medium: ${t.m}"></div>
          <div style="height:${lPct}px; background:var(--low);" title="Low: ${t.l}"></div>
        </div>
        <div style="font-size:.65rem; color:var(--muted); margin-top:6px; transform:rotate(-45deg);">${t.day.slice(5)}</div>
      </div>
    `;
  }).join("");

  container.innerHTML = `
    <div style="display:flex; gap:10px; align-items:flex-end; padding:10px 0; border-bottom:1px solid var(--line);">
      ${bars}
    </div>
    <div style="display:flex; gap:15px; justify-content:center; margin-top:10px; font-size:.8rem;">
      <span><i style="display:inline-block; width:10px; height:10px; background:var(--high); border-radius:2px;"></i> High</span>
      <span><i style="display:inline-block; width:10px; height:10px; background:var(--med); border-radius:2px;"></i> Medium</span>
      <span><i style="display:inline-block; width:10px; height:10px; background:var(--low); border-radius:2px;"></i> Low</span>
    </div>
  `;
}

/* ---------------------------------------------------------------- Scan History */
async function loadHistory() {
  const box = $("#history");
  const risk = $("#history-filter-risk").value;
  const kind = $("#history-filter-kind").value;
  const q = $("#history-search").value;

  const params = new URLSearchParams();
  if (risk) params.set("risk", risk);
  if (kind) params.set("kind", kind);
  if (q) params.set("q", q);

  try {
    const rows = await api(`/api/history?${params.toString()}`);
    if (!rows.length) {
      box.replaceChildren(h("p", { class: "muted" }, "No scans match your criteria."));
      return;
    }
    box.replaceChildren(h("table", { class: "t" },
      h("thead", null, h("tr", null,
        ["Date", "File", "Format", "Score", "High", "Med", "Low", "Redacted", "Actions"].map((x) => h("th", null, x)))),
      h("tbody", null, rows.map((r) => {
        const dt = new Date(r.created * 1000).toLocaleString();
        return h("tr", null,
          h("td", { class: "small muted" }, dt),
          h("td", null, h("strong", null, r.filename)),
          h("td", { class: "small" }, r.kind),
          h("td", null, h("span", { class: "badge " + r.level }, `${r.level} (${r.score})`)),
          h("td", { class: r.high ? "text-danger" : "muted" }, r.high),
          h("td", { class: r.medium ? "warning" : "muted" }, r.medium),
          h("td", { class: r.low ? "success" : "muted" }, r.low),
          h("td", null, r.redacted ? `✔ ${r.redacted}` : "—"),
          h("td", null,
            h("div", { class: "grp" },
              r.redacted ? h("a", { class: "link small", href: `/api/download/${r.id}/sanitised` }, "Sanitised") : null,
              h("a", { class: "link small", href: `/report/${r.id}`, target: "_blank" }, "Report"),
              h("button", {
                class: "link text-danger small",
                onclick: async () => {
                  if (confirm(`Delete scan ${r.filename}?`)) {
                    await api(`/api/scan/${r.id}`, { method: "DELETE" });
                    loadHistory();
                  }
                }
              }, "Delete")
            )
          )
        );
      }))
    ));
  } catch (e) { box.textContent = e.message; }
}

$("#history-search").addEventListener("input", () => loadHistory());
$("#history-filter-risk").addEventListener("change", () => loadHistory());
$("#history-filter-kind").addEventListener("change", () => loadHistory());
$("#clear-history").addEventListener("click", async () => {
  if (confirm("Are you sure you want to clear your scan history?")) {
    await api("/api/history", { method: "DELETE" });
    loadHistory();
  }
});

/* ---------------------------------------------------------------- Safe Team Setup */
async function loadTeamSetup() {
  if (!$("#env-preview").value.trim()) {
    generateEnvTemplate();
  }
  loadVaultItems();
}

async function generateEnvTemplate(scanId) {
  try {
    const res = await api("/api/team/env-example", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId || (S.scan ? S.scan.scan_id : null) })
    });
    $("#env-preview").value = res.env_example;
  } catch (err) {
    console.warn("Env gen error:", err);
  }
}

$("#btn-copy-env").addEventListener("click", () => {
  const txt = $("#env-preview").value;
  navigator.clipboard.writeText(txt).then(() => {
    alert("Copied .env.example to clipboard!");
  });
});

$("#btn-download-team-zip").addEventListener("click", async () => {
  const envContent = $("#env-preview").value;
  try {
    const res = await fetch("/api/team/package", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": S.csrfToken },
      body: JSON.stringify({ project_name: "LeakLensProject", env_example: envContent })
    });
    if (!res.ok) throw new Error("Failed to generate team package");
    const blob = await res.blob();
    const u = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = u; a.download = "leaklens_team_setup.zip";
    a.click();
    URL.revokeObjectURL(u);
  } catch (err) {
    alert(err.message);
  }
});

// Vault Controller
async function loadVaultItems() {
  const box = $("#vault-items");
  if (!S.user) {
    box.innerHTML = `<p class="muted small">Please log in to manage your local encrypted secrets vault.</p>`;
    return;
  }
  try {
    const items = await api("/api/vault");
    if (!items.length) {
      box.innerHTML = `<p class="muted small">Your local encrypted vault is empty.</p>`;
      return;
    }
    box.replaceChildren(...items.map((it) => {
      return h("div", { class: "vault-item" },
        h("div", null,
          h("code", null, it.key_name),
          h("span", { class: "badge pro", style: "margin: 0 .4rem" }, it.provider || "Generic"),
          h("span", { class: "small muted" }, it.masked_preview)
        ),
        h("button", {
          class: "link text-danger small",
          onclick: async () => {
            if (confirm(`Remove ${it.key_name} from local vault?`)) {
              await api(`/api/vault/${it.id}`, { method: "DELETE" });
              loadVaultItems();
            }
          }
        }, "Remove")
      );
    }));
  } catch (e) {
    box.innerHTML = `<p class="text-danger small">${e.message}</p>`;
  }
}

$("#vault-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!S.user) {
    openModal("#modal-login");
    return;
  }
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
    loadVaultItems();
  } catch (err) {
    alert("Vault error: " + err.message);
  }
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
    const u = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = u;
    a.download = `leaklens_vault_${S.user.username}.leaklens`;
    a.click();
    URL.revokeObjectURL(u);
    closeModal("#modal-vault-export");
    $("#form-vault-export").reset();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
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
  errBox.hidden = true;

  if (!fileInput.files[0]) {
    errBox.textContent = "Please select a file to import.";
    errBox.hidden = false;
    return;
  }

  const fd = new FormData();
  fd.append("file", fileInput.files[0]);
  fd.append("password", pwInput.value);

  try {
    const res = await api("/api/vault/import", {
      method: "POST",
      body: fd
    });
    alert(`Vault imported successfully! ${res.imported_count} secret(s) added.`);
    closeModal("#modal-vault-import");
    $("#form-vault-import").reset();
    loadVaultItems();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
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
