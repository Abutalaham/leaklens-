(function () {
  "use strict";

  const root = document.getElementById("view-home");
  if (!root) return;

  const prefersReducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const isSmallViewport = () => window.innerWidth <= 700;

  // 1. Canvas Particle & Optical Connection Field
  const canvas = document.getElementById("ll-home-canvas");
  const ctx = canvas ? canvas.getContext("2d") : null;
  let particles = [];
  let rafId = null;
  let isVisible = true;
  let isTabHidden = document.hidden;

  function resizeCanvas() {
    if (!canvas || !ctx) return;
    const rect = canvas.parentElement ? canvas.parentElement.getBoundingClientRect() : canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, isSmallViewport() ? 1.5 : 2);
    const w = Math.max(1, Math.floor(rect.width));
    const h = Math.max(1, Math.floor(rect.height));
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const count = isSmallViewport() ? 14 : 28;
    particles = Array.from({ length: count }, (_, i) => ({
      x: ((i * 73) % Math.max(100, w)),
      y: ((i * 59) % Math.max(100, h)),
      vx: (((i % 5) - 2) * 0.14) || 0.12,
      vy: (((i % 3) - 1) * 0.12) || -0.1,
      r: (i % 3 === 0) ? 2.1 : 1.4,
      color: i % 3 === 0 ? "rgba(56, 189, 248, 0.65)" : "rgba(139, 92, 246, 0.55)"
    }));
  }

  function stepParticles() {
    if (!ctx || !canvas) return;
    if (!isVisible || isTabHidden || prefersReducedMotion) {
      rafId = null;
      return;
    }
    const w = canvas.clientWidth || 500;
    const h = canvas.clientHeight || 460;
    ctx.clearRect(0, 0, w, h);

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0) p.x = w;
      if (p.x > w) p.x = 0;
      if (p.y < 0) p.y = h;
      if (p.y > h) p.y = 0;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.fill();

      for (let j = i + 1; j < particles.length; j++) {
        const q = particles[j];
        const dx = p.x - q.x;
        const dy = p.y - q.y;
        const distSq = dx * dx + dy * dy;
        if (distSq < 7200) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(q.x, q.y);
          ctx.strokeStyle = "rgba(56, 189, 248, 0.11)";
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }
    rafId = requestAnimationFrame(stepParticles);
  }

  function startLoop() {
    if (!rafId && !prefersReducedMotion && isVisible && !isTabHidden) {
      rafId = requestAnimationFrame(stepParticles);
    }
  }

  // 2. Pointer Parallax inside Hero (smoothly interpolated, no scroll hijacking)
  const hero = root.querySelector(".ll-home-hero");
  let targetPx = 0, targetPy = 0, curPx = 0, curPy = 0, parallaxRaf = null;

  function animateParallax() {
    curPx += (targetPx - curPx) * 0.12;
    curPy += (targetPy - curPy) * 0.12;
    root.style.setProperty("--ll-px", curPx.toFixed(3));
    root.style.setProperty("--ll-py", curPy.toFixed(3));
    if (Math.abs(targetPx - curPx) > 0.002 || Math.abs(targetPy - curPy) > 0.002) {
      parallaxRaf = requestAnimationFrame(animateParallax);
    } else {
      parallaxRaf = null;
    }
  }

  if (hero && !prefersReducedMotion) {
    hero.addEventListener("pointermove", (e) => {
      if (isSmallViewport()) return;
      const r = hero.getBoundingClientRect();
      targetPx = Math.max(-1, Math.min(1, ((e.clientX - r.left) / Math.max(1, r.width) - 0.5) * 2));
      targetPy = Math.max(-1, Math.min(1, ((e.clientY - r.top) / Math.max(1, r.height) - 0.5) * 2));
      if (!parallaxRaf) parallaxRaf = requestAnimationFrame(animateParallax);
    });
    hero.addEventListener("pointerleave", () => {
      targetPx = 0;
      targetPy = 0;
      if (!parallaxRaf) parallaxRaf = requestAnimationFrame(animateParallax);
    });
  }

  // 3. Choreographed Inspection Demo Sequence (runs once on load, replays on user action)
  const stageLabel = document.getElementById("ll-home-stage-label");
  const verifyStrip = document.getElementById("ll-home-verify-strip");
  const replayBtn = document.getElementById("ll-home-replay-btn");
  const docCards = Array.from(root.querySelectorAll(".ll-home-doc-card"));

  const demoConfig = [
    {
      selector: '[data-doc="config.py"]',
      findingText: "API_KEY = sk_live_••••••••",
      redactedText: "API_KEY = [REDACTED:API_KEY]",
      detail: "Illustrative finding · High risk · Masked preview"
    },
    {
      selector: '[data-doc=".env"]',
      findingText: "PASSWORD = ••••••••",
      redactedText: "PASSWORD = [REDACTED:SECRET]",
      detail: "Illustrative finding · High risk · Masked preview"
    },
    {
      selector: '[data-doc="report.pdf"]',
      findingText: "EMAIL = u••••@example.com",
      redactedText: "EMAIL = [REDACTED:EMAIL]",
      detail: "Illustrative finding · Medium risk · Masked preview"
    },
    {
      selector: '[data-doc="credentials.json"]',
      findingText: "API_KEY = sk_live_••••••••",
      redactedText: "API_KEY = [REDACTED:TOKEN]",
      detail: "Illustrative finding · High risk · Masked preview"
    }
  ];

  let demoTimers = [];
  function clearDemoTimers() {
    demoTimers.forEach((id) => window.clearTimeout(id));
    demoTimers = [];
  }

  function runInspectionSequence() {
    clearDemoTimers();
    root.dataset.stage = "awaken";
    root.classList.remove("is-scanning", "is-verified");
    if (verifyStrip) verifyStrip.hidden = true;
    docCards.forEach((card, idx) => {
      card.classList.remove("is-active", "is-redacted");
      const snip = card.querySelector(".ll-home-doc-snippet");
      const det = card.querySelector(".ll-home-doc-detail");
      if (snip && demoConfig[idx]) snip.textContent = demoConfig[idx].findingText;
      if (det && demoConfig[idx]) det.textContent = demoConfig[idx].detail;
    });

    if (prefersReducedMotion) {
      root.dataset.stage = "verify";
      root.classList.add("is-verified");
      if (stageLabel) stageLabel.textContent = "STAGE 07 · VERIFICATION COMPLETE (ILLUSTRATIVE DEMO)";
      if (verifyStrip) verifyStrip.hidden = false;
      docCards.forEach((card, idx) => {
        card.classList.add("is-redacted");
        const snip = card.querySelector(".ll-home-doc-snippet");
        if (snip && demoConfig[idx]) snip.textContent = demoConfig[idx].redactedText;
      });
      return;
    }

    if (stageLabel) stageLabel.textContent = "STAGE 01–04 · CHAMBER & FILES READY";

    demoTimers.push(window.setTimeout(() => {
      root.dataset.stage = "detect";
      root.classList.add("is-scanning");
      if (stageLabel) stageLabel.textContent = "STAGE 05 · DETECTING SYNTHETIC CREDENTIALS";
      docCards.forEach((c) => c.classList.add("is-active"));
    }, 950));

    demoTimers.push(window.setTimeout(() => {
      root.dataset.stage = "redact";
      if (stageLabel) stageLabel.textContent = "STAGE 06 · REDACTING SELECTED VALUES";
      docCards.forEach((card, idx) => {
        card.classList.add("is-redacted");
        const snip = card.querySelector(".ll-home-doc-snippet");
        const det = card.querySelector(".ll-home-doc-detail");
        if (snip && demoConfig[idx]) snip.textContent = demoConfig[idx].redactedText;
        if (det) det.textContent = "Masked in sanitised copy · Illustrative demo";
      });
    }, 2400));

    demoTimers.push(window.setTimeout(() => {
      root.dataset.stage = "verify";
      root.classList.remove("is-scanning");
      root.classList.add("is-verified");
      docCards.forEach((c) => c.classList.remove("is-active"));
      if (stageLabel) stageLabel.textContent = "STAGE 07 · REDACTION COMPLETE · VERIFICATION PASSED · SAFE COPY READY";
      if (verifyStrip) verifyStrip.hidden = false;
    }, 3700));
  }

  if (replayBtn) {
    replayBtn.addEventListener("click", () => runInspectionSequence());
  }

  // Interactive file card selection
  docCards.forEach((card) => {
    card.addEventListener("click", () => {
      docCards.forEach((other) => {
        if (other !== card) other.classList.remove("is-active");
      });
      card.classList.toggle("is-active");
    });
  });

  // 4. Developer Tools Snippet Switcher
  const toolSnippets = {
    vscode: {
      file: "ide-extension / diagnostics.ts",
      code: `// LeakLens IDE Guard (illustrative example)
// Flags hardcoded token-like literals in-memory before save
const config = {
  endpoint: "https://api.example.internal",
  apiKey: "sk_live_••••••••" // -> QuickFix: read from environment variable
};`
    },
    hook: {
      file: ".git/hooks/pre-commit",
      code: `#!/usr/bin/env sh
# Inspect staged diff before allowing commit
git diff --cached --name-only -z | xargs -0 leaklens scan --staged`
    },
    cli: {
      file: "terminal / standalone cli",
      code: `$ leaklens scan config.py credentials.json
[HIGH]   API_KEY     line 14  sk_live_••••••••
[MEDIUM] EMAIL       line 29  u••••@example.com
$ leaklens redact config.py --output sanitised/config.py`
    },
    api: {
      file: "http / rest endpoint",
      code: `POST /api/scan
Content-Type: multipart/form-data
# Returns structured findings, risk rationale, and redaction controls`
    },
    pat: {
      file: "auth / personal access token",
      code: `# Authenticate CLI or CI scripts using a scoped Personal Access Token
export LEAKLENS_TOKEN="ll_pat_••••••••"
leaklens scan --ci report.pdf`
    },
    sarif: {
      file: "export / leaklens-report.sarif",
      code: `{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{ "tool": { "driver": { "name": "LeakLens" } }, "results": [] }]
}`
    }
  };

  const termFile = document.getElementById("ll-home-term-file");
  const termCode = document.getElementById("ll-home-term-code");
  root.querySelectorAll(".ll-home-tool-btn[data-tool]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const key = btn.getAttribute("data-tool");
      const entry = toolSnippets[key];
      if (!entry) return;
      root.querySelectorAll(".ll-home-tool-btn").forEach((b) => b.classList.remove("is-selected"));
      btn.classList.add("is-selected");
      if (termFile) termFile.textContent = entry.file;
      if (termCode) termCode.textContent = entry.code;
    });
  });

  // 5. Accessible FAQ Accordion
  root.querySelectorAll(".ll-home-faq-trigger").forEach((trigger) => {
    trigger.addEventListener("click", () => {
      const expanded = trigger.getAttribute("aria-expanded") === "true";
      const panelId = trigger.getAttribute("aria-controls");
      const panel = panelId ? document.getElementById(panelId) : null;
      trigger.setAttribute("aria-expanded", String(!expanded));
      if (panel) panel.hidden = expanded;
    });
  });

  // 6. Smooth anchor scrolling within homepage
  root.querySelectorAll('a[href^="#ll-home-"]').forEach((link) => {
    link.addEventListener("click", (e) => {
      const targetId = link.getAttribute("href");
      const target = targetId ? document.querySelector(targetId) : null;
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: prefersReducedMotion ? "auto" : "smooth", block: "start" });
      }
    });
  });

  // 7. Visibility & Tab Lifecycle Handling
  document.addEventListener("visibilitychange", () => {
    isTabHidden = document.hidden;
    if (!isTabHidden) startLoop();
  });

  if ("IntersectionObserver" in window && canvas) {
    const io = new IntersectionObserver((entries) => {
      isVisible = entries.some((en) => en.isIntersecting);
      if (isVisible) startLoop();
    }, { threshold: 0.05 });
    io.observe(canvas.parentElement || canvas);
  }

  window.addEventListener("resize", resizeCanvas, { passive: true });

  // Kick off intro reveal + inspection demonstration once
  window.requestAnimationFrame(() => {
    resizeCanvas();
    startLoop();
    window.requestAnimationFrame(() => {
      root.classList.remove("ll-home-intro-prep");
      runInspectionSequence();
    });
  });
})();
