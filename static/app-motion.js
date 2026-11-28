(function () {
  "use strict";

  const prefersReducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // 1. 6-Stage Inspection Sequence synced to real #busy / #results state
  const busyEl = document.getElementById("busy");
  const stages = Array.from(document.querySelectorAll("#ll-scan-stages .ll-scan-stage"));
  let stageTimer = null;

  function resetStages() {
    if (stageTimer) {
      window.clearInterval(stageTimer);
      stageTimer = null;
    }
    stages.forEach((s) => s.classList.remove("is-active", "is-done"));
  }

  function startStageProgression() {
    resetStages();
    if (!stages.length) return;
    let idx = 0;
    stages[0].classList.add("is-active");
    if (prefersReducedMotion) return;

    stageTimer = window.setInterval(() => {
      if (!busyEl || busyEl.hidden) {
        resetStages();
        return;
      }
      if (idx < stages.length - 1) {
        stages[idx].classList.remove("is-active");
        stages[idx].classList.add("is-done");
        idx += 1;
        stages[idx].classList.add("is-active");
      }
    }, 380);
  }

  if (busyEl && "MutationObserver" in window) {
    const obs = new MutationObserver(() => {
      if (!busyEl.hidden) {
        startStageProgression();
      } else {
        resetStages();
      }
    });
    obs.observe(busyEl, { attributes: true, attributeFilter: ["hidden"] });
  }

  // 2. IDE Simulator live line-number gutter
  const ideTextarea = document.getElementById("ide-sim-code");
  const ideGutter = document.getElementById("ll-ide-gutter");

  function syncIdeGutter() {
    if (!ideTextarea || !ideGutter) return;
    const lineCount = Math.max(1, ideTextarea.value.split("\n").length);
    ideGutter.innerHTML = Array.from({ length: lineCount }, (_, i) => String(i + 1)).join("<br>");
  }

  if (ideTextarea && ideGutter) {
    syncIdeGutter();
    ideTextarea.addEventListener("input", syncIdeGutter);
    ideTextarea.addEventListener("scroll", () => {
      ideGutter.scrollTop = ideTextarea.scrollTop;
    });
  }

  // 3. Copy-to-clipboard for IDE Guard commands
  document.querySelectorAll(".ll-copy-btn[data-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const value = btn.getAttribute("data-copy");
      if (!value) return;
      const orig = btn.textContent;
      try {
        await navigator.clipboard.writeText(value);
        btn.textContent = "Copied ✓";
        window.setTimeout(() => { btn.textContent = orig; }, 1600);
      } catch (_) {
        btn.textContent = "Copy failed";
        window.setTimeout(() => { btn.textContent = orig; }, 1600);
      }
    });
  });
})();
