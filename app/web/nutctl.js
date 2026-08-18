"use strict";
// NUT fleet control-plane UI: talks only to /api/nutctl/* (see app/nutctl/routes.py)
// plus the shared /api/session check. No build step, no external assets — mirrors
// app.js's conventions (a tiny fetch wrapper, esc() for anything rendered from
// server data, plain <details> for collapsible sections).

const $ = (id) => document.getElementById(id);

function esc(s) {
  return (s === null || s === undefined ? "" : String(s))
    .replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

function cssEsc(v) {
  return (window.CSS && CSS.escape) ? CSS.escape(v) : String(v).replace(/"/g, '\\"');
}

// --- fetch wrapper ------------------------------------------------------------
// Every non-2xx throws an Error; `.status` and `.body` (parsed JSON, if any) are
// attached so callers can distinguish 401 (session expired) from 409 (locked /
// validation errors) from anything else, without re-parsing the response.
async function api(path, method = "GET", body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try { data = await res.json(); } catch (_) { /* no JSON body */ }
  if (res.status === 401) {
    const err = new Error("session expired, log in on the main page");
    err.status = 401;
    throw err;
  }
  if (!res.ok) {
    const err = new Error(apiErrorMessage(data, res.status));
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return data;
}

function apiErrorMessage(data, status) {
  if (data && Array.isArray(data.errors) && data.errors.length) return data.errors.join("; ");
  if (data && data.detail) return typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
  return `HTTP ${status}`;
}

// --- auth gate ------------------------------------------------------------
function showAuthGate() {
  $("authGate").hidden = false;
  $("app").hidden = true;
  stopFleetPolling();
}

function handleGlobalError(e) {
  if (e && e.status === 401) showAuthGate();
}

// --- app-wide deploy-lock banner (on-battery / missing-secrets 409s) --------
let lockState = { locked: false, reason: "" };

function applyLock(body) {
  const reason = apiErrorMessage(body, 409);
  lockState = { locked: true, reason };
  const text = reason === "on battery"
    ? "Deploys are locked: a UPS in the fleet is on battery (or in alarm). Wait for mains "
      + "power to return, or resolve the alarm, before deploying."
    : `Deploys are locked: ${reason}`;
  const el = $("lockBanner");
  el.hidden = false;
  el.innerHTML = `<svg class="icon"><use href="#i-alert"></use></svg><span>${esc(text)}</span>`;
}

function clearLock() {
  if (!lockState.locked) return;
  lockState = { locked: false, reason: "" };
  $("lockBanner").hidden = true;
  $("lockBanner").innerHTML = "";
}

// --- tabs -------------------------------------------------------------------
let currentTab = "topology";
let fleetTimer = null;

function switchTab(view) {
  currentTab = view;
  ["topology", "diff", "fleet"].forEach((v) => { $("tab-" + v).hidden = v !== view; });
  document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  if (view === "diff") {
    loadPreview();
  } else if (view === "fleet") {
    loadFleet();
    startFleetPolling();
  }
  if (view !== "fleet") stopFleetPolling();
}

function wireTabs() {
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.onclick = () => switchTab(btn.dataset.view);
  });
}

function startFleetPolling() {
  stopFleetPolling();
  // The interval keeps ticking, but the callback is a no-op unless the fleet tab
  // is both the active tab and the page is visible — no refresh loop runs against
  // a hidden tab or a backgrounded browser tab.
  fleetTimer = setInterval(() => {
    if (currentTab === "fleet" && !document.hidden) loadFleet();
  }, 30000);
}

function stopFleetPolling() {
  if (fleetTimer) { clearInterval(fleetTimer); fleetTimer = null; }
}

// --- TOPOLOGY tab -------------------------------------------------------------
async function loadTopology() {
  $("topoMsg").textContent = "Loading…";
  try {
    const t = await api("/api/nutctl/topology");
    $("topoYaml").value = t.yaml;
    renderTopoErrors(t.errors || []);
    $("topoMsg").textContent = "";
  } catch (e) {
    handleGlobalError(e);
    $("topoMsg").textContent = "Error: " + e.message;
  }
}

function renderTopoErrors(errors) {
  const box = $("topoErrors");
  if (!errors || !errors.length) { box.hidden = true; box.innerHTML = ""; return; }
  box.hidden = false;
  box.innerHTML = "<div><b>Topology is invalid:</b><ul>"
    + errors.map((e) => `<li>${esc(e)}</li>`).join("")
    + "</ul></div>";
}

$("topoSaveBtn").onclick = async () => {
  $("topoMsg").textContent = "Validating & saving…";
  try {
    await api("/api/nutctl/topology", "PUT", { yaml: $("topoYaml").value });
    renderTopoErrors([]);
    $("topoMsg").textContent = "Saved.";
  } catch (e) {
    if (e.status === 409 && e.body && Array.isArray(e.body.errors)) {
      $("topoMsg").textContent = "";
      renderTopoErrors(e.body.errors);
    } else {
      handleGlobalError(e);
      $("topoMsg").textContent = "Error: " + e.message;
    }
  }
};

$("topoReloadBtn").onclick = loadTopology;

// Summary table: preview does a live SSH sweep of the whole fleet, so it is
// loaded on demand (button) rather than automatically. It only carries names +
// drift (the per-file diff detail), not feeds/policy/tiers — that structural
// detail lives in the YAML editor above; see the task-9 report for why.
async function loadTopoSummary() {
  $("topoSummaryBody").innerHTML = `<tr><td colspan="2" class="empty">Loading…</td></tr>`;
  try {
    const preview = await api("/api/nutctl/preview");
    clearLock();
    const names = Object.keys(preview).sort();
    $("topoSummaryBody").innerHTML = names.map((name) => {
      const badge = preview[name].drift
        ? `<span class="pill warn">drift</span>`
        : `<span class="pill ok">clean</span>`;
      return `<tr><td>${esc(name)}</td><td>${badge}</td></tr>`;
    }).join("") || `<tr><td colspan="2" class="empty">No managed hosts.</td></tr>`;
  } catch (e) {
    if (e.status === 409) {
      applyLock(e.body);
      $("topoSummaryBody").innerHTML = `<tr><td colspan="2" class="empty">Locked — see banner above.</td></tr>`;
    } else {
      handleGlobalError(e);
      $("topoSummaryBody").innerHTML = `<tr><td colspan="2" class="empty">Error: ${esc(e.message)}</td></tr>`;
    }
  }
}
$("topoSummaryBtn").onclick = loadTopoSummary;

// --- DIFF & DEPLOY tab ----------------------------------------------------
async function loadPreview() {
  $("ddMsg").textContent = "Comparing the rendered topology against each host's live config files over SSH…";
  $("hostCards").innerHTML = "";
  try {
    const preview = await api("/api/nutctl/preview");
    clearLock();
    $("ddMsg").textContent = "";
    renderHostCards(preview);
  } catch (e) {
    if (e.status === 409) {
      applyLock(e.body);
      $("ddMsg").textContent = "";
    } else {
      handleGlobalError(e);
      $("ddMsg").textContent = "Error: " + e.message;
    }
  }
}

function renderHostCards(preview) {
  const names = Object.keys(preview).sort();
  $("hostCards").innerHTML = names.map((name) => hostCardHtml(name, preview[name])).join("")
    || `<p class="empty">No managed hosts in the topology.</p>`;
  names.forEach((name) => wireHostCard(name));
}

function hostCardHtml(name, h) {
  const badge = h.drift ? `<span class="pill warn">drift</span>` : `<span class="pill ok">clean</span>`;
  const paths = Object.keys(h.files || {}).sort();
  const fileBlocks = paths.length
    ? paths.map((path) => `
        <details>
          <summary>${esc(path)}</summary>
          <pre class="diff-pre">${esc(h.files[path])}</pre>
        </details>`).join("")
    : `<p class="help">No diff — the live config already matches the rendered topology.</p>`;
  return `
    <div class="card" data-host="${esc(name)}">
      <div class="card-h">
        <h3><svg class="icon"><use href="#i-server"></use></svg> ${esc(name)}</h3>
        ${badge}
        <span class="actions">
          <button class="btn-primary btn-sm host-deploy-btn">Deploy</button>
          <button class="btn-ghost btn-sm host-revert-btn">Revert</button>
        </span>
      </div>
      ${fileBlocks}
      <p class="help host-msg"></p>
    </div>`;
}

function wireHostCard(name) {
  const card = document.querySelector(`.card[data-host="${cssEsc(name)}"]`);
  if (!card) return;
  card.querySelector(".host-deploy-btn").onclick = () => deployOne(name, card);
  card.querySelector(".host-revert-btn").onclick = () => revertOne(name, card);
}

async function deployOne(name, card) {
  const msg = card.querySelector(".host-msg");
  msg.textContent = "Deploying…";
  try {
    const r = await api(`/api/nutctl/deploy/${encodeURIComponent(name)}`, "POST");
    clearLock();
    msg.textContent = r.ok
      ? "Deployed" + (r.verified ? " (verified)" : "") + (r.detail ? ": " + r.detail : "")
      : "Failed" + (r.detail ? ": " + r.detail : "");
    await loadPreview();
  } catch (e) {
    if (e.status === 409) {
      applyLock(e.body);
      msg.textContent = "Locked: " + lockState.reason;
    } else {
      handleGlobalError(e);
      msg.textContent = "Error: " + e.message;
    }
  }
}

async function revertOne(name, card) {
  if (!confirm(`Revert ${name} to its pre-deploy backup? This overwrites the current config on that host.`)) return;
  const msg = card.querySelector(".host-msg");
  msg.textContent = "Reverting…";
  try {
    const r = await api(`/api/nutctl/revert/${encodeURIComponent(name)}`, "POST");
    msg.textContent = r.ok
      ? "Reverted" + (r.verified ? " (verified)" : "")
      : "Failed" + (r.detail ? ": " + r.detail : "");
    await loadPreview();
  } catch (e) {
    handleGlobalError(e);
    msg.textContent = "Error: " + e.message;
  }
}

$("refreshPreviewBtn").onclick = loadPreview;

$("deployAllBtn").onclick = async () => {
  $("ddMsg").textContent = "Checking for pending changes…";
  let preview;
  try {
    preview = await api("/api/nutctl/preview");
    clearLock();
  } catch (e) {
    if (e.status === 409) { applyLock(e.body); $("ddMsg").textContent = ""; return; }
    handleGlobalError(e);
    $("ddMsg").textContent = "Error: " + e.message;
    return;
  }
  const pending = Object.keys(preview).filter((n) => preview[n].drift).sort();
  if (!pending.length) {
    $("ddMsg").textContent = "No hosts have pending changes — nothing to deploy.";
    return;
  }
  const ok = confirm(
    `Deploy to ${pending.length} host(s) with pending changes?\n\n - ${pending.join("\n - ")}`
  );
  if (!ok) { $("ddMsg").textContent = ""; return; }
  $("ddMsg").textContent = "Deploying fleet…";
  try {
    const r = await api("/api/nutctl/deploy-fleet", "POST");
    clearLock();
    const failed = Object.keys(r).filter((n) => !r[n].ok);
    $("ddMsg").textContent = failed.length
      ? `Deployed with failures on: ${failed.join(", ")}`
      : "Fleet deployed.";
    await loadPreview();
  } catch (e) {
    if (e.status === 409) {
      applyLock(e.body);
      $("ddMsg").textContent = "";
    } else {
      handleGlobalError(e);
      $("ddMsg").textContent = "Error: " + e.message;
    }
  }
};

// --- FLEET tab ----------------------------------------------------------
async function loadFleet() {
  try {
    const f = await api("/api/nutctl/fleet");
    renderFleet(f);
  } catch (e) {
    handleGlobalError(e);
    $("fleetAt").textContent = "Error: " + e.message;
  }
}

function fleetBadge(v) {
  if (v === true) return `<span class="pill ok">ok</span>`;
  if (v === false) return `<span class="pill crit">fail</span>`;
  return `<span class="pill muted">unknown</span>`;
}

function renderFleet(f) {
  $("fleetAt").textContent = f.at ? "last probe: " + new Date(f.at).toLocaleString() : "no probe yet";
  const hosts = f.hosts || {};
  const names = Object.keys(hosts).sort();
  $("fleetBody").innerHTML = names.map((name) => {
    const h = hosts[name];
    return `<tr><td>${esc(name)}</td>
      <td>${fleetBadge(h.ssh_ok)}</td>
      <td>${fleetBadge(h.upsmon_active)}</td>
      <td>${fleetBadge(h.config_match)}</td>
      <td class="muted">${esc(h.detail || "")}</td></tr>`;
  }).join("") || `<tr><td colspan="5" class="empty">No probe data yet — the background sweep hasn't completed.</td></tr>`;
}

// --- bootstrap --------------------------------------------------------------
async function boot() {
  let s;
  try {
    s = await api("/api/session");
  } catch (e) {
    showAuthGate();
    return;
  }
  if (!s.authenticated) { showAuthGate(); return; }
  $("authGate").hidden = true;
  $("app").hidden = false;
  wireTabs();
  await loadTopology();
}

boot().catch((e) => {
  document.body.innerHTML = "<pre style='padding:20px'>Failed to start NUT Fleet: " + esc(e.message) + "</pre>";
});
