const BAND_ORDER = ["IMMEDIATE", "ACT", "ATTEND", "TRACK*", "TRACK"];

// Mirrors the --band-* custom properties in styles.css — duplicated here
// because Cytoscape's style objects can't reference CSS variables directly.
const BAND_COLORS = {
  IMMEDIATE: "#b23030",
  ACT: "#c65a34",
  ATTEND: "#c8860a",
  "TRACK*": "#55A185",
  TRACK: "#88A682",
};

let allRows = [];
let attackPaths = {};
let chokePoints = [];
let chokePointFindingIds = new Set();
let teamBriefs = [];
let complianceData = { frameworks: [] };
let activeBands = new Set(BAND_ORDER);
let sortKey = "score";
let sortAsc = false;
let hasRunOnce = false;
let cy = null;
let activePathRef = null;

function bandSlug(band) {
  return band === "TRACK*" ? "TRACK-STAR" : band;
}

function main() {
  document.getElementById("run-btn").addEventListener("click", runAnalysis);
  document.getElementById("drawer-close").addEventListener("click", closeDrawer);
  document.getElementById("drawer-backdrop").addEventListener("click", closeDrawer);
  document.getElementById("brief-close").addEventListener("click", closeBrief);
  document.getElementById("brief-backdrop").addEventListener("click", closeBrief);
  document.getElementById("brief-copy").addEventListener("click", copyBrief);
  document.getElementById("search-input").addEventListener("input", renderTable);
  document.getElementById("team-filter").addEventListener("change", renderTable);
  document.getElementById("zone-filter").addEventListener("change", renderTable);
  document.getElementById("compliance-filter").addEventListener("change", renderTable);
  document.getElementById("alert-jump").addEventListener("click", () => {
    switchTab("triage");
    activeBands = new Set(["IMMEDIATE"]);
    renderBandFilters({});
    renderTable();
  });

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  const initialTab = location.hash.replace("#", "");
  if (["triage", "paths", "teams", "compliance"].includes(initialTab)) switchTab(initialTab);

  document.querySelectorAll("#triage-table th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (sortKey === key) {
        sortAsc = !sortAsc;
      } else {
        sortKey = key;
        sortAsc = false;
      }
      renderTable();
    });
  });

  // If a run is already cached server-side (e.g. page reload), load it
  // without making the user press the button again.
  loadLatestRun()
    .then(() => { hasRunOnce = true; })
    .catch(() => { /* no run yet — normal on first visit */ });
}

function switchTab(tab) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.dataset.panel === tab));
  history.replaceState(null, "", `#${tab}`);
  if (tab === "paths" && hasRunOnce) renderPathsTab();
  if (tab === "teams" && hasRunOnce) renderTeamsTab();
  if (tab === "compliance" && hasRunOnce) renderComplianceTab();
}

async function fetchJson(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `${url} failed (${res.status})`);
  }
  return res.json();
}

async function runAnalysis() {
  const btn = document.getElementById("run-btn");
  const statusText = document.getElementById("run-status-text");
  const dot = document.querySelector("#run-status .status-dot");
  btn.disabled = true;
  dot.className = "status-dot running";
  statusText.textContent = "Running Agents 1–7…";

  try {
    await fetchJson("/api/run", { method: "POST" });
    await loadLatestRun();
    dot.className = "status-dot done";
    statusText.textContent = `Scored ${allRows.length} findings`;
    hasRunOnce = true;
  } catch (e) {
    dot.className = "status-dot";
    statusText.textContent = `Failed: ${e.message}`;
  } finally {
    btn.disabled = false;
  }
}

async function loadLatestRun() {
  const [summary, run, dqIssues, teams, compliance] = await Promise.all([
    fetchJson("/api/summary"),
    fetchJson("/api/run/latest"),
    fetchJson("/api/data-quality-issues"),
    fetchJson("/api/teams"),
    fetchJson("/api/compliance"),
  ]);

  allRows = run.findings;
  attackPaths = run.attack_paths;
  chokePoints = run.choke_points;
  chokePointFindingIds = new Set(chokePoints.map((cp) => cp.finding_id));
  teamBriefs = teams;
  complianceData = compliance;
  hasRunOnce = true;

  renderStats(summary);
  renderBandFilters(summary.band_counts);
  renderDropdown("team-filter", summary.teams, "All teams");
  renderDropdown("zone-filter", summary.zones, "All zones");
  renderDataQualityIssues(dqIssues);
  renderAlertBanner(summary);

  document.querySelector("#run-status .status-dot").className = "status-dot done";
  document.getElementById("run-status-text").textContent = `Scored ${allRows.length} findings`;

  renderTable();

  const activePanel = document.querySelector(".tab-panel.active");
  if (activePanel) {
    if (activePanel.dataset.panel === "paths") renderPathsTab();
    if (activePanel.dataset.panel === "teams") renderTeamsTab();
    if (activePanel.dataset.panel === "compliance") renderComplianceTab();
  }

  // Deep link: #triage/<finding_id> opens that finding's drawer directly.
  const [, findingId] = location.hash.replace("#", "").split("/");
  if (findingId) {
    const row = allRows.find((r) => r.finding_id === findingId);
    if (row) openDrawer(row);
  }
}

function renderAlertBanner(summary) {
  const banner = document.getElementById("alert-banner");
  const immediate = summary.band_counts["IMMEDIATE"] || 0;
  if (immediate === 0) {
    banner.classList.add("hidden");
    return;
  }
  document.getElementById("alert-text").textContent =
    `${immediate} finding${immediate === 1 ? "" : "s"} need action within 72 hours.`;
  banner.classList.remove("hidden");
}

function renderStats(summary) {
  document.getElementById("stat-total").textContent = summary.total_findings;
  document.getElementById("stat-immediate").textContent = summary.band_counts["IMMEDIATE"] || 0;
  document.getElementById("stat-act").textContent = summary.band_counts["ACT"] || 0;
  document.getElementById("stat-dora").textContent = summary.dora_cif_scope_count;
  document.getElementById("stat-dq").textContent = summary.data_quality_issue_count;
}

function renderBandFilters(bandCounts) {
  const container = document.getElementById("band-filters");
  container.innerHTML = "";
  BAND_ORDER.forEach((band) => {
    const count = bandCounts[band] || 0;
    const chip = document.createElement("div");
    chip.className = `filter-chip ${activeBands.has(band) ? "active" : ""}`;
    chip.innerHTML = `<span class="chip-dot band-dot-${bandSlug(band)}"></span>${band} (${count})`;
    chip.addEventListener("click", () => {
      if (activeBands.has(band)) {
        activeBands.delete(band);
        chip.classList.remove("active");
      } else {
        activeBands.add(band);
        chip.classList.add("active");
      }
      renderTable();
    });
    container.appendChild(chip);
  });
}

function renderDropdown(id, values, placeholder) {
  const select = document.getElementById(id);
  const current = select.value;
  select.innerHTML = `<option value="">${placeholder}</option>`;
  values.forEach((v) => {
    const opt = document.createElement("option");
    opt.value = v;
    opt.textContent = v;
    select.appendChild(opt);
  });
  select.value = current;
}

function renderDataQualityIssues(issues) {
  const countBadge = document.getElementById("dq-count");
  const list = document.getElementById("dq-list");
  if (!issues.length) {
    countBadge.style.display = "none";
    list.textContent = "No issues.";
    return;
  }
  countBadge.style.display = "inline-block";
  countBadge.textContent = issues.length;
  list.innerHTML = "";
  issues.slice(0, 8).forEach((issue) => {
    const row = document.createElement("div");
    row.className = "italic-hint";
    row.style.marginTop = "6px";
    row.textContent = `[${issue.issue_type}] ${issue.detail}`;
    list.appendChild(row);
  });
}

function filteredRows() {
  const q = document.getElementById("search-input").value.trim().toLowerCase();
  const team = document.getElementById("team-filter").value;
  const zone = document.getElementById("zone-filter").value;
  const complianceOnly = document.getElementById("compliance-filter").value === "dora";

  return allRows.filter((r) => {
    const band = r.risk ? r.risk.band : null;
    if (band && !activeBands.has(band)) return false;
    if (team && r.responsible_team !== team) return false;
    if (zone && r.zone !== zone) return false;
    if (complianceOnly && !(r.risk && r.risk.dora_cif_scope)) return false;
    if (q) {
      const haystack = `${r.title} ${r.cve_id || ""} ${r.asset_hostname} ${r.finding_id}`.toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
}

function sortRows(rows) {
  const sorted = [...rows];
  sorted.sort((a, b) => {
    let av, bv;
    if (sortKey === "score") {
      av = a.risk ? a.risk.score : -1;
      bv = b.risk ? b.risk.score : -1;
    } else if (sortKey === "band") {
      av = a.risk ? BAND_ORDER.indexOf(a.risk.band) : 99;
      bv = b.risk ? BAND_ORDER.indexOf(b.risk.band) : 99;
    } else if (sortKey === "sla_days") {
      av = a.risk && a.risk.sla_days != null ? a.risk.sla_days : 9999;
      bv = b.risk && b.risk.sla_days != null ? b.risk.sla_days : 9999;
    } else {
      av = a[sortKey] ?? "";
      bv = b[sortKey] ?? "";
    }
    if (av < bv) return sortAsc ? -1 : 1;
    if (av > bv) return sortAsc ? 1 : -1;
    return 0;
  });
  return sorted;
}

function renderTable() {
  document.querySelectorAll("#triage-table th[data-sort]").forEach((th) => {
    th.classList.toggle("sorted", th.dataset.sort === sortKey);
    th.classList.toggle("asc", th.dataset.sort === sortKey && sortAsc);
  });

  const tbody = document.getElementById("triage-tbody");
  const emptyMsg = document.getElementById("empty-msg");

  if (!hasRunOnce) {
    return; // leave the "click Run Analysis" placeholder row alone
  }

  const rows = sortRows(filteredRows());
  tbody.innerHTML = "";

  if (!rows.length) {
    emptyMsg.classList.remove("hidden");
    return;
  }
  emptyMsg.classList.add("hidden");

  rows.forEach((r) => {
    const tr = document.createElement("tr");
    const band = r.risk ? r.risk.band : null;
    if (band) tr.classList.add(`band-${bandSlug(band)}`);
    tr.addEventListener("click", () => openDrawer(r));

    const isChoke = chokePointFindingIds.has(r.finding_id);
    tr.innerHTML = `
      <td class="expand-cell">${isChoke ? "⛓" : ""}</td>
      <td class="score-cell">${r.risk ? r.risk.score.toFixed(1) : "—"}</td>
      <td>${band ? `<span class="badge badge-band-${bandSlug(band)}">${band}</span>` : ""}</td>
      <td class="title-cell">${escapeHtml(r.title)}</td>
      <td class="mono">${escapeHtml(r.asset_hostname)}</td>
      <td class="mono">${escapeHtml(r.zone)}</td>
      <td class="mono">${escapeHtml(r.responsible_team)}</td>
      <td class="mono">${r.risk && r.risk.sla_days != null ? r.risk.sla_days + "d" : "monitor"}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ── SVG score gauge — a ring, not a wall of numbers ──
function scoreGaugeSvg(score, band) {
  const color = BAND_COLORS[band] || "#88A682";
  const r = 30, c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  return `
    <svg width="76" height="76" viewBox="0 0 76 76">
      <circle cx="38" cy="38" r="${r}" fill="none" stroke="rgba(39,37,41,0.1)" stroke-width="8"/>
      <circle cx="38" cy="38" r="${r}" fill="none" stroke="${color}" stroke-width="8"
        stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - pct)}"
        stroke-linecap="round" transform="rotate(-90 38 38)"/>
    </svg>`;
}

function openDrawer(row) {
  const risk = row.risk;
  document.getElementById("drawer-title").textContent = row.title;

  const b = risk ? risk.score_breakdown : {};
  const pathRef = (row.attack_path_refs || []).find((ref) => /^PATH-[A-Z]-Step\d+/.test(ref));
  const pathLetter = pathRef ? pathRef.match(/^PATH-([A-Z])/)[1] : null;
  const path = pathLetter ? attackPaths[`PATH-${pathLetter}`] : null;

  const body = document.getElementById("drawer-body");
  body.innerHTML = `
    <div class="badge-row">
      ${risk ? `<span class="badge badge-band-${bandSlug(risk.band)}">${risk.band}</span>` : ""}
      ${risk && risk.dora_cif_scope ? `<span class="badge badge-dora">DORA CIF</span>` : ""}
      ${chokePointFindingIds.has(row.finding_id) ? `<span class="badge badge-info">⛓ CHOKE POINT</span>` : ""}
    </div>

    ${risk ? `
    <div class="score-gauge" style="margin:14px 0">
      ${scoreGaugeSvg(risk.score, risk.band)}
      <div>
        <div class="score-gauge-value">${risk.score.toFixed(1)}</div>
        <div class="stat-label">GRS · ${risk.sla_days != null ? risk.sla_days + "-day SLA" : "monitor only"}</div>
      </div>
    </div>

    ${risk.ai_explanation ? `<div class="detail-description" style="margin-bottom:14px">${escapeHtml(risk.ai_explanation)}</div>` : ""}

    <button class="details-toggle" data-toggle="breakdown">▸ GRS breakdown (auditable)</button>
    <div class="details-content hidden" data-content="breakdown">
      <table class="breakdown-table">
        <tr><td>CVSS (norm, 0-10)</td><td>${b.cvss_norm}</td></tr>
        <tr><td>EPSS (norm, 0-10)</td><td>${b.epss_norm}</td></tr>
        <tr><td>KEV (0 or 10)</td><td>${b.kev_norm}</td></tr>
        <tr><td>Asset criticality (0-10)</td><td>${b.acw_norm}</td></tr>
        <tr><td>Toxic combination (0-10)</td><td>${b.tcm_norm}</td></tr>
        <tr><td>Impact score</td><td>${b.impact_score}</td></tr>
        <tr><td>Exposure tier ×</td><td>${b.exposure_tier}</td></tr>
        <tr><td>Compensating controls ×</td><td>${b.ccf}</td></tr>
      </table>
    </div>
    ` : `<div class="italic-hint">Not yet scored — run analysis.</div>`}

    <div class="detail-row" style="margin-top:16px">
      <div class="detail-row-label">Asset · Team</div>
      <div class="detail-row-value">${escapeHtml(row.asset_hostname)} (${escapeHtml(row.zone)}) · ${escapeHtml(row.responsible_team)}</div>
    </div>

    <button class="details-toggle" data-toggle="text">▸ Description, consequence, remediation</button>
    <div class="details-content hidden" data-content="text">
      <div class="detail-row"><div class="detail-row-label">Description</div><div class="detail-description">${escapeHtml(row.description)}</div></div>
      <div class="detail-row"><div class="detail-row-label">Consequence</div><div class="detail-description">${escapeHtml(row.consequence)}</div></div>
      <div class="detail-row"><div class="detail-row-label">Remediation</div><div class="detail-description">${escapeHtml(row.remediation_text)}</div></div>
    </div>

    ${path ? `
    <div class="detail-row" style="margin-top:16px">
      <div class="detail-row-label">Attack Path — ${path.path_ref}${path.target_asset ? ` → ${escapeHtml(path.target_asset)}` : ""}</div>
      <div class="attack-path-chain">
        ${path.steps.map((s) => `<div class="attack-path-step ${s.step_ref === pathRef ? "this-step" : ""}">${escapeHtml(s.step_ref)} — ${escapeHtml(s.description)}</div>`).join("")}
      </div>
    </div>` : ""}

    ${(row.compliance_scope || []).length ? `
    <div class="tags-row" style="margin-top:12px">
      ${row.compliance_scope.map((c) => `<span class="tag">${escapeHtml(c)}</span>`).join("")}
    </div>` : ""}
  `;

  body.querySelectorAll(".details-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const content = body.querySelector(`[data-content="${btn.dataset.toggle}"]`);
      const isHidden = content.classList.toggle("hidden");
      btn.textContent = btn.textContent.replace(/^[▸▾]/, isHidden ? "▸" : "▾");
    });
  });

  document.getElementById("drawer-backdrop").classList.remove("hidden");
  document.getElementById("drawer").classList.remove("hidden");
}

function closeDrawer() {
  document.getElementById("drawer-backdrop").classList.add("hidden");
  document.getElementById("drawer").classList.add("hidden");
}

// ══════════════════ Attack Paths tab (Cytoscape graph) ══════════════════

function renderPathsTab() {
  const list = document.getElementById("path-list");
  list.innerHTML = "";
  const pathRefs = Object.keys(attackPaths).sort();
  if (!activePathRef || !attackPaths[activePathRef]) activePathRef = pathRefs[0];

  pathRefs.forEach((ref) => {
    const path = attackPaths[ref];
    const item = document.createElement("div");
    item.className = `path-list-item ${ref === activePathRef ? "active" : ""}`;
    item.innerHTML = `${ref}<span class="path-target">→ ${escapeHtml(path.target_asset || "no single target")}</span>`;
    item.addEventListener("click", () => {
      activePathRef = ref;
      renderPathsTab();
    });
    list.appendChild(item);
  });

  renderPathGraph(activePathRef);
}

function scoreForFindingId(findingId) {
  const row = allRows.find((r) => r.finding_id === findingId);
  return row && row.risk ? row.risk : null;
}

function renderPathGraph(pathRef) {
  const path = attackPaths[pathRef];
  const summaryEl = document.getElementById("path-summary");
  if (!path) {
    summaryEl.textContent = "No attack paths discovered.";
    return;
  }
  summaryEl.innerHTML = `<strong>${path.path_ref}</strong> — ${escapeHtml(path.summary)}`;

  // Match each step to the finding that documents it (Finding.attack_path_refs).
  const stepFindings = path.steps.map((step) =>
    allRows.find((r) => (r.attack_path_refs || []).includes(step.step_ref))
  );

  const elements = [];
  path.steps.forEach((step, i) => {
    const finding = stepFindings[i];
    const risk = finding ? finding.risk : null;
    const isChoke = finding && chokePointFindingIds.has(finding.finding_id);
    elements.push({
      data: {
        id: step.step_ref,
        label: `${step.step_ref}\n${finding ? finding.asset_hostname : ""}`,
        color: risk ? BAND_COLORS[risk.band] : "#88A682",
        isChoke,
        findingId: finding ? finding.finding_id : null,
      },
    });
    if (i > 0) {
      elements.push({ data: { id: `${path.steps[i - 1].step_ref}->${step.step_ref}`, source: path.steps[i - 1].step_ref, target: step.step_ref } });
    }
  });

  if (cy) cy.destroy();
  cy = cytoscape({
    container: document.getElementById("cy"),
    elements,
    layout: { name: "breadthfirst", directed: true, spacingFactor: 1.4, padding: 40 },
    style: [
      {
        selector: "node",
        style: {
          "background-color": "data(color)",
          label: "data(label)",
          "text-wrap": "wrap",
          "text-valign": "bottom",
          "text-margin-y": 8,
          "font-size": 11,
          "font-family": "IBM Plex Mono, monospace",
          color: "#272529",
          width: 34,
          height: 34,
          "border-width": 3,
          "border-color": "#F7F2EE",
        },
      },
      {
        selector: "node[?isChoke]",
        style: { width: 46, height: 46, "border-width": 4, "border-color": "#003c30" },
      },
      {
        selector: "edge",
        style: {
          width: 3,
          "line-color": "rgba(0,60,48,0.35)",
          "target-arrow-color": "rgba(0,60,48,0.35)",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
        },
      },
    ],
  });

  cy.on("tap", "node", (evt) => {
    const findingId = evt.target.data("findingId");
    const row = allRows.find((r) => r.finding_id === findingId);
    if (row) openDrawer(row);
  });
}

// ══════════════════ Teams tab ══════════════════

function renderTeamsTab() {
  const grid = document.getElementById("teams-grid");
  grid.innerHTML = "";

  teamBriefs.forEach((team) => {
    const card = document.createElement("div");
    const worstBand = BAND_ORDER.find((b) => (team.band_counts[b] || 0) > 0) || "TRACK";
    card.className = "card";
    card.style.borderLeftColor = BAND_COLORS[worstBand];

    const barSegments = BAND_ORDER.filter((b) => team.band_counts[b])
      .map((b) => `<div class="card-bar-segment" style="flex:${team.band_counts[b]}; background:${BAND_COLORS[b]}"></div>`)
      .join("");

    card.innerHTML = `
      <div class="card-title">${escapeHtml(team.team_name)}</div>
      <div class="card-stat-row">
        <span class="card-stat">${team.total_findings} findings</span>
        ${team.choke_point_count ? `<span class="card-stat">⛓ ${team.choke_point_count} choke point(s)</span>` : ""}
        ${team.band_counts["IMMEDIATE"] ? `<span class="card-stat" style="color:${BAND_COLORS.IMMEDIATE}">${team.band_counts["IMMEDIATE"]} immediate</span>` : ""}
      </div>
      <div class="card-bar-track">${barSegments}</div>
      <button class="btn-notify">Notify Team</button>
    `;
    card.querySelector(".btn-notify").addEventListener("click", () => openBrief(team));
    grid.appendChild(card);
  });
}

function openBrief(team) {
  document.getElementById("brief-title").textContent = `Notify — ${team.team_name}`;
  document.getElementById("brief-text").value = team.brief_text;
  document.getElementById("brief-backdrop").classList.remove("hidden");
  document.getElementById("brief-modal").classList.remove("hidden");
}

function closeBrief() {
  document.getElementById("brief-backdrop").classList.add("hidden");
  document.getElementById("brief-modal").classList.add("hidden");
}

function copyBrief() {
  const textarea = document.getElementById("brief-text");
  textarea.select();
  navigator.clipboard?.writeText(textarea.value).catch(() => document.execCommand("copy"));
  const btn = document.getElementById("brief-copy");
  const original = btn.textContent;
  btn.textContent = "Copied ✓";
  setTimeout(() => { btn.textContent = original; }, 1500);
}

// ══════════════════ Compliance tab ══════════════════

function renderComplianceTab() {
  const grid = document.getElementById("compliance-grid");
  grid.innerHTML = "";

  complianceData.frameworks.forEach((fw) => {
    const worstBand = fw.worst_score >= 80 ? "IMMEDIATE" : fw.worst_score >= 60 ? "ACT" : fw.worst_score >= 40 ? "ATTEND" : fw.worst_score >= 20 ? "TRACK*" : "TRACK";
    const card = document.createElement("div");
    card.className = "card";
    card.style.borderLeftColor = BAND_COLORS[worstBand];
    const pct = fw.finding_count ? Math.round((fw.urgent_count / fw.finding_count) * 100) : 0;
    card.innerHTML = `
      <div class="card-title">${escapeHtml(fw.framework)}</div>
      <div class="card-stat-row">
        <span class="card-stat">${fw.finding_count} findings in scope</span>
        <span class="card-stat" style="color:${BAND_COLORS[worstBand]}">worst GRS ${fw.worst_score.toFixed(1)}</span>
      </div>
      <div class="card-bar-track"><div class="card-bar-segment" style="flex:${pct}; background:${BAND_COLORS.IMMEDIATE}"></div><div class="card-bar-segment" style="flex:${100 - pct}; background:var(--border-bright)"></div></div>
      <div class="stat-label">${fw.urgent_count} of ${fw.finding_count} need action now (Immediate/Act)</div>
    `;
    grid.appendChild(card);
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

main();
