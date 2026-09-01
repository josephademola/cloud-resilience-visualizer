/* ============================================================
   Cloud Resilience Visualizer — dashboard

   The landing view: "where do I stand" in three seconds, without
   clicking into anything. Deliberately does NOT compute a single
   blended posture score -- CRV has no documented, defensible weighting
   between a critical S3 exposure and a CIS AWS Foundations requirement
   gap, and inventing one would misrepresent the honest, per-framework
   picture the rest of this tool goes out of its way to preserve (see
   cis_aws_foundations.json's own mapping_rationale, and design
   decision #13). Instead: raw severity counts (no judgment call
   needed to compute a count) and a framework standing chart sized by
   each framework's OWN failing_count relative to the worst offender
   -- not a percentage, since the backend has no "total requirements
   per framework" figure to divide by, and inventing one would be the
   same mistake in a different shape.

   Depends on globals defined in topology.js (loaded before this
   file): escapeHtml, FINDINGS, TOPOLOGY_METADATA, PROJECT_TAG,
   LOADED_SNAPSHOT_META, FRAMEWORK_LABELS; and compliance.js's
   ensureComplianceData().
   ============================================================ */


// Called by topology.js's switchView() -- both on initial load
// (Dashboard is the default view) and on every later click back to it.
async function activateDashboardView() {
    const container = document.getElementById("dashboard-view-content");
    container.innerHTML = `<div class="compliance-loading">Loading dashboard...</div>`;
    try {
        const compliance = await ensureComplianceData();
        renderDashboard(container, compliance);
    } catch (err) {
        console.error("Failed to load dashboard:", err);
        container.innerHTML =
            `<div class="compliance-error">Cannot reach compliance endpoint. Is the backend running on port 8000?</div>`;
    }
}

// Also called directly by topology.js's loadSnapshotFile() when the
// Dashboard tab is the one currently open at the moment a report file
// is loaded -- no fetch needed there, the snapshot already carries a
// full compliance view.
function renderDashboard(container, compliance) {
    container.innerHTML =
        renderScopeLine() +
        renderRiskAcceptedNote(compliance.metadata) +
        renderSeverityStrip() +
        renderFrameworkStanding(compliance.frameworks);
}


// ---- Scope line: what am I looking at ----

function renderScopeLine() {
    const items = [];
    if (LOADED_SNAPSHOT_META) {
        const when = LOADED_SNAPSHOT_META.generated_at
            ? new Date(LOADED_SNAPSHOT_META.generated_at).toLocaleString()
            : "unknown time";
        items.push(iconItem("ti-file-certificate", `Archived report · ${when}`));
        if (LOADED_SNAPSHOT_META.project_tag) {
            items.push(iconItem("ti-tag", LOADED_SNAPSHOT_META.project_tag));
        }
    } else {
        const when = TOPOLOGY_METADATA.generated_at
            ? new Date(TOPOLOGY_METADATA.generated_at).toLocaleString()
            : "unknown time";
        items.push(iconItem("ti-clock", `Scanned ${when}`));
        items.push(iconItem("ti-tag", PROJECT_TAG || "Whole account"));
    }
    if (typeof TOPOLOGY_METADATA.node_count === "number") {
        items.push(iconItem("ti-affiliate", `${TOPOLOGY_METADATA.node_count} resources`));
    }
    return `<div class="dashboard-scope">${items.join("")}</div>`;
}

function iconItem(iconClass, text) {
    return `<span class="dashboard-scope-item"><i class="ti ${iconClass}"></i>${escapeHtml(text)}</span>`;
}

function renderRiskAcceptedNote(metadata) {
    const count = metadata && metadata.risk_accepted_count;
    if (!count) return "";
    return `
        <div class="risk-accepted-note">
            ${count} finding${count === 1 ? "" : "s"} consciously risk-accepted and excluded from the counts below.
            See the Findings list for full detail.
        </div>
    `;
}


// ---- Severity strip ----

// Active = not risk-accepted -- "what do I actually need to act on",
// the same definition the Findings page's "Active" filter uses, so
// the two views never disagree about what counts as open.
function renderSeverityStrip() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of FINDINGS) {
        if (f.risk_accepted) continue;
        if (counts[f.severity] !== undefined) counts[f.severity]++;
    }
    const tiles = ["critical", "high", "medium", "low"].map(sev => `
        <div class="severity-tile severity-tile-${sev}">
            <div class="severity-tile-count">${counts[sev]}</div>
            <div class="severity-tile-label">${sev}</div>
        </div>
    `).join("");
    return `<div class="dashboard-severity-strip">${tiles}</div>`;
}


// ---- Framework standing ----

// Bars are sized relative to the worst-offending framework's
// failing_count, not a percentage -- there is no "total requirements
// in NIS2" figure in the API to divide by, and computing one would
// mean inventing a denominator the mapping files don't actually
// define. Relative-to-worst is the most honest comparison the real
// data supports.
function renderFrameworkStanding(frameworks) {
    const sorted = frameworks.slice().sort((a, b) => b.failing_count - a.failing_count);
    const max = Math.max(1, ...sorted.map(fw => fw.failing_count));

    const rows = sorted.map(fw => {
        const shortName = fw.framework_short_name || FRAMEWORK_LABELS[fw.framework] || fw.framework;
        const widthPct = (fw.failing_count / max) * 100;
        return `
            <div class="framework-bar-row">
                <div class="framework-bar-label">${escapeHtml(shortName)}</div>
                <div class="framework-bar-track">
                    <div class="framework-bar-fill" style="width: ${widthPct}%"></div>
                </div>
                <div class="framework-bar-count">${fw.failing_count} ${escapeHtml(fw.unit_label)}</div>
            </div>
        `;
    }).join("");

    return `
        <div class="dashboard-section-title">Framework standing</div>
        <div class="framework-bars">${rows}</div>
    `;
}
