/* ============================================================
   Cloud Resilience Visualizer — compliance view

   Renders the compliance dashboard: four score cards at top,
   framework detail sections below. Fetches from /api/compliance
   lazily (only on first switch to the tab) and caches the result
   in memory. Subsequent switches use the cache — no re-fetch.

   Depends on API_BASE defined in topology.js (loaded before this
   file). Uses escapeHtml also defined in topology.js.
   ============================================================ */


const COMPLIANCE_API_URL = `${API_BASE}/api/compliance`;

// Cache populated on first successful fetch.
let COMPLIANCE_CACHE = null;


// Called by topology.js's switchView() on Compliance tab click.
async function activateComplianceView() {
    const container = document.getElementById("compliance-dashboard");

    // Cache hit: render immediately with no network call.
    if (COMPLIANCE_CACHE) {
        renderComplianceDashboard(container, COMPLIANCE_CACHE);
        return;
    }

    // Cache miss: show loading state, then fetch and render.
    container.innerHTML = `<div class="compliance-loading">Loading compliance data...</div>`;

    try {
        const data = await fetchCompliance();
        COMPLIANCE_CACHE = data;
        renderComplianceDashboard(container, data);
    } catch (err) {
        console.error("Failed to fetch compliance data:", err);
        container.innerHTML =
            `<div class="compliance-error">Cannot reach compliance endpoint. Is the backend running on port 8000?</div>`;
    }
}


async function fetchCompliance() {
    const response = await fetch(COMPLIANCE_API_URL, {
        headers: { "X-API-Key": API_KEY },
    });
    if (!response.ok) {
        throw new Error("Compliance fetch failed: HTTP " + response.status);
    }
    return await response.json();
}


function renderComplianceDashboard(container, data) {
    const parts = [];
    parts.push(renderDownloadBar());
    parts.push(renderScoreCards(data.frameworks));
    parts.push(renderFrameworkSections(data.frameworks));
    container.innerHTML = parts.join("");
}

function renderDownloadBar() {
    // The `download` attribute + Content-Disposition header on the
    // backend response makes the browser download rather than display
    // the PDF inline. No JS click handler needed.
    return `
        <div class="download-bar">
            <a href="${API_BASE}/api/report" class="download-btn" download>
                <i class="ti ti-download"></i>
                Download PDF report
            </a>
        </div>
    `;
}


function renderScoreCards(frameworks) {
    // Short names for the score cards. Full names appear in the
    // detail section headings below.
    const shortNames = {
        nis2: "NIS2",
        ncsc_caf: "NCSC CAF",
        mitre_attack: "MITRE ATT&amp;CK",
        cyber_essentials: "Cyber Essentials",
    };

    const cards = frameworks.map(fw => {
        const numberClass = fw.failing_count > 0
            ? "score-number score-number-failing"
            : "score-number";
        return `
            <div class="score-card">
                <div class="score-framework">${shortNames[fw.framework] || escapeHtml(fw.framework)}</div>
                <div class="${numberClass}">${fw.failing_count}</div>
                <div class="score-label">${escapeHtml(fw.unit_label)}</div>
            </div>
        `;
    }).join("");

    return `<div class="score-cards">${cards}</div>`;
}


function renderFrameworkSections(frameworks) {
    return frameworks.map(fw => `
        <section class="framework-section">
            <div class="framework-section-header">
                <div class="framework-section-title">${escapeHtml(fw.framework_full_name)}</div>
                <div class="framework-section-count">${fw.failing_count} ${escapeHtml(fw.unit_label)}</div>
            </div>
            ${renderRequirementRows(fw.failing_requirements)}
        </section>
    `).join("");
}


function renderRequirementRows(requirements) {
    if (requirements.length === 0) {
        return `<div class="requirement-empty">No requirements failing in this framework.</div>`;
    }

    return requirements.map(req => `
        <div class="requirement-row">
            <div class="requirement-header">
                <span class="framework-ref-id">${escapeHtml(req.reference_id)}</span>
                <span class="requirement-label">${escapeHtml(req.label)}</span>
                <span class="requirement-finding-count">${req.findings.length} finding${req.findings.length === 1 ? "" : "s"}</span>
            </div>
            <div class="requirement-findings">
                ${req.findings.map(f => `
                    <div class="requirement-finding">
                        <span class="finding-severity finding-severity-${escapeHtml(f.severity)}">${escapeHtml(f.severity)}</span>
                        <span class="requirement-finding-resource">${escapeHtml(f.resource_id)}</span>
                        <span class="requirement-finding-title">${escapeHtml(f.title)}</span>
                    </div>
                `).join("")}
            </div>
        </div>
    `).join("");
}