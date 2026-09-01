/* ============================================================
   Cloud Resilience Visualizer — evidence record view

   Renders GET /api/evidence in human-readable form. This is CRV's
   real differentiator over a Wiz/Prisma-style tool: a cryptographic
   chain-of-custody record for the scan, not just a findings list.
   Before this page existed, the only way to see it was a raw JSON
   response or the PDF report -- built, tested, and completely
   invisible in the UI.

   Fetches once and caches, same pattern as compliance.js. Evidence
   records aren't included in an archived snapshot file (only
   topology/findings/compliance are -- see run_scheduled_audit.py), so
   viewing a loaded report shows an explanatory message instead of
   fetching live data that would describe a DIFFERENT scan than the
   one on screen.

   Depends on globals defined in topology.js (loaded before this
   file): escapeHtml, withProjectTag, API_BASE, API_KEY,
   LOADED_SNAPSHOT_META; and compliance.js's renderDownloadBar().
   ============================================================ */


let EVIDENCE_CACHE = null;

// Called by topology.js's switchView() on Evidence tab click.
async function activateEvidenceView() {
    const container = document.getElementById("evidence-view-content");

    if (LOADED_SNAPSHOT_META) {
        container.innerHTML = `
            <div class="findings-empty">
                Evidence records are generated per live scan and aren't
                included in archived report snapshots. Switch back to a
                live scan to view one.
            </div>
        `;
        return;
    }

    if (EVIDENCE_CACHE) {
        renderEvidence(container, EVIDENCE_CACHE);
        return;
    }

    container.innerHTML = `<div class="compliance-loading">Loading evidence record...</div>`;
    try {
        const record = await fetchEvidence();
        EVIDENCE_CACHE = record;
        renderEvidence(container, record);
    } catch (err) {
        console.error("Failed to fetch evidence record:", err);
        container.innerHTML =
            `<div class="compliance-error">Cannot reach evidence endpoint. Is the backend running on port 8000?</div>`;
    }
}

async function fetchEvidence() {
    const response = await fetch(withProjectTag(`${API_BASE}/api/evidence`), {
        headers: { "X-API-Key": API_KEY },
    });
    if (!response.ok) {
        throw new Error("Evidence fetch failed: HTTP " + response.status);
    }
    return await response.json();
}

function renderEvidence(container, record) {
    const generatedAt = record.generated_at
        ? new Date(record.generated_at).toLocaleString()
        : "unknown";
    const scope = record.scope || {};
    const summary = record.findings_summary || {};
    const bySeverity = summary.by_severity || {};

    container.innerHTML = `
        <div class="evidence-header">
            <div class="evidence-title">Audit evidence record</div>
            ${renderDownloadBar()}
        </div>

        <div class="evidence-explainer">
            This record is a cryptographic proof-of-scan: a SHA-256 hash of
            the exact topology data that was scanned, plus an integrity
            hash covering the whole record. If anything in this record
            were altered after the fact — a finding count changed, a
            timestamp backdated — the integrity hash below would no
            longer match, making the tampering detectable. It proves this
            specific record hasn't been altered since it was generated;
            it does not, on its own, prove who produced it or that the
            underlying scan itself was run correctly.
        </div>

        <div class="evidence-grid">
            ${evidenceField("Generated", generatedAt)}
            ${evidenceField("Data source", record.data_source)}
            ${evidenceField("IAM identity", record.iam_identity, true)}
            ${evidenceField("Tool version", record.tool_version)}
            ${evidenceField("Scope", `${scope.project_tag || "Whole account"} · ${scope.node_count ?? "?"} resources · region ${scope.region_hint || "unknown"}`)}
            ${evidenceField("Findings", `${summary.total ?? 0} total, ${summary.risk_accepted ?? 0} risk-accepted`)}
        </div>

        <div class="dashboard-section-title">Findings by severity</div>
        <div class="evidence-severity-strip">
            ${["critical", "high", "medium", "low"].map(sev => `
                <div class="severity-tile severity-tile-${sev}">
                    <div class="severity-tile-count">${bySeverity[sev] ?? 0}</div>
                    <div class="severity-tile-label">${sev}</div>
                </div>
            `).join("")}
        </div>

        <div class="dashboard-section-title">Integrity hashes</div>
        <div class="evidence-hashes">
            ${evidenceHashRow("Input hash", record.input_hash)}
            ${evidenceHashRow("Integrity hash", record.integrity_hash)}
        </div>
    `;

    wireEvidenceCopyButtons();
}

function evidenceField(label, value, mono) {
    const cls = mono ? "evidence-field-value evidence-mono" : "evidence-field-value";
    return `
        <div class="evidence-field">
            <div class="evidence-field-label">${escapeHtml(label)}</div>
            <div class="${cls}">${escapeHtml(String(value ?? "—"))}</div>
        </div>
    `;
}

function evidenceHashRow(label, value) {
    const safeValue = escapeHtml(value || "");
    return `
        <div class="evidence-hash-row">
            <div class="evidence-hash-label">${escapeHtml(label)}</div>
            <div class="evidence-hash-value">${safeValue}</div>
            <button class="evidence-copy-btn" data-copy-value="${safeValue}" type="button">Copy</button>
        </div>
    `;
}

function wireEvidenceCopyButtons() {
    document.querySelectorAll(".evidence-copy-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(btn.dataset.copyValue);
                const original = btn.textContent;
                btn.textContent = "Copied";
                btn.disabled = true;
                setTimeout(() => {
                    btn.textContent = original;
                    btn.disabled = false;
                }, 1200);
            } catch (err) {
                console.warn("Clipboard copy failed:", err);
            }
        });
    });
}
