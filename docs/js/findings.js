/* ============================================================
   Cloud Resilience Visualizer — findings table

   The persistent, sortable, filterable findings list every modern
   CSPM tool leads with -- "what should I look at first", answered
   without clicking through resources one at a time. Reads from the
   FINDINGS array topology.js already populates at load; this is the
   exact same data the Assets details panel shows per-resource, just
   presented flat instead of one resource at a time. No separate
   fetch, no caching layer -- re-rendering from the in-memory array on
   every filter/sort click is cheap at this dataset size.

   Depends on globals defined in topology.js, loaded before this file:
   escapeHtml, groupFrameworkRefs, frameworkShortLabel, buildFindingsHtml,
   openDetailsPanel, FRAMEWORK_ORDER, FRAMEWORK_LABELS, FINDINGS.
   ============================================================ */


const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// Sort/filter are UI state, not data -- kept here rather than
// recomputed from the DOM so they survive a re-render triggered by
// clicking a different filter or column header.
let FINDINGS_SORT = { key: "severity", direction: "desc" };
let FINDINGS_FILTER = "all";

// The list actually on screen after the most recent render, indexed
// the same way as the table rows -- lets a row click look up its
// finding by data-index without re-sorting/re-filtering.
let FINDINGS_TABLE_ROWS = [];


// Called by topology.js's switchView() every time the Findings nav
// item is clicked.
function activateFindingsView() {
    const container = document.getElementById("findings-view-content");
    container.innerHTML = renderFindingsToolbar() + renderFindingsTable();
    wireFindingsToolbar();
    wireFindingsTable();
}

function filteredFindings() {
    if (FINDINGS_FILTER === "active") return FINDINGS.filter(f => !f.risk_accepted);
    if (FINDINGS_FILTER === "accepted") return FINDINGS.filter(f => f.risk_accepted);
    return FINDINGS;
}

function sortedFindings() {
    const list = filteredFindings().slice();
    const { key, direction } = FINDINGS_SORT;
    list.sort((a, b) => {
        const cmp = key === "severity"
            ? (SEVERITY_RANK[a.severity] || 0) - (SEVERITY_RANK[b.severity] || 0)
            : String(a[key]).localeCompare(String(b[key]));
        return direction === "asc" ? cmp : -cmp;
    });
    return list;
}

function renderFindingsToolbar() {
    const filters = [
        { key: "all", label: "All" },
        { key: "active", label: "Active" },
        { key: "accepted", label: "Risk Accepted" },
    ];
    const buttons = filters.map(f => `
        <button class="filter-btn ${f.key === FINDINGS_FILTER ? "filter-btn-active" : ""}" data-filter="${f.key}">${escapeHtml(f.label)}</button>
    `).join("");
    const count = filteredFindings().length;
    return `
        <div class="findings-toolbar">
            <div class="findings-filter" role="group" aria-label="Filter findings">${buttons}</div>
            <div class="findings-count">${count} finding${count === 1 ? "" : "s"}</div>
        </div>
    `;
}

function renderFindingsTable() {
    const list = sortedFindings();
    FINDINGS_TABLE_ROWS = list;

    if (list.length === 0) {
        return `<div class="findings-empty">No findings match this filter.</div>`;
    }

    const sortableColumns = [
        { key: "severity", label: "Severity" },
        { key: "resource_id", label: "Resource" },
        { key: "title", label: "Finding" },
    ];
    const headerCells = sortableColumns.map(col => {
        const isActive = FINDINGS_SORT.key === col.key;
        const arrow = isActive ? (FINDINGS_SORT.direction === "asc" ? " &uarr;" : " &darr;") : "";
        return `<th class="sortable${isActive ? " sort-active" : ""}" data-sort="${col.key}">${escapeHtml(col.label)}${arrow}</th>`;
    }).join("");

    const rows = list.map((finding, i) => `
        <tr class="findings-row" data-index="${i}" tabindex="0">
            <td><span class="finding-severity finding-severity-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span></td>
            <td class="findings-resource">${escapeHtml(finding.resource_id)}</td>
            <td class="findings-title">${escapeHtml(finding.title)}</td>
            <td class="findings-frameworks">${renderFrameworkPills(finding.framework_references)}</td>
            <td class="findings-status">${finding.risk_accepted ? '<span class="risk-accepted-pill">Risk accepted</span>' : ""}</td>
        </tr>
    `).join("");

    return `
        <table class="findings-table">
            <thead><tr>${headerCells}<th>Frameworks</th><th>Status</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}

function renderFrameworkPills(refs) {
    const grouped = groupFrameworkRefs(refs);
    return FRAMEWORK_ORDER
        .filter(key => grouped[key])
        .map(key => `<span class="fw-pill">${escapeHtml(frameworkShortLabel(key, FRAMEWORK_LABELS[key]))}</span>`)
        .join("");
}

function wireFindingsToolbar() {
    document.querySelectorAll(".findings-filter .filter-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            FINDINGS_FILTER = btn.dataset.filter;
            activateFindingsView();
        });
    });
}

function wireFindingsTable() {
    document.querySelectorAll(".findings-table th.sortable").forEach(th => {
        th.addEventListener("click", () => {
            const key = th.dataset.sort;
            if (FINDINGS_SORT.key === key) {
                FINDINGS_SORT = { key, direction: FINDINGS_SORT.direction === "asc" ? "desc" : "asc" };
            } else {
                // Severity defaults to worst-first; the two text
                // columns default to A-Z -- whichever reads naturally
                // the first time a column is clicked.
                FINDINGS_SORT = { key, direction: key === "severity" ? "desc" : "asc" };
            }
            activateFindingsView();
        });
    });

    document.querySelectorAll(".findings-row").forEach(row => {
        const openRow = () => showFindingDetails(FINDINGS_TABLE_ROWS[Number(row.dataset.index)]);
        row.addEventListener("click", openRow);
        row.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                openRow();
            }
        });
    });
}

// Reuses the exact same finding-card markup the Assets details panel
// renders per-resource (buildFindingsHtml, topology.js) and the same
// slide-in panel mechanics (openDetailsPanel, topology.js) -- a
// finding looks identical whether you got to it by clicking a node or
// a table row.
function showFindingDetails(finding) {
    const header = `
        <div class="details-header">
            <h2 class="details-name">${escapeHtml(finding.title)}</h2>
            <div class="details-type">${escapeHtml(finding.resource_id)}</div>
        </div>
    `;
    openDetailsPanel(header + buildFindingsHtml([finding]));
}
