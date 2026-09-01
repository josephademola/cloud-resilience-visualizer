/* ============================================================
   Cloud Resilience Visualizer — topology rendering

   Phase 2 update: the click panel now shows real findings
   produced by the backend scanner (severity, description,
   remediation, framework references), instead of the hardcoded
   Phase 1 "Issues" text.
   ============================================================ */


// Layout constants — sizes and gaps for each shape type, in screen pixels.
const LAYOUT = {
    vpc:      { startX: 80, startY: 100, width: 620, padding: 50 },
    subnet:   { height: 200, gap: 30 },
    igw:      { width: 130, height: 36, gap: 12 },
    resource: { width: 150, height: 60, gap: 24 },
    bucket:   { width: 230, height: 70, gap: 30, leftPad: 80 },
};

// Backend API base URL. Change this when deploying to a real host —
// for now it's the local FastAPI dev server on port 8000.
const API_BASE = "https://cloud-resilience-visualizer.onrender.com";

// API key for the backend. In development this is the insecure
// default. In production (Phase 8), this value would come from
// a build-time environment variable or a config endpoint.
const API_KEY = "crv-prod-2026-joseph";

// Phase 9a Feature 1's tag-based scoping (?project_tag=Key=Value on
// the backend) has no UI control of its own — it's read from this
// page's OWN url, e.g. bookmarking
// index.html?project_tag=Project=SomeTag shows that project's scan
// instead of the whole account. Read once at load; changing scope
// means loading a different URL, not a live in-page toggle. Never
// hardcoded here — whatever tag value is being audited only ever
// lives in whoever's browser URL bar is looking at it.
const PROJECT_TAG = new URLSearchParams(window.location.search).get("project_tag");

// Canonical framework display order and short labels -- the single
// source for the finding-card framework references below, the
// compliance score cards (compliance.js), and the findings table
// (findings.js). Was three near-identical copies before; consolidated
// here so a new framework only needs adding in one place.
const FRAMEWORK_ORDER = [
    "nis2", "ncsc_caf", "mitre_attack", "cyber_essentials",
    "iso27001", "dora", "cis_aws_foundations", "confidential",
];
const FRAMEWORK_LABELS = {
    nis2: "NIS2",
    ncsc_caf: "NCSC CAF",
    mitre_attack: "MITRE ATT&CK",
    cyber_essentials: "Cyber Essentials",
    iso27001: "ISO 27001",
    dora: "DORA",
    cis_aws_foundations: "CIS AWS",
    confidential: "Confidential Client",
};

// Module-level state, populated at init (live) or by loadSnapshotFile
// (archived report loaded from disk).
let FINDINGS = [];
let MAP = null;

// Set only when viewing a report loaded from a file instead of a live
// scan — { generated_at, project_tag } from the snapshot's own top
// level. null means "viewing live data", which is the default.
let LOADED_SNAPSHOT_META = null;


// ---- Entry point ----

document.addEventListener("DOMContentLoaded", init);

async function init() {
    document.getElementById("details-close").addEventListener("click", hideDetails);
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") hideDetails();
    });

    // Wire the sidebar nav buttons so clicks switch between sections.
    // Handler defined below in switchView().
    document.querySelectorAll(".sidebar-nav-btn").forEach(btn => {
        btn.addEventListener("click", () => switchView(btn.dataset.view));
    });

    setupSnapshotLoader();

    try {
        // Fetch topology and findings in parallel — they're independent.
        const [topology, findings] = await Promise.all([
            fetchTopology(),
            fetchFindings(),
        ]);
        renderFromData(topology, findings);
    } catch (err) {
        console.error("Failed to render topology:", err);
        const statusEl = document.getElementById("status");
        statusEl.textContent = "Cannot reach API — is the backend server running on port 8000?";
        statusEl.classList.add("status-error");
    }
}

// Shared by the live init() path and loadSnapshotFile() below --
// (re)creates the map and renders it, so loading a file after the
// live view already rendered replaces it cleanly rather than drawing
// on top of the existing layers.
function renderFromData(topology, findings) {
    if (MAP) {
        MAP.remove();
    }
    MAP = createMap();
    renderTopology(MAP, topology);
    FINDINGS = findings;
    updateStatus(topology);
}

// "Load report file" button: reads a full-snapshot.json (produced by
// scripts/run_scheduled_audit.py, downloaded from wherever it was
// archived to, e.g. a private S3 bucket) straight off local disk via
// the browser's File API. Nothing is uploaded anywhere -- this is
// pure client-side rendering of a file the user already has, using
// the exact same rendering code as the live view.
function setupSnapshotLoader() {
    const button = document.getElementById("load-report-btn");
    const input = document.getElementById("snapshot-file-input");
    button.addEventListener("click", () => input.click());
    input.addEventListener("change", async () => {
        const file = input.files[0];
        input.value = ""; // allow re-selecting the same file later
        if (!file) return;
        try {
            await loadSnapshotFile(file);
        } catch (err) {
            console.error("Failed to load report file:", err);
            alert("Could not load that file as a CRV report:\n" + err.message);
        }
    });
}

async function loadSnapshotFile(file) {
    const text = await file.text();
    const snapshot = JSON.parse(text);

    if (!snapshot.topology || !snapshot.findings || !snapshot.compliance) {
        throw new Error(
            "This doesn't look like a CRV snapshot file (missing " +
            "topology, findings, or compliance)."
        );
    }

    LOADED_SNAPSHOT_META = {
        generated_at: snapshot.generated_at || null,
        project_tag: snapshot.project_tag || null,
    };

    renderFromData(snapshot.topology, snapshot.findings.findings || []);

    // compliance.js's cache -- setting it here means switching to the
    // Compliance tab renders instantly from this file instead of
    // trying to fetch live data.
    COMPLIANCE_CACHE = snapshot.compliance;
    if (document.getElementById("compliance-view").classList.contains("view-active")) {
        renderComplianceDashboard(
            document.getElementById("compliance-dashboard"),
            COMPLIANCE_CACHE
        );
    }
}

// Section titles shown in the topbar. Keyed by the same data-view
// values as the sidebar buttons and the "<view>-view" section ids.
const SECTION_TITLES = {
    dashboard: "Dashboard",
    assets: "Assets",
    findings: "Findings",
    compliance: "Compliance",
    evidence: "Evidence",
};

function switchView(viewName) {
    // Update which sidebar button looks active.
    document.querySelectorAll(".sidebar-nav-btn").forEach(btn => {
        btn.classList.toggle("sidebar-nav-btn-active", btn.dataset.view === viewName);
    });

    // Show the requested view, hide the others.
    document.querySelectorAll(".view").forEach(view => {
        view.classList.toggle("view-active", view.id === viewName + "-view");
    });

    document.getElementById("topbar-title").textContent = SECTION_TITLES[viewName] || "";

    // The details panel is shared by Assets (a topology node) and
    // Findings (a single finding row) -- start clean on every switch;
    // each view reopens it explicitly on its own click interaction.
    hideDetails();

    if (viewName === "compliance") {
        // activateComplianceView is defined in compliance.js, loaded
        // after this file. Lazy-fetches compliance data on first switch.
        activateComplianceView();
    }

    if (viewName === "findings") {
        // activateFindingsView is defined in findings.js, loaded after
        // this file. FINDINGS is already loaded at init -- no fetch,
        // just re-render (cheap, dataset is small).
        activateFindingsView();
    }
}


// ---- Data loading ----

// Appends ?project_tag=<value> to an API path when PROJECT_TAG is
// set, URL-encoded so the tag's own "=" (e.g. "Project=SomeTag")
// survives as a single query value rather than being parsed as two.
function withProjectTag(path) {
    if (!PROJECT_TAG) return path;
    const sep = path.includes("?") ? "&" : "?";
    return `${path}${sep}project_tag=${encodeURIComponent(PROJECT_TAG)}`;
}

async function fetchTopology() {
    const response = await fetch(withProjectTag(`${API_BASE}/api/topology`), {
        headers: { "X-API-Key": API_KEY },
    });
    if (!response.ok) {
        throw new Error("Topology fetch failed: HTTP " + response.status);
    }
    return await response.json();
}

async function fetchFindings() {
    // Findings fetch is graceful: if the endpoint is temporarily
    // unavailable we proceed with an empty list rather than break
    // the whole page. Topology is required; findings are optional.
    try {
        const response = await fetch(withProjectTag(`${API_BASE}/api/findings`), {
            headers: { "X-API-Key": API_KEY },
        });
        if (!response.ok) {
            console.warn("Findings endpoint returned", response.status);
            return [];
        }
        const data = await response.json();
        return data.findings || [];
    } catch (err) {
        console.warn("Could not fetch findings:", err);
        return [];
    }
}

// ---- Map initialisation ----

function createMap() {
    return L.map("map", {
        crs: L.CRS.Simple,
        minZoom: -2,
        maxZoom: 2,
        zoomControl: false,
        attributionControl: false,
        zoomSnap: 0.25,
    });
}


// ---- Layout: assign (x, y, width, height) to every node ----

function computeLayout(topology) {
    const layouts = {};
    const byParent = groupByParent(topology.nodes);

    let cursorX = LAYOUT.vpc.startX;
    for (const vpc of topology.nodes.filter(n => n.type === "vpc")) {
        const vpcLayout = layoutVpcAndChildren(vpc, byParent, layouts, cursorX);
        cursorX += vpcLayout.width + 60;
    }

    for (const igw of topology.nodes.filter(n => n.type === "internet_gateway")) {
        const parent = layouts[igw.parent_id];
        if (!parent) continue;
        layouts[igw.id] = {
            x: parent.x + parent.width / 2 - LAYOUT.igw.width / 2,
            y: parent.y - LAYOUT.igw.height - LAYOUT.igw.gap,
            width: LAYOUT.igw.width,
            height: LAYOUT.igw.height,
        };
    }

    const rightEdge = rightmostEdge(layouts);
    let bucketY = LAYOUT.vpc.startY;
    // S3 buckets, KMS keys, IAM users, and the account node are all
    // global, non-VPC-scoped, so they share the same right-hand
    // column — the cursor simply continues downward across all four
    // types. The account node isn't really a "resource" the way a
    // bucket, key, or user is, but it renders the same way: one more
    // box in this column.
    const globalResources = topology.nodes.filter(
        n => n.type === "s3_bucket" || n.type === "kms_key"
          || n.type === "iam_user" || n.type === "account"
    );
    for (const resource of globalResources) {
        layouts[resource.id] = {
            x: rightEdge + LAYOUT.bucket.leftPad,
            y: bucketY,
            width: LAYOUT.bucket.width,
            height: LAYOUT.bucket.height,
        };
        bucketY += LAYOUT.bucket.height + LAYOUT.bucket.gap;
    }

    return layouts;
}

function layoutVpcAndChildren(vpc, byParent, layouts, x) {
    const subnets = (byParent[vpc.id] || []).filter(n => n.type === "subnet");
    const orderedSubnets = subnets.slice().sort((a, b) => {
        if (a.properties.tier === "public") return -1;
        if (b.properties.tier === "public") return 1;
        return a.id.localeCompare(b.id);
    });

    const vpcInnerPaddingTop = LAYOUT.vpc.padding;
    const vpcInnerPaddingSides = 30;
    const subnetWidth = LAYOUT.vpc.width - vpcInnerPaddingSides * 2;

    let subnetY = LAYOUT.vpc.startY + vpcInnerPaddingTop;
    for (const subnet of orderedSubnets) {
        layouts[subnet.id] = {
            x: x + vpcInnerPaddingSides,
            y: subnetY,
            width: subnetWidth,
            height: LAYOUT.subnet.height,
        };
        layoutResourcesInSubnet(subnet, byParent, layouts);
        subnetY += LAYOUT.subnet.height + LAYOUT.subnet.gap;
    }

    const totalSubnetHeight = orderedSubnets.length * LAYOUT.subnet.height
                              + Math.max(0, orderedSubnets.length - 1) * LAYOUT.subnet.gap;
    const vpcHeight = vpcInnerPaddingTop + totalSubnetHeight + LAYOUT.vpc.padding;

    layouts[vpc.id] = {
        x: x,
        y: LAYOUT.vpc.startY,
        width: LAYOUT.vpc.width,
        height: vpcHeight,
    };
    return layouts[vpc.id];
}

function layoutResourcesInSubnet(subnet, byParent, layouts) {
    const resources = (byParent[subnet.id] || []).filter(
        n => n.type === "ec2_instance" || n.type === "rds_instance"
    );
    if (resources.length === 0) return;

    const subnetLayout = layouts[subnet.id];
    const totalWidth = resources.length * LAYOUT.resource.width
                       + Math.max(0, resources.length - 1) * LAYOUT.resource.gap;
    const startX = subnetLayout.x + (subnetLayout.width - totalWidth) / 2;
    const y = subnetLayout.y + subnetLayout.height / 2 - LAYOUT.resource.height / 2 + 12;

    let cursorX = startX;
    for (const resource of resources) {
        layouts[resource.id] = {
            x: cursorX,
            y: y,
            width: LAYOUT.resource.width,
            height: LAYOUT.resource.height,
        };
        cursorX += LAYOUT.resource.width + LAYOUT.resource.gap;
    }
}


// ---- Rendering ----

function renderTopology(map, topology) {
    const layouts = computeLayout(topology);

    const renderOrder = ["vpc", "subnet", "internet_gateway", "ec2_instance", "rds_instance", "s3_bucket", "kms_key", "iam_user", "account"];
    for (const type of renderOrder) {
        for (const node of topology.nodes.filter(n => n.type === type)) {
            renderNode(map, node, layouts[node.id], layouts);
        }
    }

    fitMapToContent(map, layouts);
}

function renderNode(map, node, layout, allLayouts) {
    if (!layout) return;

    const rect = L.rectangle(boundsFromScreen(layout), {
        className: nodeClassName(node),
        interactive: true,
    }).addTo(map);

    rect.on("click", () => showDetails(node));

    if (node.type === "internet_gateway" && node.parent_id) {
        const parent = allLayouts[node.parent_id];
        if (parent) drawIgwConnector(map, layout, parent);
    }

    L.marker(centreFromScreen(node, layout), {
        icon: L.divIcon({
            className: "node-label " + labelClassName(node),
            html: nodeLabelHtml(node),
            iconSize: [layout.width, 30],
            iconAnchor: [layout.width / 2, 15],
        }),
        interactive: false,
        keyboard: false,
    }).addTo(map);
}

function drawIgwConnector(map, igwLayout, vpcLayout) {
    const fromX = igwLayout.x + igwLayout.width / 2;
    const fromY = igwLayout.y + igwLayout.height;
    const toX   = vpcLayout.x + vpcLayout.width / 2;
    const toY   = vpcLayout.y;

    L.polyline(
        [[-fromY, fromX], [-toY, toX]],
        { className: "topo-connector", interactive: false }
    ).addTo(map);
}

function nodeClassName(node) {
    let cls = "topo-node node-" + node.type;
    if (node.type === "subnet") {
        cls += " node-subnet-" + (node.properties.tier === "public" ? "public" : "private");
    }
    if (hasFindings(node)) {
        cls += " node-misconfigured";
    }
    return cls;
}

function labelClassName(node) {
    if (node.type === "vpc" || node.type === "subnet") return "label-container";
    if (hasFindings(node)) return "label-resource label-misconfig";
    return "label-resource";
}

function nodeLabelHtml(node) {
    const iconClass = iconForType(node);
    const iconHtml = iconClass ? `<i class="ti ${iconClass}"></i>` : "";
    // Leaflet's divIcon sets this string as innerHTML directly, so
    // every value from node data -- live-scanned OR loaded from a
    // file -- must be escaped here, same as everywhere else in this
    // file that builds HTML from resource data.
    const name = escapeHtml(node.name);

    switch (node.type) {
        case "vpc":
            return `VPC · ${name} · ${escapeHtml(node.properties.cidr_block)}`;
        case "subnet":
            return `${node.properties.tier === "public" ? "Public" : "Private"} subnet · ${escapeHtml(node.properties.cidr_block)}`;
        case "internet_gateway":
            return `${iconHtml}<span>Internet gateway</span>`;
        case "ec2_instance":
            return `${iconHtml}<span>${name} · ${escapeHtml(node.properties.instance_type || "")}</span>`;
        case "rds_instance":
            return `${iconHtml}<span>${name} · ${escapeHtml(node.properties.engine)}</span>`;
        case "s3_bucket":
            return `${iconHtml}<span>${name}</span>`;
        case "kms_key":
            return `${iconHtml}<span>${name}</span>`;
        case "account":
            return `${iconHtml}<span>${name}</span>`;
        case "iam_user":
            return `${iconHtml}<span>${name}</span>`;
        default:
            return name;
    }
}

function iconForType(node) {
    switch (node.type) {
        case "internet_gateway": return "ti-world";
        case "ec2_instance":     return "ti-server";
        case "rds_instance":     return "ti-database";
        case "s3_bucket":        return hasFindings(node) ? "ti-alert-triangle" : "ti-bucket";
        case "kms_key":          return hasFindings(node) ? "ti-alert-triangle" : "ti-key";
        case "account":          return hasFindings(node) ? "ti-alert-triangle" : "ti-shield";
        case "iam_user":         return hasFindings(node) ? "ti-alert-triangle" : "ti-user";
        default:                 return null;
    }
}


// ---- Findings lookup helpers ----

function findingsForResource(resourceId) {
    return FINDINGS.filter(f => f.resource_id === resourceId);
}

function hasFindings(node) {
    return findingsForResource(node.id).length > 0;
}


// ---- Layout math helpers ----

function groupByParent(nodes) {
    const map = {};
    for (const n of nodes) {
        const key = n.parent_id || "__root__";
        (map[key] = map[key] || []).push(n);
    }
    return map;
}

function rightmostEdge(layouts) {
    let max = 0;
    for (const id in layouts) {
        const l = layouts[id];
        if (l.x + l.width > max) max = l.x + l.width;
    }
    return max;
}

function boundsFromScreen(layout) {
    const sw = [-layout.y - layout.height, layout.x];
    const ne = [-layout.y,                 layout.x + layout.width];
    return [sw, ne];
}

function centreFromScreen(node, layout) {
    if (node.type === "vpc" || node.type === "subnet") {
        return [-(layout.y + 14), layout.x + layout.width / 2];
    }
    return [-(layout.y + layout.height / 2), layout.x + layout.width / 2];
}

function fitMapToContent(map, layouts) {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const id in layouts) {
        const l = layouts[id];
        if (l.x < minX) minX = l.x;
        if (l.y < minY) minY = l.y;
        if (l.x + l.width > maxX) maxX = l.x + l.width;
        if (l.y + l.height > maxY) maxY = l.y + l.height;
    }
    const padding = 50;
    map.fitBounds([
        [-maxY - padding, minX - padding],
        [-minY + padding, maxX + padding],
    ]);
}

function updateStatus(topology) {
    const total = topology.nodes.length;
    const findingCount = FINDINGS.length;
    const findingText = findingCount === 0
        ? "no findings"
        : `${findingCount} finding${findingCount === 1 ? "" : "s"}`;
    const statusEl = document.getElementById("status");

    // textContent, not innerHTML, below -- the browser never
    // interprets this as markup, so values from a URL or a loaded
    // file need no escaping here.
    if (LOADED_SNAPSHOT_META) {
        const when = LOADED_SNAPSHOT_META.generated_at
            ? new Date(LOADED_SNAPSHOT_META.generated_at).toLocaleString()
            : "unknown time";
        const scopeText = LOADED_SNAPSHOT_META.project_tag
            ? ` · scoped to ${LOADED_SNAPSHOT_META.project_tag}`
            : "";
        statusEl.textContent =
            `Archived report · generated ${when} · ${total} resources · ${findingText}${scopeText}`;
    } else {
        const scopeText = PROJECT_TAG ? ` · scoped to ${PROJECT_TAG}` : "";
        statusEl.textContent = `${total} resources · ${findingText}${scopeText}`;
    }
    statusEl.classList.add("status-loaded");
}


// ---- Details panel ----

function showDetails(node) {
    openDetailsPanel(buildDetailsHtml(node));
}

// Shared by showDetails() (Assets: a topology node) and
// showFindingDetails() (Findings: a single finding row, findings.js)
// -- the slide-in panel itself doesn't care what kind of content it's
// showing, only the two callers know how to build that content.
function openDetailsPanel(html) {
    const panel   = document.getElementById("details-panel");
    const content = document.getElementById("details-content");
    content.innerHTML = html;
    panel.classList.add("details-open");
    panel.setAttribute("aria-hidden", "false");
}

function hideDetails() {
    const panel = document.getElementById("details-panel");
    panel.classList.remove("details-open");
    panel.setAttribute("aria-hidden", "true");
}

function buildDetailsHtml(node) {
    const parts = [];

    parts.push(`<div class="details-header">`);
    parts.push(`<h2 class="details-name">${escapeHtml(node.name)}</h2>`);
    parts.push(`<div class="details-type">${escapeHtml(humanType(node))}</div>`);
    parts.push(`</div>`);

    parts.push(`<div class="details-section-title">Properties</div>`);
    parts.push(buildPropertiesHtml(node));

    // Real findings from the backend scanner, populated at init.
    // If the node has any findings, render one card per finding.
    const findings = findingsForResource(node.id);
    if (findings.length > 0) {
        parts.push(`<div class="details-section-title">Findings (${findings.length})</div>`);
        parts.push(buildFindingsHtml(findings));
    }

    return parts.join("");
}

function buildPropertiesHtml(node) {
    const props = node.properties || {};
    const rows  = [propertyRow("Resource ID", node.id, false)];

    for (const key in props) {
        const value = props[key];
        // access_keys is a list of {access_key_id, status, create_date}
        // objects, not a scalar — it needs its own row per key rather
        // than the generic single-value row every other property gets.
        if (key === "access_keys") {
            rows.push(...buildAccessKeyRows(value));
            continue;
        }
        const isBad = isBadProperty(key, value);
        rows.push(propertyRow(humanKey(key), formatValue(value), isBad));
    }
    return rows.join("");
}

function buildAccessKeyRows(accessKeys) {
    if (!accessKeys || accessKeys.length === 0) {
        return [propertyRow("Access keys", "(none)", false)];
    }
    return accessKeys.map(key => {
        const label = `Access key ${key.access_key_id || "(unknown)"}`;
        const isBad = isActiveKeyOlderThan90Days(key);
        const value = `${key.status || "unknown"}, created ${formatValue(key.create_date)}`;
        return propertyRow(label, value, isBad);
    });
}

function isActiveKeyOlderThan90Days(key) {
    if (key.status !== "Active") return false;
    const created = key.create_date ? new Date(key.create_date) : null;
    if (!created || isNaN(created.getTime())) return true; // fail closed
    const ageMs = Date.now() - created.getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    return ageDays > 90;
}

function propertyRow(key, value, isBad) {
    const cls = isBad ? "value value-bad" : "value";
    return `<div class="details-property">`
         + `<span class="key">${escapeHtml(key)}</span>`
         + `<span class="${cls}">${escapeHtml(value)}</span>`
         + `</div>`;
}


// ---- Findings rendering ----

function buildFindingsHtml(findings) {
    return findings.map(renderFindingCard).join("");
}

function renderFindingCard(finding) {
    const grouped = groupFrameworkRefs(finding.framework_references);
    return `
        <div class="finding-card finding-card-${escapeHtml(finding.severity)}">
            <div class="finding-header">
                <div class="finding-title">${escapeHtml(finding.title)}</div>
                <span class="finding-severity finding-severity-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
            </div>
            ${finding.risk_accepted ? renderRiskAcceptedBadge(finding.risk_acceptance) : ""}
            <div class="finding-description">${escapeHtml(finding.description)}</div>
            <div class="finding-section-title">Remediation</div>
            <div class="finding-remediation">${escapeHtml(finding.remediation)}</div>
            <div class="finding-section-title">Framework references</div>
            <div class="finding-frameworks">${renderFrameworkRefs(grouped)}</div>
        </div>
    `;
}

function renderRiskAcceptedBadge(riskAcceptance) {
    const ra = riskAcceptance || {};
    const acceptedBy = ra.accepted_by ? escapeHtml(ra.accepted_by) : "unspecified";
    const acceptedDate = ra.accepted_date ? escapeHtml(ra.accepted_date) : "unspecified";
    const expires = ra.expires ? escapeHtml(ra.expires) : "indefinite";
    const reason = ra.reason ? escapeHtml(ra.reason) : "";
    return `
        <div class="finding-risk-accepted">
            <span class="finding-risk-accepted-badge">Risk accepted</span>
            <div class="finding-risk-accepted-detail">
                Accepted by ${acceptedBy} on ${acceptedDate} &middot; expires ${expires}
                ${reason ? `<br>${reason}` : ""}
            </div>
        </div>
    `;
}

function groupFrameworkRefs(refs) {
    const groups = {};
    for (const r of refs) {
        if (!groups[r.framework]) groups[r.framework] = [];
        groups[r.framework].push(r);
    }
    return groups;
}

function renderFrameworkRefs(groups) {
    const parts = [];
    for (const key of FRAMEWORK_ORDER) {
        if (!groups[key]) continue;
        const label = frameworkShortLabel(key, FRAMEWORK_LABELS[key]);
        parts.push(`<div class="framework-group">`);
        parts.push(`<div class="framework-name">${escapeHtml(label)}</div>`);
        for (const ref of groups[key]) {
            parts.push(`<div class="framework-ref">`
                + `<span class="framework-ref-id">${escapeHtml(ref.reference_id)}</span>`
                + `<span class="framework-ref-label">${escapeHtml(ref.label)}</span>`
                + `</div>`);
        }
        parts.push(`</div>`);
    }
    return parts.join("");
}

// Looks up the confidential framework's real display name from
// COMPLIANCE_CACHE (compliance.js, populated once the Compliance tab
// has been visited, or immediately when a report file is loaded via
// loadSnapshotFile) instead of the generic default here -- same
// dynamic-label mechanism as compliance.js's score cards. Falls back
// to the hardcoded default when compliance data hasn't loaded yet.
function frameworkShortLabel(key, fallback) {
    const fw = COMPLIANCE_CACHE
        && COMPLIANCE_CACHE.frameworks.find(f => f.framework === key);
    return (fw && fw.framework_short_name) || fallback;
}


// ---- Display formatting helpers ----

function humanType(node) {
    switch (node.type) {
        case "vpc":              return "Virtual Private Cloud";
        case "subnet":           return `${node.properties.tier === "public" ? "Public" : "Private"} subnet`;
        case "internet_gateway": return "Internet Gateway";
        case "ec2_instance":     return "EC2 Instance";
        case "rds_instance":     return "RDS Instance";
        case "s3_bucket":        return "S3 Bucket";
        case "kms_key":          return "KMS Key";
        case "account":          return "AWS Account";
        case "iam_user":         return "IAM User";
        default:                 return node.type;
    }
}

function humanKey(key) {
    return key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function formatValue(value) {
    if (value === null || value === undefined) return "—";
    if (Array.isArray(value)) return value.length === 0 ? "(none)" : value.join(", ");
    if (typeof value === "boolean") return value ? "true" : "false";
    return String(value);
}

function isBadProperty(key, value) {
    if (key === "is_public_via_acl" && value === true) return true;
    if (key === "is_public_via_authenticated_users_acl" && value === true) return true;
    if (key === "public_access_block_fully_enabled" && value === false) return true;
    if (key === "encryption_enabled" && value === false) return true;
    if (key === "encryption_algorithm" && value === "AES256") return true;
    if (key === "versioning_enabled" && value === false) return true;
    if (key === "logging_enabled" && value === false) return true;
    if (key === "lifecycle_configured" && value === false) return true;
    if (key === "lifecycle_rule_enabled" && value === false) return true;
    if (key === "tls_enforced" && value === false) return true;
    if (key === "key_rotation_enabled" && value === false) return true;
    if (key === "key_state" && value === "PendingDeletion") return true;
    if (key === "key_policy_overly_broad" && value === true) return true;
    if (key === "root_access_keys_present" && value === true) return true;
    if (key === "has_console_login" && value === true) return true;
    if (key === "has_admin_policy_attached" && value === true) return true;
    if (key === "has_wildcard_action_resource_policy" && value === true) return true;
    if (key === "account_mfa_enabled" && value === false) return true;
    if (key === "password_policy_min_length" && (value === null || value < 14)) return true;
    if (key === "cloudtrail_logging_enabled" && value === false) return true;
    if (key === "account_s3_block_public_access_enabled" && value === false) return true;
    if (key === "publicly_accessible" && value === true) return true;
    if (key === "has_any_tags" && value === false) return true;
    return false;
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}