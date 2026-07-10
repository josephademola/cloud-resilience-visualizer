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
const API_BASE = "http://localhost:8000";

// Module-level state, populated at init.
let FINDINGS = [];


// ---- Entry point ----

document.addEventListener("DOMContentLoaded", init);

async function init() {
    document.getElementById("details-close").addEventListener("click", hideDetails);
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") hideDetails();
    });

    try {
        // Fetch topology and findings in parallel — they're independent.
        const [topology, findings] = await Promise.all([
            fetchTopology(),
            fetchFindings(),
        ]);
        FINDINGS = findings;

        const map = createMap();
        renderTopology(map, topology);
        updateStatus(topology);
    } catch (err) {
        console.error("Failed to render topology:", err);
        document.getElementById("status").textContent =
            "Cannot reach API — is the backend server running on port 8000?";
    }
}


// ---- Data loading ----

async function fetchTopology() {
    const response = await fetch(`${API_BASE}/api/topology`);
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
        const response = await fetch(`${API_BASE}/api/findings`);
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
    for (const bucket of topology.nodes.filter(n => n.type === "s3_bucket")) {
        layouts[bucket.id] = {
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

    const renderOrder = ["vpc", "subnet", "internet_gateway", "ec2_instance", "rds_instance", "s3_bucket"];
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

    switch (node.type) {
        case "vpc":
            return `VPC · ${node.name} · ${node.properties.cidr_block}`;
        case "subnet":
            return `${node.properties.tier === "public" ? "Public" : "Private"} subnet · ${node.properties.cidr_block}`;
        case "internet_gateway":
            return `${iconHtml}<span>Internet gateway</span>`;
        case "ec2_instance":
            return `${iconHtml}<span>${node.name} · ${node.properties.instance_type || ""}</span>`;
        case "rds_instance":
            return `${iconHtml}<span>${node.name} · ${node.properties.engine}</span>`;
        case "s3_bucket":
            return `${iconHtml}<span>${node.name}</span>`;
        default:
            return node.name;
    }
}

function iconForType(node) {
    switch (node.type) {
        case "internet_gateway": return "ti-world";
        case "ec2_instance":     return "ti-server";
        case "rds_instance":     return "ti-database";
        case "s3_bucket":        return hasFindings(node) ? "ti-alert-triangle" : "ti-bucket";
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
    document.getElementById("status").textContent = `${total} resources · ${findingText}`;
}


// ---- Details panel ----

function showDetails(node) {
    const panel   = document.getElementById("details-panel");
    const content = document.getElementById("details-content");
    content.innerHTML = buildDetailsHtml(node);
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
        const isBad = isBadProperty(key, value);
        rows.push(propertyRow(humanKey(key), formatValue(value), isBad));
    }
    return rows.join("");
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
            <div class="finding-description">${escapeHtml(finding.description)}</div>
            <div class="finding-section-title">Remediation</div>
            <div class="finding-remediation">${escapeHtml(finding.remediation)}</div>
            <div class="finding-section-title">Framework references</div>
            <div class="finding-frameworks">${renderFrameworkRefs(grouped)}</div>
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
    const frameworkOrder = ["nis2", "ncsc_caf", "mitre_attack", "cyber_essentials"];
    const frameworkLabels = {
        nis2: "NIS2",
        ncsc_caf: "NCSC CAF",
        mitre_attack: "MITRE ATT&CK",
        cyber_essentials: "Cyber Essentials",
    };
    const parts = [];
    for (const key of frameworkOrder) {
        if (!groups[key]) continue;
        parts.push(`<div class="framework-group">`);
        parts.push(`<div class="framework-name">${frameworkLabels[key]}</div>`);
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


// ---- Display formatting helpers ----

function humanType(node) {
    switch (node.type) {
        case "vpc":              return "Virtual Private Cloud";
        case "subnet":           return `${node.properties.tier === "public" ? "Public" : "Private"} subnet`;
        case "internet_gateway": return "Internet Gateway";
        case "ec2_instance":     return "EC2 Instance";
        case "rds_instance":     return "RDS Instance";
        case "s3_bucket":        return "S3 Bucket";
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
    if (key === "public_access_block_fully_enabled" && value === false) return true;
    if (key === "encryption_enabled" && value === false) return true;
    if (key === "publicly_accessible" && value === true) return true;
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