/* ============================================================
   Cloud Resilience Visualizer — topology rendering
   
   What this file does:
   1. Fetches the topology.json that the backend normalizer wrote.
   2. Computes (x, y) coordinates for every node based on parent-child
      containment — VPC contains subnets, subnets contain instances.
   3. Renders the shapes and labels on a Leaflet map configured with
      L.CRS.Simple, which treats the canvas as a flat XY grid rather
      than a geographic map.
   
   Coordinate convention:
   We work in screen coordinates internally (x grows rightward, y grows
   downward). Leaflet's CRS.Simple uses latLng with y growing upward,
   so we flip y when converting to Leaflet's bounds/points.
   ============================================================ */


// Layout constants — sizes and gaps for each shape type, in screen pixels.
const LAYOUT = {
    vpc:           { startX: 80,  startY: 100, width: 620, padding: 50 },
    subnet:        { height: 200, gap: 30 },
    igw:           { width: 130,  height: 36, gap: 12 },     // sits above the VPC
    resource:      { width: 150,  height: 60, gap: 24 },     // EC2 / RDS markers
    bucket:        { width: 230,  height: 70, gap: 30, leftPad: 80 },
};


// ---- Entry point ----

document.addEventListener("DOMContentLoaded", init);

async function init() {
    try {
        const topology = await fetchTopology();
        const map = createMap();
        renderTopology(map, topology);
        updateStatus(topology);
    } catch (err) {
        console.error("Failed to render topology:", err);
        document.getElementById("status").textContent = "Error loading topology — see console";
    }
}


// ---- Data loading ----

async function fetchTopology() {
    // topology.json sits next to index.html (copied there by the
    // normalizer's __main__ block). Fetched as a sibling file.
    const response = await fetch("./topology.json");
    if (!response.ok) {
        throw new Error("Fetch failed: HTTP " + response.status);
    }
    return await response.json();
}


// ---- Map initialisation ----

function createMap() {
    // L.CRS.Simple turns Leaflet from a geographic map into a flat XY
    // canvas. We disable zoom controls and attribution because they
    // belong to the world of geographic tiles.
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

    // VPCs anchor everything. With one VPC, this loop runs once.
    let cursorX = LAYOUT.vpc.startX;
    for (const vpc of topology.nodes.filter(n => n.type === "vpc")) {
        const vpcLayout = layoutVpcAndChildren(vpc, byParent, layouts, cursorX);
        cursorX += vpcLayout.width + 60;
    }

    // IGWs render above their parent VPC, centred on its top edge.
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

    // S3 buckets are global — placed to the right of all VPCs.
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

    // Lay out subnets stacked vertically inside the VPC. Public on top
    // (where the internet-facing tier lives), private below.
    const orderedSubnets = subnets.slice().sort((a, b) => {
        // public first, then private, then anything else alphabetically by id
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

    // VPC height grows to enclose all subnets plus padding above and below.
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

    // Render order matters for z-stacking: containers first so smaller
    // shapes appear on top. Leaflet renders SVG paths in DOM order.
    const renderOrder = ["vpc", "subnet", "internet_gateway", "ec2_instance", "rds_instance", "s3_bucket"];
    for (const type of renderOrder) {
        for (const node of topology.nodes.filter(n => n.type === type)) {
            renderNode(map, node, layouts[node.id]);
        }
    }

    fitMapToContent(map, layouts);
}

function renderNode(map, node, layout) {
    if (!layout) return;

    // Draw the shape itself as an SVG rectangle on the map.
    L.rectangle(boundsFromScreen(layout), {
        className: nodeClassName(node),
        interactive: false,
    }).addTo(map);

    // Draw the text/icon label on top.
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

function nodeClassName(node) {
    let cls = "topo-node node-" + node.type;
    if (node.type === "subnet") {
        cls += " node-subnet-" + (node.properties.tier === "public" ? "public" : "private");
    }
    if (isMisconfigured(node)) {
        cls += " node-misconfigured";
    }
    return cls;
}

function labelClassName(node) {
    if (node.type === "vpc" || node.type === "subnet") return "label-container";
    if (isMisconfigured(node)) return "label-resource label-misconfig";
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
        case "s3_bucket":        return isMisconfigured(node) ? "ti-alert-triangle" : "ti-bucket";
        default:                 return null;
    }
}


// ---- Helpers ----

function isMisconfigured(node) {
    if (node.type !== "s3_bucket") return false;
    const p = node.properties;
    return p.is_public_via_acl
        || !p.public_access_block_fully_enabled
        || !p.encryption_enabled;
}

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

// Convert screen-coord layout {x, y, width, height} into Leaflet
// SW/NE bounds. Y is flipped because L.CRS.Simple has y growing up.
function boundsFromScreen(layout) {
    const sw = [-layout.y - layout.height, layout.x];
    const ne = [-layout.y,                 layout.x + layout.width];
    return [sw, ne];
}

// Centre point for label markers. Containers get a label near their
// top edge; resources get one centred on the rectangle.
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
    const misconfigs = topology.nodes.filter(isMisconfigured).length;
    const findingText = misconfigs === 0
        ? "no findings"
        : `${misconfigs} misconfiguration${misconfigs === 1 ? "" : "s"}`;
    document.getElementById("status").textContent = `${total} resources · ${findingText}`;
}