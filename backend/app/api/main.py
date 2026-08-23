"""
FastAPI application entry point.

Exposes the tool's data over HTTP:
    GET /api/topology  -> the normalised AWS topology
    GET /api/findings  -> security findings from the scanner

The frontend fetches from these endpoints instead of reading static
JSON files off disk. Same data, real client-server architecture.

Design notes:

- Endpoints reuse existing library code — normalize() and
  scan_s3_buckets() — and add no business logic of their own. This
  file is an HTTP wrapper. Every rule, every mapping, every schema
  decision still lives where it did before.

- CORS is configured to allow the Live Server frontend origin. In
  production this list would be tighter and driven by config; for
  local dev it's fine to allow both loopback aliases on port 5500.

- Endpoints re-read the mock AWS data on every request. Fast enough
  at this scale (< 5ms) that caching adds complexity without
  meaningful gain. In Phase 6 the mock read is replaced with real
  boto3 calls — the endpoint contract stays the same.

- ConfidentialClient's control catalogue (confidential_controls.json) is
  client-confidential and is not committed to this repo. _scan_all()
  strips its framework references from findings, and
  build_compliance_view() omits its dashboard section entirely,
  unless project_tag is explicitly "Project=ConfidentialClient". The
  mapping file also simply won't exist wherever it wasn't placed
  locally — app.mappings.loader skips a missing mapping file rather
  than crashing, so this degrades safely in any environment.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from app.aws_normalizer import (
    normalize,
    get_tagged_resource_arns,
    filter_topology_by_tag,
)
from app.models.finding import Finding, finding_to_dict
from app.scanners.s3_scanner import scan_s3_buckets
from app.scanners.kms_scanner import scan_kms_keys
from app.scanners.iam_scanner import scan_iam
from app.scanners.account_scanner import scan_account
from app.compliance import build_compliance_view
from fastapi.responses import Response

from app.reports.pdf_report import build_pdf_report
import os
from app.evidence.builder import build_evidence_record
from app.api.auth import require_api_key


app = FastAPI(
    title="Cloud Resilience Visualizer API",
    description=(
        "Reads AWS configuration, normalises it into a topology "
        "graph, scans for misconfigurations, and returns both over "
        "HTTP."
    ),
    version="0.1.0",
)

@app.get("/api/health")
def health_check() -> dict:
    """
    Liveness check — no auth required.
    Load balancers and monitoring tools use this to verify the
    server is up without needing an API key.
    """
    return {"status": "ok", "version": "0.1.0"}

# CORS middleware: browsers block cross-origin fetch requests by
# default (frontend on :5500 -> backend on :8000 counts as
# "cross-origin"). This tells the browser the Live Server frontend
# is allowed to call us. Both 127.0.0.1 and localhost are listed
# because different browsers use different defaults for loopback.
app.add_middleware(
    CORSMiddleware,
   allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:5501",
        "http://localhost:5501",
        "https://josephademola.github.io",
    ],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# Path to the mock AWS data. In Phase 6 this read is replaced with
# real boto3 API calls; the shape of what the normaliser consumes
# stays identical.
_MOCK_PATH = Path(__file__).parent.parent / "data" / "mock_aws.json"


def _load_aws_data(project_tag: str | None = None) -> dict:
    """
    Load AWS data from the configured source.

    USE_LIVE_AWS=true -> real AWS via boto3
    otherwise         -> mock_aws.json

    project_tag (Phase 9a Feature 1, e.g. "Project=ConfidentialClient") is
    passed through to fetch_aws_data() in live mode, which queries
    the Resource Groups Tagging API for it. mock_aws.json's
    resourcegroupstaggingapi section is static regardless of what was
    asked for — the tag-matching in get_tagged_resource_arns() still
    filters correctly against whatever project_tag was actually
    requested, so an unrelated tag correctly yields no matches even
    in mock mode.
    """
    if os.environ.get("USE_LIVE_AWS") == "true":
        from app.aws_client import fetch_aws_data
        return fetch_aws_data(project_tag)

    with open(_MOCK_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _get_topology(project_tag: str | None = None) -> dict:
    """
    Load raw AWS data, normalise it, and apply tag-based scoping if
    project_tag is given (Phase 9a Feature 1). Centralises the
    raw-load + normalise + filter sequence every endpoint below needs.
    """
    raw = _load_aws_data(project_tag)
    topology = normalize(raw)
    if project_tag:
        tag_key, _, tag_value = project_tag.partition("=")
        tagged_arns = get_tagged_resource_arns(raw, tag_key, tag_value)
        topology = filter_topology_by_tag(topology, tagged_arns)
    return topology


def _is_confidential_scope(project_tag: str | None) -> bool:
    """True only when the scan is explicitly scoped to ConfidentialClient."""
    if not project_tag:
        return False
    _, _, tag_value = project_tag.partition("=")
    return tag_value == "ConfidentialClient"


def _scan_all(topology: dict, project_tag: str | None = None) -> list[Finding]:
    """
    Run every scanner against the topology and combine their findings.

    Each scanner only looks at the node types it knows about (S3
    buckets, KMS keys, ...), so calling all of them against the same
    topology is safe — order here is scanner-registration order, not
    resource order, and determines nothing about correctness.

    ConfidentialClient's control catalogue is client-confidential: its
    framework references are stripped from every finding unless the
    scan is explicitly scoped to Project=ConfidentialClient. An unscoped
    scan, or one scoped to a different tagged project, must never
    surface another client's internal control mappings.
    """
    findings = (
        scan_s3_buckets(topology)
        + scan_kms_keys(topology)
        + scan_iam(topology)
        + scan_account(topology)
    )

    if _is_confidential_scope(project_tag):
        return findings

    return [
        dataclasses.replace(
            f,
            framework_references=tuple(
                r for r in f.framework_references if r.framework != "confidential"
            ),
        )
        for f in findings
    ]

_PROJECT_TAG_QUERY = Query(
    None,
    description=(
        'Optional "Key=Value" tag filter (Phase 9a Feature 1), e.g. '
        '"Project=ConfidentialClient". Scopes the scan to resources '
        "carrying that tag, plus account-wide findings, which always "
        "apply regardless of scope."
    ),
)


@app.get("/api/topology", dependencies=[Depends(require_api_key)])
def get_topology(project_tag: str | None = _PROJECT_TAG_QUERY) -> dict:
    """Return the normalised AWS topology."""
    return _get_topology(project_tag)


@app.get("/api/findings", dependencies=[Depends(require_api_key)])
def get_findings(project_tag: str | None = _PROJECT_TAG_QUERY) -> dict:
    """Return security findings from the scanner."""
    topology = _get_topology(project_tag)
    findings = _scan_all(topology, project_tag)
    return {
        "metadata": {
            "schema_version": "1.0",
            "finding_count": len(findings),
        },
        "findings": [finding_to_dict(f) for f in findings],
    }

@app.get("/api/compliance", dependencies=[Depends(require_api_key)])
def get_compliance(project_tag: str | None = _PROJECT_TAG_QUERY) -> dict:
    """Return compliance view — findings grouped by framework requirement."""
    topology = _get_topology(project_tag)
    findings = _scan_all(topology, project_tag)
    return build_compliance_view(
        findings, include_confidential=_is_confidential_scope(project_tag)
    )

@app.get("/api/report", dependencies=[Depends(require_api_key)])
def get_report(project_tag: str | None = _PROJECT_TAG_QUERY) -> Response:
    """
    Generate and return the PDF audit report.

    Returns raw PDF bytes with Content-Disposition set to attachment,
    which tells the browser to download rather than display inline.
    """
    topology = _get_topology(project_tag)
    findings = _scan_all(topology, project_tag)
    compliance = build_compliance_view(
        findings, include_confidential=_is_confidential_scope(project_tag)
    )
    pdf_bytes = build_pdf_report(topology, findings, compliance)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="cloud-resilience-report.pdf"',
        },
    )

@app.get("/api/evidence", dependencies=[Depends(require_api_key)])
def get_evidence(project_tag: str | None = _PROJECT_TAG_QUERY) -> dict:
    """
    Return an audit evidence record for the most recent scan.

    The record contains a SHA-256 hash of the input topology (so
    auditors can verify the scan ran against unmodified data), a
    summary of findings by severity, tool version, timestamp, and
    an integrity hash covering the full record. Any post-hoc
    modification of the record would produce a different hash.

    project_tag (Phase 9a Feature 4) scopes the scan the same way it
    does on the other endpoints, and is additionally recorded in the
    evidence record's scope section, so a stored evidence bundle
    self-documents which project it covered.
    """
    import os
    topology = _get_topology(project_tag)
    findings = _scan_all(topology, project_tag)

    # In live mode, fetch the real IAM identity so the record
    # shows which account and user ran the scan.
    if os.environ.get("USE_LIVE_AWS") == "true":
        try:
            import boto3
            sts = boto3.client("sts")
            iam_identity = sts.get_caller_identity()["Arn"]
        except Exception:
            iam_identity = "unknown"
        data_source = "live"
    else:
        iam_identity = "mock-mode"
        data_source = "mock"

    return build_evidence_record(
        topology,
        findings,
        iam_identity=iam_identity,
        data_source=data_source,
        project_tag=project_tag,
    )