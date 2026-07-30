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
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.aws_normalizer import normalize
from app.models.finding import finding_to_dict
from app.scanners.s3_scanner import scan_s3_buckets
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
    ],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# Path to the mock AWS data. In Phase 6 this read is replaced with
# real boto3 API calls; the shape of what the normaliser consumes
# stays identical.
_MOCK_PATH = Path(__file__).parent.parent / "data" / "mock_aws.json"


def _load_aws_data() -> dict:
    """
    Load AWS data from the configured source.

    USE_LIVE_AWS=true -> real AWS via boto3
    otherwise         -> mock_aws.json
    """
    if os.environ.get("USE_LIVE_AWS") == "true":
        from app.aws_client import fetch_aws_data
        return fetch_aws_data()

    with open(_MOCK_PATH, encoding="utf-8") as fh:
        return json.load(fh)

@app.get("/api/topology", dependencies=[Depends(require_api_key)])
def get_topology() -> dict:
    """Return the normalised AWS topology."""
    raw = _load_aws_data()
    return normalize(raw)


@app.get("/api/findings", dependencies=[Depends(require_api_key)])
def get_findings() -> dict:
    """Return security findings from the scanner."""
    raw = _load_aws_data()
    topology = normalize(raw)
    findings = scan_s3_buckets(topology)
    return {
        "metadata": {
            "schema_version": "1.0",
            "finding_count": len(findings),
        },
        "findings": [finding_to_dict(f) for f in findings],
    }

@app.get("/api/compliance", dependencies=[Depends(require_api_key)])
def get_compliance() -> dict:
    """Return compliance view — findings grouped by framework requirement."""
    raw = _load_aws_data()
    topology = normalize(raw)
    findings = scan_s3_buckets(topology)
    return build_compliance_view(findings)

@app.get("/api/report", dependencies=[Depends(require_api_key)])
def get_report() -> Response:
    """
    Generate and return the PDF audit report.

    Returns raw PDF bytes with Content-Disposition set to attachment,
    which tells the browser to download rather than display inline.
    """
    raw = _load_aws_data()
    topology = normalize(raw)
    findings = scan_s3_buckets(topology)
    compliance = build_compliance_view(findings)
    pdf_bytes = build_pdf_report(topology, findings, compliance)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="cloud-resilience-report.pdf"',
        },
    )

@app.get("/api/evidence", dependencies=[Depends(require_api_key)])
def get_evidence() -> dict:
    """
    Return an audit evidence record for the most recent scan.

    The record contains a SHA-256 hash of the input topology (so
    auditors can verify the scan ran against unmodified data), a
    summary of findings by severity, tool version, timestamp, and
    an integrity hash covering the full record. Any post-hoc
    modification of the record would produce a different hash.
    """
    import os
    raw = _load_aws_data()
    topology = normalize(raw)
    findings = scan_s3_buckets(topology)

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
    )