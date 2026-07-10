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

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.aws_normalizer import normalize
from app.models.finding import finding_to_dict
from app.scanners.s3_scanner import scan_s3_buckets


app = FastAPI(
    title="Cloud Resilience Visualizer API",
    description=(
        "Reads AWS configuration, normalises it into a topology "
        "graph, scans for misconfigurations, and returns both over "
        "HTTP."
    ),
    version="0.1.0",
)

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
    ],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# Path to the mock AWS data. In Phase 6 this read is replaced with
# real boto3 API calls; the shape of what the normaliser consumes
# stays identical.
_MOCK_PATH = Path(__file__).parent.parent / "data" / "mock_aws.json"


def _load_mock_aws_data() -> dict:
    """Read the mock AWS data from disk. Extracted so tests can mock it."""
    with open(_MOCK_PATH, encoding="utf-8") as fh:
        return json.load(fh)


@app.get("/api/topology")
def get_topology() -> dict:
    """Return the normalised AWS topology."""
    raw = _load_mock_aws_data()
    return normalize(raw)


@app.get("/api/findings")
def get_findings() -> dict:
    """Return security findings from the scanner."""
    raw = _load_mock_aws_data()
    topology = normalize(raw)
    findings = scan_s3_buckets(topology)
    return {
        "metadata": {
            "schema_version": "1.0",
            "finding_count": len(findings),
        },
        "findings": [finding_to_dict(f) for f in findings],
    }