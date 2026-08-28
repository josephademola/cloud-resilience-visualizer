"""
Scheduled compliance audit runner.

Runs the same scan-and-scope pipeline as GET /api/evidence, but
in-process — no FastAPI, no HTTP server, no API key. Designed to run
inside a scheduled GitHub Actions job against real AWS via OIDC
credentials, and write two JSON files for a later workflow step to
upload to a private S3 bucket:

  - The evidence record (hash-verified audit/chain-of-custody proof —
    counts and a hash, not full data, by design; see
    docs/design_decisions.md #7). Unchanged by this script's second
    output below.
  - A full snapshot (topology + full findings + compliance view, the
    same shapes /api/topology, /api/findings, /api/compliance return)
    for the frontend's "Load report file" feature to render visually
    later, entirely client-side, without needing a live backend or
    AWS credentials in the browser. This is additive -- the evidence
    record's own contract/shape is untouched.

Deliberately prints nothing about the scan's actual RESULTS (finding
counts, severities) to stdout — this repo is public, and its GitHub
Actions logs are visible on that public surface. A real client's
security posture must never be inferable from a log line, even a
coarse summary. Only the two output files (uploaded straight to
private S3, never to a GitHub artifact) carry that data.

Reuses app.api.main's scope-gating logic (_get_topology, _scan_all)
directly rather than re-implementing it, so a future change to how
scoping or the confidential framework works only needs to happen in
one place.

Required environment:
    AWS credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
        AWS_SESSION_TOKEN) — supplied by aws-actions/configure-aws-credentials
        via OIDC when run in CI.
    AUDIT_PROJECT_TAG   -- "Key=Value" tag to scope the scan to, e.g.
                           "Project=<tag-value>". Required — this script
                           always scans a specific tagged project, never
                           a whole account.

Optional environment:
    AUDIT_OUTPUT_PATH    -- where to write the evidence JSON.
                            Defaults to "evidence-report.json".
    SNAPSHOT_OUTPUT_PATH -- where to write the full snapshot JSON.
                            Defaults to "full-snapshot.json".
    CONFIDENTIAL_PROJECT_TAG -- passed through to app.api.main's
                           _is_confidential_scope() so a scan correctly
                           scoped to the confidential client's project
                           also includes that framework's references.
                           See docs/design_decisions.md #11.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("USE_LIVE_AWS", "true")

from app.api.main import (  # noqa: E402
    _get_iam_identity_and_data_source,
    _get_topology,
    _is_confidential_scope,
    _scan_all,
)
from app.compliance import build_compliance_view  # noqa: E402
from app.evidence.builder import build_evidence_record  # noqa: E402
from app.models.finding import finding_to_dict  # noqa: E402


def main() -> None:
    project_tag = os.environ.get("AUDIT_PROJECT_TAG")
    if not project_tag:
        raise SystemExit(
            "AUDIT_PROJECT_TAG environment variable is required, e.g. "
            '"Project=<tag-value>"'
        )

    topology = _get_topology(project_tag)
    findings = _scan_all(topology, project_tag)
    iam_identity, data_source = _get_iam_identity_and_data_source()

    record = build_evidence_record(
        topology,
        findings,
        iam_identity=iam_identity,
        data_source=data_source,
        project_tag=project_tag,
    )

    output_path = Path(os.environ.get("AUDIT_OUTPUT_PATH", "evidence-report.json"))
    output_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

    confidential_scope = _is_confidential_scope(project_tag)
    mapping_path = (
        Path(__file__).resolve().parent.parent
        / "app" / "mappings" / "confidential_controls.json"
    )
    # Diagnostic only -- a boolean and a file-existence check, neither
    # of which reveals the actual tag value, secret contents, or any
    # finding. Safe for the public workflow log.
    print(
        f"Confidential scope matched: {confidential_scope} | "
        f"confidential_controls.json present: {mapping_path.exists()}"
    )

    compliance = build_compliance_view(
        findings, include_confidential=confidential_scope
    )
    snapshot = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_tag": project_tag,
        "topology": topology,
        "findings": {
            "metadata": {
                "schema_version": "1.0",
                "finding_count": len(findings),
            },
            "findings": [finding_to_dict(f) for f in findings],
        },
        "compliance": compliance,
    }
    snapshot_path = Path(
        os.environ.get("SNAPSHOT_OUTPUT_PATH", "full-snapshot.json")
    )
    snapshot_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    # Deliberately no finding counts/severities here -- this print
    # goes to a public GitHub Actions log. The full data only ever
    # goes to the two output files above, which the workflow uploads
    # to private S3, never to a public GitHub artifact.
    print(f"Evidence record written to {output_path}")
    print(f"Full snapshot written to {snapshot_path}")


if __name__ == "__main__":
    main()
