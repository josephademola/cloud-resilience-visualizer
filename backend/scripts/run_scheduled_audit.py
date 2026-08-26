"""
Scheduled compliance audit runner.

Runs the same scan-and-scope pipeline as GET /api/evidence, but
in-process — no FastAPI, no HTTP server, no API key. Designed to run
inside a scheduled GitHub Actions job against real AWS via OIDC
credentials, and write the evidence record to a JSON file for a later
workflow step to upload to a private S3 bucket.

Deliberately prints nothing about the scan's actual RESULTS (finding
counts, severities) to stdout — this repo is public, and its GitHub
Actions logs are visible on that public surface. A real client's
security posture must never be inferable from a log line, even a
coarse summary. Only the evidence record file (uploaded straight to
private S3, never to a GitHub artifact) carries that data.

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
    AUDIT_OUTPUT_PATH   -- where to write the evidence JSON.
                           Defaults to "evidence-report.json".
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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("USE_LIVE_AWS", "true")

from app.api.main import (  # noqa: E402
    _get_iam_identity_and_data_source,
    _get_topology,
    _scan_all,
)
from app.evidence.builder import build_evidence_record  # noqa: E402


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

    # Deliberately no finding counts/severities here -- this print
    # goes to a public GitHub Actions log. The full record (with
    # results) only ever goes to output_path, which the workflow
    # uploads to private S3, never to a public GitHub artifact.
    print(f"Evidence record written to {output_path}")


if __name__ == "__main__":
    main()
