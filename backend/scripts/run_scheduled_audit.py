"""
Scheduled compliance audit runner.

Runs the same scan-and-scope pipeline as GET /api/evidence, but
in-process — no FastAPI, no HTTP server, no API key. Designed to run
inside a scheduled GitHub Actions job against real AWS via OIDC
credentials, and write the evidence record to a JSON file for upload
as a workflow artifact.

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

    summary = record["findings_summary"]
    print(
        f"Evidence record written to {output_path} — "
        f"{summary['total']} findings "
        f"(critical={summary['by_severity']['critical']}, "
        f"high={summary['by_severity']['high']}, "
        f"medium={summary['by_severity']['medium']}, "
        f"low={summary['by_severity']['low']})"
    )


if __name__ == "__main__":
    main()
