"""
Integration test for the S3 scanner.

Where the unit tests in test_s3_scanner.py exercise individual rule
functions with small hand-built bucket fixtures, this file does the
opposite: it runs the full scanner against the real topology.json
and locks in the expected end-to-end behaviour.

If a mapping file loses an entry, or the scanner stops emitting a
finding it should be emitting, or the framework references stop
being stitched in properly — every unit test could still pass while
this integration test would catch the regression.

The topology is loaded once at module import; the scanner runs once.
All tests read from the resulting findings list; none mutate it.
"""

from pathlib import Path
import json

from app.scanners.s3_scanner import scan_s3_buckets


# Path to the topology, computed relative to this test file so the
# tests work regardless of which directory pytest is invoked from.
_TOPOLOGY_PATH = (
    Path(__file__).resolve().parent.parent / "app" / "data" / "topology.json"
)

# Load and scan once at import. Every test reads from these constants;
# none mutate them.
with open(_TOPOLOGY_PATH, encoding="utf-8") as _fh:
    TOPOLOGY = json.load(_fh)

FINDINGS = scan_s3_buckets(TOPOLOGY)


class TestScannerEndToEnd:

    def test_produces_three_findings_against_misconfigured_bucket(self):
        # The mock's 'cloudres-fintech-uploads' bucket has all three
        # S3 misconfigurations. All three rules must fire, producing
        # three findings on the same resource.
        uploads_findings = [
            f for f in FINDINGS if f.resource_id == "cloudres-fintech-uploads"
        ]
        assert len(uploads_findings) == 3
        finding_type_ids = [f.finding_type_id for f in uploads_findings]
        assert finding_type_ids == [
            "S3_PUBLIC_VIA_ACL",
            "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
            "S3_ENCRYPTION_DISABLED",
        ]

    def test_secure_bucket_produces_no_findings(self):
        # The 'cloudres-fintech-logs' bucket in the mock is fully
        # configured — no ACL grant, PAB enabled, encryption on.
        # It must produce zero findings. If this ever fails, either
        # the mock has been changed or the scanner has developed a
        # false-positive bug.
        logs_findings = [
            f for f in FINDINGS if f.resource_id == "cloudres-fintech-logs"
        ]
        assert logs_findings == []

    def test_all_findings_map_to_all_four_frameworks(self):
        # End-to-end proof that the mapping loader is stitching
        # references into every finding. If any finding has
        # references from fewer than four frameworks, something is
        # wrong: either a mapping file has lost an entry, or the
        # loader isn't combining across files correctly.
        expected_frameworks = {
            "nis2",
            "ncsc_caf",
            "mitre_attack",
            "cyber_essentials",
        }
        for finding in FINDINGS:
            frameworks_present = {
                r.framework for r in finding.framework_references
            }
            assert frameworks_present == expected_frameworks, (
                f"{finding.finding_type_id} missing frameworks: "
                f"{expected_frameworks - frameworks_present}"
            )

    def test_findings_are_deterministic(self):
        # Running the scanner twice on the same input must produce
        # identical output. Auditors need deterministic tools —
        # "the same misconfig sometimes gets flagged and sometimes
        # doesn't" would be unacceptable for compliance work.
        # Frozen dataclasses give us value equality for free.
        second_run = scan_s3_buckets(TOPOLOGY)
        assert FINDINGS == second_run