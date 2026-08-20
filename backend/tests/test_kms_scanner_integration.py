"""
Integration test for the KMS scanner.

Mirrors test_scanner_integration.py's structure: runs the full
scanner against the real topology.json and locks in the expected
end-to-end behaviour, including the AWS-managed-key exclusion that
happens upstream in the normalizer.
"""

from pathlib import Path
import json

from app.scanners.kms_scanner import scan_kms_keys


_TOPOLOGY_PATH = (
    Path(__file__).resolve().parent.parent / "app" / "data" / "topology.json"
)

with open(_TOPOLOGY_PATH, encoding="utf-8") as _fh:
    TOPOLOGY = json.load(_fh)

FINDINGS = scan_kms_keys(TOPOLOGY)


class TestKmsScannerEndToEnd:

    def test_produces_two_findings_against_doomed_customer_key(self):
        # The mock's customer-managed key stacks both KMS misconfigs:
        # rotation never enabled, and now scheduled for deletion. The
        # AWS-managed key never appears in the topology at all (see
        # the normalizer integration test), so it can't produce a
        # finding either.
        assert len(FINDINGS) == 2
        finding_type_ids = [f.finding_type_id for f in FINDINGS]
        assert finding_type_ids == [
            "KMS_KEY_ROTATION_DISABLED",
            "KMS_KEY_PENDING_DELETION",
        ]
        severities = {f.finding_type_id: f.severity.value for f in FINDINGS}
        assert severities["KMS_KEY_ROTATION_DISABLED"] == "high"
        assert severities["KMS_KEY_PENDING_DELETION"] == "critical"

    def test_all_findings_map_to_all_four_frameworks(self):
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
        second_run = scan_kms_keys(TOPOLOGY)
        assert FINDINGS == second_run
