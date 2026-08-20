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

    def test_produces_one_finding_against_unrotated_customer_key(self):
        # The mock's customer-managed key has rotation disabled. The
        # AWS-managed key never appears in the topology at all (see
        # the normalizer integration test), so it can't produce a
        # finding either.
        assert len(FINDINGS) == 1
        assert FINDINGS[0].finding_type_id == "KMS_KEY_ROTATION_DISABLED"
        assert FINDINGS[0].severity.value == "high"

    def test_finding_maps_to_all_four_frameworks(self):
        expected_frameworks = {
            "nis2",
            "ncsc_caf",
            "mitre_attack",
            "cyber_essentials",
        }
        frameworks_present = {
            r.framework for r in FINDINGS[0].framework_references
        }
        assert frameworks_present == expected_frameworks

    def test_findings_are_deterministic(self):
        second_run = scan_kms_keys(TOPOLOGY)
        assert FINDINGS == second_run
