"""
Integration test for the account scanner.

Mirrors test_kms_scanner_integration.py's structure: runs the full
scanner against the real topology.json and locks in the expected
end-to-end behaviour.
"""

from pathlib import Path
import json

from app.scanners.account_scanner import scan_account


_TOPOLOGY_PATH = (
    Path(__file__).resolve().parent.parent / "app" / "data" / "topology.json"
)

with open(_TOPOLOGY_PATH, encoding="utf-8") as _fh:
    TOPOLOGY = json.load(_fh)

FINDINGS = scan_account(TOPOLOGY)


class TestAccountScannerEndToEnd:

    def test_produces_one_finding_against_missing_cloudtrail(self):
        # The mock has no CloudTrail trail configured at all.
        assert len(FINDINGS) == 1
        assert FINDINGS[0].finding_type_id == "ACCOUNT_CLOUDTRAIL_DISABLED"
        assert FINDINGS[0].severity.value == "critical"
        assert FINDINGS[0].resource_id == "123456789012"

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
        second_run = scan_account(TOPOLOGY)
        assert FINDINGS == second_run
