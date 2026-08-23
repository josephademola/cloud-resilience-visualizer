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

    def test_produces_two_findings_against_misconfigured_account(self):
        # The mock has no CloudTrail trail configured and no
        # account-level S3 Public Access Block configured.
        assert len(FINDINGS) == 2
        finding_type_ids = [f.finding_type_id for f in FINDINGS]
        assert finding_type_ids == [
            "ACCOUNT_CLOUDTRAIL_DISABLED",
            "ACCOUNT_S3_BLOCK_PUBLIC_ACCESS_DISABLED",
        ]
        assert all(f.resource_id == "123456789012" for f in FINDINGS)
        severities = {f.finding_type_id: f.severity.value for f in FINDINGS}
        assert severities["ACCOUNT_CLOUDTRAIL_DISABLED"] == "critical"
        assert severities["ACCOUNT_S3_BLOCK_PUBLIC_ACCESS_DISABLED"] == "high"

    def test_all_findings_map_to_all_six_public_frameworks(self):
        # Subset check, not exact equality: confidential_controls.json
        # is gitignored and only present on machines where it was
        # placed locally (docs/design_decisions.md #11), so whether
        # "confidential" is ALSO present is environment-dependent.
        # These scanner functions are called directly here, bypassing
        # main.py's scope-gating entirely -- that confidentiality
        # guarantee is tested in test_api.py instead.
        expected_frameworks = {
            "nis2",
            "ncsc_caf",
            "mitre_attack",
            "cyber_essentials",
            "iso27001",
            "dora",
        }
        for finding in FINDINGS:
            frameworks_present = {
                r.framework for r in finding.framework_references
            }
            assert expected_frameworks.issubset(frameworks_present), (
                f"{finding.finding_type_id} missing frameworks: "
                f"{expected_frameworks - frameworks_present}"
            )

    def test_findings_are_deterministic(self):
        second_run = scan_account(TOPOLOGY)
        assert FINDINGS == second_run
