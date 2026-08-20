"""
Integration test for the IAM scanner.

Mirrors test_kms_scanner_integration.py's structure: runs the full
scanner against the real topology.json and locks in the expected
end-to-end behaviour.
"""

from pathlib import Path
import json

from app.scanners.iam_scanner import scan_iam


_TOPOLOGY_PATH = (
    Path(__file__).resolve().parent.parent / "app" / "data" / "topology.json"
)

with open(_TOPOLOGY_PATH, encoding="utf-8") as _fh:
    TOPOLOGY = json.load(_fh)

FINDINGS = scan_iam(TOPOLOGY)


class TestIamScannerEndToEnd:

    def test_produces_three_findings_against_misconfigured_account(self):
        # The mock's account has active root access keys, no MFA,
        # and no password policy. All three rules fire on the same
        # account resource.
        assert len(FINDINGS) == 3
        finding_type_ids = [f.finding_type_id for f in FINDINGS]
        assert finding_type_ids == [
            "IAM_ROOT_ACCESS_KEYS_ACTIVE",
            "IAM_ACCOUNT_MFA_NOT_ENABLED",
            "IAM_PASSWORD_POLICY_WEAK",
        ]
        assert all(f.resource_id == "123456789012" for f in FINDINGS)
        severities = {f.finding_type_id: f.severity.value for f in FINDINGS}
        assert severities["IAM_ROOT_ACCESS_KEYS_ACTIVE"] == "critical"
        assert severities["IAM_ACCOUNT_MFA_NOT_ENABLED"] == "high"
        assert severities["IAM_PASSWORD_POLICY_WEAK"] == "medium"

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
        second_run = scan_iam(TOPOLOGY)
        assert FINDINGS == second_run
