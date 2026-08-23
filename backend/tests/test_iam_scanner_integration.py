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
        # and no password policy. All three account-level rules fire
        # on the same account resource.
        account_findings = [f for f in FINDINGS if f.resource_id == "123456789012"]
        assert len(account_findings) == 3
        finding_type_ids = [f.finding_type_id for f in account_findings]
        assert finding_type_ids == [
            "IAM_ROOT_ACCESS_KEYS_ACTIVE",
            "IAM_ACCOUNT_MFA_NOT_ENABLED",
            "IAM_PASSWORD_POLICY_WEAK",
        ]
        severities = {f.finding_type_id: f.severity.value for f in account_findings}
        assert severities["IAM_ROOT_ACCESS_KEYS_ACTIVE"] == "critical"
        assert severities["IAM_ACCOUNT_MFA_NOT_ENABLED"] == "high"
        assert severities["IAM_PASSWORD_POLICY_WEAK"] == "medium"

    def test_produces_one_finding_against_the_legacy_service_account(self):
        # The mock's IAM user has a single old active access key.
        user_findings = [
            f for f in FINDINGS
            if f.resource_id == "cloudres-fintech-legacy-svc-account"
        ]
        assert len(user_findings) == 1
        assert user_findings[0].finding_type_id == "IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS"
        assert user_findings[0].severity.value == "medium"

    def test_produces_four_findings_total(self):
        assert len(FINDINGS) == 4

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
        second_run = scan_iam(TOPOLOGY)
        assert FINDINGS == second_run
