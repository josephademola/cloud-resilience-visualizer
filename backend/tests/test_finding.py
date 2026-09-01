"""
Unit tests for app.models.finding.

Covers the risk_acceptance field added in Phase 4 (2026-08-28) and its
serialisation via finding_to_dict -- the rest of the Finding dataclass
is exercised indirectly by every scanner's own test file already.
"""

from app.models.finding import Finding, Severity, finding_to_dict


def _finding(risk_acceptance: dict | None = None) -> Finding:
    return Finding(
        finding_type_id="S3_PUBLIC_VIA_ACL",
        title="Test finding",
        severity=Severity.CRITICAL,
        resource_id="test-bucket",
        description="test",
        remediation="test",
        risk_acceptance=risk_acceptance,
    )


class TestRiskAcceptanceField:

    def test_defaults_to_none(self):
        assert _finding().risk_acceptance is None

    def test_can_be_set_at_construction(self):
        acceptance = {"reason": "accepted", "accepted_by": "Jane Doe"}
        finding = _finding(risk_acceptance=acceptance)
        assert finding.risk_acceptance == acceptance


class TestFindingToDict:

    def test_risk_accepted_is_false_and_acceptance_is_none_by_default(self):
        result = finding_to_dict(_finding())
        assert result["risk_accepted"] is False
        assert result["risk_acceptance"] is None

    def test_risk_accepted_is_true_when_acceptance_present(self):
        acceptance = {
            "reason": "Bucket being decommissioned",
            "accepted_by": "Jane Doe",
            "accepted_date": "2026-01-01",
            "expires": None,
        }
        result = finding_to_dict(_finding(risk_acceptance=acceptance))
        assert result["risk_accepted"] is True
        assert result["risk_acceptance"] == acceptance
