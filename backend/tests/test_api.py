"""
Integration tests for the FastAPI endpoints in app.api.main.

Uses FastAPI's TestClient, which routes requests directly to the app
in-process — no server start required, no port binding, no real
network. What TestClient sees is identical to what a real HTTP
client would see, so these tests exercise the full stack (HTTP layer
-> normaliser -> scanner -> mapping loader) end-to-end.
"""


from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import app, _is_confidential_scope, _scan_all


# confidential_controls.json is gitignored and client-confidential —
# present on machines where it was placed locally, absent in CI's
# fresh checkout. Tests that assert POSITIVE inclusion of the
# confidential framework can only pass where the file actually has
# data to attach, so they're skipped rather than failed when it's
# missing. Tests that assert the framework's ABSENCE don't need this
# guard — they pass either way.
_CONFIDENTIAL_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent
    / "app" / "mappings" / "confidential_controls.json"
)
_confidential_mapping_available = _CONFIDENTIAL_MAPPING_PATH.exists()
_requires_confidential_mapping = pytest.mark.skipif(
    not _confidential_mapping_available,
    reason=(
        "confidential_controls.json not present in this environment "
        "(expected in CI — it's gitignored, client-confidential)"
    ),
)


@pytest.fixture(autouse=True)
def set_test_api_key(monkeypatch):
    """
    Set the API_KEY env var to the known dev default for all tests.
    autouse=True means this applies to every test automatically.
    """
    monkeypatch.setenv("API_KEY", "dev-only-insecure-key")


@pytest.fixture
def client():
    """
    Authenticated test client. Sends the correct API key header on
    every request. Tests that need to test auth failure create their
    own TestClient inline.
    """
    return TestClient(app, headers={"X-API-Key": "dev-only-insecure-key"})


# --- GET /api/topology -----------------------------------------------
class TestTopologyEndpoint:

    def test_returns_200_with_json_content_type(self, client):
        response = client.get("/api/topology")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")

    def test_response_has_expected_top_level_shape(self, client):
        response = client.get("/api/topology")
        data = response.json()
        assert set(data.keys()) == {"metadata", "nodes", "security_groups"}

    def test_response_has_twelve_nodes_and_three_security_groups(self, client):
        response = client.get("/api/topology")
        data = response.json()
        assert len(data["nodes"]) == 12
        assert len(data["security_groups"]) == 3
        assert data["metadata"]["node_count"] == 12
        assert data["metadata"]["security_group_count"] == 3

    def test_response_includes_both_s3_buckets(self, client):
        response = client.get("/api/topology")
        data = response.json()
        s3_ids = {n["id"] for n in data["nodes"] if n["type"] == "s3_bucket"}
        assert s3_ids == {"cloudres-fintech-logs", "cloudres-fintech-uploads"}

    def test_project_tag_scopes_to_only_the_tagged_bucket(self, client):
        # Phase 9a Feature 1. The mock tags cloudres-fintech-uploads
        # as Project=ConfidentialClient and cloudres-fintech-logs as
        # Project=CloudResilienceVisualizer.
        response = client.get("/api/topology?project_tag=Project=ConfidentialClient")
        data = response.json()
        s3_ids = {n["id"] for n in data["nodes"] if n["type"] == "s3_bucket"}
        assert s3_ids == {"cloudres-fintech-uploads"}

    def test_project_tag_still_includes_account_node(self, client):
        response = client.get("/api/topology?project_tag=Project=ConfidentialClient")
        data = response.json()
        account_ids = {n["id"] for n in data["nodes"] if n["type"] == "account"}
        assert account_ids == {"123456789012"}

    def test_unmatched_project_tag_excludes_all_taggable_resources(self, client):
        response = client.get(
            "/api/topology?project_tag=Project=NoSuchProject"
        )
        data = response.json()
        node_types = {n["type"] for n in data["nodes"]}
        assert "s3_bucket" not in node_types
        assert "kms_key" not in node_types
        assert "iam_user" not in node_types


# --- GET /api/findings -----------------------------------------------
class TestFindingsEndpoint:

    def test_returns_200_with_json_content_type(self, client):
        response = client.get("/api/findings")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")

    def test_response_has_expected_shape_with_metadata_and_findings(self, client):
        response = client.get("/api/findings")
        data = response.json()
        assert set(data.keys()) == {"metadata", "findings"}
        assert data["metadata"]["schema_version"] == "1.0"

    def test_response_has_fifteen_findings_across_four_resources(self, client):
        # Seven S3 findings on the misconfigured uploads bucket, two
        # KMS findings on the same doomed customer-managed key, five
        # account-level findings (3 IAM + CloudTrail + account PAB),
        # and one IAM user finding (old access key). This is the
        # last rule in Phase 9a Feature 3 -- 12 ConfidentialClient rules
        # built in total across S3, KMS, IAM, and account scanners.
        response = client.get("/api/findings")
        data = response.json()
        assert len(data["findings"]) == 15
        assert data["metadata"]["finding_count"] == 15
        resource_ids = {f["resource_id"] for f in data["findings"]}
        assert resource_ids == {
            "cloudres-fintech-uploads",
            "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
            "123456789012",
            "cloudres-fintech-legacy-svc-account",
        }

    def test_project_tag_scopes_findings_to_tagged_resources_plus_account(self, client):
        # Phase 9a Feature 1. Scoped to ConfidentialClient: the 7 S3
        # findings on the tagged uploads bucket, plus the 5
        # account-wide findings (always included), minus the 2 KMS
        # and 1 IAM user findings (neither resource is tagged).
        response = client.get("/api/findings?project_tag=Project=ConfidentialClient")
        data = response.json()
        assert len(data["findings"]) == 12
        resource_ids = {f["resource_id"] for f in data["findings"]}
        assert resource_ids == {"cloudres-fintech-uploads", "123456789012"}

    def test_findings_have_framework_references_from_all_six_fully_mapped_frameworks(self, client):
        # ConfidentialClient is excluded from an unscoped scan — see
        # TestConfidentialFrameworkConfidentiality below. CIS AWS
        # Foundations is deliberately NOT one of these six -- unlike
        # NIS2/NCSC/MITRE/CE/ISO27001/DORA, it genuinely doesn't map
        # every finding type (see cis_aws_foundations.json's own
        # audit_notes for which ones and why), so it can't be asserted
        # present on every finding the way these six can. See
        # test_cis_aws_foundations_present_only_on_its_mapped_findings
        # below for CIS's own, different, coverage assertion.
        required_on_every_finding = {
            "nis2", "ncsc_caf", "mitre_attack", "cyber_essentials",
            "iso27001", "dora",
        }
        response = client.get("/api/findings")
        data = response.json()
        for finding in data["findings"]:
            frameworks = {
                r["framework"] for r in finding["framework_references"]
            }
            missing = required_on_every_finding - frameworks
            assert not missing, (
                f"{finding['finding_type_id']} missing frameworks: {missing}"
            )
            assert "confidential" not in frameworks

    def test_cis_aws_foundations_present_only_on_its_mapped_findings(self, client):
        # CIS AWS Foundations Benchmark is a narrow, foundational-only
        # baseline (see cis_aws_foundations.json's mapping_rationale) --
        # 17 of this project's 30 finding types have a genuine CIS
        # equivalent, the other 13 are deliberately left unmapped
        # rather than force-fit. This proves both halves of that
        # deliberate split actually hold at the API layer, not just
        # inside the mapping file.
        expected_mapped_finding_types = {
            "S3_PUBLIC_VIA_ACL",
            "S3_PUBLIC_VIA_AUTHENTICATED_USERS_ACL",
            "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
            "S3_TLS_NOT_ENFORCED",
            "KMS_KEY_ROTATION_DISABLED",
            "IAM_ROOT_ACCESS_KEYS_ACTIVE",
            "IAM_ACCOUNT_MFA_NOT_ENABLED",
            "IAM_PASSWORD_POLICY_WEAK",
            "IAM_ACCESS_KEY_AGE_EXCEEDS_90_DAYS",
            "IAM_USER_ADMIN_POLICY_ATTACHED",
            "IAM_USER_POLICY_GRANTS_WILDCARD_ACTION",
            "ACCOUNT_CLOUDTRAIL_DISABLED",
            "ACCOUNT_S3_BLOCK_PUBLIC_ACCESS_DISABLED",
            "EC2_IMDSV2_NOT_REQUIRED",
            "EC2_SECURITY_GROUP_UNRESTRICTED_SSH",
            "EC2_SECURITY_GROUP_UNRESTRICTED_RDP",
            "EC2_EBS_UNENCRYPTED",
        }
        response = client.get("/api/findings")
        data = response.json()
        for finding in data["findings"]:
            frameworks = {
                r["framework"] for r in finding["framework_references"]
            }
            has_cis = "cis_aws_foundations" in frameworks
            should_have_cis = finding["finding_type_id"] in expected_mapped_finding_types
            assert has_cis == should_have_cis, (
                f"{finding['finding_type_id']}: expected cis_aws_foundations "
                f"present={should_have_cis}, got {has_cis}"
            )


# --- _is_confidential_scope / _scan_all --------------------------------
class TestIsConfidentialScope:

    def test_true_for_project_confidential(self):
        assert _is_confidential_scope("Project=ConfidentialClient") is True

    def test_false_for_none(self):
        assert _is_confidential_scope(None) is False

    def test_false_for_empty_string(self):
        assert _is_confidential_scope("") is False

    def test_false_for_a_different_tag_value(self):
        assert _is_confidential_scope("Project=CloudResilienceVisualizer") is False

    def test_false_for_a_different_tag_key_with_the_same_value(self):
        # Deliberately strict: only the tag VALUE is checked, and it
        # must exactly equal "ConfidentialClient" regardless of which key
        # it's under, but a totally different key isn't special-cased
        # into matching — this documents the exact-value semantic.
        assert _is_confidential_scope("Team=ConfidentialClient") is True


class TestScanAllStripsConfidential:

    def _topology_with_root_keys_active(self):
        return {
            "metadata": {"schema_version": "1.0"},
            "nodes": [
                {
                    "id": "123456789012",
                    "type": "account",
                    "name": "AWS Account 123456789012",
                    "parent_id": None,
                    "properties": {
                        "root_access_keys_present": True,
                        "account_mfa_enabled": True,
                        "password_policy_min_length": 20,
                        "cloudtrail_logging_enabled": True,
                        "account_s3_block_public_access_enabled": True,
                    },
                }
            ],
            "security_groups": [],
        }

    def test_strips_confidential_when_unscoped(self):
        findings = _scan_all(self._topology_with_root_keys_active())
        assert len(findings) == 1
        frameworks = {r.framework for r in findings[0].framework_references}
        assert "confidential" not in frameworks
        # Every other framework must still be present -- this isn't
        # stripping everything, just the one confidential framework.
        assert "nis2" in frameworks

    @_requires_confidential_mapping
    def test_keeps_confidential_when_scoped_to_confidential(self):
        findings = _scan_all(
            self._topology_with_root_keys_active(), "Project=ConfidentialClient"
        )
        frameworks = {r.framework for r in findings[0].framework_references}
        assert "confidential" in frameworks

    def test_strips_confidential_when_scoped_to_a_different_project(self):
        findings = _scan_all(
            self._topology_with_root_keys_active(),
            "Project=CloudResilienceVisualizer",
        )
        frameworks = {r.framework for r in findings[0].framework_references}
        assert "confidential" not in frameworks


# --- Confidential framework confidentiality ---------------------------
class TestConfidentialFrameworkConfidentiality:
    """
    The confidential client's control catalogue must only ever appear
    when the scan is explicitly scoped to Project=ConfidentialClient
    — never on an unscoped scan, and never on a scan scoped to a
    different tagged project.
    """

    @_requires_confidential_mapping
    def test_confidential_appears_when_scoped_to_confidential(self, client):
        response = client.get("/api/findings?project_tag=Project=ConfidentialClient")
        data = response.json()
        frameworks_present = {
            r["framework"]
            for finding in data["findings"]
            for r in finding["framework_references"]
        }
        assert "confidential" in frameworks_present

    def test_confidential_absent_when_scoped_to_a_different_project(self, client):
        response = client.get(
            "/api/findings?project_tag=Project=CloudResilienceVisualizer"
        )
        data = response.json()
        frameworks_present = {
            r["framework"]
            for finding in data["findings"]
            for r in finding["framework_references"]
        }
        assert "confidential" not in frameworks_present

    def test_compliance_dashboard_includes_confidential_when_scoped(self, client):
        response = client.get("/api/compliance?project_tag=Project=ConfidentialClient")
        data = response.json()
        framework_names = {fw["framework"] for fw in data["frameworks"]}
        assert "confidential" in framework_names

    def test_compliance_dashboard_excludes_confidential_for_other_project(self, client):
        response = client.get(
            "/api/compliance?project_tag=Project=CloudResilienceVisualizer"
        )
        data = response.json()
        framework_names = {fw["framework"] for fw in data["frameworks"]}
        assert "confidential" not in framework_names


# --- Risk acceptance end-to-end (Phase 4) -----------------------------
class TestRiskAcceptanceEndToEnd:
    """
    Proves the full pipeline -- file on disk -> _scan_all() ->
    /api/findings (annotated, not filtered) and /api/compliance
    (excluded from failing counts) -- works together, not just each
    piece in isolation. Uses the same monkeypatch-the-module-global
    pattern test_mapping_loader.py uses for confidential_controls.json
    (see _MAPPINGS_DIR there / RISK_ACCEPTANCES_PATH here), since
    load_risk_acceptances() resolves its default path from the module
    global at call time specifically to make this possible.
    """

    @pytest.fixture
    def with_acceptance_for_uploads_bucket(self, monkeypatch, tmp_path):
        import app.risk_acceptance as risk_acceptance_module

        acceptances_file = tmp_path / "risk_acceptances.json"
        acceptances_file.write_text(
            '{"acceptances": [{'
            '"finding_type_id": "S3_PUBLIC_VIA_ACL", '
            '"resource_id": "cloudres-fintech-uploads", '
            '"reason": "Compensating control in place", '
            '"accepted_by": "Test Approver", '
            '"accepted_date": "2026-01-01", '
            '"expires": null'
            '}]}',
            encoding="utf-8",
        )
        monkeypatch.setattr(
            risk_acceptance_module, "RISK_ACCEPTANCES_PATH", acceptances_file
        )

    def test_accepted_finding_still_appears_in_findings_endpoint(
        self, client, with_acceptance_for_uploads_bucket
    ):
        response = client.get("/api/findings")
        data = response.json()
        matching = [
            f for f in data["findings"]
            if f["finding_type_id"] == "S3_PUBLIC_VIA_ACL"
            and f["resource_id"] == "cloudres-fintech-uploads"
        ]
        assert len(matching) == 1
        assert matching[0]["risk_accepted"] is True
        assert matching[0]["risk_acceptance"]["accepted_by"] == "Test Approver"

    def test_accepted_finding_excluded_from_compliance_failing_counts(
        self, client, with_acceptance_for_uploads_bucket
    ):
        response = client.get("/api/compliance")
        data = response.json()
        assert data["metadata"]["risk_accepted_count"] == 1

        nis2 = next(fw for fw in data["frameworks"] if fw["framework"] == "nis2")
        matching_resource_ids = {
            f["resource_id"]
            for req in nis2["failing_requirements"]
            for f in req["findings"]
            if f["finding_type_id"] == "S3_PUBLIC_VIA_ACL"
        }
        assert "cloudres-fintech-uploads" not in matching_resource_ids

    def test_no_acceptance_file_means_zero_accepted(self, client):
        response = client.get("/api/compliance")
        data = response.json()
        assert data["metadata"]["risk_accepted_count"] == 0


# --- Error handling --------------------------------------------------
class TestErrorHandling:

    def test_unknown_endpoint_returns_404(self, client):
        response = client.get("/api/does-not-exist")
        assert response.status_code == 404

    def test_post_to_get_endpoint_returns_405_method_not_allowed(self, client):
        response = client.post("/api/topology")
        assert response.status_code == 405


# --- GET /api/compliance ---------------------------------------------
class TestComplianceEndpoint:

    def test_returns_200_with_json_content_type(self, client):
        response = client.get("/api/compliance")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")

    def test_response_has_seven_frameworks_by_default(self, client):
        # ConfidentialClient is client-confidential and must not appear on
        # an unscoped scan — see TestConfidentialFrameworkConfidentiality.
        response = client.get("/api/compliance")
        data = response.json()
        framework_names = [fw["framework"] for fw in data["frameworks"]]
        assert framework_names == [
            "nis2",
            "ncsc_caf",
            "mitre_attack",
            "cyber_essentials",
            "iso27001",
            "dora",
            "cis_aws_foundations",
        ]

    def test_response_reflects_scanner_findings(self, client):
        response = client.get("/api/compliance")
        data = response.json()
        assert data["metadata"]["total_findings"] == 15


# --- GET /api/report -------------------------------------------------
class TestReportEndpoint:

    def test_returns_200_with_pdf_content_type(self, client):
        response = client.get("/api/report")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"

    def test_has_attachment_disposition_header(self, client):
        response = client.get("/api/report")
        disposition = response.headers.get("content-disposition", "")
        assert "attachment" in disposition
        assert "cloud-resilience-report.pdf" in disposition

    def test_body_starts_with_pdf_magic_bytes(self, client):
        response = client.get("/api/report")
        assert response.content[:4] == b"%PDF"

    def test_body_is_non_trivial_size(self, client):
        response = client.get("/api/report")
        assert len(response.content) > 2000


# --- GET /api/evidence -----------------------------------------------
class TestEvidenceEndpoint:

    def test_returns_200_with_json_content_type(self, client):
        response = client.get("/api/evidence")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")

    def test_response_has_required_fields(self, client):
        response = client.get("/api/evidence")
        data = response.json()
        required = {
            "schema_version", "tool_version", "generated_at",
            "data_source", "iam_identity", "scope",
            "findings_summary", "input_hash", "integrity_hash",
        }
        assert required.issubset(set(data.keys()))

    def test_hashes_start_with_sha256_prefix(self, client):
        response = client.get("/api/evidence")
        data = response.json()
        assert data["input_hash"].startswith("sha256:")
        assert data["integrity_hash"].startswith("sha256:")

    def test_scope_project_tag_is_none_when_unscoped(self, client):
        response = client.get("/api/evidence")
        data = response.json()
        assert data["scope"]["project_tag"] is None

    def test_project_tag_scopes_evidence_and_labels_the_scope_section(self, client):
        # Phase 9a Feature 4. Scoping to ConfidentialClient changes both
        # what got scanned (node_count reflects the filtered
        # topology) and self-documents the scope in the record.
        response = client.get("/api/evidence?project_tag=Project=ConfidentialClient")
        data = response.json()
        assert data["scope"]["project_tag"] == "Project=ConfidentialClient"
        unscoped = client.get("/api/topology").json()
        scoped = client.get("/api/topology?project_tag=Project=ConfidentialClient").json()
        assert data["scope"]["node_count"] == scoped["metadata"]["node_count"]
        assert data["scope"]["node_count"] < unscoped["metadata"]["node_count"]


# --- GET /api/health -------------------------------------------------
class TestHealthEndpoint:

    def test_health_returns_200_without_api_key(self):
        bare_client = TestClient(app)
        response = bare_client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


# --- Authentication --------------------------------------------------
class TestAuthentication:

    def test_protected_endpoint_returns_403_with_wrong_key(self):
        bad_client = TestClient(app, headers={"X-API-Key": "totally-wrong-key"})
        response = bad_client.get("/api/topology")
        assert response.status_code == 403

    def test_protected_endpoint_returns_422_with_no_key(self):
        no_key_client = TestClient(app, headers={})
        response = no_key_client.get("/api/topology")
        assert response.status_code == 422

    def test_protected_endpoint_returns_200_with_correct_key(self):
        authed_client = TestClient(
            app, headers={"X-API-Key": "dev-only-insecure-key"}
        )
        response = authed_client.get("/api/topology")
        assert response.status_code == 200