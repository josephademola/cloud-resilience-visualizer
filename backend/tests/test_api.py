"""
Integration tests for the FastAPI endpoints in app.api.main.

Uses FastAPI's TestClient, which routes requests directly to the app
in-process — no server start required, no port binding, no real
network. What TestClient sees is identical to what a real HTTP
client would see, so these tests exercise the full stack (HTTP layer
-> normaliser -> scanner -> mapping loader) end-to-end.
"""


import pytest
from fastapi.testclient import TestClient

from app.api.main import app


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

    def test_response_has_eleven_nodes_and_three_security_groups(self, client):
        response = client.get("/api/topology")
        data = response.json()
        assert len(data["nodes"]) == 11
        assert len(data["security_groups"]) == 3
        assert data["metadata"]["node_count"] == 11
        assert data["metadata"]["security_group_count"] == 3

    def test_response_includes_both_s3_buckets(self, client):
        response = client.get("/api/topology")
        data = response.json()
        s3_ids = {n["id"] for n in data["nodes"] if n["type"] == "s3_bucket"}
        assert s3_ids == {"cloudres-fintech-logs", "cloudres-fintech-uploads"}


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

    def test_response_has_ten_findings_across_three_resources(self, client):
        # Seven S3 findings on the misconfigured uploads bucket, two
        # KMS findings (rotation disabled, pending deletion) on the
        # same doomed customer-managed key, and one IAM finding on
        # the account itself — the first finding not tied to any
        # specific bucket, key, or instance.
        response = client.get("/api/findings")
        data = response.json()
        assert len(data["findings"]) == 10
        assert data["metadata"]["finding_count"] == 10
        resource_ids = {f["resource_id"] for f in data["findings"]}
        assert resource_ids == {
            "cloudres-fintech-uploads",
            "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
            "123456789012",
        }

    def test_findings_have_framework_references_from_all_four_frameworks(self, client):
        response = client.get("/api/findings")
        data = response.json()
        expected = {"nis2", "ncsc_caf", "mitre_attack", "cyber_essentials"}
        for finding in data["findings"]:
            frameworks = {
                r["framework"] for r in finding["framework_references"]
            }
            assert frameworks == expected, (
                f"{finding['finding_type_id']} missing frameworks: "
                f"{expected - frameworks}"
            )


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

    def test_response_has_four_frameworks_in_expected_order(self, client):
        response = client.get("/api/compliance")
        data = response.json()
        framework_names = [fw["framework"] for fw in data["frameworks"]]
        assert framework_names == [
            "nis2",
            "ncsc_caf",
            "mitre_attack",
            "cyber_essentials",
        ]

    def test_response_reflects_scanner_findings(self, client):
        response = client.get("/api/compliance")
        data = response.json()
        assert data["metadata"]["total_findings"] == 10


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