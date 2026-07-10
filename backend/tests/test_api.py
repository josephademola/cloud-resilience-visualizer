"""
Integration tests for the FastAPI endpoints in app.api.main.

Uses FastAPI's TestClient, which routes requests directly to the app
in-process — no server start required, no port binding, no real
network. What TestClient sees is identical to what a real HTTP
client would see, so these tests exercise the full stack (HTTP layer
-> normaliser -> scanner -> mapping loader) end-to-end.

If any layer regresses, at least one of these tests fails. They're
the tripwire that catches API-shape breakage before the frontend
does.
"""

from fastapi.testclient import TestClient

from app.api.main import app

# One TestClient shared across tests. TestClient is safe for
# in-process use and creating one per test is unnecessary overhead.
client = TestClient(app)


# --- GET /api/topology -----------------------------------------------
class TestTopologyEndpoint:

    def test_returns_200_with_json_content_type(self):
        response = client.get("/api/topology")
        assert response.status_code == 200
        # startswith() is more robust than exact equality: some
        # setups add "; charset=utf-8" to the content-type.
        assert response.headers["content-type"].startswith("application/json")

    def test_response_has_expected_top_level_shape(self):
        response = client.get("/api/topology")
        data = response.json()
        assert set(data.keys()) == {"metadata", "nodes", "security_groups"}

    def test_response_has_nine_nodes_and_three_security_groups(self):
        # Same counts locked in by the normaliser integration test.
        # A regression in the normaliser would cascade to this test.
        response = client.get("/api/topology")
        data = response.json()
        assert len(data["nodes"]) == 9
        assert len(data["security_groups"]) == 3
        assert data["metadata"]["node_count"] == 9
        assert data["metadata"]["security_group_count"] == 3

    def test_response_includes_both_s3_buckets(self):
        # Specific data spot-check: both bucket IDs are present.
        # Catches accidents where the mock or normaliser drops a
        # bucket that later tests assume is there.
        response = client.get("/api/topology")
        data = response.json()
        s3_ids = {n["id"] for n in data["nodes"] if n["type"] == "s3_bucket"}
        assert s3_ids == {"cloudres-fintech-logs", "cloudres-fintech-uploads"}


# --- GET /api/findings -----------------------------------------------
class TestFindingsEndpoint:

    def test_returns_200_with_json_content_type(self):
        response = client.get("/api/findings")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")

    def test_response_has_expected_shape_with_metadata_and_findings(self):
        response = client.get("/api/findings")
        data = response.json()
        assert set(data.keys()) == {"metadata", "findings"}
        assert data["metadata"]["schema_version"] == "1.0"

    def test_response_has_three_findings_all_for_misconfigured_bucket(self):
        # Locks in the scanner integration behaviour at the HTTP layer:
        # the mock has exactly one misconfigured bucket with three
        # issues, so the endpoint must return three findings all
        # referencing that bucket.
        response = client.get("/api/findings")
        data = response.json()
        assert len(data["findings"]) == 3
        assert data["metadata"]["finding_count"] == 3
        resource_ids = {f["resource_id"] for f in data["findings"]}
        assert resource_ids == {"cloudres-fintech-uploads"}

    def test_findings_have_framework_references_from_all_four_frameworks(self):
        # End-to-end proof that the mapping loader is wired in through
        # the API layer. If a mapping file dropped an entry or the
        # loader stopped combining across files, this test catches it
        # here rather than downstream in the browser.
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

    def test_unknown_endpoint_returns_404(self):
        # FastAPI returns 404 for unmatched routes automatically.
        # Locking this in prevents accidentally adding a catch-all
        # route that would swallow typos.
        response = client.get("/api/does-not-exist")
        assert response.status_code == 404

    def test_post_to_get_endpoint_returns_405_method_not_allowed(self):
        # We only expose these endpoints as GET. FastAPI returns 405
        # (Method Not Allowed) for wrong-method requests to known
        # paths — different signal from 404, which we want to preserve.
        response = client.post("/api/topology")
        assert response.status_code == 405