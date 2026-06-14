"""
Integration test for the AWS normalizer.

Where the unit tests in test_aws_normalizer.py and
test_aws_normalizer_resources.py exercise individual functions with
small hand-built fixtures, this file does the opposite: it runs the
whole pipeline against the real mock_aws.json and asserts the
resulting topology has the expected structure end-to-end.

If a refactor changes a property name, breaks the parent_id linkage,
or accidentally drops a resource, every unit test could still pass
while this integration test would catch the regression.

The mock_aws.json is loaded once at module-import time and shared
across every test. The tests treat it as read-only.
"""

from datetime import datetime
from pathlib import Path

from app.aws_normalizer import normalize_from_file


# Path to the mock data, computed relative to this test file so the
# tests work regardless of which directory pytest is invoked from.
_MOCK_PATH = (
    Path(__file__).resolve().parent.parent / "app" / "data" / "mock_aws.json"
)

# Load and normalize once at import. Every test reads from this dict;
# none mutate it. The whole load takes < 0.01s, so the simplicity of
# a module-level constant beats introducing a pytest fixture here.
TOPOLOGY = normalize_from_file(_MOCK_PATH)


def _nodes_of_type(node_type: str) -> list[dict]:
    """Return all topology nodes whose 'type' field matches."""
    return [n for n in TOPOLOGY["nodes"] if n["type"] == node_type]


class TestNormalizeEndToEnd:

    def test_metadata_is_complete_and_valid(self):
        # Three things asserted at once: schema_version frozen at 1.0,
        # node and SG counts match the known mock environment, and the
        # timestamp parses as a real ISO-8601 datetime (rather than
        # some malformed string).
        meta = TOPOLOGY["metadata"]
        assert meta["schema_version"] == "1.0"
        assert meta["node_count"] == 9
        assert meta["security_group_count"] == 3
        # If this raises ValueError, the timestamp format is broken.
        datetime.fromisoformat(meta["generated_at"])

    def test_node_type_breakdown_matches_mock(self):
        # The mock environment is fixed: 1 VPC, 2 subnets, 1 IGW,
        # 2 EC2 instances, 1 RDS, 2 S3 buckets = 9 nodes total.
        # Asserting the breakdown (not just the total) catches the
        # case where two resources are silently swapped (e.g. an EC2
        # missing and an extra S3 appearing — total still 9, but the
        # mix is wrong).
        type_counts: dict[str, int] = {}
        for node in TOPOLOGY["nodes"]:
            type_counts[node["type"]] = type_counts.get(node["type"], 0) + 1
        assert type_counts == {
            "vpc": 1,
            "subnet": 2,
            "internet_gateway": 1,
            "ec2_instance": 2,
            "rds_instance": 1,
            "s3_bucket": 2,
        }

    def test_all_subnets_have_vpc_as_parent(self):
        # Every subnet must be parented to a VPC that actually exists
        # in the topology.
        vpc_ids = {n["id"] for n in _nodes_of_type("vpc")}
        for subnet in _nodes_of_type("subnet"):
            assert subnet["parent_id"] in vpc_ids

    def test_all_ec2_instances_have_subnet_as_parent(self):
        subnet_ids = {n["id"] for n in _nodes_of_type("subnet")}
        for instance in _nodes_of_type("ec2_instance"):
            assert instance["parent_id"] in subnet_ids

    def test_rds_instance_has_subnet_as_parent(self):
        subnet_ids = {n["id"] for n in _nodes_of_type("subnet")}
        for db in _nodes_of_type("rds_instance"):
            assert db["parent_id"] in subnet_ids

    def test_internet_gateway_attached_to_vpc(self):
        # The mock's IGW is attached to the VPC — its state should be
        # "available" (not "detached") and parent_id must point at
        # the VPC.
        vpc_ids = {n["id"] for n in _nodes_of_type("vpc")}
        igws = _nodes_of_type("internet_gateway")
        assert len(igws) == 1
        igw = igws[0]
        assert igw["parent_id"] in vpc_ids
        assert igw["properties"]["state"] == "available"

    def test_all_s3_buckets_have_no_parent(self):
        # S3 is a global service. No bucket should have a parent_id,
        # even though buckets appear in the same nodes list as
        # VPC-scoped resources.
        for bucket in _nodes_of_type("s3_bucket"):
            assert bucket["parent_id"] is None

    def test_no_dangling_parent_references(self):
        # Every non-None parent_id must point to a node that actually
        # exists in the topology. If a subnet says
        # "parent_id = vpc-deadbeef" but no vpc-deadbeef node exists,
        # the frontend would render an orphaned shape. This test
        # catches that whole class of bug at the data layer.
        node_ids = {n["id"] for n in TOPOLOGY["nodes"]}
        for node in TOPOLOGY["nodes"]:
            if node["parent_id"] is not None:
                assert node["parent_id"] in node_ids, (
                    f"Node {node['id']} ({node['type']}) references "
                    f"missing parent {node['parent_id']}"
                )

    def test_secure_logs_bucket_has_all_safe_flags(self):
        # The 'cloudres-fintech-logs' bucket in the mock is the
        # deliberately well-configured bucket. All three S3 booleans
        # should reflect the safe state.
        logs = next(
            (n for n in _nodes_of_type("s3_bucket")
             if n["id"] == "cloudres-fintech-logs"),
            None,
        )
        assert logs is not None, "Expected 'cloudres-fintech-logs' in topology"
        props = logs["properties"]
        assert props["is_public_via_acl"] is False
        assert props["public_access_block_fully_enabled"] is True
        assert props["encryption_enabled"] is True

    def test_misconfigured_uploads_bucket_has_all_three_flags_set(self):
        # The 'cloudres-fintech-uploads' bucket is the deliberate
        # misconfig in the mock: AllUsers ACL grant, all four PAB
        # flags off, no encryption. This is the misconfig that the
        # future scanner will need to flag against three frameworks
        # (NIS2, NCSC CAF, MITRE ATT&CK). If this assertion ever
        # fails, the seed misconfig has been silently lost from the
        # mock — a portfolio-credibility risk worth catching loudly.
        uploads = next(
            (n for n in _nodes_of_type("s3_bucket")
             if n["id"] == "cloudres-fintech-uploads"),
            None,
        )
        assert uploads is not None, "Expected 'cloudres-fintech-uploads' in topology"
        props = uploads["properties"]
        assert props["is_public_via_acl"] is True
        assert props["public_access_block_fully_enabled"] is False
        assert props["encryption_enabled"] is False

    def test_three_security_groups_belong_to_vpc(self):
        # The mock has three chained SGs (web -> app -> db). Each
        # must report the VPC's id and appear in the topology's
        # security_groups list, NOT in nodes.
        sgs = TOPOLOGY["security_groups"]
        assert len(sgs) == 3
        vpc_ids = {n["id"] for n in _nodes_of_type("vpc")}
        for sg in sgs:
            assert sg["vpc_id"] in vpc_ids
        # Also confirm SGs aren't accidentally leaking into the
        # nodes list — a regression where someone tried to "fix" the
        # design by making SGs renderable as topology shapes.
        node_types = {n["type"] for n in TOPOLOGY["nodes"]}
        assert "security_group" not in node_types