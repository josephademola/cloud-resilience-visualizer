"""
Unit tests for the tag-based target selection functions in
app.aws_normalizer (Phase 9a Feature 1).

get_tagged_resource_arns() reads the Resource Groups Tagging API
shape and returns matching ARNs; filter_topology_by_tag() applies
that set to a topology, keeping account-wide and not-yet-taggable
node types regardless of scope.
"""

from app.aws_normalizer import get_tagged_resource_arns, filter_topology_by_tag


# --- get_tagged_resource_arns ---------------------------------------------
class TestGetTaggedResourceArns:

    def test_returns_arns_matching_tag_key_and_value(self):
        aws_data = {
            "resourcegroupstaggingapi": {
                "get_resources": {
                    "ResourceTagMappingList": [
                        {
                            "ResourceARN": "arn:aws:s3:::bucket-a",
                            "Tags": [{"Key": "Project", "Value": "ConfidentialClient"}],
                        },
                        {
                            "ResourceARN": "arn:aws:s3:::bucket-b",
                            "Tags": [{"Key": "Project", "Value": "OtherProject"}],
                        },
                    ]
                }
            }
        }
        result = get_tagged_resource_arns(aws_data, "Project", "ConfidentialClient")
        assert result == {"arn:aws:s3:::bucket-a"}

    def test_matches_resource_with_multiple_tags(self):
        aws_data = {
            "resourcegroupstaggingapi": {
                "get_resources": {
                    "ResourceTagMappingList": [
                        {
                            "ResourceARN": "arn:aws:s3:::bucket-a",
                            "Tags": [
                                {"Key": "Environment", "Value": "production"},
                                {"Key": "Project", "Value": "ConfidentialClient"},
                            ],
                        },
                    ]
                }
            }
        }
        result = get_tagged_resource_arns(aws_data, "Project", "ConfidentialClient")
        assert result == {"arn:aws:s3:::bucket-a"}

    def test_returns_empty_set_when_no_tag_matches(self):
        # This is what makes mock mode behave honestly even though
        # its resourcegroupstaggingapi section is static: querying
        # for a tag key/value nothing carries still yields no
        # matches, exactly like a real filtered AWS call would.
        aws_data = {
            "resourcegroupstaggingapi": {
                "get_resources": {
                    "ResourceTagMappingList": [
                        {
                            "ResourceARN": "arn:aws:s3:::bucket-a",
                            "Tags": [{"Key": "Project", "Value": "ConfidentialClient"}],
                        },
                    ]
                }
            }
        }
        result = get_tagged_resource_arns(aws_data, "Project", "SomeOtherProject")
        assert result == set()

    def test_returns_empty_set_when_key_missing_entirely(self):
        assert get_tagged_resource_arns({}, "Project", "ConfidentialClient") == set()


# --- filter_topology_by_tag -----------------------------------------------
class TestFilterTopologyByTag:

    def _topology(self, nodes):
        return {
            "metadata": {"schema_version": "1.0", "node_count": len(nodes)},
            "nodes": nodes,
            "security_groups": [],
        }

    def test_keeps_taggable_node_when_arn_in_tagged_set(self):
        topology = self._topology([
            {
                "id": "uploads",
                "type": "s3_bucket",
                "properties": {"arn": "arn:aws:s3:::uploads"},
            },
        ])
        result = filter_topology_by_tag(topology, {"arn:aws:s3:::uploads"})
        assert [n["id"] for n in result["nodes"]] == ["uploads"]

    def test_drops_taggable_node_when_arn_not_in_tagged_set(self):
        topology = self._topology([
            {
                "id": "logs",
                "type": "s3_bucket",
                "properties": {"arn": "arn:aws:s3:::logs"},
            },
        ])
        result = filter_topology_by_tag(topology, {"arn:aws:s3:::uploads"})
        assert result["nodes"] == []

    def test_always_keeps_account_node_regardless_of_tags(self):
        # Account-wide findings (root MFA, CloudTrail, ...) aren't
        # facts about a tagged resource, so tag scoping can't apply.
        topology = self._topology([
            {"id": "123456789012", "type": "account", "properties": {}},
            {
                "id": "logs",
                "type": "s3_bucket",
                "properties": {"arn": "arn:aws:s3:::logs"},
            },
        ])
        result = filter_topology_by_tag(topology, set())
        assert [n["id"] for n in result["nodes"]] == ["123456789012"]

    def test_always_keeps_node_types_without_arn_tracking(self):
        # vpc/subnet/ec2_instance/rds_instance don't have ARNs yet
        # and have no scanner coverage — filtering them would just
        # break the topology diagram's visual context for no benefit.
        topology = self._topology([
            {"id": "vpc-1", "type": "vpc", "properties": {}},
            {"id": "subnet-1", "type": "subnet", "properties": {}},
            {"id": "i-1", "type": "ec2_instance", "properties": {}},
            {"id": "db-1", "type": "rds_instance", "properties": {}},
        ])
        result = filter_topology_by_tag(topology, set())
        assert {n["id"] for n in result["nodes"]} == {
            "vpc-1", "subnet-1", "i-1", "db-1",
        }

    def test_updates_node_count_in_metadata(self):
        topology = self._topology([
            {
                "id": "uploads",
                "type": "s3_bucket",
                "properties": {"arn": "arn:aws:s3:::uploads"},
            },
            {
                "id": "logs",
                "type": "s3_bucket",
                "properties": {"arn": "arn:aws:s3:::logs"},
            },
        ])
        result = filter_topology_by_tag(topology, {"arn:aws:s3:::uploads"})
        assert result["metadata"]["node_count"] == 1

    def test_does_not_mutate_the_original_topology(self):
        topology = self._topology([
            {
                "id": "uploads",
                "type": "s3_bucket",
                "properties": {"arn": "arn:aws:s3:::uploads"},
            },
            {
                "id": "logs",
                "type": "s3_bucket",
                "properties": {"arn": "arn:aws:s3:::logs"},
            },
        ])
        original_count = len(topology["nodes"])
        filter_topology_by_tag(topology, {"arn:aws:s3:::uploads"})
        assert len(topology["nodes"]) == original_count
