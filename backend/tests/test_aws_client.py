"""
Unit tests for app.aws_client.

Uses moto to intercept boto3 calls, so tests run against a fake
AWS environment in-process. No real AWS credentials, no network,
no cost — tests are deterministic and free to run.

These tests verify:
  - Top-level response shape matches mock_aws.json exactly.
  - Every EC2, RDS, and S3 service key is present.
  - ResponseMetadata is stripped from every response.
  - datetime fields are converted to ISO strings (the fix from
    chunk 6.1 — json.dump chokes on native datetime).
  - Empty accounts produce empty lists rather than raising.
  - Real resources created via boto3 appear in fetch_aws_data output.
  - Every bucket in list_buckets has a matching bucket_details entry.
"""

import json

import boto3
import pytest
from moto import mock_aws

from app.aws_client import fetch_aws_data


# ---- Fixtures --------------------------------------------------------

@pytest.fixture
def aws_credentials(monkeypatch):
    """
    Set fake AWS credentials before any test. If moto ever fails to
    intercept a call (misconfiguration, missing import, etc.), boto3
    falls back to these credentials — which are invalid — and raises
    a clear auth error rather than accidentally hitting real AWS.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-2")


@pytest.fixture
def moto_aws(aws_credentials):
    """
    Provide a moto-mocked AWS environment. Tests using this fixture
    get a fresh, empty AWS account that vanishes after the test.
    """
    with mock_aws():
        yield


# ---- fetch_aws_data --------------------------------------------------

class TestFetchAwsData:

    def test_returns_expected_top_level_shape(self, moto_aws):
        # Top-level keys must match mock_aws.json exactly so the
        # normaliser downstream can process either data source.
        data = fetch_aws_data()
        assert set(data.keys()) == {"ec2", "rds", "s3", "kms", "iam"}

    def test_ec2_section_has_all_expected_service_keys(self, moto_aws):
        # The normaliser calls specific keys under "ec2" — miss any
        # and the topology loses a resource type. Locking this in.
        data = fetch_aws_data()
        assert set(data["ec2"].keys()) == {
            "describe_vpcs",
            "describe_subnets",
            "describe_internet_gateways",
            "describe_instances",
            "describe_security_groups",
        }

    def test_s3_section_has_list_and_details(self, moto_aws):
        # The normaliser reads both list_buckets AND bucket_details.
        data = fetch_aws_data()
        assert "list_buckets" in data["s3"]
        assert "bucket_details" in data["s3"]

    def test_kms_section_has_list_and_details(self, moto_aws):
        data = fetch_aws_data()
        assert "list_keys" in data["kms"]
        assert "key_details" in data["kms"]

    def test_iam_section_has_account_id_and_summary(self, moto_aws):
        # The normaliser reads both account_id (for the node's id)
        # and get_account_summary (for its properties).
        data = fetch_aws_data()
        assert "account_id" in data["iam"]
        assert isinstance(data["iam"]["account_id"], str)
        assert data["iam"]["account_id"] != ""
        assert "get_account_summary" in data["iam"]
        assert "SummaryMap" in data["iam"]["get_account_summary"]

    def test_bucket_details_has_all_seven_s3_calls(self, moto_aws):
        # The normaliser reads all seven per-bucket calls (one per
        # S3 scanner rule). Miss any and that rule silently sees
        # "not configured" for every bucket, regardless of reality.
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket="test-bucket-shape",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        data = fetch_aws_data()
        assert set(data["s3"]["bucket_details"]["test-bucket-shape"].keys()) == {
            "get_bucket_acl",
            "get_public_access_block",
            "get_bucket_encryption",
            "get_bucket_versioning",
            "get_bucket_logging",
            "get_bucket_lifecycle_configuration",
            "get_bucket_policy",
        }

    def test_key_details_entry_exists_for_every_key(self, moto_aws):
        # Same invariant as bucket_details: every key in list_keys
        # must have a corresponding key_details entry, or that key
        # silently never gets scanned.
        kms = boto3.client("kms", region_name="eu-west-2")
        created = kms.create_key(Description="test-key")
        key_id = created["KeyMetadata"]["KeyId"]

        data = fetch_aws_data()
        listed_key_ids = {k["KeyId"] for k in data["kms"]["list_keys"]["Keys"]}
        detail_key_ids = set(data["kms"]["key_details"].keys())
        assert key_id in listed_key_ids
        assert listed_key_ids == detail_key_ids

    def test_key_details_has_both_kms_calls(self, moto_aws):
        kms = boto3.client("kms", region_name="eu-west-2")
        created = kms.create_key(Description="test-key")
        key_id = created["KeyMetadata"]["KeyId"]

        data = fetch_aws_data()
        assert set(data["kms"]["key_details"][key_id].keys()) == {
            "describe_key",
            "get_key_rotation_status",
        }
        # Confirm the shape the normaliser actually reads is present.
        assert "KeyMetadata" in data["kms"]["key_details"][key_id]["describe_key"]
        assert (
            data["kms"]["key_details"][key_id]["describe_key"]["KeyMetadata"]["KeyManager"]
            == "CUSTOMER"
        )

    def test_response_metadata_is_stripped_from_every_response(self, moto_aws):
        # boto3 wraps responses with ResponseMetadata (request IDs,
        # HTTP status, retry counts). Not part of the data model —
        # should never reach the normaliser.
        data = fetch_aws_data()
        for service_key, service_data in data["ec2"].items():
            assert "ResponseMetadata" not in service_data, (
                f"ec2.{service_key} still has ResponseMetadata"
            )
        for service_key, service_data in data["rds"].items():
            assert "ResponseMetadata" not in service_data, (
                f"rds.{service_key} still has ResponseMetadata"
            )
        assert "ResponseMetadata" not in data["s3"]["list_buckets"]
        assert "ResponseMetadata" not in data["kms"]["list_keys"]
        assert "ResponseMetadata" not in data["iam"]["get_account_summary"]

    def test_output_is_fully_json_serialisable(self, moto_aws):
        # This is the acceptance test for the datetime fix. boto3
        # returns creation dates as native Python datetime objects;
        # json.dump raises on those. _serialise_datetimes must
        # convert every one to an ISO string.
        # Create resources so there are timestamps to serialise.
        ec2 = boto3.client("ec2", region_name="eu-west-2")
        ec2.create_vpc(CidrBlock="10.0.0.0/16")

        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket="test-datetime-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

        data = fetch_aws_data()
        # If any datetime escaped conversion, this line raises.
        json.dumps(data)

    def test_empty_account_returns_empty_lists(self, moto_aws):
        # A fresh moto account mirrors real AWS: it has a default VPC
        # per region but no custom resources. The important invariant
        # is that the response structure is valid (lists, not None or
        # missing keys) — not that every list is empty.
        data = fetch_aws_data()
        # Structure is valid — lists present, not None
        assert isinstance(data["ec2"]["describe_vpcs"]["Vpcs"], list)
        assert isinstance(data["ec2"]["describe_subnets"]["Subnets"], list)
        assert isinstance(data["s3"]["list_buckets"]["Buckets"], list)
        assert isinstance(data["s3"]["bucket_details"], dict)
        assert isinstance(data["rds"]["describe_db_instances"]["DBInstances"], list)
        assert isinstance(data["kms"]["list_keys"]["Keys"], list)
        assert isinstance(data["kms"]["key_details"], dict)
        assert isinstance(data["iam"]["get_account_summary"]["SummaryMap"], dict)
        # No custom resources beyond the default VPC/subnets
        assert data["s3"]["list_buckets"]["Buckets"] == []
        assert data["rds"]["describe_db_instances"]["DBInstances"] == []

    def test_created_vpc_appears_in_output(self, moto_aws):
        # Full smoke test: create a real resource via boto3, verify
        # fetch_aws_data sees it. Proves moto is intercepting.
        ec2 = boto3.client("ec2", region_name="eu-west-2")
        response = ec2.create_vpc(CidrBlock="10.99.0.0/16")
        created_vpc_id = response["Vpc"]["VpcId"]

        data = fetch_aws_data()
        vpc_ids = [v["VpcId"] for v in data["ec2"]["describe_vpcs"]["Vpcs"]]
        assert created_vpc_id in vpc_ids

    def test_bucket_details_entry_exists_for_every_bucket(self, moto_aws):
        # Invariant: every bucket in list_buckets must have a
        # corresponding entry in bucket_details. If they diverge,
        # some buckets won't get scanned.
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket="test-bucket-alpha",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.create_bucket(
            Bucket="test-bucket-bravo",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )

        data = fetch_aws_data()
        listed_bucket_names = {
            b["Name"] for b in data["s3"]["list_buckets"]["Buckets"]
        }
        detail_bucket_names = set(data["s3"]["bucket_details"].keys())
        assert listed_bucket_names == detail_bucket_names