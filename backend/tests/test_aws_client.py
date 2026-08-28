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
        # resourcegroupstaggingapi is always present now (docs/
        # design_decisions.md #12), not just on scoped scans.
        data = fetch_aws_data()
        assert set(data.keys()) == {
            "ec2", "rds", "s3", "kms", "iam", "cloudtrail", "s3control",
            "resourcegroupstaggingapi",
        }

    def test_includes_tagging_section_even_when_no_project_tag_given(self, moto_aws):
        # Always fetched now (docs/design_decisions.md #12) --
        # aws_normalizer._apply_tag_presence needs the full,
        # unfiltered picture of what's tagged on every scan, not just
        # scoped ones, to power RESOURCE_MISSING_TAGS. That finding is
        # specifically aimed at unscoped scans, so this section can no
        # longer be skipped when project_tag is absent.
        data = fetch_aws_data()
        assert "resourcegroupstaggingapi" in data
        assert "get_resources" in data["resourcegroupstaggingapi"]

    def test_unscoped_tagging_call_is_not_filtered_by_tag(self, moto_aws):
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket="tagged-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_bucket_tagging(
            Bucket="tagged-bucket",
            Tagging={"TagSet": [{"Key": "Environment", "Value": "production"}]},
        )

        # No project_tag given -- the unscoped call must still surface
        # this bucket's tags, since it isn't limited to one specific
        # tag key/value the way a scoped call is.
        data = fetch_aws_data()
        mappings = data["resourcegroupstaggingapi"]["get_resources"][
            "ResourceTagMappingList"
        ]
        tagged_arns = {m["ResourceARN"] for m in mappings}
        assert "arn:aws:s3:::tagged-bucket" in tagged_arns

    def test_includes_tagging_section_when_project_tag_given(self, moto_aws):
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket="tagged-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_bucket_tagging(
            Bucket="tagged-bucket",
            Tagging={"TagSet": [{"Key": "Project", "Value": "ConfidentialClient"}]},
        )

        data = fetch_aws_data(project_tag="Project=ConfidentialClient")
        assert "resourcegroupstaggingapi" in data
        mappings = data["resourcegroupstaggingapi"]["get_resources"][
            "ResourceTagMappingList"
        ]
        tagged_arns = {m["ResourceARN"] for m in mappings}
        assert "arn:aws:s3:::tagged-bucket" in tagged_arns

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
        assert "list_aliases" in data["kms"]

    def test_kms_section_list_aliases_reflects_created_alias(self, moto_aws):
        kms = boto3.client("kms", region_name="eu-west-2")
        key = kms.create_key()
        key_id = key["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName="alias/test-key", TargetKeyId=key_id)

        data = fetch_aws_data()
        aliases = data["kms"]["list_aliases"]["Aliases"]
        matching = [a for a in aliases if a["AliasName"] == "alias/test-key"]
        assert len(matching) == 1
        assert matching[0]["TargetKeyId"] == key_id

    def test_iam_section_has_account_id_and_summary(self, moto_aws):
        # The normaliser reads both account_id (for the node's id)
        # and get_account_summary (for its properties).
        data = fetch_aws_data()
        assert "account_id" in data["iam"]
        assert isinstance(data["iam"]["account_id"], str)
        assert data["iam"]["account_id"] != ""
        assert "get_account_summary" in data["iam"]
        assert "SummaryMap" in data["iam"]["get_account_summary"]

    def test_iam_section_has_password_policy_error_marker_when_unset(self, moto_aws):
        # A fresh moto account has no password policy configured,
        # same as a fresh real account. get_account_password_policy
        # raises NoSuchEntityException; _safe_call must catch it and
        # produce an '_error' marker rather than letting the whole
        # scan blow up.
        data = fetch_aws_data()
        assert "get_account_password_policy" in data["iam"]
        assert "_error" in data["iam"]["get_account_password_policy"]

    def test_iam_section_reflects_configured_password_policy(self, moto_aws):
        iam = boto3.client("iam", region_name="eu-west-2")
        iam.update_account_password_policy(MinimumPasswordLength=16)

        data = fetch_aws_data()
        policy = data["iam"]["get_account_password_policy"]
        assert "_error" not in policy
        assert policy["PasswordPolicy"]["MinimumPasswordLength"] == 16

    def test_iam_section_has_list_users_and_user_details(self, moto_aws):
        data = fetch_aws_data()
        assert "list_users" in data["iam"]
        assert "user_details" in data["iam"]

    def test_user_details_entry_exists_for_every_user(self, moto_aws):
        # Same invariant as bucket_details/key_details: every user in
        # list_users must have a corresponding user_details entry.
        iam = boto3.client("iam", region_name="eu-west-2")
        iam.create_user(UserName="test-user-alpha")
        iam.create_user(UserName="test-user-bravo")

        data = fetch_aws_data()
        listed_usernames = {u["UserName"] for u in data["iam"]["list_users"]["Users"]}
        detail_usernames = set(data["iam"]["user_details"].keys())
        assert listed_usernames == detail_usernames

    def test_user_details_reflects_created_access_key(self, moto_aws):
        iam = boto3.client("iam", region_name="eu-west-2")
        iam.create_user(UserName="test-user-with-key")
        iam.create_access_key(UserName="test-user-with-key")

        data = fetch_aws_data()
        key_metadata = data["iam"]["user_details"]["test-user-with-key"][
            "list_access_keys"
        ]["AccessKeyMetadata"]
        assert len(key_metadata) == 1
        assert key_metadata[0]["Status"] == "Active"

    def test_user_details_has_login_profile_error_marker_when_no_console_access(
        self, moto_aws
    ):
        iam = boto3.client("iam", region_name="eu-west-2")
        iam.create_user(UserName="test-user-programmatic-only")

        data = fetch_aws_data()
        login_profile = data["iam"]["user_details"][
            "test-user-programmatic-only"
        ]["get_login_profile"]
        assert "_error" in login_profile

    def test_user_details_reflects_created_console_login_profile(self, moto_aws):
        iam = boto3.client("iam", region_name="eu-west-2")
        iam.create_user(UserName="test-user-with-console-login")
        iam.create_login_profile(
            UserName="test-user-with-console-login", Password="Sup3rSecret!23"
        )

        data = fetch_aws_data()
        login_profile = data["iam"]["user_details"][
            "test-user-with-console-login"
        ]["get_login_profile"]
        assert "_error" not in login_profile
        assert login_profile["LoginProfile"]["UserName"] == "test-user-with-console-login"

    def test_cloudtrail_section_has_describe_trails_and_trail_status(self, moto_aws):
        data = fetch_aws_data()
        assert "describe_trails" in data["cloudtrail"]
        assert "trail_status" in data["cloudtrail"]
        assert isinstance(data["cloudtrail"]["describe_trails"]["trailList"], list)
        assert isinstance(data["cloudtrail"]["trail_status"], dict)

    def test_trail_status_entry_exists_for_every_trail(self, moto_aws):
        cloudtrail = boto3.client("cloudtrail", region_name="eu-west-2")
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket="test-cloudtrail-bucket",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_bucket_policy(
            Bucket="test-cloudtrail-bucket",
            Policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::test-cloudtrail-bucket/*",
                }],
            }),
        )
        cloudtrail.create_trail(
            Name="test-trail", S3BucketName="test-cloudtrail-bucket"
        )

        data = fetch_aws_data()
        trail_names = {
            t["Name"] for t in data["cloudtrail"]["describe_trails"]["trailList"]
        }
        status_names = set(data["cloudtrail"]["trail_status"].keys())
        assert trail_names == status_names

    def test_s3control_section_has_error_marker_when_unset(self, moto_aws):
        # A fresh moto/real account has no account-level Public
        # Access Block configured. get_public_access_block raises
        # NoSuchPublicAccessBlockConfigurationException; _safe_call
        # must catch it, same as the password policy case.
        data = fetch_aws_data()
        assert "get_public_access_block" in data["s3control"]
        assert "_error" in data["s3control"]["get_public_access_block"]

    def test_s3control_section_reflects_configured_pab(self, moto_aws):
        sts = boto3.client("sts", region_name="eu-west-2")
        account_id = sts.get_caller_identity()["Account"]

        s3control = boto3.client("s3control", region_name="eu-west-2")
        s3control.put_public_access_block(
            AccountId=account_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        data = fetch_aws_data()
        pab = data["s3control"]["get_public_access_block"]
        assert "_error" not in pab
        assert pab["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True

    def test_trail_status_reflects_logging_state(self, moto_aws):
        cloudtrail = boto3.client("cloudtrail", region_name="eu-west-2")
        s3 = boto3.client("s3", region_name="eu-west-2")
        s3.create_bucket(
            Bucket="test-cloudtrail-bucket-2",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-2"},
        )
        s3.put_bucket_policy(
            Bucket="test-cloudtrail-bucket-2",
            Policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": "arn:aws:s3:::test-cloudtrail-bucket-2/*",
                }],
            }),
        )
        cloudtrail.create_trail(
            Name="test-trail-2", S3BucketName="test-cloudtrail-bucket-2"
        )
        cloudtrail.start_logging(Name="test-trail-2")

        data = fetch_aws_data()
        assert data["cloudtrail"]["trail_status"]["test-trail-2"]["IsLogging"] is True

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

    def test_key_details_has_all_three_kms_calls(self, moto_aws):
        kms = boto3.client("kms", region_name="eu-west-2")
        created = kms.create_key(Description="test-key")
        key_id = created["KeyMetadata"]["KeyId"]

        data = fetch_aws_data()
        assert set(data["kms"]["key_details"][key_id].keys()) == {
            "describe_key",
            "get_key_rotation_status",
            "get_key_policy",
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
        assert isinstance(data["iam"]["list_users"]["Users"], list)
        assert isinstance(data["iam"]["user_details"], dict)
        assert isinstance(data["cloudtrail"]["describe_trails"]["trailList"], list)
        assert isinstance(data["s3control"]["get_public_access_block"], dict)
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