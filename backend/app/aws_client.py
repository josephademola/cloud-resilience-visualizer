"""
Live AWS client.

Reads real AWS configuration via boto3 and returns the data in
exactly the same shape as mock_aws.json. The normaliser downstream
doesn't know or care whether it's reading a static mock or a real
account — which is why we designed the mock to look like boto3
responses in the first place. Phase 6 is the payoff for that
decision.

Design notes:

- boto3 client construction uses the default profile and default
  region — whatever `aws configure` set up on this machine. No
  hardcoded credentials, no hardcoded region.

- Every per-resource or account-wide call that could plausibly fail
  in a healthy account (per-bucket S3 calls, per-key KMS calls,
  per-user IAM calls, per-trail CloudTrail calls, and account-wide
  calls like get_account_password_policy) goes through the single
  _safe_call() helper, which catches ClientError and produces the
  '_error' marker the mock uses, rather than each resource type
  having its own near-identical wrapper. The normaliser's helpers
  already treat missing keys as fail-closed, so an error on
  encryption fetch becomes 'encryption not enabled' downstream —
  which is the right security default.

- boto3's 'ResponseMetadata' key gets stripped from every response
  before returning. That metadata contains request IDs and HTTP
  status; it's not part of the data model and shouldn't leak into
  the topology.

- No caching, no pagination, no retries beyond boto3's defaults.
  These are Phase 8 optimisations. Right now we're proving the
  swap works.
"""

from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import ClientError


def fetch_aws_data() -> dict[str, Any]:
    """
    Query the configured AWS account and return the environment in
    exactly the shape of mock_aws.json.

    Raises whatever boto3 raises for unrecoverable errors (invalid
    credentials, network failure, IAM permission denied). Per-bucket
    S3 errors are caught individually and represented via '_error'
    markers in the response.
    """
    ec2 = boto3.client("ec2")
    rds = boto3.client("rds")
    s3 = boto3.client("s3")
    kms = boto3.client("kms")
    iam = boto3.client("iam")
    sts = boto3.client("sts")
    cloudtrail = boto3.client("cloudtrail")

    return {
        "ec2": {
            "describe_vpcs": _strip_metadata(ec2.describe_vpcs()),
            "describe_subnets": _strip_metadata(ec2.describe_subnets()),
            "describe_internet_gateways": _strip_metadata(
                ec2.describe_internet_gateways()
            ),
            "describe_instances": _strip_metadata(ec2.describe_instances()),
            "describe_security_groups": _strip_metadata(
                ec2.describe_security_groups()
            ),
        },
        "rds": {
            "describe_db_instances": _strip_metadata(rds.describe_db_instances()),
        },
        "s3": {
            "list_buckets": _strip_metadata(s3.list_buckets()),
            "bucket_details": _fetch_bucket_details(s3),
        },
        "kms": {
            "list_keys": _strip_metadata(kms.list_keys()),
            "key_details": _fetch_kms_key_details(kms),
        },
        "iam": {
            "account_id": sts.get_caller_identity()["Account"],
            "get_account_summary": _strip_metadata(iam.get_account_summary()),
            "get_account_password_policy": _safe_call(
                iam.get_account_password_policy
            ),
            "list_users": _strip_metadata(iam.list_users()),
            "user_details": _fetch_iam_user_details(iam),
        },
        "cloudtrail": {
            "describe_trails": _strip_metadata(cloudtrail.describe_trails()),
            "trail_status": _fetch_trail_statuses(cloudtrail),
        },
    }


def _fetch_bucket_details(s3) -> dict[str, dict]:
    """
    For each bucket in the account, fetch ACL, PAB, encryption,
    versioning, logging, lifecycle, and policy config. Per-bucket
    errors are captured as '_error' markers rather than propagated —
    one broken bucket shouldn't kill the whole scan.
    """
    buckets_response = s3.list_buckets()
    details: dict[str, dict] = {}

    for bucket in buckets_response.get("Buckets", []):
        name = bucket["Name"]
        details[name] = {
            "get_bucket_acl": _safe_call(s3.get_bucket_acl, Bucket=name),
            "get_public_access_block": _safe_call(
                s3.get_public_access_block, Bucket=name
            ),
            "get_bucket_encryption": _safe_call(
                s3.get_bucket_encryption, Bucket=name
            ),
            "get_bucket_versioning": _safe_call(
                s3.get_bucket_versioning, Bucket=name
            ),
            "get_bucket_logging": _safe_call(
                s3.get_bucket_logging, Bucket=name
            ),
            "get_bucket_lifecycle_configuration": _safe_call(
                s3.get_bucket_lifecycle_configuration, Bucket=name
            ),
            "get_bucket_policy": _safe_call(
                s3.get_bucket_policy, Bucket=name
            ),
        }
    return details


def _fetch_kms_key_details(kms) -> dict[str, dict]:
    """
    For each KMS key in the account, fetch its metadata and rotation
    status. Per-key errors are captured as '_error' markers rather
    than propagated, same tolerance as per-bucket S3 detail calls —
    for example, get_key_rotation_status raises for asymmetric or
    HMAC keys, which don't support rotation at all.
    """
    keys_response = kms.list_keys()
    details: dict[str, dict] = {}

    for key in keys_response.get("Keys", []):
        key_id = key["KeyId"]
        details[key_id] = {
            "describe_key": _safe_call(kms.describe_key, KeyId=key_id),
            "get_key_rotation_status": _safe_call(
                kms.get_key_rotation_status, KeyId=key_id
            ),
        }
    return details


def _fetch_iam_user_details(iam) -> dict[str, dict]:
    """
    For each IAM user in the account, fetch their access key
    metadata. Per-user errors are captured as '_error' markers
    rather than propagated, same tolerance as per-bucket and per-key
    detail calls.
    """
    users_response = iam.list_users()
    details: dict[str, dict] = {}

    for user in users_response.get("Users", []):
        username = user["UserName"]
        details[username] = {
            "list_access_keys": _safe_call(
                iam.list_access_keys, UserName=username
            ),
        }
    return details


def _fetch_trail_statuses(cloudtrail) -> dict[str, dict]:
    """
    For each CloudTrail trail in the account, fetch its logging
    status. Per-trail errors are captured as '_error' markers rather
    than propagated, same tolerance as every other per-resource
    detail call. Empty when the account has no trails at all.
    """
    trails_response = cloudtrail.describe_trails()
    statuses: dict[str, dict] = {}

    for trail in trails_response.get("trailList", []):
        name = trail["Name"]
        statuses[name] = _safe_call(cloudtrail.get_trail_status, Name=name)

    return statuses


def _safe_call(method, **kwargs) -> dict:
    """
    Call an AWS API method — with or without an identifying keyword
    argument (Bucket=, KeyId=, UserName=, Name=, or none at all for
    an account-wide call like get_account_summary). On success,
    return the response minus boto3 metadata. On failure, return an
    '_error' marker rather than propagating: a failure here is often
    expected, not exceptional — a healthy account that simply never
    configured the thing being asked about (NoSuchEntityException for
    no password policy), or a resource that doesn't support the
    operation (get_key_rotation_status on an asymmetric KMS key). One
    broken resource shouldn't invalidate the whole scan.
    """
    try:
        response = method(**kwargs)
        return _strip_metadata(response)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "UnknownError")
        return {"_error": error_code}


def _strip_metadata(response: dict) -> dict:
    """
    Remove boto3's ResponseMetadata key AND convert nested datetime
    objects to ISO-8601 strings.

    boto3 returns creation dates, launch times etc. as native
    Python datetime objects. The mock file has these as strings,
    so we convert to keep the shape identical. json.dump chokes on
    raw datetime; the mock stayed as strings for exactly this reason.
    """
    if isinstance(response, dict):
        cleaned = {k: v for k, v in response.items() if k != "ResponseMetadata"}
        return _serialise_datetimes(cleaned)
    return response


def _serialise_datetimes(obj):
    """
    Walk a nested dict/list structure and convert every datetime
    value to its ISO-8601 string representation. Recursive so it
    handles boto3's deep responses (VPCs contain Tags which contain
    strings, subnets contain instances which contain timestamps).
    """
    from datetime import datetime

    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _serialise_datetimes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_serialise_datetimes(item) for item in obj]
    return obj