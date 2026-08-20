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

- Per-bucket S3 calls (ACL, PAB, encryption, versioning, logging,
  lifecycle, policy) and per-key KMS calls (describe_key,
  rotation status) can fail individually without invalidating the
  whole scan. We catch ClientError and produce the '_error' marker
  the mock uses. The normaliser's helpers already treat missing keys
  as fail-closed, so an error on encryption fetch becomes
  'encryption not enabled' downstream — which is the right security
  default.

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
            "get_bucket_acl": _safe_bucket_call(s3.get_bucket_acl, name),
            "get_public_access_block": _safe_bucket_call(
                s3.get_public_access_block, name
            ),
            "get_bucket_encryption": _safe_bucket_call(
                s3.get_bucket_encryption, name
            ),
            "get_bucket_versioning": _safe_bucket_call(
                s3.get_bucket_versioning, name
            ),
            "get_bucket_logging": _safe_bucket_call(
                s3.get_bucket_logging, name
            ),
            "get_bucket_lifecycle_configuration": _safe_bucket_call(
                s3.get_bucket_lifecycle_configuration, name
            ),
            "get_bucket_policy": _safe_bucket_call(
                s3.get_bucket_policy, name
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
            "describe_key": _safe_kms_call(kms.describe_key, key_id),
            "get_key_rotation_status": _safe_kms_call(
                kms.get_key_rotation_status, key_id
            ),
        }
    return details


def _safe_bucket_call(method, bucket_name: str) -> dict:
    """
    Call a per-bucket S3 method. On success, return the response
    minus boto3 metadata. On failure, return an '_error' marker.
    """
    try:
        response = method(Bucket=bucket_name)
        return _strip_metadata(response)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "UnknownError")
        return {"_error": error_code}


def _safe_kms_call(method, key_id: str) -> dict:
    """
    Call a per-key KMS method. On success, return the response minus
    boto3 metadata. On failure, return an '_error' marker.
    """
    try:
        response = method(KeyId=key_id)
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