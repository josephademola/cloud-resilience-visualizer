"""
Unit tests for the AWS normalizer module.

This file covers the small helper functions in isolation — the tag
lookup helpers and the three S3 boolean computers. The per-resource
normalizers and the public normalize() function are covered in a
separate test file.
"""

from app.aws_normalizer import (
    _get_tag,
    _name_or_id,
    _is_bucket_public_via_acl,
    _is_pab_fully_enabled,
    _is_bucket_encryption_enabled,
    S3_ALL_USERS_URI,
)


# --- _get_tag ---------------------------------------------------------
class TestGetTag:

    def test_returns_value_when_key_present(self):
        tags = [{"Key": "Name", "Value": "web-01"}]
        assert _get_tag(tags, "Name") == "web-01"

    def test_returns_none_when_key_missing(self):
        tags = [{"Key": "Environment", "Value": "prod"}]
        assert _get_tag(tags, "Name") is None

    def test_returns_none_for_empty_list(self):
        assert _get_tag([], "Name") is None

    def test_returns_none_for_none_input(self):
        assert _get_tag(None, "Name") is None

    def test_returns_first_match_when_duplicate_keys(self):
        # AWS shouldn't produce duplicate tag keys, but defensively
        # handle them: return the first match deterministically.
        tags = [
            {"Key": "Name", "Value": "first"},
            {"Key": "Name", "Value": "second"},
        ]
        assert _get_tag(tags, "Name") == "first"


# --- _name_or_id ------------------------------------------------------
class TestNameOrId:

    def test_returns_name_tag_when_present(self):
        tags = [{"Key": "Name", "Value": "my-bucket"}]
        assert _name_or_id(tags, "fallback-id") == "my-bucket"

    def test_returns_fallback_when_tags_none(self):
        assert _name_or_id(None, "fallback-id") == "fallback-id"

    def test_returns_fallback_when_name_tag_absent(self):
        tags = [{"Key": "Environment", "Value": "prod"}]
        assert _name_or_id(tags, "fallback-id") == "fallback-id"

    def test_returns_fallback_when_name_tag_is_empty_string(self):
        # An empty Name value should fall back to the ID, not return ''.
        tags = [{"Key": "Name", "Value": ""}]
        assert _name_or_id(tags, "fallback-id") == "fallback-id"


# --- _is_bucket_public_via_acl ---------------------------------------
class TestIsBucketPublicViaAcl:

    def test_detects_allusers_grant(self):
        acl = {
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": S3_ALL_USERS_URI},
                    "Permission": "READ",
                }
            ]
        }
        assert _is_bucket_public_via_acl(acl) is True

    def test_returns_false_for_owner_only_grant(self):
        acl = {
            "Grants": [
                {
                    "Grantee": {"Type": "CanonicalUser", "ID": "abc"},
                    "Permission": "FULL_CONTROL",
                }
            ]
        }
        assert _is_bucket_public_via_acl(acl) is False

    def test_returns_false_for_empty_grants(self):
        assert _is_bucket_public_via_acl({"Grants": []}) is False

    def test_returns_false_for_missing_grants_key(self):
        assert _is_bucket_public_via_acl({}) is False


# --- _is_pab_fully_enabled -------------------------------------------
class TestIsPabFullyEnabled:

    def test_returns_true_when_all_four_flags_true(self):
        pab = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        assert _is_pab_fully_enabled(pab) is True

    def test_returns_false_when_any_flag_is_false(self):
        pab = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,  # one flag off
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        assert _is_pab_fully_enabled(pab) is False

    def test_returns_false_when_config_missing(self):
        # Treat missing PAB as "not enabled" — the safer assumption.
        assert _is_pab_fully_enabled({}) is False


# --- _is_bucket_encryption_enabled -----------------------------------
class TestIsBucketEncryptionEnabled:

    def test_returns_true_when_rules_present(self):
        encryption = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        }
        assert _is_bucket_encryption_enabled(encryption) is True

    def test_returns_false_when_error_marker_present(self):
        # Our mock convention: _error means encryption is absent.
        encryption = {"_error": "ServerSideEncryptionConfigurationNotFoundError"}
        assert _is_bucket_encryption_enabled(encryption) is False

    def test_returns_false_when_rules_empty(self):
        encryption = {"ServerSideEncryptionConfiguration": {"Rules": []}}
        assert _is_bucket_encryption_enabled(encryption) is False