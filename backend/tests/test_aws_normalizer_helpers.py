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
    _is_bucket_public_via_authenticated_users_acl,
    S3_AUTHENTICATED_USERS_URI,
    _is_pab_fully_enabled,
    _is_bucket_encryption_enabled,
    _is_bucket_versioning_enabled,
    _is_bucket_logging_enabled,
    _is_bucket_lifecycle_configured,
    _has_enabled_lifecycle_rule,
    _is_tls_enforced,
    _has_overly_broad_key_policy_principal,
    _has_admin_policy_attached,
    _has_wildcard_action_resource_policy,
    S3_ALL_USERS_URI,
    _security_group_allows_ingress_on_port,
    _instance_has_unencrypted_ebs_volume,
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


# --- _is_bucket_public_via_authenticated_users_acl ---------------------
class TestIsBucketPublicViaAuthenticatedUsersAcl:

    def test_detects_authenticatedusers_grant(self):
        acl = {
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": S3_AUTHENTICATED_USERS_URI},
                    "Permission": "READ",
                }
            ]
        }
        assert _is_bucket_public_via_authenticated_users_acl(acl) is True

    def test_returns_false_for_owner_only_grant(self):
        acl = {
            "Grants": [
                {
                    "Grantee": {"Type": "CanonicalUser", "ID": "abc"},
                    "Permission": "FULL_CONTROL",
                }
            ]
        }
        assert _is_bucket_public_via_authenticated_users_acl(acl) is False

    def test_returns_false_for_allusers_grant(self):
        # Distinct grantee, distinct property -- an AllUsers grant
        # alone must not also trip the AuthenticatedUsers check.
        acl = {
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": S3_ALL_USERS_URI},
                    "Permission": "READ",
                }
            ]
        }
        assert _is_bucket_public_via_authenticated_users_acl(acl) is False

    def test_returns_false_for_empty_grants(self):
        assert _is_bucket_public_via_authenticated_users_acl({"Grants": []}) is False

    def test_returns_false_for_missing_grants_key(self):
        assert _is_bucket_public_via_authenticated_users_acl({}) is False


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


# --- _is_bucket_versioning_enabled -------------------------------------
class TestIsBucketVersioningEnabled:

    def test_returns_true_when_status_is_enabled(self):
        assert _is_bucket_versioning_enabled({"Status": "Enabled"}) is True

    def test_returns_false_when_status_is_suspended(self):
        # Versioning that was turned on and later suspended is not
        # currently protecting the bucket.
        assert _is_bucket_versioning_enabled({"Status": "Suspended"}) is False

    def test_returns_false_when_never_configured(self):
        # Real boto3 returns an empty dict, not an error, when
        # versioning has never been touched on a bucket.
        assert _is_bucket_versioning_enabled({}) is False


# --- _is_bucket_logging_enabled -----------------------------------------
class TestIsBucketLoggingEnabled:

    def test_returns_true_when_logging_enabled_key_present(self):
        logging_config = {
            "LoggingEnabled": {
                "TargetBucket": "logs-bucket",
                "TargetPrefix": "access/",
            }
        }
        assert _is_bucket_logging_enabled(logging_config) is True

    def test_returns_false_when_never_configured(self):
        # Real boto3 returns an empty dict, not an error, when access
        # logging has never been configured on a bucket.
        assert _is_bucket_logging_enabled({}) is False


# --- _is_bucket_lifecycle_configured -------------------------------------
class TestIsBucketLifecycleConfigured:

    def test_returns_true_when_rules_present(self):
        lifecycle = {"Rules": [{"ID": "expire-old", "Status": "Enabled"}]}
        assert _is_bucket_lifecycle_configured(lifecycle) is True

    def test_returns_false_when_error_marker_present(self):
        # Our mock convention: _error means no lifecycle configuration
        # exists, matching real boto3's NoSuchLifecycleConfiguration.
        lifecycle = {"_error": "NoSuchLifecycleConfiguration"}
        assert _is_bucket_lifecycle_configured(lifecycle) is False

    def test_returns_false_when_rules_empty(self):
        assert _is_bucket_lifecycle_configured({"Rules": []}) is False


# --- _has_enabled_lifecycle_rule -------------------------------------------
class TestHasEnabledLifecycleRule:

    def test_returns_true_when_a_rule_is_enabled(self):
        lifecycle = {"Rules": [{"ID": "expire-old", "Status": "Enabled"}]}
        assert _has_enabled_lifecycle_rule(lifecycle) is True

    def test_returns_false_when_all_rules_disabled(self):
        lifecycle = {"Rules": [{"ID": "expire-old", "Status": "Disabled"}]}
        assert _has_enabled_lifecycle_rule(lifecycle) is False

    def test_returns_true_when_at_least_one_of_several_rules_is_enabled(self):
        lifecycle = {
            "Rules": [
                {"ID": "old-disabled-rule", "Status": "Disabled"},
                {"ID": "current-rule", "Status": "Enabled"},
            ]
        }
        assert _has_enabled_lifecycle_rule(lifecycle) is True

    def test_returns_false_when_error_marker_present(self):
        lifecycle = {"_error": "NoSuchLifecycleConfiguration"}
        assert _has_enabled_lifecycle_rule(lifecycle) is False

    def test_returns_false_when_rules_empty(self):
        assert _has_enabled_lifecycle_rule({"Rules": []}) is False


# --- _is_tls_enforced -----------------------------------------------------
class TestIsTlsEnforced:

    _DENY_POLICY = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransport",'
        '"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*",'
        '"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}'
    )

    def test_returns_true_when_deny_statement_present(self):
        assert _is_tls_enforced({"Policy": self._DENY_POLICY}) is True

    def test_returns_false_when_error_marker_present(self):
        # Our mock convention: _error means no bucket policy exists at
        # all, matching real boto3's NoSuchBucketPolicy.
        assert _is_tls_enforced({"_error": "NoSuchBucketPolicy"}) is False

    def test_returns_false_when_policy_has_no_deny_statement(self):
        allow_only_policy = (
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"AWS":"arn:aws:iam::123456789012:root"},'
            '"Action":"s3:GetObject","Resource":"*"}]}'
        )
        assert _is_tls_enforced({"Policy": allow_only_policy}) is False

    def test_returns_false_when_policy_is_unparseable(self):
        assert _is_tls_enforced({"Policy": "not valid json"}) is False


# --- _has_overly_broad_key_policy_principal --------------------------------
class TestHasOverlyBroadKeyPolicyPrincipal:

    _ROOT_ONLY_POLICY = (
        '{"Version":"2012-10-17","Statement":[{"Sid":"EnableRootAccess",'
        '"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},'
        '"Action":"kms:*","Resource":"*"}]}'
    )

    def test_returns_false_for_root_only_policy(self):
        # The standard baseline every KMS key policy legitimately has
        # -- a specific account ARN, not a wildcard.
        assert _has_overly_broad_key_policy_principal(
            {"Policy": self._ROOT_ONLY_POLICY}
        ) is False

    def test_returns_true_for_bare_wildcard_principal(self):
        policy = (
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}'
        )
        assert _has_overly_broad_key_policy_principal({"Policy": policy}) is True

    def test_returns_true_for_aws_wildcard_principal(self):
        policy = (
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"AWS":"*"},"Action":"kms:Decrypt","Resource":"*"}]}'
        )
        assert _has_overly_broad_key_policy_principal({"Policy": policy}) is True

    def test_returns_false_when_wildcard_has_a_condition(self):
        # A Condition is a legitimate way to narrow "*" back down
        # (e.g. restricting to an AWS Organization) -- only an
        # UNCONDITIONED wildcard is flagged.
        policy = (
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"AWS":"*"},"Action":"kms:Decrypt","Resource":"*",'
            '"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-example"}}}]}'
        )
        assert _has_overly_broad_key_policy_principal({"Policy": policy}) is False

    def test_returns_false_when_wildcard_is_in_a_deny_statement(self):
        # A Deny with a wildcard principal RESTRICTS access, it
        # doesn't grant it -- only Allow statements are checked.
        policy = (
            '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",'
            '"Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}'
        )
        assert _has_overly_broad_key_policy_principal({"Policy": policy}) is False

    def test_returns_false_when_error_marker_present(self):
        assert _has_overly_broad_key_policy_principal(
            {"_error": "NotFoundException"}
        ) is False

    def test_returns_false_when_policy_is_unparseable(self):
        assert _has_overly_broad_key_policy_principal(
            {"Policy": "not valid json"}
        ) is False

    def test_returns_false_when_policy_key_missing(self):
        assert _has_overly_broad_key_policy_principal({}) is False


# --- _has_admin_policy_attached ---------------------------------------
class TestHasAdminPolicyAttached:

    def test_returns_true_when_administrator_access_attached(self):
        response = {
            "AttachedPolicies": [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                }
            ]
        }
        assert _has_admin_policy_attached(response) is True

    def test_returns_false_when_other_policies_attached(self):
        response = {
            "AttachedPolicies": [
                {
                    "PolicyName": "ReadOnlyAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                }
            ]
        }
        assert _has_admin_policy_attached(response) is False

    def test_returns_false_when_no_policies_attached(self):
        assert _has_admin_policy_attached({"AttachedPolicies": []}) is False

    def test_returns_false_when_error_marker_present(self):
        # Detection signal: an errored/missing fetch means we don't
        # know, and we don't invent an admin grant out of that
        # absence, same semantic as has_console_login.
        assert _has_admin_policy_attached({"_error": "NotFoundException"}) is False

    def test_returns_false_when_key_missing_entirely(self):
        assert _has_admin_policy_attached({}) is False


# --- _has_wildcard_action_resource_policy ------------------------------
class TestHasWildcardActionResourcePolicy:

    def _managed_document(self, statement: dict) -> dict:
        return {
            "attached_policy_documents": {
                "arn:aws:iam::123456789012:policy/custom": {
                    "PolicyVersion": {
                        "Document": {"Version": "2012-10-17", "Statement": [statement]}
                    }
                }
            }
        }

    def _inline_document(self, statement: dict) -> dict:
        return {
            "inline_policy_documents": {
                "custom-inline": {
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [statement],
                    }
                }
            }
        }

    def test_returns_true_for_wildcard_in_managed_policy(self):
        statement = {"Effect": "Allow", "Action": "*", "Resource": "*"}
        assert _has_wildcard_action_resource_policy(
            self._managed_document(statement)
        ) is True

    def test_returns_true_for_wildcard_in_inline_policy(self):
        statement = {"Effect": "Allow", "Action": "*", "Resource": "*"}
        assert _has_wildcard_action_resource_policy(
            self._inline_document(statement)
        ) is True

    def test_returns_true_when_wildcard_is_inside_an_action_list(self):
        statement = {"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": "*"}
        assert _has_wildcard_action_resource_policy(
            self._managed_document(statement)
        ) is True

    def test_returns_false_when_only_action_is_wildcard(self):
        statement = {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}
        assert _has_wildcard_action_resource_policy(
            self._managed_document(statement)
        ) is False

    def test_returns_false_when_only_resource_is_wildcard(self):
        statement = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        assert _has_wildcard_action_resource_policy(
            self._managed_document(statement)
        ) is False

    def test_returns_false_when_statement_is_deny(self):
        statement = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        assert _has_wildcard_action_resource_policy(
            self._managed_document(statement)
        ) is False

    def test_returns_false_when_condition_narrows_wildcard(self):
        statement = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
        }
        assert _has_wildcard_action_resource_policy(
            self._managed_document(statement)
        ) is False

    def test_returns_false_for_least_privilege_policy(self):
        statement = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::bucket/*",
        }
        assert _has_wildcard_action_resource_policy(
            self._managed_document(statement)
        ) is False

    def test_ignores_errored_managed_policy_document(self):
        details = {
            "attached_policy_documents": {
                "arn:aws:iam::aws:policy/Broken": {"_error": "NotFoundException"}
            }
        }
        assert _has_wildcard_action_resource_policy(details) is False

    def test_ignores_errored_inline_policy_document(self):
        details = {
            "inline_policy_documents": {
                "broken-inline": {"_error": "NoSuchEntityException"}
            }
        }
        assert _has_wildcard_action_resource_policy(details) is False


# --- _security_group_allows_ingress_on_port ----------------------------
class TestSecurityGroupAllowsIngressOnPort:

    def _sg(self, *rules: dict) -> dict:
        return {"GroupId": "sg-test", "IpPermissions": list(rules)}

    def test_returns_true_for_exact_port_open_to_ipv4_world(self):
        sg = self._sg({
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        })
        assert _security_group_allows_ingress_on_port(sg, 22) is True

    def test_returns_true_for_port_inside_a_wider_open_range(self):
        sg = self._sg({
            "IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        })
        assert _security_group_allows_ingress_on_port(sg, 22) is True

    def test_returns_true_for_ipv6_world_range(self):
        sg = self._sg({
            "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        })
        assert _security_group_allows_ingress_on_port(sg, 3389) is True

    def test_returns_true_for_all_traffic_protocol_negative_one(self):
        # IpProtocol "-1" has no FromPort/ToPort at all -- it already
        # covers every port, this one included.
        sg = self._sg({
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        })
        assert _security_group_allows_ingress_on_port(sg, 22) is True

    def test_returns_false_when_port_is_outside_the_rule_range(self):
        sg = self._sg({
            "IpProtocol": "tcp", "FromPort": 80, "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        })
        assert _security_group_allows_ingress_on_port(sg, 22) is False

    def test_returns_false_when_open_port_is_scoped_to_a_specific_cidr(self):
        # A real restriction (e.g. an office IP range), not the world --
        # this must not be flagged.
        sg = self._sg({
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "203.0.113.0/24"}],
        })
        assert _security_group_allows_ingress_on_port(sg, 22) is False

    def test_returns_false_for_udp_protocol(self):
        sg = self._sg({
            "IpProtocol": "udp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        })
        assert _security_group_allows_ingress_on_port(sg, 22) is False

    def test_returns_false_for_security_group_with_no_rules(self):
        assert _security_group_allows_ingress_on_port(self._sg(), 22) is False


# --- _instance_has_unencrypted_ebs_volume -------------------------------
class TestInstanceHasUnencryptedEbsVolume:

    def _volumes_response(self, *volumes: dict) -> dict:
        return {"Volumes": list(volumes)}

    def _volume(self, instance_id: str, encrypted: bool) -> dict:
        return {
            "Encrypted": encrypted,
            "Attachments": [{"InstanceId": instance_id}],
        }

    def test_returns_true_when_attached_volume_is_unencrypted(self):
        response = self._volumes_response(self._volume("i-1", encrypted=False))
        assert _instance_has_unencrypted_ebs_volume("i-1", response) is True

    def test_returns_false_when_attached_volume_is_encrypted(self):
        response = self._volumes_response(self._volume("i-1", encrypted=True))
        assert _instance_has_unencrypted_ebs_volume("i-1", response) is False

    def test_returns_true_when_any_of_multiple_attached_volumes_is_unencrypted(self):
        response = self._volumes_response(
            self._volume("i-1", encrypted=True),
            self._volume("i-1", encrypted=False),
        )
        assert _instance_has_unencrypted_ebs_volume("i-1", response) is True

    def test_ignores_volumes_attached_to_a_different_instance(self):
        response = self._volumes_response(self._volume("i-other", encrypted=False))
        assert _instance_has_unencrypted_ebs_volume("i-1", response) is False

    def test_returns_false_when_instance_has_no_attached_volumes(self):
        # No '_error' marker, just genuinely nothing attached -- a
        # real, if unusual, state, not missing data.
        assert _instance_has_unencrypted_ebs_volume("i-1", {"Volumes": []}) is False

    def test_returns_true_fail_closed_on_error_marker(self):
        # A total fetch failure -- can't confirm any volume's
        # encryption state, so don't assume they're all encrypted.
        assert _instance_has_unencrypted_ebs_volume(
            "i-1", {"_error": "AccessDenied"}
        ) is True

    def test_returns_false_when_no_policies_at_all(self):
        assert _has_wildcard_action_resource_policy({}) is False

    def test_handles_single_statement_as_dict_not_list(self):
        # AWS permits a policy document's Statement to be a single
        # dict rather than a one-item list when there's only one
        # statement.
        details = {
            "attached_policy_documents": {
                "arn:aws:iam::123456789012:policy/custom": {
                    "PolicyVersion": {
                        "Document": {
                            "Version": "2012-10-17",
                            "Statement": {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            },
                        }
                    }
                }
            }
        }
        assert _has_wildcard_action_resource_policy(details) is True