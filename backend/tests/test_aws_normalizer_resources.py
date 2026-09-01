"""
Unit tests for the per-resource normalizer functions in
app.aws_normalizer.

Each test class targets one _normalize_* function and verifies:
  - The happy path: well-formed input produces the expected node shape.
  - Defensive behaviour: missing required fields are skipped (logged
    as a warning) rather than raising, so one bad record never kills
    the whole run.
  - Edge cases specific to that resource type (e.g. detached IGWs,
    explicit Tier tags overriding the heuristic).

Fixtures are deliberately small and hand-built — the smallest dict
that exercises the code path under test. End-to-end behaviour against
the real mock_aws.json lives in a separate integration test file.
"""

from app.aws_normalizer import (
    _normalize_vpcs,
    _normalize_subnets,
    _normalize_internet_gateways,
    _normalize_ec2_instances,
    _normalize_rds_instances,
    _normalize_s3_buckets,
    _normalize_kms_keys,
    _normalize_account,
    _normalize_iam_users,
    _normalize_security_groups,
)

# --- _normalize_vpcs --------------------------------------------------
class TestNormalizeVpcs:

    def test_returns_single_vpc_node_with_correct_shape(self):
        ec2_data = {
            "describe_vpcs": {
                "Vpcs": [
                    {
                        "VpcId": "vpc-aaa111",
                        "CidrBlock": "10.0.0.0/16",
                        "IsDefault": False,
                        "State": "available",
                        "Tags": [{"Key": "Name", "Value": "production-vpc"}],
                    }
                ]
            }
        }
        nodes = _normalize_vpcs(ec2_data)
        assert nodes == [
            {
                "id": "vpc-aaa111",
                "type": "vpc",
                "name": "production-vpc",
                "parent_id": None,
                "properties": {
                    "cidr_block": "10.0.0.0/16",
                    "is_default": False,
                    "state": "available",
                },
            }
        ]

    def test_uses_vpc_id_as_name_when_no_name_tag(self):
        # No Name tag in input -> the VpcId itself is the display name.
        ec2_data = {
            "describe_vpcs": {
                "Vpcs": [
                    {"VpcId": "vpc-no-name", "CidrBlock": "10.1.0.0/16"}
                ]
            }
        }
        nodes = _normalize_vpcs(ec2_data)
        assert len(nodes) == 1
        assert nodes[0]["name"] == "vpc-no-name"

    def test_skips_vpc_with_missing_id(self):
        # Without VpcId, nothing else in the topology could reference this
        # VPC as a parent. The normalizer logs a warning and continues
        # rather than raising — one bad record doesn't kill the run.
        ec2_data = {
            "describe_vpcs": {
                "Vpcs": [
                    {"CidrBlock": "10.0.0.0/16"},  # no VpcId
                    {"VpcId": "vpc-valid", "CidrBlock": "10.1.0.0/16"},
                ]
            }
        }
        nodes = _normalize_vpcs(ec2_data)
        assert len(nodes) == 1
        assert nodes[0]["id"] == "vpc-valid"

    def test_returns_empty_list_when_no_vpcs(self):
        ec2_data = {"describe_vpcs": {"Vpcs": []}}
        assert _normalize_vpcs(ec2_data) == []

    def test_returns_empty_list_when_describe_vpcs_missing(self):
        # Outer defensive read: a missing branch behaves the same as
        # "no resources of that service exist."
        assert _normalize_vpcs({}) == []


# --- _normalize_subnets ----------------------------------------------
class TestNormalizeSubnets:

    def test_returns_public_subnet_with_correct_shape(self):
        # MapPublicIpOnLaunch=True with no Tier tag -> heuristic
        # classifies the subnet as "public".
        ec2_data = {
            "describe_subnets": {
                "Subnets": [
                    {
                        "SubnetId": "subnet-pub111",
                        "VpcId": "vpc-aaa111",
                        "CidrBlock": "10.0.1.0/24",
                        "AvailabilityZone": "eu-west-2a",
                        "MapPublicIpOnLaunch": True,
                        "Tags": [{"Key": "Name", "Value": "public-1a"}],
                    }
                ]
            }
        }
        nodes = _normalize_subnets(ec2_data)
        assert nodes == [
            {
                "id": "subnet-pub111",
                "type": "subnet",
                "name": "public-1a",
                "parent_id": "vpc-aaa111",
                "properties": {
                    "cidr_block": "10.0.1.0/24",
                    "availability_zone": "eu-west-2a",
                    "tier": "public",
                    "map_public_ip_on_launch": True,
                },
            }
        ]

    def test_infers_private_tier_when_map_public_ip_false(self):
        # No Tier tag, MapPublicIpOnLaunch=False -> default to "private".
        ec2_data = {
            "describe_subnets": {
                "Subnets": [
                    {
                        "SubnetId": "subnet-priv111",
                        "VpcId": "vpc-aaa111",
                        "MapPublicIpOnLaunch": False,
                    }
                ]
            }
        }
        nodes = _normalize_subnets(ec2_data)
        assert nodes[0]["properties"]["tier"] == "private"
        assert nodes[0]["properties"]["map_public_ip_on_launch"] is False

    def test_explicit_tier_tag_overrides_heuristic(self):
        # Documented priority: explicit Tier tag > MapPublicIpOnLaunch
        # heuristic > default. Here the heuristic would say "public" but
        # the tag says "isolated"; the tag must win.
        ec2_data = {
            "describe_subnets": {
                "Subnets": [
                    {
                        "SubnetId": "subnet-aaa",
                        "VpcId": "vpc-aaa",
                        "MapPublicIpOnLaunch": True,
                        "Tags": [{"Key": "Tier", "Value": "isolated"}],
                    }
                ]
            }
        }
        nodes = _normalize_subnets(ec2_data)
        assert nodes[0]["properties"]["tier"] == "isolated"

    def test_skips_subnet_with_missing_subnet_id(self):
        ec2_data = {
            "describe_subnets": {
                "Subnets": [
                    {"VpcId": "vpc-aaa"},  # no SubnetId
                    {"SubnetId": "subnet-ok", "VpcId": "vpc-aaa"},
                ]
            }
        }
        nodes = _normalize_subnets(ec2_data)
        assert len(nodes) == 1
        assert nodes[0]["id"] == "subnet-ok"

    def test_skips_subnet_with_missing_vpc_id(self):
        # A subnet without a parent VPC has nowhere to sit in the
        # topology — drop it rather than guess.
        ec2_data = {
            "describe_subnets": {
                "Subnets": [
                    {"SubnetId": "subnet-orphan"},  # no VpcId
                ]
            }
        }
        assert _normalize_subnets(ec2_data) == []

    def test_returns_empty_list_when_no_subnets(self):
        assert _normalize_subnets({}) == []


# --- _normalize_internet_gateways ------------------------------------
class TestNormalizeInternetGateways:

    def test_returns_attached_igw_with_parent_and_state(self):
        ec2_data = {
            "describe_internet_gateways": {
                "InternetGateways": [
                    {
                        "InternetGatewayId": "igw-aaa111",
                        "Attachments": [
                            {"VpcId": "vpc-bbb222", "State": "available"}
                        ],
                        "Tags": [{"Key": "Name", "Value": "main-igw"}],
                    }
                ]
            }
        }
        nodes = _normalize_internet_gateways(ec2_data)
        assert nodes == [
            {
                "id": "igw-aaa111",
                "type": "internet_gateway",
                "name": "main-igw",
                "parent_id": "vpc-bbb222",
                "properties": {"state": "available"},
            }
        ]

    def test_detached_igw_has_null_parent_and_detached_state(self):
        # A freshly-created or freshly-orphaned IGW has no Attachments.
        # The function explicitly handles this as a "visible orphan" —
        # parent_id None, state "detached" — useful for later scanners
        # that flag unattached resources.
        ec2_data = {
            "describe_internet_gateways": {
                "InternetGateways": [
                    {
                        "InternetGatewayId": "igw-orphan",
                        "Attachments": [],
                    }
                ]
            }
        }
        nodes = _normalize_internet_gateways(ec2_data)
        assert nodes[0]["parent_id"] is None
        assert nodes[0]["properties"]["state"] == "detached"

    def test_uses_first_attachment_when_multiple(self):
        # Real AWS only attaches an IGW to one VPC, but the code reads
        # attachments[0] defensively. Lock that "first wins" behaviour
        # in so a future refactor can't silently change it.
        ec2_data = {
            "describe_internet_gateways": {
                "InternetGateways": [
                    {
                        "InternetGatewayId": "igw-multi",
                        "Attachments": [
                            {"VpcId": "vpc-first", "State": "available"},
                            {"VpcId": "vpc-second", "State": "attaching"},
                        ],
                    }
                ]
            }
        }
        nodes = _normalize_internet_gateways(ec2_data)
        assert nodes[0]["parent_id"] == "vpc-first"
        assert nodes[0]["properties"]["state"] == "available"

    def test_skips_igw_with_missing_id(self):
        ec2_data = {
            "describe_internet_gateways": {
                "InternetGateways": [
                    {"Attachments": []},  # no InternetGatewayId
                ]
            }
        }
        assert _normalize_internet_gateways(ec2_data) == []

    def test_returns_empty_list_when_no_igws(self):
        assert _normalize_internet_gateways({}) == []


# --- _normalize_ec2_instances ----------------------------------------
class TestNormalizeEc2Instances:

    def test_returns_instance_with_correct_shape(self):
        # Happy path: one reservation, one instance, full configuration.
        # Covers nested State.Name extraction and SecurityGroups -> sg_ids.
        ec2_data = {
            "describe_instances": {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-aaa111",
                                "SubnetId": "subnet-aaa",
                                "InstanceType": "t3.micro",
                                "State": {"Code": 16, "Name": "running"},
                                "PrivateIpAddress": "10.0.1.10",
                                "PublicIpAddress": "54.1.2.3",
                                "PlatformDetails": "Linux/UNIX",
                                "SecurityGroups": [
                                    {"GroupId": "sg-aaa", "GroupName": "web-sg"}
                                ],
                                "Tags": [{"Key": "Name", "Value": "web-01"}],
                            }
                        ]
                    }
                ]
            }
        }
        nodes = _normalize_ec2_instances(ec2_data)
        assert nodes == [
            {
                "id": "i-aaa111",
                "type": "ec2_instance",
                "name": "web-01",
                "parent_id": "subnet-aaa",
                "properties": {
                    "instance_type": "t3.micro",
                    "state": "running",
                    "private_ip": "10.0.1.10",
                    "public_ip": "54.1.2.3",
                    "platform": "Linux/UNIX",
                    "security_group_ids": ["sg-aaa"],
                    "imdsv2_required": False,
                    "has_unrestricted_ssh_ingress": False,
                    "has_unrestricted_rdp_ingress": False,
                    "has_unencrypted_ebs_volume": False,
                    "is_public_ip_in_private_subnet": False,
                },
            }
        ]

    def test_flattens_multiple_reservations_into_single_node_list(self):
        # AWS groups instances into "reservations" (one reservation =
        # one RunInstances API call). The topology doesn't care about
        # that grouping — we want one flat list of instances.
        ec2_data = {
            "describe_instances": {
                "Reservations": [
                    {"Instances": [{"InstanceId": "i-aaa", "SubnetId": "subnet-x"}]},
                    {"Instances": [{"InstanceId": "i-bbb", "SubnetId": "subnet-x"}]},
                    {"Instances": [{"InstanceId": "i-ccc", "SubnetId": "subnet-x"}]},
                ]
            }
        }
        nodes = _normalize_ec2_instances(ec2_data)
        assert [n["id"] for n in nodes] == ["i-aaa", "i-bbb", "i-ccc"]

    def test_flattens_multiple_instances_in_same_reservation(self):
        # AWS also allows N instances per RunInstances call -> N
        # instances share one reservation. Each must appear as its
        # own topology node.
        ec2_data = {
            "describe_instances": {
                "Reservations": [
                    {
                        "Instances": [
                            {"InstanceId": "i-aaa", "SubnetId": "subnet-x"},
                            {"InstanceId": "i-bbb", "SubnetId": "subnet-x"},
                        ]
                    }
                ]
            }
        }
        nodes = _normalize_ec2_instances(ec2_data)
        assert [n["id"] for n in nodes] == ["i-aaa", "i-bbb"]

    def test_filters_out_security_groups_with_missing_group_id(self):
        # A malformed SecurityGroups entry (no GroupId) should be
        # silently filtered rather than crashing the whole node.
        ec2_data = {
            "describe_instances": {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-aaa",
                                "SubnetId": "subnet-x",
                                "SecurityGroups": [
                                    {"GroupId": "sg-valid", "GroupName": "ok"},
                                    {"GroupName": "missing-id"},  # no GroupId
                                ],
                            }
                        ]
                    }
                ]
            }
        }
        nodes = _normalize_ec2_instances(ec2_data)
        assert nodes[0]["properties"]["security_group_ids"] == ["sg-valid"]

    def test_skips_instance_with_missing_instance_id(self):
        ec2_data = {
            "describe_instances": {
                "Reservations": [
                    {
                        "Instances": [
                            {"SubnetId": "subnet-x"},  # no InstanceId
                            {"InstanceId": "i-ok", "SubnetId": "subnet-x"},
                        ]
                    }
                ]
            }
        }
        nodes = _normalize_ec2_instances(ec2_data)
        assert [n["id"] for n in nodes] == ["i-ok"]

    def test_skips_instance_with_missing_subnet_id(self):
        # An instance with no SubnetId can't be placed in the topology.
        ec2_data = {
            "describe_instances": {
                "Reservations": [
                    {"Instances": [{"InstanceId": "i-orphan"}]},  # no SubnetId
                ]
            }
        }
        assert _normalize_ec2_instances(ec2_data) == []

    def test_returns_empty_list_when_no_reservations(self):
        assert _normalize_ec2_instances({}) == []


# --- _normalize_rds_instances ----------------------------------------
class TestNormalizeRdsInstances:

    def test_returns_rds_with_correct_shape(self):
        # Happy path: a well-configured RDS instance with one subnet
        # in its subnet group and one security group.
        rds_data = {
            "describe_db_instances": {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "prod-db",
                        "Engine": "mysql",
                        "EngineVersion": "8.0.35",
                        "DBInstanceStatus": "available",
                        "PubliclyAccessible": False,
                        "StorageEncrypted": True,
                        "MultiAZ": False,
                        "BackupRetentionPeriod": 7,
                        "DBSubnetGroup": {
                            "Subnets": [{"SubnetIdentifier": "subnet-priv"}]
                        },
                        "VpcSecurityGroups": [
                            {"VpcSecurityGroupId": "sg-db", "Status": "active"}
                        ],
                    }
                ]
            }
        }
        nodes = _normalize_rds_instances(rds_data)
        assert nodes == [
            {
                "id": "prod-db",
                "type": "rds_instance",
                "name": "prod-db",
                "parent_id": "subnet-priv",
                "properties": {
                    "engine": "mysql",
                    "engine_version": "8.0.35",
                    "status": "available",
                    "publicly_accessible": False,
                    "storage_encrypted": True,
                    "multi_az": False,
                    "backup_retention_days": 7,
                    "security_group_ids": ["sg-db"],
                },
            }
        ]

    def test_uses_first_subnet_in_subnet_group_as_parent(self):
        # Multi-AZ RDS spans multiple subnets, but the topology needs
        # one parent for layout. The function picks the first listed.
        rds_data = {
            "describe_db_instances": {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "multi-az-db",
                        "DBSubnetGroup": {
                            "Subnets": [
                                {"SubnetIdentifier": "subnet-first"},
                                {"SubnetIdentifier": "subnet-second"},
                            ]
                        },
                    }
                ]
            }
        }
        nodes = _normalize_rds_instances(rds_data)
        assert nodes[0]["parent_id"] == "subnet-first"

    def test_parent_id_is_none_when_db_subnet_group_missing(self):
        # No DBSubnetGroup at all -> nothing to infer a parent from.
        # Same end-state as an empty Subnets list (both reach the
        # `subnets = []` branch); the missing-group case is the more
        # common real-world shape so we test that one.
        rds_data = {
            "describe_db_instances": {
                "DBInstances": [
                    {"DBInstanceIdentifier": "orphan-db"}  # no DBSubnetGroup
                ]
            }
        }
        nodes = _normalize_rds_instances(rds_data)
        assert nodes[0]["parent_id"] is None

    def test_extracts_vpc_security_group_id_not_group_id(self):
        # RDS uses 'VpcSecurityGroupId' where EC2 uses 'GroupId' — an
        # AWS API naming inconsistency the function docstring flags.
        # Lock this defence in: an entry with only the EC2-style
        # 'GroupId' field must be filtered out, only the RDS-style
        # field counts.
        rds_data = {
            "describe_db_instances": {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "db-1",
                        "VpcSecurityGroups": [
                            {"VpcSecurityGroupId": "sg-right"},
                            {"GroupId": "sg-wrong"},  # EC2-style; ignored
                        ],
                    }
                ]
            }
        }
        nodes = _normalize_rds_instances(rds_data)
        assert nodes[0]["properties"]["security_group_ids"] == ["sg-right"]

    def test_skips_rds_with_missing_identifier(self):
        rds_data = {
            "describe_db_instances": {
                "DBInstances": [
                    {"Engine": "mysql"},  # no DBInstanceIdentifier
                    {"DBInstanceIdentifier": "ok-db", "Engine": "postgres"},
                ]
            }
        }
        nodes = _normalize_rds_instances(rds_data)
        assert [n["id"] for n in nodes] == ["ok-db"]

    def test_returns_empty_list_when_no_db_instances(self):
        assert _normalize_rds_instances({}) == []


# --- _normalize_s3_buckets -------------------------------------------
class TestNormalizeS3Buckets:

    # The well-known URI representing "anyone on the internet". A grant
    # to this URI in a bucket ACL is the canonical public-bucket signal.
    ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"

    def test_returns_secure_bucket_with_all_protections_on(self):
        # Happy path: bucket with no public ACL grant, all four PAB
        # flags enabled, and server-side encryption configured.
        # Every misconfig boolean should be the "safe" value.
        # parent_id is always None: S3 is a global service, not VPC-scoped.
        s3_data = {
            "list_buckets": {
                "Buckets": [
                    {"Name": "secure-logs", "CreationDate": "2024-01-15T10:00:00Z"}
                ]
            },
            "bucket_details": {
                "secure-logs": {
                    "get_bucket_acl": {
                        "Grants": [
                            {
                                "Grantee": {"Type": "CanonicalUser", "ID": "owner"},
                                "Permission": "FULL_CONTROL",
                            }
                        ]
                    },
                    "get_public_access_block": {
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        }
                    },
                    "get_bucket_encryption": {
                        "ServerSideEncryptionConfiguration": {
                            "Rules": [
                                {
                                    "ApplyServerSideEncryptionByDefault": {
                                        "SSEAlgorithm": "AES256"
                                    }
                                }
                            ]
                        }
                    },
                    "get_bucket_versioning": {"Status": "Enabled"},
                    "get_bucket_logging": {
                        "LoggingEnabled": {
                            "TargetBucket": "audit-logs",
                            "TargetPrefix": "secure-logs/",
                        }
                    },
                    "get_bucket_lifecycle_configuration": {
                        "Rules": [{"ID": "expire-old", "Status": "Enabled"}]
                    },
                    "get_bucket_policy": {
                        "Policy": (
                            '{"Version":"2012-10-17","Statement":['
                            '{"Effect":"Deny","Principal":"*","Action":"s3:*",'
                            '"Resource":"*","Condition":{"Bool":'
                            '{"aws:SecureTransport":"false"}}}]}'
                        )
                    },
                },
            },
        }
        nodes = _normalize_s3_buckets(s3_data)
        assert nodes == [
            {
                "id": "secure-logs",
                "type": "s3_bucket",
                "name": "secure-logs",
                "parent_id": None,
                "properties": {
                    "creation_date": "2024-01-15T10:00:00Z",
                    "is_public_via_acl": False,
                    "is_public_via_authenticated_users_acl": False,
                    "public_access_block_fully_enabled": True,
                    "encryption_enabled": True,
                    "encryption_algorithm": "AES256",
                    "encryption_kms_key_id": None,
                    "versioning_enabled": True,
                    "logging_enabled": True,
                    "lifecycle_configured": True,
                    "lifecycle_rule_enabled": True,
                    "tls_enforced": True,
                    "arn": "arn:aws:s3:::secure-logs",
                },
            }
        ]

    def test_returns_misconfigured_bucket_with_all_seven_flags_failing(self):
        # The S3 nightmare bucket: public ACL grant, PAB completely off,
        # encryption, lifecycle, and policy APIs would have raised in
        # real boto3 (our mock represents that as {"_error": "..."}),
        # and versioning and logging were never configured. All seven
        # misconfig booleans must reflect the insecure state.
        s3_data = {
            "list_buckets": {"Buckets": [{"Name": "public-uploads"}]},
            "bucket_details": {
                "public-uploads": {
                    "get_bucket_acl": {
                        "Grants": [
                            {
                                "Grantee": {
                                    "Type": "Group",
                                    "URI": self.ALL_USERS_URI,
                                },
                                "Permission": "READ",
                            }
                        ]
                    },
                    "get_public_access_block": {
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": False,
                            "IgnorePublicAcls": False,
                            "BlockPublicPolicy": False,
                            "RestrictPublicBuckets": False,
                        }
                    },
                    "get_bucket_encryption": {
                        "_error": "ServerSideEncryptionConfigurationNotFoundError"
                    },
                    "get_bucket_lifecycle_configuration": {
                        "_error": "NoSuchLifecycleConfiguration"
                    },
                    "get_bucket_policy": {
                        "_error": "NoSuchBucketPolicy"
                    },
                },
            },
        }
        nodes = _normalize_s3_buckets(s3_data)
        props = nodes[0]["properties"]
        assert props["is_public_via_acl"] is True
        assert props["public_access_block_fully_enabled"] is False
        assert props["encryption_enabled"] is False
        assert props["versioning_enabled"] is False
        assert props["logging_enabled"] is False
        assert props["lifecycle_configured"] is False
        assert props["tls_enforced"] is False

    def test_defaults_safely_when_bucket_details_missing(self):
        # A bucket appears in list_buckets but has no entry in
        # bucket_details (e.g. the detail API calls failed). The
        # helpers should treat absence as "not protected" rather than
        # crashing — fail-closed, not fail-open.
        s3_data = {
            "list_buckets": {"Buckets": [{"Name": "no-details-bucket"}]},
            "bucket_details": {},
        }
        nodes = _normalize_s3_buckets(s3_data)
        props = nodes[0]["properties"]
        assert props["is_public_via_acl"] is False
        assert props["public_access_block_fully_enabled"] is False
        assert props["encryption_enabled"] is False
        assert props["versioning_enabled"] is False
        assert props["logging_enabled"] is False
        assert props["lifecycle_configured"] is False
        assert props["tls_enforced"] is False

    def test_skips_bucket_with_missing_name(self):
        s3_data = {
            "list_buckets": {
                "Buckets": [
                    {},  # no Name
                    {"Name": "ok-bucket"},
                ]
            },
            "bucket_details": {},
        }
        nodes = _normalize_s3_buckets(s3_data)
        assert [n["id"] for n in nodes] == ["ok-bucket"]

    def test_returns_empty_list_when_no_buckets(self):
        assert _normalize_s3_buckets({}) == []


# --- _normalize_kms_keys -----------------------------------------------
class TestNormalizeKmsKeys:

    def test_returns_customer_managed_key_with_rotation_status(self):
        kms_data = {
            "list_keys": {
                "Keys": [{"KeyId": "key-1", "KeyArn": "arn:aws:kms:eu-west-2:123456789012:key/key-1"}]
            },
            "key_details": {
                "key-1": {
                    "describe_key": {
                        "KeyMetadata": {
                            "KeyId": "key-1",
                            "Description": "app-key",
                            "KeyState": "Enabled",
                            "KeyManager": "CUSTOMER",
                        }
                    },
                    "get_key_rotation_status": {"KeyRotationEnabled": False},
                }
            },
        }
        nodes = _normalize_kms_keys(kms_data)
        assert nodes == [
            {
                "id": "key-1",
                "type": "kms_key",
                "name": "app-key",
                "parent_id": None,
                "properties": {
                    "key_state": "Enabled",
                    "key_rotation_enabled": False,
                    "arn": "arn:aws:kms:eu-west-2:123456789012:key/key-1",
                    "has_alias": False,
                    "key_policy_overly_broad": False,
                },
            }
        ]

    def test_excludes_aws_managed_keys(self):
        # AWS-managed keys rotate automatically with no owner control
        # over the setting — they must never become topology nodes.
        # See docs/design_decisions.md #9.
        kms_data = {
            "list_keys": {"Keys": [{"KeyId": "aws/s3"}]},
            "key_details": {
                "aws/s3": {
                    "describe_key": {
                        "KeyMetadata": {
                            "KeyId": "aws/s3",
                            "KeyState": "Enabled",
                            "KeyManager": "AWS",
                        }
                    },
                    "get_key_rotation_status": {"KeyRotationEnabled": True},
                }
            },
        }
        assert _normalize_kms_keys(kms_data) == []

    def test_defaults_safely_when_key_details_missing(self):
        # A key appears in list_keys but has no entry in key_details.
        # Missing KeyManager is not "CUSTOMER", so it's excluded —
        # fail-closed on inclusion, not on the rotation property.
        kms_data = {
            "list_keys": {"Keys": [{"KeyId": "no-details-key"}]},
            "key_details": {},
        }
        assert _normalize_kms_keys(kms_data) == []

    def test_defaults_rotation_to_false_when_status_missing(self):
        kms_data = {
            "list_keys": {"Keys": [{"KeyId": "key-1"}]},
            "key_details": {
                "key-1": {
                    "describe_key": {
                        "KeyMetadata": {
                            "KeyId": "key-1",
                            "KeyManager": "CUSTOMER",
                        }
                    },
                },
            },
        }
        nodes = _normalize_kms_keys(kms_data)
        assert nodes[0]["properties"]["key_rotation_enabled"] is False

    def test_skips_key_with_missing_key_id(self):
        kms_data = {
            "list_keys": {"Keys": [{}, {"KeyId": "ok-key"}]},
            "key_details": {
                "ok-key": {
                    "describe_key": {
                        "KeyMetadata": {"KeyManager": "CUSTOMER"}
                    },
                },
            },
        }
        nodes = _normalize_kms_keys(kms_data)
        assert [n["id"] for n in nodes] == ["ok-key"]

    def test_returns_empty_list_when_no_keys(self):
        assert _normalize_kms_keys({}) == []

    def test_has_alias_true_when_alias_targets_this_key(self):
        kms_data = {
            "list_keys": {"Keys": [{"KeyId": "key-1"}]},
            "key_details": {
                "key-1": {
                    "describe_key": {
                        "KeyMetadata": {"KeyId": "key-1", "KeyManager": "CUSTOMER"}
                    },
                }
            },
            "list_aliases": {
                "Aliases": [{"AliasName": "alias/my-key", "TargetKeyId": "key-1"}]
            },
        }
        nodes = _normalize_kms_keys(kms_data)
        assert nodes[0]["properties"]["has_alias"] is True

    def test_has_alias_false_when_no_alias_targets_this_key(self):
        kms_data = {
            "list_keys": {"Keys": [{"KeyId": "key-1"}]},
            "key_details": {
                "key-1": {
                    "describe_key": {
                        "KeyMetadata": {"KeyId": "key-1", "KeyManager": "CUSTOMER"}
                    },
                }
            },
            "list_aliases": {
                "Aliases": [{"AliasName": "alias/other-key", "TargetKeyId": "key-2"}]
            },
        }
        nodes = _normalize_kms_keys(kms_data)
        assert nodes[0]["properties"]["has_alias"] is False

    def test_has_alias_false_when_list_aliases_entirely_missing(self):
        kms_data = {
            "list_keys": {"Keys": [{"KeyId": "key-1"}]},
            "key_details": {
                "key-1": {
                    "describe_key": {
                        "KeyMetadata": {"KeyId": "key-1", "KeyManager": "CUSTOMER"}
                    },
                }
            },
        }
        nodes = _normalize_kms_keys(kms_data)
        assert nodes[0]["properties"]["has_alias"] is False


# --- _normalize_account --------------------------------------------------
class TestNormalizeAccount:

    def test_returns_account_node_with_all_properties(self):
        iam_data = {
            "account_id": "123456789012",
            "get_account_summary": {
                "SummaryMap": {
                    "AccountAccessKeysPresent": 1,
                    "AccountMFAEnabled": 0,
                }
            },
            "get_account_password_policy": {
                "PasswordPolicy": {"MinimumPasswordLength": 8}
            },
        }
        cloudtrail_data = {
            "describe_trails": {
                "trailList": [{"Name": "main-trail"}]
            },
            "trail_status": {"main-trail": {"IsLogging": True}},
        }
        s3control_data = {
            "get_public_access_block": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        }
        assert _normalize_account(iam_data, cloudtrail_data, s3control_data) == [
            {
                "id": "123456789012",
                "type": "account",
                "name": "AWS Account 123456789012",
                "parent_id": None,
                "properties": {
                    "root_access_keys_present": True,
                    "account_mfa_enabled": False,
                    "password_policy_min_length": 8,
                    "cloudtrail_logging_enabled": True,
                    "account_s3_block_public_access_enabled": True,
                },
            }
        ]

    def test_account_s3_pab_disabled_when_never_configured(self):
        # Real boto3 raises NoSuchPublicAccessBlockConfigurationException;
        # our mock convention represents that as an '_error' marker.
        # _is_pab_fully_enabled already handles this correctly without
        # special-casing, since a missing PublicAccessBlockConfiguration
        # key defaults every flag to False.
        iam_data = {"account_id": "123456789012"}
        s3control_data = {
            "get_public_access_block": {
                "_error": "NoSuchPublicAccessBlockConfigurationException"
            }
        }
        nodes = _normalize_account(iam_data, s3control_data=s3control_data)
        assert nodes[0]["properties"]["account_s3_block_public_access_enabled"] is False

    def test_account_s3_pab_disabled_when_any_flag_false(self):
        iam_data = {"account_id": "123456789012"}
        s3control_data = {
            "get_public_access_block": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": True,
                }
            }
        }
        nodes = _normalize_account(iam_data, s3control_data=s3control_data)
        assert nodes[0]["properties"]["account_s3_block_public_access_enabled"] is False

    def test_cloudtrail_logging_disabled_when_no_trails_exist(self):
        iam_data = {"account_id": "123456789012"}
        cloudtrail_data = {"describe_trails": {"trailList": []}}
        nodes = _normalize_account(iam_data, cloudtrail_data)
        assert nodes[0]["properties"]["cloudtrail_logging_enabled"] is False

    def test_cloudtrail_logging_disabled_when_trail_exists_but_not_logging(self):
        iam_data = {"account_id": "123456789012"}
        cloudtrail_data = {
            "describe_trails": {"trailList": [{"Name": "stopped-trail"}]},
            "trail_status": {"stopped-trail": {"IsLogging": False}},
        }
        nodes = _normalize_account(iam_data, cloudtrail_data)
        assert nodes[0]["properties"]["cloudtrail_logging_enabled"] is False

    def test_cloudtrail_logging_enabled_when_any_trail_is_logging(self):
        # Two trails, only one logging — still counts as covered.
        iam_data = {"account_id": "123456789012"}
        cloudtrail_data = {
            "describe_trails": {
                "trailList": [{"Name": "stopped-trail"}, {"Name": "active-trail"}]
            },
            "trail_status": {
                "stopped-trail": {"IsLogging": False},
                "active-trail": {"IsLogging": True},
            },
        }
        nodes = _normalize_account(iam_data, cloudtrail_data)
        assert nodes[0]["properties"]["cloudtrail_logging_enabled"] is True

    def test_cloudtrail_logging_defaults_to_false_when_no_cloudtrail_data(self):
        # cloudtrail_data is an optional second argument.
        nodes = _normalize_account({"account_id": "123456789012"})
        assert nodes[0]["properties"]["cloudtrail_logging_enabled"] is False

    def test_password_policy_min_length_is_none_when_no_policy_configured(self):
        # Real boto3 raises NoSuchEntityException; our mock convention
        # represents that as an '_error' marker, same as the S3
        # encryption/lifecycle/policy calls.
        iam_data = {
            "account_id": "123456789012",
            "get_account_password_policy": {
                "_error": "NoSuchEntityException"
            },
        }
        nodes = _normalize_account(iam_data)
        assert nodes[0]["properties"]["password_policy_min_length"] is None

    def test_returns_account_node_with_root_keys_absent_and_mfa_enabled(self):
        iam_data = {
            "account_id": "123456789012",
            "get_account_summary": {
                "SummaryMap": {
                    "AccountAccessKeysPresent": 0,
                    "AccountMFAEnabled": 1,
                }
            },
        }
        nodes = _normalize_account(iam_data)
        assert nodes[0]["properties"]["root_access_keys_present"] is False
        assert nodes[0]["properties"]["account_mfa_enabled"] is True

    def test_defaults_both_iam_flags_to_false_when_summary_missing(self):
        iam_data = {"account_id": "123456789012"}
        nodes = _normalize_account(iam_data)
        assert nodes[0]["properties"]["root_access_keys_present"] is False
        assert nodes[0]["properties"]["account_mfa_enabled"] is False
        assert nodes[0]["properties"]["password_policy_min_length"] is None
        assert nodes[0]["properties"]["account_s3_block_public_access_enabled"] is False

    def test_returns_empty_list_when_account_id_missing(self):
        assert _normalize_account({}) == []


# --- _normalize_iam_users -------------------------------------------------
class TestNormalizeIamUsers:

    def test_returns_user_with_access_keys(self):
        iam_data = {
            "list_users": {
                "Users": [
                    {
                        "UserName": "svc-account",
                        "Arn": "arn:aws:iam::123456789012:user/svc-account",
                    }
                ]
            },
            "user_details": {
                "svc-account": {
                    "list_access_keys": {
                        "AccessKeyMetadata": [
                            {
                                "AccessKeyId": "AKIAEXAMPLE",
                                "Status": "Active",
                                "CreateDate": "2022-03-10T09:00:00+00:00",
                            }
                        ]
                    }
                }
            },
        }
        assert _normalize_iam_users(iam_data) == [
            {
                "id": "svc-account",
                "type": "iam_user",
                "name": "svc-account",
                "parent_id": None,
                "properties": {
                    "access_keys": [
                        {
                            "access_key_id": "AKIAEXAMPLE",
                            "status": "Active",
                            "create_date": "2022-03-10T09:00:00+00:00",
                        }
                    ],
                    "arn": "arn:aws:iam::123456789012:user/svc-account",
                    "has_console_login": False,
                    "has_admin_policy_attached": False,
                    "has_wildcard_action_resource_policy": False,
                },
            }
        ]

    def test_returns_user_with_empty_access_keys_when_none_exist(self):
        iam_data = {
            "list_users": {"Users": [{"UserName": "console-only-user"}]},
            "user_details": {
                "console-only-user": {
                    "list_access_keys": {"AccessKeyMetadata": []}
                }
            },
        }
        nodes = _normalize_iam_users(iam_data)
        assert nodes[0]["properties"]["access_keys"] == []

    def test_defaults_safely_when_user_details_missing(self):
        # A user appears in list_users but has no entry in
        # user_details (e.g. the detail API call failed). Fail
        # closed to an empty key list rather than crashing.
        iam_data = {
            "list_users": {"Users": [{"UserName": "no-details-user"}]},
            "user_details": {},
        }
        nodes = _normalize_iam_users(iam_data)
        assert nodes[0]["properties"]["access_keys"] == []

    def test_skips_user_with_missing_username(self):
        iam_data = {
            "list_users": {"Users": [{}, {"UserName": "ok-user"}]},
            "user_details": {},
        }
        nodes = _normalize_iam_users(iam_data)
        assert [n["id"] for n in nodes] == ["ok-user"]

    def test_returns_empty_list_when_no_users(self):
        assert _normalize_iam_users({}) == []

    def test_has_console_login_true_when_login_profile_present(self):
        iam_data = {
            "list_users": {"Users": [{"UserName": "console-user"}]},
            "user_details": {
                "console-user": {
                    "get_login_profile": {
                        "LoginProfile": {"UserName": "console-user"}
                    }
                }
            },
        }
        nodes = _normalize_iam_users(iam_data)
        assert nodes[0]["properties"]["has_console_login"] is True

    def test_has_console_login_false_when_error_marker_present(self):
        iam_data = {
            "list_users": {"Users": [{"UserName": "programmatic-user"}]},
            "user_details": {
                "programmatic-user": {
                    "get_login_profile": {"_error": "NoSuchEntityException"}
                }
            },
        }
        nodes = _normalize_iam_users(iam_data)
        assert nodes[0]["properties"]["has_console_login"] is False

    def test_has_console_login_false_when_key_entirely_missing(self):
        # Detection signal, fail-open: absent data must never be
        # interpreted as "console login exists" just because it isn't
        # an explicit error marker either.
        iam_data = {
            "list_users": {"Users": [{"UserName": "no-detail-user"}]},
            "user_details": {"no-detail-user": {}},
        }
        nodes = _normalize_iam_users(iam_data)
        assert nodes[0]["properties"]["has_console_login"] is False


# --- _normalize_security_groups --------------------------------------
class TestNormalizeSecurityGroups:

    def test_returns_sg_with_renamed_fields_and_preserved_raw_rules(self):
        # Two things asserted at once:
        #   1. boto3's IpPermissions / IpPermissionsEgress get renamed
        #      to ingress_rules / egress_rules in our output shape.
        #   2. The rule content itself is preserved raw — including the
        #      nested IpRanges, UserIdGroupPairs, etc. Scanners in the
        #      next milestone need the full fidelity to walk the rules.
        ec2_data = {
            "describe_security_groups": {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-aaa111",
                        "GroupName": "web-sg",
                        "Description": "Allow inbound HTTP/HTTPS",
                        "VpcId": "vpc-bbb222",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                "UserIdGroupPairs": [],
                            }
                        ],
                        "IpPermissionsEgress": [
                            {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                        ],
                    }
                ]
            }
        }
        groups = _normalize_security_groups(ec2_data)
        assert groups == [
            {
                "id": "sg-aaa111",
                "name": "web-sg",
                "description": "Allow inbound HTTP/HTTPS",
                "vpc_id": "vpc-bbb222",
                "ingress_rules": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "UserIdGroupPairs": [],
                    }
                ],
                "egress_rules": [
                    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
                ],
            }
        ]

    def test_uses_group_id_as_name_when_group_name_missing(self):
        # Unlike VPCs/subnets/etc., SG name fallback is on GroupName
        # (not a Tags lookup). If GroupName is absent, the GroupId is
        # the display name.
        ec2_data = {
            "describe_security_groups": {
                "SecurityGroups": [{"GroupId": "sg-no-name"}]
            }
        }
        groups = _normalize_security_groups(ec2_data)
        assert groups[0]["name"] == "sg-no-name"

    def test_skips_sg_with_missing_group_id(self):
        ec2_data = {
            "describe_security_groups": {
                "SecurityGroups": [
                    {"GroupName": "orphan"},  # no GroupId
                    {"GroupId": "sg-ok", "GroupName": "ok"},
                ]
            }
        }
        groups = _normalize_security_groups(ec2_data)
        assert [g["id"] for g in groups] == ["sg-ok"]

    def test_returns_empty_list_when_no_security_groups(self):
        assert _normalize_security_groups({}) == []
