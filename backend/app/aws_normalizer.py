"""
AWS Normalizer
==============

Transforms boto3-shaped AWS data into a flat, frontend-friendly topology
graph.

INPUT
-----
A dictionary matching the structure of mock_aws.json: top-level keys
'ec2', 's3', 'rds', each containing boto3 API method names mapped to
their typical response shapes
(e.g. {"ec2": {"describe_vpcs": {"Vpcs": [...]}}, ...}).

OUTPUT
------
A dictionary with three top-level keys:

  - metadata: schema version, generation timestamp, node counts
  - nodes: flat list of {id, type, name, parent_id, properties} dicts
  - security_groups: separate list of SG definitions (not topology nodes)

The same input shape is produced both by mock data and by a real boto3
caller. The normalizer is intentionally agnostic about the source.

DESIGN NOTES
------------
- Pure functions: each helper takes input, returns output. No global
  state, no side effects (until the CLI runner at the bottom of the
  file).
- Defensive reads: every optional field is accessed via dict.get()
  with a fallback, so missing fields produce sensible defaults rather
  than KeyError exceptions.
- Tags are looked up via helpers that handle None and empty lists.
"""

from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Module-level logger. Using __name__ means the logger inherits the
# module's dotted path ("app.aws_normalizer"). Calling code can
# configure its verbosity (e.g. logging.basicConfig(level=DEBUG)).
logger = logging.getLogger(__name__)


# --- Type aliases for readability ------------------------------------
# These don't change runtime behaviour; they just make function
# signatures self-documenting. Reading `AwsData` in a parameter list
# is clearer than the raw `dict[str, Any]`.
AwsData = dict[str, Any]

# The taggable, currently-scanned resource types (Phase 9a Feature 1).
# Shared by filter_topology_by_tag() and _apply_tag_presence() so both
# agree on exactly which node types carry an 'arn' property that maps
# onto the Resource Groups Tagging API.
TAGGABLE_NODE_TYPES = frozenset({"s3_bucket", "kms_key", "iam_user"})
TopologyNode = dict[str, Any]
SecurityGroup = dict[str, Any]


# --- Tag helpers ------------------------------------------------------
def _get_tag(tags: list[dict[str, str]] | None, key: str) -> str | None:
    """
    Return the value of the AWS tag matching `key`, or None if absent.

    AWS returns tags as a list of {"Key": ..., "Value": ...} dicts,
    which is awkward to query repeatedly. This helper makes lookups
    one-liners and handles three null-shaped inputs safely: None,
    empty list, and lists where the key just isn't present.

    Examples:
        >>> _get_tag([{"Key": "Name", "Value": "web-01"}], "Name")
        'web-01'
        >>> _get_tag([], "Name") is None
        True
        >>> _get_tag(None, "Name") is None
        True
    """
    if not tags:
        return None
    for tag in tags:
        if tag.get("Key") == key:
            return tag.get("Value")
    return None


def _name_or_id(tags: list[dict[str, str]] | None, fallback_id: str) -> str:
    """
    Return the Name tag value if present, otherwise the resource ID.

    Real AWS environments tag resources inconsistently — some have a
    Name, some don't. Centralising the fallback here means every
    downstream caller (frontend, scanners, narrative templates) sees
    a usable display string without re-implementing the fallback.
    """
    return _get_tag(tags, "Name") or fallback_id



# --- Per-resource normalizers -----------------------------------------
def _normalize_vpcs(ec2_data: dict[str, Any]) -> list[TopologyNode]:
    """
    Transform describe_vpcs response into a list of topology nodes.

    Each VPC becomes one node with parent_id = None (VPCs sit at the
    top of the containment hierarchy in a region).

    Args:
        ec2_data: The 'ec2' branch of the mock_aws.json structure.

    Returns:
        A list of TopologyNode dicts, one per VPC. Empty list if no
        VPCs are present in the input.
    """
    nodes: list[TopologyNode] = []

    # Safely navigate from ec2_data -> describe_vpcs -> Vpcs.
    # Each .get(..., {}) or .get(..., []) is a guard against missing
    # keys, so partial data never causes a KeyError crash.
    vpcs_response = ec2_data.get("describe_vpcs", {})
    vpc_list = vpcs_response.get("Vpcs", [])

    for vpc in vpc_list:
        vpc_id = vpc.get("VpcId")
        if not vpc_id:
            # VpcId is structurally required: without it we can't
            # address this node from anywhere else (no subnet could
            # declare parent_id = ?). We log and skip rather than
            # raise, so one bad record doesn't kill the whole run.
            logger.warning("Skipping VPC with missing VpcId")
            continue

        nodes.append({
            "id": vpc_id,
            "type": "vpc",
            "name": _name_or_id(vpc.get("Tags"), vpc_id),
            "parent_id": None,
            "properties": {
                "cidr_block": vpc.get("CidrBlock"),
                "is_default": vpc.get("IsDefault", False),
                "state": vpc.get("State"),
            },
        })

    return nodes



def _normalize_subnets(ec2_data: dict[str, Any]) -> list[TopologyNode]:
    """
    Transform describe_subnets response into topology nodes.

    Each subnet's parent_id is its containing VPC. Tier (public vs.
    private) is determined by:
      1. The 'Tier' tag if present (explicit user choice), OR
      2. The MapPublicIpOnLaunch flag (instances get a public IP by
         default in this subnet -> effectively a public subnet).
    """
    nodes: list[TopologyNode] = []

    subnets_response = ec2_data.get("describe_subnets", {})
    subnet_list = subnets_response.get("Subnets", [])

    for subnet in subnet_list:
        subnet_id = subnet.get("SubnetId")
        vpc_id = subnet.get("VpcId")
        if not subnet_id or not vpc_id:
            logger.warning(
                "Skipping subnet with missing SubnetId or VpcId: %r", subnet
            )
            continue

        # Tier: explicit tag wins, else infer from MapPublicIpOnLaunch.
        # This mirrors how most CSPM tools classify subnets in practice.
        tier_tag = _get_tag(subnet.get("Tags"), "Tier")
        if tier_tag:
            tier = tier_tag
        elif subnet.get("MapPublicIpOnLaunch"):
            tier = "public"
        else:
            tier = "private"

        nodes.append({
            "id": subnet_id,
            "type": "subnet",
            "name": _name_or_id(subnet.get("Tags"), subnet_id),
            "parent_id": vpc_id,
            "properties": {
                "cidr_block": subnet.get("CidrBlock"),
                "availability_zone": subnet.get("AvailabilityZone"),
                "tier": tier,
                "map_public_ip_on_launch": subnet.get(
                    "MapPublicIpOnLaunch", False
                ),
            },
        })

    return nodes


def _normalize_internet_gateways(
    ec2_data: dict[str, Any],
) -> list[TopologyNode]:
    """
    Transform describe_internet_gateways response into topology nodes.

    An IGW is attached to a VPC via its 'Attachments' list. In normal
    AWS environments an IGW is attached to exactly one VPC (or none,
    if it's freshly created and unattached). We take the first
    attachment as the parent. A detached IGW gets parent_id = None and
    state = 'detached' — useful as a visible "orphan resource" finding
    later.
    """
    nodes: list[TopologyNode] = []

    igw_response = ec2_data.get("describe_internet_gateways", {})
    igw_list = igw_response.get("InternetGateways", [])

    for igw in igw_list:
        igw_id = igw.get("InternetGatewayId")
        if not igw_id:
            logger.warning(
                "Skipping internet gateway with missing InternetGatewayId"
            )
            continue

        # First attachment (if any) gives parent VPC and state.
        attachments = igw.get("Attachments", [])
        if attachments:
            parent_vpc = attachments[0].get("VpcId")
            state = attachments[0].get("State", "unknown")
        else:
            parent_vpc = None
            state = "detached"

        nodes.append({
            "id": igw_id,
            "type": "internet_gateway",
            "name": _name_or_id(igw.get("Tags"), igw_id),
            "parent_id": parent_vpc,
            "properties": {
                "state": state,
            },
        })

    return nodes


def _normalize_ec2_instances(ec2_data: dict[str, Any],) -> list[TopologyNode]:
    """
    Transform describe_instances response into topology nodes.

    EC2's describe_instances response is structured as a list of
    Reservations, each containing a list of Instances. A "reservation"
    is an AWS concept representing a single API call to launch one or
    more instances — instances launched in the same RunInstances call
    share a reservation ID. For our purposes the reservation grouping
    is just historical metadata; we flatten it away and treat each
    instance independently.

    Each instance's parent_id is its containing subnet.
    """
    nodes: list[TopologyNode] = []

    instances_response = ec2_data.get("describe_instances", {})
    reservations = instances_response.get("Reservations", [])

    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")
            subnet_id = instance.get("SubnetId")
            if not instance_id or not subnet_id:
                logger.warning(
                    "Skipping EC2 instance with missing InstanceId "
                    "or SubnetId: %r",
                    instance,
                )
                continue

            # State is a nested object {Code: int, Name: str}.
            # We want just the human-readable name ("running",
            # "stopped", "terminated", etc.).
            state_name = instance.get("State", {}).get("Name")

            # Security groups arrive as a list of {GroupId, GroupName}
            # dicts. We only need the IDs in the topology output;
            # full SG details live in the security_groups section.
            sg_ids = [
                sg["GroupId"]
                for sg in instance.get("SecurityGroups", [])
                if sg.get("GroupId")
            ]

            nodes.append({
                "id": instance_id,
                "type": "ec2_instance",
                "name": _name_or_id(instance.get("Tags"), instance_id),
                "parent_id": subnet_id,
                "properties": {
                    "instance_type": instance.get("InstanceType"),
                    "state": state_name,
                    "private_ip": instance.get("PrivateIpAddress"),
                    "public_ip": instance.get("PublicIpAddress"),
                    "platform": instance.get("PlatformDetails"),
                    "security_group_ids": sg_ids,
                },
            })

    return nodes


def _normalize_rds_instances(rds_data: dict[str, Any],) -> list[TopologyNode]:
    """
    Transform describe_db_instances response into topology nodes.

    RDS instances live inside a "DB Subnet Group" — a named bundle of
    one or more subnets that RDS can place its primary and replicas in.
    For visualisation we pick the first subnet in the group as the
    parent. Multi-AZ deployments span multiple subnets, but the primary
    still lives in one at a time; using the first listed subnet gives
    a stable, predictable parent for layout.

    Security groups arrive under VpcSecurityGroups with field name
    'VpcSecurityGroupId' — different from EC2's 'GroupId' (an AWS API
    naming inconsistency we have to live with).
    """
    nodes: list[TopologyNode] = []

    rds_response = rds_data.get("describe_db_instances", {})
    db_list = rds_response.get("DBInstances", [])

    for db in db_list:
        db_id = db.get("DBInstanceIdentifier")
        if not db_id:
            logger.warning(
                "Skipping RDS instance with missing DBInstanceIdentifier"
            )
            continue

        # Parent: first subnet in the DB Subnet Group, or None if the
        # group is missing or empty.
        subnets = db.get("DBSubnetGroup", {}).get("Subnets", [])
        parent_subnet = (
            subnets[0].get("SubnetIdentifier") if subnets else None
        )

        # Security group IDs — note the field is 'VpcSecurityGroupId',
        # NOT 'GroupId' like it is in EC2.
        sg_ids = [
            sg["VpcSecurityGroupId"]
            for sg in db.get("VpcSecurityGroups", [])
            if sg.get("VpcSecurityGroupId")
        ]

        nodes.append({
            "id": db_id,
            "type": "rds_instance",
            "name": db_id,  # RDS uses DBInstanceIdentifier as its display name
            "parent_id": parent_subnet,
            "properties": {
                "engine": db.get("Engine"),
                "engine_version": db.get("EngineVersion"),
                "status": db.get("DBInstanceStatus"),
                "publicly_accessible": db.get("PubliclyAccessible", False),
                "storage_encrypted": db.get("StorageEncrypted", False),
                "multi_az": db.get("MultiAZ", False),
                "backup_retention_days": db.get("BackupRetentionPeriod"),
                "security_group_ids": sg_ids,
            },
        })

    return nodes


def _normalize_account(
    iam_data: dict[str, Any],
    cloudtrail_data: dict[str, Any] | None = None,
    s3control_data: dict[str, Any] | None = None,
) -> list[TopologyNode]:
    """
    Transform account-wide facts from multiple AWS services into a
    single 'account' topology node.

    Unlike every other _normalize_* function, this doesn't produce
    one node per resource — at most one node, representing the whole
    AWS account. Findings like root access keys, account-wide MFA, or
    CloudTrail coverage aren't tied to any specific bucket, key, or
    instance; they're facts about the account as a whole, so they
    need an account-level node to attach to. Same shape as the S3
    normaliser folding 7 different per-bucket API calls into one
    node — multiple AWS services, one conceptual resource.
    """
    account_id = iam_data.get("account_id")
    if not account_id:
        logger.warning("Skipping account node: missing account_id")
        return []

    summary = iam_data.get("get_account_summary", {}).get("SummaryMap", {})

    password_policy = iam_data.get("get_account_password_policy", {})
    min_length = None
    if "_error" not in password_policy:
        min_length = password_policy.get("PasswordPolicy", {}).get(
            "MinimumPasswordLength"
        )

    cloudtrail_data = cloudtrail_data or {}
    trails = cloudtrail_data.get("describe_trails", {}).get("trailList", [])
    trail_statuses = cloudtrail_data.get("trail_status", {})
    cloudtrail_logging_enabled = any(
        trail_statuses.get(trail.get("Name"), {}).get("IsLogging", False)
        for trail in trails
    )

    # s3control's account-level Public Access Block has the identical
    # response shape as a bucket's — reuse the existing helper rather
    # than duplicate the same four-flag check at a different scope.
    s3control_data = s3control_data or {}
    account_pab = s3control_data.get("get_public_access_block", {})
    account_s3_block_public_access_enabled = _is_pab_fully_enabled(account_pab)

    return [{
        "id": account_id,
        "type": "account",
        "name": f"AWS Account {account_id}",
        "parent_id": None,
        "properties": {
            "root_access_keys_present": summary.get(
                "AccountAccessKeysPresent", 0
            ) > 0,
            "account_mfa_enabled": summary.get("AccountMFAEnabled", 0) > 0,
            "password_policy_min_length": min_length,
            "cloudtrail_logging_enabled": cloudtrail_logging_enabled,
            "account_s3_block_public_access_enabled": account_s3_block_public_access_enabled,
        },
    }]


def _normalize_iam_users(iam_data: dict[str, Any]) -> list[TopologyNode]:
    """
    Transform list_users + user_details into topology nodes, one per
    IAM user.

    Unlike _normalize_account (a singleton), this produces one node
    per user, the same shape as S3 buckets or KMS keys — IAM users
    are individual resources, not a single account-wide fact.

    access_keys is stored as a raw list (id, status, creation date)
    rather than a pre-computed "is old" boolean. Whether a key counts
    as old depends on the current date, which this function
    deliberately never looks at — that calculation belongs entirely
    to the scanner rule. See docs/design_decisions.md #10.
    """
    nodes: list[TopologyNode] = []

    user_list = iam_data.get("list_users", {}).get("Users", [])
    user_details = iam_data.get("user_details", {})

    for user in user_list:
        username = user.get("UserName")
        if not username:
            logger.warning("Skipping IAM user with missing UserName")
            continue

        details = user_details.get(username, {})
        key_metadata = details.get("list_access_keys", {}).get(
            "AccessKeyMetadata", []
        )

        access_keys = [
            {
                "access_key_id": key.get("AccessKeyId"),
                "status": key.get("Status"),
                "create_date": key.get("CreateDate"),
            }
            for key in key_metadata
            if key.get("AccessKeyId")
        ]

        nodes.append({
            "id": username,
            "type": "iam_user",
            "name": username,
            "parent_id": None,  # IAM is global, not in any VPC
            "properties": {
                "access_keys": access_keys,
                "arn": user.get("Arn"),
                "has_console_login": _has_console_login(
                    details.get("get_login_profile", {})
                ),
            },
        })

    return nodes


def _has_console_login(login_profile_response: dict[str, Any]) -> bool:
    """
    Return True if the user has a console login profile (password
    access), False if they're programmatic-only.

    A detection signal, not a protection signal (see the module-level
    "Missing-property semantics" convention this codebase follows
    throughout): missing/absent data means "not detected", not
    "detected" -- checking for the presence of "LoginProfile"
    specifically (rather than the ABSENCE of "_error") is what makes
    that hold. An empty dict (user_details entry missing this key
    entirely, e.g. an older data source or a failed detail fetch)
    must resolve to False here, the same as a real
    {"_error": "NoSuchEntityException"} response does -- both mean
    "no evidence of a login profile", never "assume one exists".

    Real boto3 get_login_profile() raises NoSuchEntityException when
    a user has never had console access configured -- that's the
    good, expected state for a service account, not an error. Our
    mock represents that the same way it represents every other
    "raises when absent" boto3 call: {"_error": "NoSuchEntityException"}.
    """
    return "LoginProfile" in login_profile_response


def _normalize_kms_keys(kms_data: dict[str, Any]) -> list[TopologyNode]:
    """
    Transform list_keys + key_details into topology nodes.

    KMS is a global service, not VPC-scoped — every key gets
    parent_id = None and renders at the topology's top level, same
    as S3 buckets.

    Only customer-managed keys (KeyManager == "CUSTOMER") become
    topology nodes. AWS-managed keys (e.g. aws/s3) rotate
    automatically and the account owner has no control over that
    setting; including them would let the rotation-disabled rule
    flag a control nobody can actually act on. See
    docs/design_decisions.md #9.

    has_alias is computed from the account-wide list_aliases response
    (not per-key -- KMS has no "list aliases for this key" API, only
    "list every alias in the account", each carrying the KeyId it
    targets) rather than a specific expected alias name, since this
    codebase never hardcodes resource names. A key having zero
    aliases pointing to it is the generalisable, environment-agnostic
    version of "does this key's alias still correctly target it" --
    if an alias got repointed elsewhere, this key would show up with
    none.
    """
    nodes: list[TopologyNode] = []

    key_list = kms_data.get("list_keys", {}).get("Keys", [])
    key_details = kms_data.get("key_details", {})
    aliased_key_ids = {
        alias["TargetKeyId"]
        for alias in kms_data.get("list_aliases", {}).get("Aliases", [])
        if alias.get("TargetKeyId")
    }

    for key in key_list:
        key_id = key.get("KeyId")
        if not key_id:
            logger.warning("Skipping KMS key with missing KeyId")
            continue

        details = key_details.get(key_id, {})
        metadata = details.get("describe_key", {}).get("KeyMetadata", {})

        if metadata.get("KeyManager") != "CUSTOMER":
            continue

        rotation = details.get("get_key_rotation_status", {})

        nodes.append({
            "id": key_id,
            "type": "kms_key",
            "name": metadata.get("Description") or key_id,
            "parent_id": None,  # KMS is global, not in any VPC
            "properties": {
                "key_state": metadata.get("KeyState"),
                "key_rotation_enabled": rotation.get("KeyRotationEnabled", False),
                "arn": key.get("KeyArn"),
                "has_alias": key_id in aliased_key_ids,
            },
        })

    return nodes


# AWS's well-known URI representing "anyone on the internet."
# A Grantee with this URI in a bucket's ACL means the bucket is open
# to the world via ACL — the canonical S3 public-exposure signature.
S3_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"


def _is_bucket_public_via_acl(acl_response: dict[str, Any]) -> bool:
    """
    Return True if the bucket's ACL grants any permission to the
    AllUsers group (i.e. anyone on the internet).
    """
    grants = acl_response.get("Grants", [])
    for grant in grants:
        grantee = grant.get("Grantee", {})
        if grantee.get("URI") == S3_ALL_USERS_URI:
            return True
    return False


def _is_pab_fully_enabled(pab_response: dict[str, Any]) -> bool:
    """
    Return True only when ALL FOUR Public Access Block flags are True.

    The four flags work together; leaving any one False leaves a gap.
    Treating them as a single boolean simplifies downstream logic.
    """
    pab = pab_response.get("PublicAccessBlockConfiguration", {})
    return all([
        pab.get("BlockPublicAcls", False),
        pab.get("IgnorePublicAcls", False),
        pab.get("BlockPublicPolicy", False),
        pab.get("RestrictPublicBuckets", False),
    ])


def _is_bucket_encryption_enabled(encryption_response: dict[str, Any]) -> bool:
    """
    Return True if server-side encryption is configured for the bucket.

    Real boto3 raises ServerSideEncryptionConfigurationNotFoundError
    when no encryption is set. Our mock represents that error as
    {"_error": "ServerSideEncryptionConfigurationNotFoundError"}.
    A real-AWS data source in a later milestone will produce the same
    shape by catching the exception in the boto3 client layer — the
    normalizer doesn't need to change.
    """
    if "_error" in encryption_response:
        return False
    sse_config = encryption_response.get(
        "ServerSideEncryptionConfiguration", {}
    )
    rules = sse_config.get("Rules", [])
    return len(rules) > 0


def _get_encryption_default(
    encryption_response: dict[str, Any],
) -> dict[str, Any]:
    """
    Return the first rule's ApplyServerSideEncryptionByDefault block,
    or {} if there's no encryption configured at all (error marker or
    an empty Rules list).

    Only the first rule is read because that's the one S3 actually
    applies as the bucket's default -- get_bucket_encryption() can
    only ever return at most one rule in practice, but reading [0]
    defensively rather than assuming makes that explicit.
    """
    if "_error" in encryption_response:
        return {}
    rules = encryption_response.get(
        "ServerSideEncryptionConfiguration", {}
    ).get("Rules", [])
    if not rules:
        return {}
    return rules[0].get("ApplyServerSideEncryptionByDefault", {})


def _is_bucket_versioning_enabled(versioning_response: dict[str, Any]) -> bool:
    """
    Return True if bucket versioning is enabled.

    Real boto3 get_bucket_versioning() returns an empty dict when
    versioning has never been configured on the bucket (not an error,
    unlike encryption). It returns {"Status": "Enabled"} or
    {"Status": "Suspended"} once versioning has been turned on at
    least once. Only "Enabled" counts as protected — a bucket that
    was enabled and later suspended is not currently protected.
    """
    return versioning_response.get("Status") == "Enabled"


def _is_bucket_logging_enabled(logging_response: dict[str, Any]) -> bool:
    """
    Return True if server access logging is configured for the bucket.

    Real boto3 get_bucket_logging() returns an empty dict when logging
    has never been configured (not an error, same as versioning). Once
    configured it returns {"LoggingEnabled": {"TargetBucket": ...,
    "TargetPrefix": ...}}.
    """
    return "LoggingEnabled" in logging_response


def _is_bucket_lifecycle_configured(lifecycle_response: dict[str, Any]) -> bool:
    """
    Return True if the bucket has at least one lifecycle rule.

    Real boto3 get_bucket_lifecycle_configuration() raises
    NoSuchLifecycleConfiguration when no rules have ever been set,
    unlike versioning/logging which return an empty dict. Our mock
    represents that error the same way it represents the equivalent
    encryption error: {"_error": "NoSuchLifecycleConfiguration"}.
    """
    if "_error" in lifecycle_response:
        return False
    rules = lifecycle_response.get("Rules", [])
    return len(rules) > 0


def _has_enabled_lifecycle_rule(lifecycle_response: dict[str, Any]) -> bool:
    """
    Return True if at least one of the bucket's lifecycle rules has
    Status == "Enabled".

    A rule can exist but be switched off (Status: "Disabled") --
    created once, then disabled during testing or a migration and
    never re-enabled. _is_bucket_lifecycle_configured() alone can't
    tell that apart from a genuinely active rule, since it only
    checks whether any rule exists at all. No specific expiration-day
    threshold is checked here (e.g. "expire within N days") since
    that number is engagement-specific configuration this codebase
    has no generic way to know -- same reasoning as not hardcoding an
    expected KMS alias name or ARN elsewhere in this module.
    """
    if "_error" in lifecycle_response:
        return False
    rules = lifecycle_response.get("Rules", [])
    return any(rule.get("Status") == "Enabled" for rule in rules)


def _is_tls_enforced(policy_response: dict[str, Any]) -> bool:
    """
    Return True if the bucket policy denies non-TLS (plain HTTP) access.

    Real boto3 get_bucket_policy() raises NoSuchBucketPolicy when no
    policy is attached (mock: {"_error": "NoSuchBucketPolicy"}). When
    a policy exists, boto3 returns it as a JSON-encoded string under
    "Policy" -- it is not parsed for you. A bucket enforces TLS when
    at least one Deny statement's Condition matches
    Bool.aws:SecureTransport == "false".
    """
    if "_error" in policy_response:
        return False
    policy_json = policy_response.get("Policy")
    if not policy_json:
        return False
    try:
        policy = json.loads(policy_json)
    except (json.JSONDecodeError, TypeError):
        return False
    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Deny":
            continue
        secure_transport = (
            statement.get("Condition", {})
            .get("Bool", {})
            .get("aws:SecureTransport")
        )
        if secure_transport in ("false", False):
            return True
    return False


def _normalize_s3_buckets(s3_data: dict[str, Any]) -> list[TopologyNode]:
    """
    Transform S3 list_buckets + bucket_details into topology nodes.

    S3 is a global service, not VPC-scoped — every bucket gets
    parent_id = None and renders at the topology's top level.

    The misconfiguration analysis (public-via-ACL, PAB-enabled,
    encrypted) is computed HERE and stored as plain booleans in the
    node properties. Downstream code (scanners, frontend) reads the
    booleans directly without re-parsing AWS's verbose shapes.
    Centralising the parse means there is exactly one place to update
    if AWS ever changes the response format.
    """
    nodes: list[TopologyNode] = []

    bucket_list = s3_data.get("list_buckets", {}).get("Buckets", [])
    bucket_details = s3_data.get("bucket_details", {})

    for bucket in bucket_list:
        name = bucket.get("Name")
        if not name:
            logger.warning("Skipping S3 bucket with missing Name")
            continue

        # Pull per-bucket details. Empty dicts if missing.
        details = bucket_details.get(name, {})
        acl = details.get("get_bucket_acl", {})
        pab = details.get("get_public_access_block", {})
        encryption = details.get("get_bucket_encryption", {})
        versioning = details.get("get_bucket_versioning", {})
        logging_config = details.get("get_bucket_logging", {})
        lifecycle = details.get("get_bucket_lifecycle_configuration", {})
        policy = details.get("get_bucket_policy", {})

        encryption_default = _get_encryption_default(encryption)

        nodes.append({
            "id": name,
            "type": "s3_bucket",
            "name": name,
            "parent_id": None,  # S3 is global, not in any VPC
            "properties": {
                "creation_date": bucket.get("CreationDate"),
                "is_public_via_acl": _is_bucket_public_via_acl(acl),
                "public_access_block_fully_enabled": _is_pab_fully_enabled(pab),
                "encryption_enabled": _is_bucket_encryption_enabled(encryption),
                "encryption_algorithm": encryption_default.get("SSEAlgorithm"),
                "encryption_kms_key_id": encryption_default.get("KMSMasterKeyID"),
                "versioning_enabled": _is_bucket_versioning_enabled(versioning),
                "logging_enabled": _is_bucket_logging_enabled(logging_config),
                "lifecycle_configured": _is_bucket_lifecycle_configured(lifecycle),
                "lifecycle_rule_enabled": _has_enabled_lifecycle_rule(lifecycle),
                "tls_enforced": _is_tls_enforced(policy),
                "arn": f"arn:aws:s3:::{name}",
            },
        })

    return nodes



def _normalize_security_groups(
    ec2_data: dict[str, Any],
) -> list[SecurityGroup]:
    """
    Transform describe_security_groups response into the topology's
    security_groups section.

    Security groups are NOT topology nodes — they don't render on the
    canvas. They're attached to resources as labels. This function
    captures their definitions in a separate list, so the frontend's
    click panels can resolve sg-XXX references to human-readable names,
    and Phase 2 scanners can walk the rule lists to detect overly-
    permissive ingress.

    Rule shapes are preserved AS-IS from boto3 (IpPermissions /
    IpPermissionsEgress). They contain nested structure (IpRanges,
    UserIdGroupPairs, PrefixListIds) that scanners need in full
    fidelity — flattening here would lose information.
    """
    groups: list[SecurityGroup] = []

    sg_response = ec2_data.get("describe_security_groups", {})
    sg_list = sg_response.get("SecurityGroups", [])

    for sg in sg_list:
        sg_id = sg.get("GroupId")
        if not sg_id:
            logger.warning("Skipping security group with missing GroupId")
            continue

        groups.append({
            "id": sg_id,
            "name": sg.get("GroupName", sg_id),
            "description": sg.get("Description"),
            "vpc_id": sg.get("VpcId"),
            "ingress_rules": sg.get("IpPermissions", []),
            "egress_rules": sg.get("IpPermissionsEgress", []),
        })

    return groups


# --- Public API -------------------------------------------------------
def normalize(aws_data: AwsData) -> dict[str, Any]:
    """
    Transform a complete boto3-shaped AWS data dict into a flat
    topology graph suitable for frontend rendering.

    This is the module's public entry point. It calls every
    _normalize_* helper, combines their output into a single nodes
    list and a separate security_groups list, and wraps both with a
    metadata header.

    Args:
        aws_data: A dict matching the structure of mock_aws.json.
            Top-level keys are 'ec2', 's3', 'rds', 'kms', 'iam',
            'cloudtrail', and 's3control'. Missing branches are
            treated as empty (no resources of that service exist).

    Returns:
        A dict with three keys:
          - 'metadata': schema version, UTC timestamp, counts
          - 'nodes': flat list of TopologyNode dicts
          - 'security_groups': flat list of SecurityGroup dicts
    """
    ec2_data = aws_data.get("ec2", {})
    s3_data = aws_data.get("s3", {})
    rds_data = aws_data.get("rds", {})
    kms_data = aws_data.get("kms", {})
    iam_data = aws_data.get("iam", {})
    cloudtrail_data = aws_data.get("cloudtrail", {})
    s3control_data = aws_data.get("s3control", {})

    # Combine every per-resource normalizer's output into one flat
    # node list. Order is chosen for human readability when reading
    # the resulting topology.json: top-level containers (VPCs) first,
    # then everything that nests inside them, then global services
    # (S3, KMS, IAM users) and finally the account-level node, which
    # isn't scoped to any resource at all. The frontend doesn't
    # depend on this order — it rebuilds the hierarchy from
    # parent_id — but it makes the file easier for humans to scan.
    nodes: list[TopologyNode] = []
    nodes.extend(_normalize_vpcs(ec2_data))
    nodes.extend(_normalize_subnets(ec2_data))
    nodes.extend(_normalize_internet_gateways(ec2_data))
    nodes.extend(_normalize_ec2_instances(ec2_data))
    nodes.extend(_normalize_rds_instances(rds_data))
    nodes.extend(_normalize_s3_buckets(s3_data))
    nodes.extend(_normalize_kms_keys(kms_data))
    nodes.extend(_normalize_iam_users(iam_data))
    nodes.extend(_normalize_account(iam_data, cloudtrail_data, s3control_data))

    _apply_tag_presence(nodes, aws_data)

    security_groups = _normalize_security_groups(ec2_data)

    return {
        "metadata": {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "node_count": len(nodes),
            "security_group_count": len(security_groups),
        },
        "nodes": nodes,
        "security_groups": security_groups,
    }


def _apply_tag_presence(nodes: list[TopologyNode], aws_data: AwsData) -> None:
    """
    Set has_any_tags on every taggable node, in place, from the
    Resource Groups Tagging API's get_resources() response.

    A resource with zero tags never appears in get_resources() at
    all (that's how the API behaves, not an artifact of this
    codebase) -- so "this node's ARN isn't in the response" IS "this
    resource has no tags", not missing/unknown data. That's why this
    is a plain membership check rather than a fail-open/fail-closed
    judgment call like the rest of this module's properties.

    This runs unconditionally (every scan, scoped or not) because the
    tag-presence finding (scanners/tagging_scanner.py) is specifically
    aimed at UNSCOPED scans: a scoped scan already filters every
    taggable node down to ones that matched the requested tag via
    filter_topology_by_tag(), so they'd trivially all show
    has_any_tags=True anyway. Only an unscoped scan sees the resources
    this check actually exists to catch.
    """
    tagged_arns = {
        mapping["ResourceARN"]
        for mapping in (
            aws_data.get("resourcegroupstaggingapi", {})
            .get("get_resources", {})
            .get("ResourceTagMappingList", [])
        )
        if mapping.get("ResourceARN") and mapping.get("Tags")
    }

    for node in nodes:
        if node.get("type") not in TAGGABLE_NODE_TYPES:
            continue
        arn = node.get("properties", {}).get("arn")
        node["properties"]["has_any_tags"] = arn in tagged_arns


def get_tagged_resource_arns(
    aws_data: AwsData, tag_key: str, tag_value: str
) -> set[str]:
    """
    Return the set of resource ARNs tagged with tag_key=tag_value,
    from the Resource Groups Tagging API's get_resources() response.

    Reads aws_data['resourcegroupstaggingapi']['get_resources']
    ['ResourceTagMappingList'] — same key present whether aws_data
    came from mock_aws.json or a live scan (Phase 9a Feature 1).
    Missing or absent data returns an empty set rather than raising,
    so an unscoped scan (no project_tag given) never reaches this
    function in the first place, and a live account this key doesn't
    apply to just yields no matches.
    """
    mappings = (
        aws_data.get("resourcegroupstaggingapi", {})
        .get("get_resources", {})
        .get("ResourceTagMappingList", [])
    )
    return {
        mapping["ResourceARN"]
        for mapping in mappings
        if any(
            tag.get("Key") == tag_key and tag.get("Value") == tag_value
            for tag in mapping.get("Tags", [])
        )
        and mapping.get("ResourceARN")
    }


def filter_topology_by_tag(
    topology: dict[str, Any], tagged_arns: set[str]
) -> dict[str, Any]:
    """
    Return a new topology containing only nodes tagged into scope,
    for Phase 9a Feature 1 (tag-based target selection).

    Two categories of node are always kept regardless of tagged_arns:
      - 'account' nodes: root MFA, CloudTrail coverage, and the other
        account-wide findings aren't facts about one project's
        resources, they're facts about the whole AWS account. There
        is no sensible way to scope "is root MFA enabled" to one
        tagged project.
      - Every node type that doesn't yet carry an 'arn' property
        (vpc, subnet, internet_gateway, ec2_instance, rds_instance):
        these have no scanner coverage yet either, so tag-filtering
        them would just break the topology diagram's visual context
        (an EC2 instance's parent subnet disappearing under it) for
        no present benefit. Revisit once EC2/RDS scanners exist and
        gain their own ARNs.

    S3 buckets, KMS keys, and IAM users — the taggable, currently-
    scanned resource types — are kept only if their 'arn' property is
    in tagged_arns.
    """
    filtered_nodes = [
        node for node in topology.get("nodes", [])
        if node.get("type") not in TAGGABLE_NODE_TYPES
        or node.get("properties", {}).get("arn") in tagged_arns
    ]

    return {
        **topology,
        "nodes": filtered_nodes,
        "metadata": {
            **topology.get("metadata", {}),
            "node_count": len(filtered_nodes),
        },
    }


# --- File I/O helpers and CLI runner ---------------------------------
def normalize_from_file(input_path: str | Path) -> dict[str, Any]:
    """
    Load AWS data from a JSON file and normalize it.

    Convenience wrapper around normalize() for the common case where
    input lives in a file on disk (which is true throughout Phase 1
    while we use mock_aws.json).

    Args:
        input_path: Path to a JSON file matching mock_aws.json schema.

    Returns:
        The normalized topology dict (same shape as normalize()).
    """
    input_path = Path(input_path)
    with open(input_path, "r", encoding="utf-8") as f:
        aws_data = json.load(f)
    return normalize(aws_data)


if __name__ == "__main__":
    import os

    data_dir = Path(__file__).parent / "data"
    output_file = data_dir / "topology.json"

    # Data source is controlled by USE_LIVE_AWS env var. Default is
    # mock (safe) — you have to explicitly opt in to hit real AWS.
    if os.environ.get("USE_LIVE_AWS") == "true":
        print("Source:  live AWS (USE_LIVE_AWS=true)")
        from app.aws_client import fetch_aws_data
        aws_data = fetch_aws_data()
    else:
        mock_file = data_dir / "mock_aws.json"
        print(f"Source:  {mock_file}")
        with open(mock_file, "r", encoding="utf-8") as f:
            aws_data = json.load(f)

    topology = normalize(aws_data)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(topology, f, indent=2)

    print(f"Wrote:   {output_file}")
    print(
        f"Stats:   {topology['metadata']['node_count']} nodes, "
        f"{topology['metadata']['security_group_count']} security groups"
    )