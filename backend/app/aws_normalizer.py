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
            Top-level keys are 'ec2', 's3', and 'rds'. Missing
            branches are treated as empty (no resources of that
            service exist).

    Returns:
        A dict with three keys:
          - 'metadata': schema version, UTC timestamp, counts
          - 'nodes': flat list of TopologyNode dicts
          - 'security_groups': flat list of SecurityGroup dicts
    """
    ec2_data = aws_data.get("ec2", {})
    s3_data = aws_data.get("s3", {})
    rds_data = aws_data.get("rds", {})

    # Combine every per-resource normalizer's output into one flat
    # node list. Order is chosen for human readability when reading
    # the resulting topology.json: top-level containers (VPCs) first,
    # then everything that nests inside them, then global services
    # (S3) last. The frontend doesn't depend on this order — it
    # rebuilds the hierarchy from parent_id — but it makes the file
    # easier for humans to scan.
    nodes: list[TopologyNode] = []
    nodes.extend(_normalize_vpcs(ec2_data))
    nodes.extend(_normalize_subnets(ec2_data))
    nodes.extend(_normalize_internet_gateways(ec2_data))
    nodes.extend(_normalize_ec2_instances(ec2_data))
    nodes.extend(_normalize_rds_instances(rds_data))
    nodes.extend(_normalize_s3_buckets(s3_data))

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
    # CLI runner: read mock_aws.json from the data folder beside this
    # module, normalize it, and write topology.json to the same folder.
    # Run with: python -m app.aws_normalizer (from the backend folder)

    # Configure logging so warnings from the helpers are visible when
    # running interactively.
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    data_dir = Path(__file__).parent / "data"
    input_file = data_dir / "mock_aws.json"
    output_file = data_dir / "topology.json"

    print(f"Reading: {input_file}")
    topology = normalize_from_file(input_file)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(topology, f, indent=2)

    print(f"Wrote:   {output_file}")
    print(
        f"Stats:   {topology['metadata']['node_count']} nodes, "
        f"{topology['metadata']['security_group_count']} security groups"
    )

    # Also write a copy to the frontend folder so the visualisation
    # can fetch it without crossing into the backend tree. Keeps the
    # normalizer as the single source of truth: edit the mock, rerun
    # this command, both copies update.
    frontend_dir = Path(__file__).parent.parent.parent / "frontend"
    if frontend_dir.exists():
        frontend_file = frontend_dir / "topology.json"
        with open(frontend_file, "w", encoding="utf-8") as f:
            json.dump(topology, f, indent=2)
        print(f"Copied:  {frontend_file}")