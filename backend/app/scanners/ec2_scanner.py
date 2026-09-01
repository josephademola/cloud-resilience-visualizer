"""
EC2 misconfiguration scanner.

Walks every EC2 instance in a topology and produces Finding objects
for each rule that fails.

Current rules:
    - IMDSv2 not required                            -> MEDIUM
    - Security group allows unrestricted SSH (22)     -> HIGH
    - Security group allows unrestricted RDP (3389)   -> HIGH
    - Public IP address inside a private subnet       -> MEDIUM
    - An attached EBS volume is not encrypted         -> HIGH

Design notes:

- One function per rule, same pattern as every other scanner in this
  codebase. Each takes an ec2_instance node dict and returns either a
  Finding or None.

- The two security-group rules are attributed to the INSTANCE, not the
  security group itself, even though the underlying misconfiguration
  lives on the SG. Security groups aren't topology nodes (see
  aws_normalizer.py's _normalize_security_groups docstring) and every
  other finding in this codebase has a resource_id that resolves to a
  clickable node -- attributing the finding to each instance that
  actually uses the bad security group keeps that consistent, and is
  arguably more actionable anyway ("this specific machine is exposed"
  rather than an abstract SG object that may or may not be attached to
  anything). A security group with a bad rule but zero attached
  instances produces no finding under this design -- a known, narrow
  limitation, not an oversight; documented here rather than silently
  accepted.

- Missing-property semantics:
    * has_unrestricted_ssh_ingress / has_unrestricted_rdp_ingress /
      is_public_ip_in_private_subnet: detection signals. Missing data
      means we didn't detect the condition, not that it's absent --
      no finding.
    * imdsv2_required: a protection signal, same fail-closed semantic
      as encryption_enabled. If we can't confirm IMDSv2 is required,
      we don't assume it is.
    * has_unencrypted_ebs_volume: also fail-closed at the normaliser
      layer (see aws_normalizer._instance_has_unencrypted_ebs_volume) --
      by the time the scanner sees this property, a total volume-fetch
      failure has already resolved to True. The scanner rule itself
      just checks the boolean.
"""

from __future__ import annotations

from typing import Any

from app.mappings.loader import get_framework_references
from app.models.finding import Finding, Severity
from app.scanners.content_loader import get_content


def scan_ec2_instances(topology: dict[str, Any]) -> list[Finding]:
    """
    Walk every EC2 instance in the topology and return all findings.
    """
    findings: list[Finding] = []

    rules = (
        _check_imdsv2_required,
        _check_unrestricted_ssh,
        _check_unrestricted_rdp,
        _check_public_ip_in_private_subnet,
        _check_ebs_unencrypted,
    )

    for node in topology.get("nodes", []):
        if node.get("type") != "ec2_instance":
            continue

        for rule in rules:
            finding = rule(node)
            if finding is not None:
                findings.append(finding)

    return findings


# ---- Individual rules ----


def _check_imdsv2_required(instance: dict[str, Any]) -> Finding | None:
    """
    IMDSv2 (token-required instance metadata access) must be enforced.

    IMDSv1 has no request-signing step, which is exactly what makes
    SSRF-based credential theft against the instance metadata service
    possible -- an attacker who can make the instance issue an
    arbitrary HTTP request can read its IAM role credentials directly.
    """
    props = instance.get("properties", {})
    if props.get("imdsv2_required", False):
        return None
    return _build_finding("EC2_IMDSV2_NOT_REQUIRED", instance["id"])


def _check_unrestricted_ssh(instance: dict[str, Any]) -> Finding | None:
    """A security group attached to this instance must not open SSH (22) to the world."""
    props = instance.get("properties", {})
    if not props.get("has_unrestricted_ssh_ingress", False):
        return None
    return _build_finding("EC2_SECURITY_GROUP_UNRESTRICTED_SSH", instance["id"])


def _check_unrestricted_rdp(instance: dict[str, Any]) -> Finding | None:
    """A security group attached to this instance must not open RDP (3389) to the world."""
    props = instance.get("properties", {})
    if not props.get("has_unrestricted_rdp_ingress", False):
        return None
    return _build_finding("EC2_SECURITY_GROUP_UNRESTRICTED_RDP", instance["id"])


def _check_public_ip_in_private_subnet(instance: dict[str, Any]) -> Finding | None:
    """
    An instance with a public IP address should not live in a subnet
    classified as private -- that's a contradiction in the network
    design, not just a loose end: the subnet's own tier says this
    instance shouldn't be internet-reachable, and it is anyway.
    """
    props = instance.get("properties", {})
    if not props.get("is_public_ip_in_private_subnet", False):
        return None
    return _build_finding("EC2_PUBLIC_IP_IN_PRIVATE_SUBNET", instance["id"])


def _check_ebs_unencrypted(instance: dict[str, Any]) -> Finding | None:
    """At least one EBS volume attached to this instance is not encrypted."""
    props = instance.get("properties", {})
    if not props.get("has_unencrypted_ebs_volume", False):
        return None
    return _build_finding("EC2_EBS_UNENCRYPTED", instance["id"])


# ---- Shared finding constructor ----

def _build_finding(finding_type_id: str, resource_id: str) -> Finding:
    """
    Construct a Finding by combining detection metadata (finding_type_id
    and resource_id) with content from content_loader and framework
    references from mapping loader.
    """
    content = get_content(finding_type_id)
    return Finding(
        finding_type_id=finding_type_id,
        title=content["title"],
        severity=Severity(content["severity"]),
        resource_id=resource_id,
        description=content["description"],
        remediation=content["remediation"],
        framework_references=get_framework_references(finding_type_id),
    )
