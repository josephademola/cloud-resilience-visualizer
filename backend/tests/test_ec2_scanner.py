"""
Unit tests for app.scanners.ec2_scanner.

Mirrors test_kms_scanner.py's structure: one test class per rule
function, covering the happy path, the negative case, and the
documented missing-data semantic for each property, plus a class for
the top-level scan_ec2_instances walker.
"""

from app.models.finding import Finding, Severity
from app.scanners.ec2_scanner import (
    _check_imdsv2_required,
    _check_unrestricted_ssh,
    _check_unrestricted_rdp,
    _check_public_ip_in_private_subnet,
    _check_ebs_unencrypted,
    scan_ec2_instances,
)


def _ec2_instance(instance_id: str = "i-test", **props) -> dict:
    """Build a minimal ec2_instance-shaped topology node dict."""
    return {
        "id": instance_id,
        "type": "ec2_instance",
        "name": instance_id,
        "parent_id": "subnet-test",
        "properties": props,
    }


# --- _check_imdsv2_required ---------------------------------------------
class TestCheckImdsv2Required:

    def test_returns_finding_when_imdsv2_not_required(self):
        finding = _check_imdsv2_required(_ec2_instance(imdsv2_required=False))
        assert finding is not None
        assert finding.finding_type_id == "EC2_IMDSV2_NOT_REQUIRED"

    def test_returns_none_when_imdsv2_required(self):
        finding = _check_imdsv2_required(_ec2_instance(imdsv2_required=True))
        assert finding is None

    def test_produces_finding_when_property_missing_fail_closed(self):
        # A protection signal, same fail-closed semantic as
        # key_rotation_enabled: if we can't confirm IMDSv2 is
        # required, we don't assume it is.
        finding = _check_imdsv2_required(_ec2_instance())
        assert finding is not None
        assert finding.finding_type_id == "EC2_IMDSV2_NOT_REQUIRED"

    def test_finding_has_medium_severity_and_correct_shape(self):
        finding = _check_imdsv2_required(
            _ec2_instance("i-web-01", imdsv2_required=False)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.MEDIUM
        assert finding.resource_id == "i-web-01"
        assert len(finding.framework_references) > 0


# --- _check_unrestricted_ssh ---------------------------------------------
class TestCheckUnrestrictedSsh:

    def test_returns_finding_when_ssh_open_to_world(self):
        finding = _check_unrestricted_ssh(
            _ec2_instance(has_unrestricted_ssh_ingress=True)
        )
        assert finding is not None
        assert finding.finding_type_id == "EC2_SECURITY_GROUP_UNRESTRICTED_SSH"

    def test_returns_none_when_ssh_not_open_to_world(self):
        finding = _check_unrestricted_ssh(
            _ec2_instance(has_unrestricted_ssh_ingress=False)
        )
        assert finding is None

    def test_returns_none_when_property_missing(self):
        # A detection signal: missing data means we didn't detect the
        # condition, not that it's absent -- no finding, same
        # semantic as key_state in the KMS scanner.
        finding = _check_unrestricted_ssh(_ec2_instance())
        assert finding is None

    def test_finding_has_high_severity_and_correct_shape(self):
        finding = _check_unrestricted_ssh(
            _ec2_instance("i-exposed", has_unrestricted_ssh_ingress=True)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.HIGH
        assert finding.resource_id == "i-exposed"
        assert len(finding.framework_references) > 0


# --- _check_unrestricted_rdp ---------------------------------------------
class TestCheckUnrestrictedRdp:

    def test_returns_finding_when_rdp_open_to_world(self):
        finding = _check_unrestricted_rdp(
            _ec2_instance(has_unrestricted_rdp_ingress=True)
        )
        assert finding is not None
        assert finding.finding_type_id == "EC2_SECURITY_GROUP_UNRESTRICTED_RDP"

    def test_returns_none_when_rdp_not_open_to_world(self):
        finding = _check_unrestricted_rdp(
            _ec2_instance(has_unrestricted_rdp_ingress=False)
        )
        assert finding is None

    def test_returns_none_when_property_missing(self):
        finding = _check_unrestricted_rdp(_ec2_instance())
        assert finding is None

    def test_finding_has_high_severity_and_correct_shape(self):
        finding = _check_unrestricted_rdp(
            _ec2_instance("i-exposed", has_unrestricted_rdp_ingress=True)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.HIGH
        assert finding.resource_id == "i-exposed"
        assert len(finding.framework_references) > 0


# --- _check_public_ip_in_private_subnet -----------------------------------
class TestCheckPublicIpInPrivateSubnet:

    def test_returns_finding_when_public_ip_in_private_subnet(self):
        finding = _check_public_ip_in_private_subnet(
            _ec2_instance(is_public_ip_in_private_subnet=True)
        )
        assert finding is not None
        assert finding.finding_type_id == "EC2_PUBLIC_IP_IN_PRIVATE_SUBNET"

    def test_returns_none_when_not_public_ip_in_private_subnet(self):
        finding = _check_public_ip_in_private_subnet(
            _ec2_instance(is_public_ip_in_private_subnet=False)
        )
        assert finding is None

    def test_returns_none_when_property_missing(self):
        finding = _check_public_ip_in_private_subnet(_ec2_instance())
        assert finding is None

    def test_finding_has_medium_severity_and_correct_shape(self):
        finding = _check_public_ip_in_private_subnet(
            _ec2_instance("i-mislabelled", is_public_ip_in_private_subnet=True)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.MEDIUM
        assert finding.resource_id == "i-mislabelled"
        assert len(finding.framework_references) > 0


# --- _check_ebs_unencrypted ------------------------------------------------
class TestCheckEbsUnencrypted:

    def test_returns_finding_when_volume_unencrypted(self):
        finding = _check_ebs_unencrypted(
            _ec2_instance(has_unencrypted_ebs_volume=True)
        )
        assert finding is not None
        assert finding.finding_type_id == "EC2_EBS_UNENCRYPTED"

    def test_returns_none_when_volume_encrypted(self):
        finding = _check_ebs_unencrypted(
            _ec2_instance(has_unencrypted_ebs_volume=False)
        )
        assert finding is None

    def test_returns_none_when_property_missing(self):
        # The normalizer already resolves a total volume-fetch
        # failure to True (fail-closed at that layer) -- by the time
        # the scanner sees this property, missing/False both mean the
        # same thing: no confirmed unencrypted volume.
        finding = _check_ebs_unencrypted(_ec2_instance())
        assert finding is None

    def test_finding_has_high_severity_and_correct_shape(self):
        finding = _check_ebs_unencrypted(
            _ec2_instance("i-unprotected", has_unencrypted_ebs_volume=True)
        )
        assert isinstance(finding, Finding)
        assert finding.severity == Severity.HIGH
        assert finding.resource_id == "i-unprotected"
        assert len(finding.framework_references) > 0


# --- scan_ec2_instances ----------------------------------------------------
class TestScanEc2Instances:

    def test_returns_empty_list_when_topology_has_no_nodes_key(self):
        assert scan_ec2_instances({}) == []

    def test_returns_empty_list_when_no_ec2_instances_present(self):
        topology = {
            "nodes": [
                {"id": "bucket-1", "type": "s3_bucket", "properties": {}},
                {"id": "key-1", "type": "kms_key", "properties": {}},
            ]
        }
        assert scan_ec2_instances(topology) == []

    def test_ignores_non_ec2_nodes(self):
        topology = {
            "nodes": [
                _ec2_instance("i-flagged", imdsv2_required=False),
                {"id": "bucket-1", "type": "s3_bucket"},  # no properties dict
            ]
        }
        findings = scan_ec2_instances(topology)
        assert all(f.resource_id == "i-flagged" for f in findings)

    def test_returns_zero_findings_for_fully_hardened_instance(self):
        topology = {
            "nodes": [
                _ec2_instance(
                    "i-hardened",
                    imdsv2_required=True,
                    has_unrestricted_ssh_ingress=False,
                    has_unrestricted_rdp_ingress=False,
                    is_public_ip_in_private_subnet=False,
                    has_unencrypted_ebs_volume=False,
                )
            ]
        }
        assert scan_ec2_instances(topology) == []

    def test_returns_five_findings_for_instance_with_every_issue(self):
        topology = {
            "nodes": [
                _ec2_instance(
                    "i-worst-case",
                    imdsv2_required=False,
                    has_unrestricted_ssh_ingress=True,
                    has_unrestricted_rdp_ingress=True,
                    is_public_ip_in_private_subnet=True,
                    has_unencrypted_ebs_volume=True,
                )
            ]
        }
        findings = scan_ec2_instances(topology)
        assert len(findings) == 5
        assert all(f.resource_id == "i-worst-case" for f in findings)
        assert [f.finding_type_id for f in findings] == [
            "EC2_IMDSV2_NOT_REQUIRED",
            "EC2_SECURITY_GROUP_UNRESTRICTED_SSH",
            "EC2_SECURITY_GROUP_UNRESTRICTED_RDP",
            "EC2_PUBLIC_IP_IN_PRIVATE_SUBNET",
            "EC2_EBS_UNENCRYPTED",
        ]

    def test_scans_multiple_instances_independently(self):
        topology = {
            "nodes": [
                _ec2_instance("i-clean", imdsv2_required=True),
                _ec2_instance("i-dirty", imdsv2_required=False),
            ]
        }
        findings = scan_ec2_instances(topology)
        assert len(findings) == 1
        assert findings[0].resource_id == "i-dirty"
        assert findings[0].finding_type_id == "EC2_IMDSV2_NOT_REQUIRED"
