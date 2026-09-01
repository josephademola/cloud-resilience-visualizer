"""
Integration test for the EC2 scanner.

Mirrors test_kms_scanner_integration.py's structure: runs the full
scanner against the real topology.json and locks in the expected
end-to-end behaviour.

Unlike KMS's flagship "doomed key" fixture, mock_aws.json's two EC2
instances are deliberately kept in a fully hardened state (IMDSv2
required, encrypted EBS volumes, no wide-open admin ports) -- the
project's established convention of proving bad-state detection
through unit tests (test_ec2_scanner.py) rather than committing an
insecure-looking instance to the shared mock data everyone's local
dev server and screenshots run against. Zero findings here is the
expected, correct outcome, not a gap in coverage.
"""

from pathlib import Path
import json

from app.scanners.ec2_scanner import scan_ec2_instances


_TOPOLOGY_PATH = (
    Path(__file__).resolve().parent.parent / "app" / "data" / "topology.json"
)

with open(_TOPOLOGY_PATH, encoding="utf-8") as _fh:
    TOPOLOGY = json.load(_fh)

FINDINGS = scan_ec2_instances(TOPOLOGY)


class TestEc2ScannerEndToEnd:

    def test_produces_zero_findings_against_hardened_mock_instances(self):
        assert FINDINGS == []

    def test_topology_actually_contains_ec2_instances(self):
        # Guards against this test suite silently passing for the
        # wrong reason (e.g. topology.json missing EC2 nodes
        # entirely) -- zero findings must mean "hardened", not
        # "nothing to scan".
        ec2_nodes = [
            n for n in TOPOLOGY.get("nodes", []) if n.get("type") == "ec2_instance"
        ]
        assert len(ec2_nodes) >= 1

    def test_findings_are_deterministic(self):
        second_run = scan_ec2_instances(TOPOLOGY)
        assert FINDINGS == second_run
