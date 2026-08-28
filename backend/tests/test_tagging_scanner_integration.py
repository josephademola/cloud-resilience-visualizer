"""
Integration test for the tagging scanner.

Mirrors test_account_scanner_integration.py's structure: runs the
full scanner against the real topology.json and locks in the
expected end-to-end behaviour.
"""

from pathlib import Path
import json

from app.scanners.tagging_scanner import scan_tagging


_TOPOLOGY_PATH = (
    Path(__file__).resolve().parent.parent / "app" / "data" / "topology.json"
)

with open(_TOPOLOGY_PATH, encoding="utf-8") as _fh:
    TOPOLOGY = json.load(_fh)

FINDINGS = scan_tagging(TOPOLOGY)


class TestTaggingScannerEndToEnd:

    def test_produces_zero_findings_against_fully_tagged_mock(self):
        # Every taggable resource in mock_aws.json's
        # resourcegroupstaggingapi section carries at least one tag
        # (kept deliberately tagged so this new rule doesn't ripple
        # through every other scanner's hardcoded finding counts) --
        # see TestCheckHasAnyTags in test_tagging_scanner.py for the
        # untagged case, tested directly with a synthetic fixture.
        assert FINDINGS == []

    def test_findings_are_deterministic(self):
        second_run = scan_tagging(TOPOLOGY)
        assert FINDINGS == second_run
