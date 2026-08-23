"""
Unit tests for app.mappings.loader.

The loader reads every framework JSON file present in app/mappings/
and provides a single lookup by finding_type_id. Six files are always
committed to the repo; a seventh (confidential_controls.json) is
gitignored and only present on machines where it was placed locally
(see docs/design_decisions.md #11) — the loader tolerates its
absence, and these tests treat "seven" as a possible bonus, not a
guarantee. These tests verify:

  - Known finding types return references from every framework that
    maps them (the "combining" behaviour).
  - Unknown finding types return an empty tuple, not raise.
  - Meta keys ("_meta") are excluded — they document files, they
    aren't finding entries.
  - The returned value is a tuple (immutable) so callers can pass it
    directly to Finding(framework_references=...).

These tests read the real mapping files in app/mappings/ rather than
mocking them. Small project, static content, no reason to fake it.
"""

import json

from app.mappings import loader as loader_module
from app.mappings.loader import get_framework_references
from app.models.finding import FrameworkReference


# --- get_framework_references ----------------------------------------
class TestGetFrameworkReferences:

    def test_returns_references_for_known_finding_type(self):
        # S3_PUBLIC_VIA_ACL is mapped in every mapping file we ship.
        # The loader combines all of them into one flat list.
        refs = get_framework_references("S3_PUBLIC_VIA_ACL")
        assert len(refs) > 0

    def test_combines_references_from_all_six_public_frameworks(self):
        # S3_PUBLIC_VIA_ACL has entries in all six publicly-committed
        # mapping files. The loader must combine them so a downstream
        # reader sees all six framework names. Deliberately a subset
        # check, not an exact-equality one: confidential_controls.json
        # is gitignored and client-confidential (see
        # docs/design_decisions.md #11) — it exists on this developer's
        # machine but not in CI's fresh checkout, so whether
        # "confidential" is ALSO present is environment-dependent and
        # not part of this test's contract. The six public frameworks
        # being present always is the actual guarantee.
        refs = get_framework_references("S3_PUBLIC_VIA_ACL")
        frameworks_present = {r.framework for r in refs}
        assert {
            "nis2",
            "ncsc_caf",
            "mitre_attack",
            "cyber_essentials",
            "iso27001",
            "dora",
        }.issubset(frameworks_present)

    def test_returns_empty_tuple_for_unknown_finding_type(self):
        # An ID that doesn't exist in any mapping file should give
        # back an empty tuple rather than raise. The scanner will
        # normally only ask for IDs it just emitted, so this is
        # defensive — but wrong IDs shouldn't crash the whole run.
        refs = get_framework_references("NONSENSE_FINDING_TYPE_XYZ")
        assert refs == ()

    def test_skips_meta_keys_when_iterating(self):
        # Each mapping file starts with a "_meta" block that documents
        # the framework. It must NOT be exposed as if it were a
        # finding type — asking for "_meta" should return nothing.
        refs = get_framework_references("_meta")
        assert refs == ()

    def test_returns_tuple_not_list(self):
        # The scanner passes the return value straight into a
        # frozen Finding dataclass, which expects a tuple. Locking in
        # the tuple type here means a refactor can't silently turn
        # this into a list and break the frozen invariant downstream.
        refs = get_framework_references("S3_PUBLIC_VIA_ACL")
        assert isinstance(refs, tuple)
        # Each item is itself a FrameworkReference dataclass instance
        # (also frozen), not a raw dict.
        for ref in refs:
            assert isinstance(ref, FrameworkReference)


# --- Missing mapping file tolerance ------------------------------------
class TestMissingMappingFile:
    """
    confidential_controls.json is deliberately not committed to the
    repo (client-confidential) -- it only exists on machines/
    environments where someone placed it locally. The loader must
    degrade gracefully wherever it's absent (e.g. the deployed
    instance), not crash the whole app over one missing file.
    """

    def test_load_all_mappings_skips_a_missing_file_without_raising(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "nis2.json").write_text(
            json.dumps({
                "TEST_FINDING": [
                    {"framework": "nis2", "reference_id": "X", "label": "Y"}
                ]
            }),
            encoding="utf-8",
        )
        monkeypatch.setattr(loader_module, "_MAPPINGS_DIR", tmp_path)
        monkeypatch.setattr(
            loader_module, "_FRAMEWORK_FILES", ("nis2.json", "does_not_exist.json")
        )
        monkeypatch.setattr(loader_module, "_MAPPINGS_CACHE", None)

        refs = loader_module.get_framework_references("TEST_FINDING")

        assert len(refs) == 1
        assert refs[0].framework == "nis2"