# pylint: disable=redefined-outer-name

import pytest

from surfactant.relationships import elf_relationship
from surfactant.relationships.elf_relationship import establish_relationships
from surfactant.sbomtypes import SBOM, Relationship, Software

SW1_UUID = "11111111-1111-4111-8111-111111111111"
SW2_UUID = "22222222-2222-4222-8222-222222222222"
SW3A_UUID = "33333333-3333-4333-8333-333333333333"
SW3B_UUID = "44444444-4444-4444-8444-444444444444"
SW4_CONSUMER_UUID = "55555555-5555-4555-8555-555555555555"
SW4_UUID = "66666666-6666-4666-8666-666666666666"
SW5_UUID = "77777777-7777-4777-8777-777777777777"
SW6_UUID = "88888888-8888-4888-8888-888888888888"
SW7_UUID = "99999999-9999-4999-8999-999999999999"
SW8_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SW9_UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
BIN_UUID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
UNRELATED_UUID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
FALSEMATCH_UUID = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"


@pytest.fixture
def example_sbom():
    sbom = SBOM()

    sw1 = Software(
        UUID=SW1_UUID,
        notHashable=True,
        fileName=["libfoo.so.1"],
        installPath=["/usr/lib/libfoo.so.1"],
    )
    sw2 = Software(
        UUID=SW2_UUID,
        notHashable=True,
        fileName=["libbar.so"],
        installPath=["/opt/myapp/lib/libbar.so"],
    )

    sw3a = Software(
        UUID=SW3A_UUID,
        notHashable=True,
        installPath=["/opt/myapp/bin/myapp"],
        metadata=[{"elfDependencies": ["/usr/lib/libfoo.so.1"]}],
    )
    sw3b = Software(
        UUID=SW3B_UUID,
        notHashable=True,
        installPath=["/opt/myapp/bin/myapp"],
        metadata=[{"elfDependencies": ["libbar.so"], "elfRunpath": ["$ORIGIN/../lib"]}],
    )
    sw4_consumer = Software(
        UUID=SW4_CONSUMER_UUID,
        notHashable=True,
        installPath=["/bin/testbin"],
        metadata=[{"elfDependencies": ["libxyz.so"]}],
    )
    sw4 = Software(
        UUID=SW4_UUID,
        notHashable=True,
        fileName=["libxyz.so"],
        installPath=["/lib/libxyz.so"],
        metadata=[{"elfDependencies": ["libxyz.so"]}],
    )
    sw5 = Software(
        UUID=SW5_UUID,
        notHashable=True,
        fileName=["libdep.so"],
        installPath=["/app/lib/libdep.so"],
    )
    sw6 = Software(
        UUID=SW6_UUID,
        notHashable=True,
        installPath=["/app/bin/mybin"],
        metadata=[{"elfDependencies": ["libdep.so"], "elfRunpath": ["$ORIGIN/../lib"]}],
    )
    sw7 = Software(
        UUID=SW7_UUID,
        notHashable=True,
        installPath=["/legacy/bin/legacyapp"],
        metadata=[{"elfDependencies": ["libbar.so"], "elfRpath": ["/opt/myapp/lib"]}],
    )
    sw8 = Software(
        UUID=SW8_UUID,
        notHashable=True,
        fileName=["libalias.so"],
        installPath=["/opt/alt/lib/libreal.so"],
    )
    sw9 = Software(
        UUID=SW9_UUID,
        notHashable=True,
        installPath=["/opt/alt/bin/app"],
        metadata=[{"elfDependencies": ["libalias.so"], "elfRunpath": ["/opt/alt/lib"]}],
    )

    # First add all software so fs_tree has the real file nodes
    for sw in [sw1, sw2, sw3a, sw3b, sw4, sw4_consumer, sw5, sw6, sw7, sw8, sw9]:
        sbom.add_software(sw)

    # Now add the symlink mapping for sw8 (alias -> real file)
    sbom.record_symlink("/opt/alt/lib/libalias.so", "/opt/alt/lib/libreal.so", subtype="file")

    # And expand pending file symlinks so fs_tree exposes the alias path
    sbom.expand_pending_file_symlinks()

    return sbom, {
        "absolute": (sw3a, SW1_UUID),
        "relative": (sw3b, SW2_UUID),
        "system": (sw4_consumer, SW4_UUID),
        "origin": (sw6, SW5_UUID),
        "rpath": (sw7, SW2_UUID),
        "symlink": (sw9, SW8_UUID),
    }


@pytest.mark.parametrize("label", ["absolute", "relative", "system", "origin", "rpath", "symlink"])
def test_elf_relationship_cases(example_sbom, label):
    """
    Validate ELF relationship resolution across multiple scenarios.

    This test is parameterized to exercise the six primary resolution paths used by
    the ELF plugin. For each `label`, the `example_sbom` fixture returns:
      - `sw`:   the consumer `Software` object under test
      - `expected_uuid`: the UUID of the supplier `Software` that should be linked via a
                         `Relationship(sw.UUID, expected_uuid, "Uses")`

    The cases covered:
      - "absolute": dependency is an absolute path (e.g., /usr/lib/libfoo.so.1)
      - "relative": dependency name + runpath derived from $ORIGIN, e.g. "$ORIGIN/../lib"
      - "system":   dependency resolved via standard system library directories (e.g., /lib)
      - "origin":   dependency resolved via $ORIGIN expansion relative to the binary
      - "rpath":    dependency resolved via legacy RPATH entries
      - "symlink":  dependency resolved through a symlink edge in the SBOM fs_tree

    Expectations:
      - Exactly one "Uses" relationship is emitted.
      - The dependency resolves to `expected_uuid`, and never to the consumer itself.
    """
    sbom, case_map = example_sbom

    # Retrieve the consumer under test and the expected supplier UUID
    sw, expected_uuid = case_map[label]

    # Pull the ELF metadata for this software (may include elfDependencies, elfRunpath/Rpath, etc.)
    metadata = sw.metadata[0] if sw.metadata else {}

    # Execute the plugin and assert a single, correct relationship is produced
    result = elf_relationship.establish_relationships(sbom, sw, metadata)

    # Sanity checks: one result, and it matches the expected supplier UUID
    assert result is not None, f"{label} case failed: no result"
    assert len(result) == 1, f"{label} case failed: expected 1 relationship"
    assert result[0] == Relationship(sw.UUID, expected_uuid, "Uses"), (
        f"{label} case mismatch: {result[0]} != {expected_uuid}"
    )


def test_no_match_edge_case():
    """
    Test case: No matching dependency by any means (fs_tree, legacy, or heuristic).
    Expect no relationships.
    """
    binary = Software(
        UUID=BIN_UUID,
        notHashable=True,
        fileName=["mybin"],
        installPath=["/some/bin/mybin"],
        metadata=[{"elfDependencies": ["libnotfound.so"], "elfRunpath": ["/some/lib"]}],
    )

    unrelated = Software(
        UUID=UNRELATED_UUID,
        notHashable=True,
        fileName=["libsomethingelse.so"],
        installPath=["/unrelated/path/libsomethingelse.so"],
    )

    sbom = SBOM(hardware=[], software=[binary, unrelated])

    metadata = binary.metadata[0]
    results = establish_relationships(sbom, binary, metadata)

    assert results is not None
    assert len(results) == 0, "Expected no relationships for unmatched dependency"


def test_symlink_heuristic_guard():
    """
    Tests that the symlink heuristic does not falsely match entries where
    fileName matches but installPath is in a different directory.
    """
    binary = Software(
        UUID=BIN_UUID,
        notHashable=True,
        fileName=["myapp"],
        installPath=["/opt/app/bin/myapp"],
        metadata=[{"elfDependencies": ["libalias.so"], "elfRunpath": ["/opt/app/lib"]}],
    )

    # Same file name, but located in a different directory -> should NOT match
    candidate = Software(
        UUID=FALSEMATCH_UUID,
        notHashable=True,
        fileName=["libalias.so"],
        installPath=["/different/dir/libalias.so"],
    )

    sbom = SBOM(hardware=[], software=[binary, candidate])

    metadata = binary.metadata[0]
    results = establish_relationships(sbom, binary, metadata)

    assert results is not None
    assert all(rel.yUUID != FALSEMATCH_UUID for rel in results), "Heuristic should not have matched"
