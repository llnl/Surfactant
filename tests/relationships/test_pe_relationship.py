# pylint: disable=redefined-outer-name
import pathlib

import pytest

from surfactant.relationships import pe_relationship
from surfactant.sbomtypes import SBOM, Relationship, Software

DLL_UUID = "11111111-1111-4111-8111-111111111111"
BIN_UUID = "22222222-2222-4222-8222-222222222222"
DLL2_UUID = "33333333-3333-4333-8333-333333333333"
BIN2_UUID = "44444444-4444-4444-8444-444444444444"
DLL3_UUID = "55555555-5555-4555-8555-555555555555"
BIN3_UUID = "66666666-6666-4666-8666-666666666666"
DLL4_UUID = "77777777-7777-4777-8777-777777777777"
BIN4_UUID = "88888888-8888-4888-8888-888888888888"
DLL5_UUID = "99999999-9999-4999-8999-999999999999"
BIN5_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DLL6_UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
BIN6_UUID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


@pytest.fixture
def basic_pe_sbom():
    """
    Create a minimal SBOM with:
      - One binary located in C:/bin
      - One DLL located in C:/bin
      - The binary declares a direct PE import of 'foo.dll'

    Returns:
        Tuple[SBOM, Software, Software]: the SBOM, the binary, and the DLL
    """
    sbom = SBOM()

    dll = Software(
        UUID=DLL_UUID,
        notHashable=True,
        fileName=["foo.dll"],
        installPath=["C:/bin/foo.dll"],
    )

    binary = Software(
        UUID=BIN_UUID,
        notHashable=True,
        installPath=["C:/bin/app.exe"],
        metadata=[{"peImport": ["foo.dll"]}],
    )

    # Add both software components to the SBOM
    sbom.add_software(dll)
    sbom.add_software(binary)

    return sbom, binary, dll


def test_pe_import_via_fs_tree(basic_pe_sbom):
    """
    Test that a PE import is resolved correctly via fs_tree-based path matching.
    """
    sbom, binary, dll = basic_pe_sbom

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert results is not None
    assert len(results) == 1
    assert results[0] == Relationship(binary.UUID, dll.UUID, "Uses")


def test_pe_import_legacy_fallback(monkeypatch):
    """
    Verify that a PE dependency is resolved when fs_tree-based resolution is unavailable.

    This test exercises the legacy installPath-only fallback logic, which mirrors
    the behavior of legacy pe_relationships.
    """
    sbom = SBOM()

    dll = Software(
        UUID=DLL2_UUID,
        notHashable=True,
        fileName=["bar.dll"],
        installPath=["D:/tools/bar.dll"],
    )

    binary = Software(
        UUID=BIN2_UUID,
        notHashable=True,
        installPath=["D:/tools/app.exe"],
        metadata=[{"peBoundImport": ["bar.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    # Force Phase 1 to fail so Phase 2 is exercised
    monkeypatch.setattr(sbom, "get_software_by_path", lambda *a, **k: None)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert results == [Relationship(BIN2_UUID, DLL2_UUID, "Uses")]


def test_pe_same_directory_match():
    """
    Verify that a DLL with a matching fileName in the importer's directory is resolved.

    Note:
    - This will typically resolve in Phase 1 (fs_tree exact path). If fs_tree were
      unavailable for the exact path, the resolver's fallback also matches by
      fileName + same directory. (In the current resolver, Phase 2 uses that criterion.)
    """
    sbom = SBOM()

    dll = Software(
        UUID=DLL3_UUID,
        notHashable=True,
        fileName=["common.dll"],
        installPath=["E:/bin/common.dll"],
    )

    binary = Software(
        UUID=BIN3_UUID,
        notHashable=True,
        fileName=["app"],
        installPath=["E:/bin/app.exe"],
        metadata=[{"peDelayImport": ["common.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    # extra sanity check on normalized parent dir
    assert pathlib.PurePosixPath("E:/bin/common.dll").parent.as_posix() == "E:/bin"
    assert results is not None
    assert results == [Relationship(BIN3_UUID, DLL3_UUID, "Uses")]


def test_pe_no_match():
    """
    Ensure no relationship is emitted if the imported DLL cannot be resolved
    through any mechanism (fs_tree or legacy).
    """
    sbom = SBOM()

    dll = Software(
        UUID=DLL4_UUID,
        notHashable=True,
        fileName=["missing.dll"],
        installPath=["Z:/opt/ghost.dll"],
    )

    binary = Software(
        UUID=BIN4_UUID,
        notHashable=True,
        installPath=["Z:/opt/app.exe"],
        metadata=[{"peImport": ["doesnotexist.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert results == []


def test_pe_has_required_fields():
    """
    Unit test for has_required_fields(): ensure it returns True only if at least
    one valid PE field is present in the metadata.
    """
    assert pe_relationship.has_required_fields({"peImport": ["foo.dll"]})
    assert pe_relationship.has_required_fields({"peBoundImport": ["bar.dll"]})
    assert pe_relationship.has_required_fields({"peDelayImport": ["baz.dll"]})
    assert not pe_relationship.has_required_fields({"unrelated": []})


def test_pe_no_false_positive_mismatched_basename():
    """
    Ensure the resolver does not incorrectly match a DLL name to an installPath
    whose filename does not equal the imported DLL name, even if the directory
    matches and fileName[] contains the imported name.
    """
    sbom = SBOM()

    # Software entry claims multiple DLL names
    dll = Software(
        UUID=DLL5_UUID,
        notHashable=True,
        fileName=["afile.dll", "bfile.dll"],
        installPath=[
            "C:/somedir/afile.dll",  # in probedir, but wrong basename
            "C:/anotherdir/bfile.dll",  # correct basename, wrong directory
        ],
    )

    binary = Software(
        UUID=BIN5_UUID,
        notHashable=True,
        installPath=["C:/somedir/app.exe"],
        metadata=[{"peImport": ["bfile.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    # No relationship should be created because no installPath satisfies:
    #   dir == probedir AND basename == imported name
    assert results == []


def test_pe_case_insensitive_matching():
    """
    Verify that PE dependency resolution is case-insensitive, as required for
    Windows DLL lookup semantics. The imported DLL name (`foo.dll`) differs in
    case from the installed file's basename (`Foo.DLL`), but the resolver should
    still match them.
    """
    sbom = SBOM()

    dll = Software(
        UUID=DLL6_UUID,
        notHashable=True,
        fileName=["Foo.DLL"],  # DLL declared with uppercase letters
        installPath=["C:/bin/Foo.DLL"],  # actual installed path (Windows-style)
    )

    binary = Software(
        UUID=BIN6_UUID,
        notHashable=True,
        installPath=["C:/bin/app.exe"],
        metadata=[{"peImport": ["foo.dll"]}],  # import uses lowercase
    )

    # Add components to the SBOM
    sbom.add_software(dll)
    sbom.add_software(binary)

    # Resolve PE imports
    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    # The resolver should treat basenames case-insensitively and produce a match
    assert results == [Relationship(BIN6_UUID, DLL6_UUID, "Uses")]


def test_pe_legacy_fallback_directory_case_mismatch():
    """
    Ensure the legacy fallback resolves dependencies when directory casing differs.

    Phase 1 (fs_tree) performs a parent-directory + basename lookup with a limited
    Windows-style case-insensitive fallback that only compares basenames inside the
    exact parent node. This test exercises the legacy installPath-only fallback:
    when the importer and dependency use differing directory casing (e.g. "C:/bin"
    vs "c:/BIN"), fs_tree may not match but the legacy installPath matcher should,
    producing the expected Uses relationship.
    """
    sbom = SBOM()

    dll = Software(
        UUID=DLL_UUID,
        notHashable=True,
        installPath=["C:/bin/foo.dll"],
    )

    binary = Software(
        UUID=BIN_UUID,
        notHashable=True,
        installPath=["c:/BIN/app.exe"],  # directory casing differs
        metadata=[{"peImport": ["foo.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert results == [Relationship(BIN_UUID, DLL_UUID, "Uses")]
