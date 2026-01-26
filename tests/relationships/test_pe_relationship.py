# pylint: disable=redefined-outer-name
import pathlib

import pytest

from surfactant.relationships import pe_relationship
from surfactant.sbomtypes import SBOM, Relationship, Software


@pytest.fixture
def basic_pe_sbom():
    """
    Create a minimal SBOM with:
      - One binary (UUID: uuid-bin) located in C:/bin
      - One DLL (UUID: uuid-dll) located in C:/bin
      - The binary declares a direct PE import of 'foo.dll'

    Returns:
        Tuple[SBOM, Software, Software]: the SBOM, the binary, and the DLL
    """
    sbom = SBOM()

    dll = Software(
        UUID="uuid-dll",
        fileName=["foo.dll"],
        installPath=["C:/bin/foo.dll"],
    )

    binary = Software(
        UUID="uuid-bin",
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


def test_pe_import_legacy_fallback():
    """
    Test that PE relationship fallback works when fs_tree does not contain the path.
    It should fall back to installPath + fileName matching.
    """
    sbom = SBOM()

    dll = Software(
        UUID="uuid-dll",
        fileName=["bar.dll"],
        installPath=["D:/tools/bar.dll"],
    )

    binary = Software(
        UUID="uuid-bin",
        installPath=["D:/tools/app.exe"],
        metadata=[{"peBoundImport": ["bar.dll"]}],
    )

    sbom.add_software(dll)
    sbom.add_software(binary)

    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    assert results is not None
    assert results == [Relationship("uuid-bin", "uuid-dll", "Uses")]


def test_pe_same_directory_match():
    """
    Verify that a DLL with a matching fileName in the importer's directory is resolved.

    Note:
    - This will typically resolve in Phase 1 (fs_tree exact path). If fs_tree were
      unavailable for the exact path, the resolver’s fallback also matches by
      fileName + shared directory. (In the current resolver, Phase 2 and Phase 3
      both use that criterion.)
    """
    sbom = SBOM()

    dll = Software(
        UUID="uuid-dll",
        fileName=["common.dll"],
        installPath=["E:/bin/common.dll"],  # <== change this
    )

    binary = Software(
        UUID="uuid-bin",
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
    assert results == [Relationship("uuid-bin", "uuid-dll", "Uses")]


def test_pe_no_match():
    """
    Ensure no relationship is emitted if the imported DLL cannot be resolved
    through any mechanism (fs_tree, legacy, or heuristic).
    """
    sbom = SBOM()

    dll = Software(
        UUID="uuid-dll",
        fileName=["missing.dll"],
        installPath=["Z:/opt/ghost.dll"],
    )

    binary = Software(
        UUID="uuid-bin",
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
        UUID="uuid-dll",
        fileName=["afile.dll", "bfile.dll"],
        installPath=[
            "C:/somedir/afile.dll",  # in probedir, but wrong basename
            "C:/anotherdir/bfile.dll",  # correct basename, wrong directory
        ],
    )

    binary = Software(
        UUID="uuid-bin",
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
        UUID="uuid-dll",
        fileName=["Foo.DLL"],  # DLL declared with uppercase letters
        installPath=["C:/bin/Foo.DLL"],  # actual installed path (Windows-style)
    )

    binary = Software(
        UUID="uuid-bin",
        installPath=["C:/bin/app.exe"],
        metadata=[{"peImport": ["foo.dll"]}],  # import uses lowercase
    )

    # Add components to the SBOM
    sbom.add_software(dll)
    sbom.add_software(binary)

    # Resolve PE imports
    results = pe_relationship.establish_relationships(sbom, binary, binary.metadata[0])

    # The resolver should treat basenames case-insensitively and produce a match
    assert results == [Relationship("uuid-bin", "uuid-dll", "Uses")]
