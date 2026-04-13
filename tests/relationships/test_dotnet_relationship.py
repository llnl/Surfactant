# pylint: disable=redefined-outer-name
import pytest

from surfactant.relationships import dotnet_relationship
from surfactant.sbomtypes import SBOM, Relationship, Software

SUPPLIER_UUID = "11111111-1111-4111-8111-111111111111"
CONSUMER_UUID = "22222222-2222-4222-8222-222222222222"
LIB_UUID = "33333333-3333-4333-8333-333333333333"
APP_UUID = "44444444-4444-4444-8444-444444444444"
NATIVE_UUID = "55555555-5555-4555-8555-555555555555"
LIB1_UUID = "66666666-6666-4666-8666-666666666666"
LIB2_UUID = "77777777-7777-4777-8777-777777777777"
LIB3_UUID = "88888888-8888-4888-8888-888888888888"
LIB_HEUR_UUID = "99999999-9999-4999-8999-999999999999"
APP_HEUR_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
LIB4_UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
LIB6_UUID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


@pytest.fixture
def sbom_fixture():
    """
    Fixture: returns a basic SBOM with a .NET supplier and consumer.
    - Supplier exports SomeLibrary.dll with version metadata.
    - Consumer references SomeLibrary.dll in its dotnetAssemblyRef.
    """
    sbom = SBOM()

    supplier = Software(
        UUID=SUPPLIER_UUID,
        notHashable=True,
        fileName=["SomeLibrary.dll"],
        installPath=["/app/bin/SomeLibrary.dll"],
        metadata=[{"dotnetAssembly": {"Name": "SomeLibrary", "Version": "1.0.0.0"}}],
    )

    consumer = Software(
        UUID=CONSUMER_UUID,
        notHashable=True,
        installPath=["/app/bin/App.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "SomeLibrary", "Version": "1.0.0.0"}]}],
    )

    sbom.add_software(supplier)
    sbom.add_software(consumer)

    return sbom, consumer, supplier


def test_dotnet_fs_tree_match(sbom_fixture):
    """
    Test Phase 1: fs_tree resolution using get_software_by_path.
    Ensures the plugin emits a relationship if the path is indexed.
    """
    sbom, consumer, supplier = sbom_fixture

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship(consumer.UUID, supplier.UUID, "Uses")]


def test_dotnet_codebase_match():
    """
    Test: codeBase.href resolution from app.config.
    Ensures href is respected as a valid relative match.
    """
    sbom = SBOM()

    supplier = Software(
        UUID=LIB_UUID,
        notHashable=True,
        fileName=["lib.dll"],
        installPath=["/app/private/lib.dll"],
    )

    consumer = Software(
        UUID=APP_UUID,
        notHashable=True,
        installPath=["/app/main.exe"],
        metadata=[
            {
                "dotnetAssemblyRef": [{"Name": "lib"}],
                "appConfigFile": {
                    "runtime": {
                        "assemblyBinding": {
                            "dependentAssembly": [{"codeBase": {"href": "private/lib.dll"}}]
                        }
                    }
                },
            }
        ],
    )

    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship(APP_UUID, LIB_UUID, "Uses")]


def test_dotnet_implmap_unmanaged_match():
    """
    Test: unmanaged import from dotnetImplMap should resolve as native.
    Ensures fallback probing with name variants like native.dll, native.so, etc.
    """
    sbom = SBOM()

    supplier = Software(
        UUID=NATIVE_UUID,
        notHashable=True,
        fileName=["native.so"],
        installPath=["/app/lib/native.so"],
    )

    consumer = Software(
        UUID=CONSUMER_UUID,
        notHashable=True,
        installPath=["/app/lib/main.exe"],
        metadata=[{"dotnetImplMap": [{"Name": "native"}], "dotnetAssemblyRef": []}],
    )

    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship(CONSUMER_UUID, NATIVE_UUID, "Uses")]


def test_dotnet_same_directory():
    """
    Test: assembly in same directory as consumer should be resolved.
    Covers legacy phase and base probing behavior.
    """
    sbom = SBOM()
    supplier = Software(
        UUID=LIB1_UUID,
        notHashable=True,
        fileName=["samedirlib.dll"],
        installPath=["/app/samedirlib.dll"],
    )
    consumer = Software(
        UUID=APP_UUID,
        notHashable=True,
        installPath=["/app/main.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "samedirlib"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship(APP_UUID, LIB1_UUID, "Uses")]


def test_dotnet_subdir():
    """
    Test: DLL in legacy-probed subdirectory is found by probing.
    Covers Phase 2 fallback behavior.
    """
    sbom = SBOM()
    supplier = Software(
        UUID=LIB2_UUID,
        notHashable=True,
        fileName=["subdirlib.dll"],
        installPath=["/app/subdirlib/subdirlib.dll"],
    )
    consumer = Software(
        UUID=APP_UUID,
        notHashable=True,
        installPath=["/app/main.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "subdirlib"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship(APP_UUID, LIB2_UUID, "Uses")]


def test_dotnet_culture_subdir():
    """
    Test: DLL match is allowed only if the Culture metadata agrees.

    Important note:
    - The .NET resolver does not auto-probe culture-specific subdirectories.
    - Instead, it uses the Culture field as a filter when evaluating candidates.
    - In this case the supplier resides under '/app/culture/' and declares
      Culture='culture', while the consumer requests Culture='culture'.
    - Because version/culture filters pass, the supplier is accepted.

    This test ensures culture mismatches are excluded and matches are accepted
    only when Culture aligns.
    """
    sbom = SBOM()
    supplier = Software(
        UUID=LIB3_UUID,
        notHashable=True,
        fileName=["culturelib.dll"],
        installPath=["/app/culture/culturelib.dll"],
    )
    consumer = Software(
        UUID=APP_UUID,
        notHashable=True,
        installPath=["/app/main.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "culturelib", "Culture": "culture"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship(APP_UUID, LIB3_UUID, "Uses")]


def test_dotnet_no_match_without_exact_basename():
    """
    Test: a DLL in the same directory is NOT matched when its basename does
    not align with the referenced assembly name.

    Scenario:
      - Consumer imports 'heur' (filename variants: 'heur', 'heur.dll').
      - Provider lives in the same directory but is installed as
        '/app/bin/heur.dll.bak'.

    Expected behavior:
      - Phase 1 (fs_tree): no exact path '/app/bin/heur' or '/app/bin/heur.dll'.
      - Phase 2 (installPath + fileName): installPath does not end with
        'heur' or 'heur.dll', so no match is accepted.
      - No heuristic "same-directory" fallback is applied, so no relationship
        is created.
    """
    sbom = SBOM()

    supplier = Software(
        UUID=LIB_HEUR_UUID,
        notHashable=True,
        fileName=["heur.dll"],
        installPath=["/app/bin/heur.dll.bak"],
    )

    consumer = Software(
        UUID=APP_HEUR_UUID,
        notHashable=True,
        installPath=["/app/bin/app.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "heur"}]}],
    )

    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])

    assert results == []


def test_dotnet_private_path():
    """
    Test: DLL resolved from app.config probing.privatePath directories.
    Ensures private paths are appended to probe set.
    """
    sbom = SBOM()
    supplier = Software(
        UUID=LIB4_UUID,
        notHashable=True,
        fileName=["pvtlib.dll"],
        installPath=["/app/bin/custom/pvtlib.dll"],
    )
    consumer = Software(
        UUID=APP_UUID,
        notHashable=True,
        installPath=["/app/bin/app.exe"],
        metadata=[
            {
                "dotnetAssemblyRef": [{"Name": "pvtlib"}],
                "appConfigFile": {
                    "runtime": {"assemblyBinding": {"probing": {"privatePath": "custom"}}}
                },
            }
        ],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == [Relationship(APP_UUID, LIB4_UUID, "Uses")]


# def test_dotnet_version_mismatch_filtered():
#     """
#     Test: supplier has wrong version; should be filtered out by version check.
#     """
#     sbom = SBOM()
#     supplier = Software(
#         UUID="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
#         notHashable=True,
#         fileName=["wrong.dll"],
#         installPath=["/lib/wrong.dll"],
#         metadata=[{"dotnetAssembly": {"Name": "wrong", "Version": "2.0.0.0"}}],
#     )
#     consumer = Software(
#         UUID=APP_UUID,
#         notHashable=True,
#         installPath=["/lib/app.exe"],
#         metadata=[{"dotnetAssemblyRef": [{"Name": "wrong", "Version": "1.0.0.0"}]}],
#     )
#     sbom.add_software(supplier)
#     sbom.add_software(consumer)

#     results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
#     assert results == []


def test_dotnet_culture_mismatch_filtered():
    """
    Test: supplier has wrong culture; should be filtered out by culture check.
    """
    sbom = SBOM()
    supplier = Software(
        UUID=LIB6_UUID,
        notHashable=True,
        fileName=["wrongcult.dll"],
        installPath=["/lib/wrongcult.dll"],
        metadata=[{"dotnetAssembly": {"Name": "wrongcult", "Culture": "xx"}}],
    )
    consumer = Software(
        UUID=APP_UUID,
        notHashable=True,
        installPath=["/lib/app.exe"],
        metadata=[{"dotnetAssemblyRef": [{"Name": "wrongcult", "Culture": "yy"}]}],
    )
    sbom.add_software(supplier)
    sbom.add_software(consumer)

    results = dotnet_relationship.establish_relationships(sbom, consumer, consumer.metadata[0])
    assert results == []
