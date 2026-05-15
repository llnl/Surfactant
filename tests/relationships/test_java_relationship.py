# pylint: disable=redefined-outer-name

from surfactant.relationships import java_relationship
from surfactant.sbomtypes import SBOM, Relationship, Software


def test_legacy_export_match():
    """
    Phase 2: Validate the legacy export-dict fallback
    """
    sbom = SBOM()

    supplier = Software(
        UUID="11111111-1111-4111-8111-111111111111",
        fileName=["HelloWorld.class"],
        installPath=["/app/classes/com/example/HelloWorld.class"],
        sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        metadata=[
            {"javaClasses": {"com.example.HelloWorld": {"javaExports": ["com.example.HelloWorld"]}}}
        ],
    )

    importer = Software(
        UUID="22222222-2222-4222-8222-222222222222",
        installPath=["/other/bin/app.jar"],
        sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        metadata=[
            {"javaClasses": {"com.example.Main": {"javaImports": ["com.example.HelloWorld"]}}}
        ],
    )

    sbom.add_software(supplier)
    sbom.add_software(importer)

    results = java_relationship.establish_relationships(sbom, importer, importer.metadata[0])

    assert results is not None
    assert results == [Relationship(importer.UUID, supplier.UUID, "Uses")]


def test_no_match_returns_empty():
    """
    Validate that no relationship is returned when no match is possible
    """
    sbom = SBOM()

    supplier = Software(
        UUID="33333333-3333-4333-8333-333333333333",
        fileName=["Other.class"],
        installPath=["/somewhere/Other.class"],
        sha256="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    )

    importer = Software(
        UUID="44444444-4444-4444-8444-444444444444",
        installPath=["/bin/app.jar"],
        sha256="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        metadata=[
            {"javaClasses": {"com.example.Main": {"javaImports": ["com.example.HelloWorld"]}}}
        ],
    )

    sbom.add_software(supplier)
    sbom.add_software(importer)

    results = java_relationship.establish_relationships(sbom, importer, importer.metadata[0])

    assert results == []
