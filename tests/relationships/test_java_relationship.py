# pylint: disable=redefined-outer-name
import pytest

from surfactant.relationships import java_relationship
from surfactant.sbomtypes import SBOM, Relationship, Software


def test_legacy_export_match():
    """
    Phase 2: Validate the legacy export-dict fallback
    """
    sbom = SBOM()

    supplier = Software(
        UUID="uuid-supplier",
        fileName=["HelloWorld.class"],
        installPath=["/app/classes/com/example/HelloWorld.class"],
        metadata=[
            {"javaClasses": {"com.example.HelloWorld": {"javaExports": ["com.example.HelloWorld"]}}}
        ],
    )

    importer = Software(
        UUID="uuid-importer",
        installPath=["/other/bin/app.jar"],
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
        UUID="uuid-supplier", fileName=["Other.class"], installPath=["/somewhere/Other.class"]
    )

    importer = Software(
        UUID="uuid-importer",
        installPath=["/bin/app.jar"],
        metadata=[
            {"javaClasses": {"com.example.Main": {"javaImports": ["com.example.HelloWorld"]}}}
        ],
    )

    sbom.add_software(supplier)
    sbom.add_software(importer)

    results = java_relationship.establish_relationships(sbom, importer, importer.metadata[0])

    assert results == []
