import weakref
from typing import Dict, List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software


def has_required_fields(metadata) -> bool:
    """Check whether the metadata includes Java class information."""
    return isinstance(metadata, dict) and "javaClasses" in metadata


class _ExportDict:
    """Legacy export lookup table: Java export class -> supplier UUID.

    Mirrors java_relationship._ExportDict (Legacy), but caches per-SBOM instance
    (via weakref).
    """

    _sbom_ref: Optional[weakref.ref[SBOM]] = None
    supplied_by: Dict[str, str] = {}

    @classmethod
    def create_export_dict(cls, sbom: SBOM) -> None:
        """Build (or reuse) the export lookup map for the provided SBOM."""
        if cls._sbom_ref is not None and cls._sbom_ref() is sbom:  # pylint: disable=not-callable
            return

        cls._sbom_ref = weakref.ref(sbom)
        cls.supplied_by = {}

        for software_entry in sbom.software:
            if not software_entry.metadata:
                continue
            for md in software_entry.metadata:
                if not isinstance(md, dict):
                    continue
                java_classes = md.get("javaClasses")
                if not java_classes:
                    continue
                for class_info in java_classes.values():
                    for export in class_info.get("javaExports", []):
                        cls.supplied_by[export] = software_entry.UUID

    @classmethod
    def get_supplier(cls, import_name: str) -> Optional[str]:
        return cls.supplied_by.get(import_name)


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """Establish 'Uses' relationships for Java class-level imports.

    Resolution phases (new -> old):
      1. TODO: Not Implemented: [fs_tree] Attempt to resolve the imported class to a Software entry by
         path lookup in SBOM.fs_tree (sbom.get_software_by_path()).
      2. [legacy] Fall back to the legacy export-dict behavior
         (javaExports -> supplier UUID).

    The Phase-2 fallback is intended to mirror java_relationship.py (Legacy) as
    closely as possible, and should produce the same relationships when fs_tree
    cannot resolve an import.
    """
    if not has_required_fields(metadata):
        logger.debug(f"[Java][skip] No javaClasses metadata for UUID={software.UUID}")
        return None

    java_classes = metadata["javaClasses"]
    dependent_uuid = software.UUID

    # Build legacy export dict once per SBOM instance.
    _ExportDict.create_export_dict(sbom)

    relationships: List[Relationship] = []

    for class_info in java_classes.values():
        for import_name in class_info.get("javaImports", []):
            supplier_uuid: Optional[str] = None
            method: Optional[str] = None

            # ------------------------------------------------------------------
            # Phase 1: fs_tree / path-based resolution (conservative)
            # ------------------------------------------------------------------
            # TODO: Not Implemented: Attempt to resolve the imported class via SBOM.fs_tree.

            # ------------------------------------------------------------------
            # Phase 2: legacy export-dict behavior (matches legacy plugin)
            # ------------------------------------------------------------------
            if supplier_uuid is None:
                supplier_uuid = _ExportDict.get_supplier(import_name)
                method = "legacy_exports" if supplier_uuid else None
                logger.debug(f"[Java][legacy] {import_name} -> UUID={supplier_uuid}")

            # Emit relationship if resolved and not self.
            if supplier_uuid and supplier_uuid != dependent_uuid:
                rel = Relationship(dependent_uuid, supplier_uuid, "Uses")
                if rel not in relationships:
                    if method:
                        logger.debug(
                            f"[Java][final] {dependent_uuid} Uses {import_name} -> UUID={supplier_uuid} [{method}]"
                        )
                    relationships.append(rel)

    logger.debug(f"[Java][final] emitted {len(relationships)} relationships")
    return relationships
