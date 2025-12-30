from typing import Dict, List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software


def has_required_fields(metadata) -> bool:
    """
    Check whether the metadata includes Java class information.
    """
    return "javaClasses" in metadata


class _ExportDict:
    supplied_by: Dict[str, str] = {}

    @classmethod
    def create_export_dict(cls, sbom: SBOM):
        """
        Build a map from exported class name → supplier UUID.

        This mirrors the behavior of java_relationship_legacy._ExportDict,
        but is rebuilt per-SBOM to avoid leaking state across calls/tests.
        """
        cls.supplied_by = {}
        for software_entry in sbom.software:
            if not software_entry.metadata:
                continue
            for metadata in software_entry.metadata:
                if not isinstance(metadata, dict):
                    continue
                java_classes = metadata.get("javaClasses")
                if not java_classes:
                    continue
                for class_info in java_classes.values():
                    for export in class_info.get("javaExports", []):
                        cls.supplied_by[export] = software_entry.UUID

    @classmethod
    def get_supplier(cls, export: str) -> Optional[str]:
        return cls.supplied_by.get(export)


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """
    SurfActant plugin: Establish 'Uses' relationships for Java class-level imports.

    Resolution phases:
      1. [fs_tree] Exact path match using fs_tree.
      2. [legacy] installPath + fileName match.

    Args:
        sbom (SBOM): The SBOM object containing all software entries and path graphs.
        software (Software): The software entry declaring Java class dependencies.
        metadata (dict): Metadata containing 'javaClasses' with import/export info.

    Returns:
        Optional[List[Relationship]]: List of `Uses` relationships, or None if not applicable.
    """
    if not has_required_fields(metadata):
        logger.debug(f"[Java][skip] No javaClasses metadata for UUID={software.UUID}")
        return None

    # Build legacy export dict once per process (no-op if already built)
    _ExportDict.create_export_dict(sbom)

    relationships: List[Relationship] = []
    dependent_uuid = software.UUID
    java_classes = metadata["javaClasses"]

    # Collect imported class names
    imports = {imp for cls in java_classes.values() for imp in cls.get("javaImports", [])}
    logger.debug(f"[Java][import] {software.UUID} importing {len(imports)} classes")

    for import_class in imports:
        class_path = class_to_path(import_class)
        matched_uuids = set()
        used_method = {}

        logger.debug(f"[Java][import] resolving {import_class} → {class_path}")

        # ------------------------------------------------------------------
        # Phase 1: fs_tree / path-based resolution
        # ------------------------------------------------------------------
        # For each software entry, try to resolve the imported class path
        # for ipath in software.installPath or []:
        #     # Normalize to a path and append the class_path
        #     base_dir = pathlib.PurePath(ipath).parent.as_posix()
        #     full_path = f"{base_dir}/{class_path}"
        #     match = sbom.get_software_by_path(full_path)
        #     ok = bool(match and match.UUID != dependent_uuid)
        #     logger.debug(
        #         f"[Java][fs_tree] {full_path} → {'UUID=' + match.UUID if ok else 'no match'}"
        #     )
        #     if ok:
        #         matched_uuids.add(match.UUID)
        #         used_method[match.UUID] = "fs_tree"

        # ------------------------------------------------------------------
        # Phase 2 (backup): legacy export-dict behavior
        # ------------------------------------------------------------------
        if not matched_uuids:
            supplier_uuid = _ExportDict.get_supplier(import_class)
            if supplier_uuid and supplier_uuid != dependent_uuid:
                matched_uuids.add(supplier_uuid)
                used_method[supplier_uuid] = "legacy_exports"

        # -----------------------------
        # Emit 'Uses' relationships
        # -----------------------------
        if matched_uuids:
            for uuid in matched_uuids:
                if uuid == dependent_uuid:
                    continue
                rel = Relationship(dependent_uuid, uuid, "Uses")
                if rel not in relationships:
                    method = used_method.get(uuid, "unknown")
                    logger.debug(
                        f"[Java][final] {dependent_uuid} Uses {import_class} → UUID={uuid} [{method}]"
                    )
                    relationships.append(rel)
        else:
            logger.debug(f"[Java][final] {dependent_uuid} Uses {import_class} → no match")

    logger.debug(f"[Java][final] emitted {len(relationships)} relationships")
    return relationships


def class_to_path(class_name: str) -> str:
    """
    Convert a fully qualified Java class name to a relative path.

    Example:
        "com.example.MyClass" → "com/example/MyClass.class"
    """
    return f"{class_name.replace('.', '/')}.class"
