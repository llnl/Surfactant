# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import Any, List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software
from surfactant.utils.paths import normalize_path

from ._internal.windows_utils import find_installed_software


def has_required_fields(metadata: dict[str, Any]) -> bool:
    """Returns True if any known PE import fields are present in the metadata.

    Note: SBOM metadata items are not guaranteed to be dicts (plugins may emit
    dataclasses/objects). We therefore guard the key check.
    """
    return any(k in metadata for k in ("peImport", "peBoundImport", "peDelayImport"))


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata: dict
) -> Optional[List[Relationship]]:
    """
    SurfActant plugin: establish 'Uses' relationships based on PE import metadata.

    Handles peImport, peBoundImport, and peDelayImport using a Windows-specific resolver.
    Phases:
      1. [fs_tree] Exact path match via sbom.get_software_by_path()
      2. [legacy]  installPath + fileName matching
    """
    if not has_required_fields(metadata):
        logger.debug(f"[PE][skip] No PE import metadata for UUID={software.UUID} ({software.name})")
        return None

    relationships: List[Relationship] = []
    field_map = {
        "peImport": "Direct",  # NOTE: UWP apps have their own search order for libraries; they use a .appx or .msix file extension and appear to be zip files, so our SBOM probably doesn't even include them
        "peBoundImport": "Bound",
        "peDelayImport": "Delay",
    }

    # metadata is dict here due to has_required_fields() guard above
    for field, label in field_map.items():
        if field in metadata:
            entries = metadata[field] or []
            logger.debug(
                f"[PE][import] {label} imports for {software.name} ({software.UUID}): {len(entries)}"
            )
            relationships.extend(get_windows_pe_dependencies(sbom, software, entries))

    logger.debug(f"[PE][final] emitted {len(relationships)} relationships")
    return relationships


def get_windows_pe_dependencies(sbom: SBOM, sw: Software, peImports) -> List[Relationship]:
    """
    Resolve dynamically loaded PE (Windows) DLL dependencies and generate ``Uses`` relationships.

    This function attempts dependency resolution in **two phases**, combining modern
    SBOM graph/fs_tree capabilities with legacy fallbacks:

      1. **Primary: Direct path resolution via ``sbom.fs_tree``**
         Uses ``get_software_by_path()`` to match DLL names to concrete file locations,
         following symlink edges in ``fs_tree`` (including synthesized directory-link
         children) with Windows-style case-insensitive matching.

      2. **Legacy installPath fallback**
         If phase 1 yields no matches for a DLL, the resolver delegates to
         ``find_installed_software()``, reproducing the legacy PE relationship
         algorithm. This fallback matches dependencies strictly by comparing
         ``PureWindowsPath(probedir, dll_name)`` against each candidate's
         ``installPath`` entries.

    Background and References
    -------------------------
    This function models how Windows determines which DLLs a process loads when calling
    ``LoadLibrary``, ``LoadLibraryEx``, or related APIs. It reconstructs the *searchable*
    subset of the Windows loader's DLL search order using static information.

    Relevant documentation:
        - Dynamic-link library search order:
          https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
        - DLL redirection:
          https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
        - API sets overview:
          https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets

    DLL Search Order (Desktop Applications)
    ---------------------------------------
    Windows uses a multi-stage search strategy influenced by directory context,
    SafeDllSearchMode, manifests, KnownDLLs, LOAD_LIBRARY_SEARCH flags, PATH, and other
    runtime settings. This implementation approximates only those behaviors that can be
    resolved statically from the SBOM:

      - **Explicit or redirected paths** (e.g., LoadLibrary full paths, .local redirection)
      - **Application directory search**
      - **Directories implied by the importing file's ``installPath``**
      - **Name-based matching when directory information is limited**

    Features not modeled statically include:
      - In-memory module reuse
      - KnownDLLs registry lookup
      - API set resolution (these DLLs are not files on disk)
      - Manifest configuration, SxS isolation, and SafeDllSearchMode state
      - ``PATH`` environment variable lookup

    API Sets
    --------
    Windows 10/11 API set DLLs (e.g., ``api-ms-win-core-file-l1-1-0.dll``) are logical
    contract names, not real files. They are always resolved internally by the Windows
    loader and cannot be matched using filesystem-based analysis.

    Scope and Static Analysis Limitations
    -------------------------------------
    Because this analysis cannot observe runtime information such as registry state,
    loader flags, search path modifications, or process environment, resolution is
    conservatively limited to:

      - The directory/paths associated with the importing software (``installPath``)
      - Alias/symlink paths injected during SBOM generation
      - Legacy name/directory matching when no direct fs_tree match exists

    Notes & Implementation Details
    ------------------------------
    - If ``installPath`` is missing for the importing software, resolution is skipped.
      Such files are often extracted intermediates or installer artifacts.
    - TODO: add support for resolving DLLs using relative positions inside a
      ``containerPath`` when multiple files derive from the same container UUID.
    - Missing DLL logs are suppressed by default because they overwhelmingly correspond
      to Windows system libraries that are intentionally not bundled with applications.

    Args:
        sbom (SBOM): The SBOM containing software entries and the populated fs_tree.
        sw (Software): The importing software item declaring DLL dependencies.
        peImports (list[str]): Base names of imported DLLs (e.g., ``['KERNEL32.dll']``).

    Returns:
        List[Relationship]: ``Uses`` relationships of the form
            ``Relationship(xUUID=sw.UUID, yUUID=dep.UUID, relationship="Uses")``.
    """

    relationships: List[Relationship] = []

    # No installPath is probably temporary files/installer
    # TODO maybe resolve dependencies using relative locations in containerPath, for files originating from the same container UUID?
    if sw.installPath is None:
        logger.debug(f"[PE][skip] No installPath for {sw.name} ({sw.UUID}); skipping resolution")
        return relationships

    dependent_uuid = sw.UUID

    for fname in peImports:
        if not fname:
            continue

        logger.debug(f"[PE][import] resolving '{fname}' for UUID={dependent_uuid}")

        matched_uuids = set()
        used_method: dict[str, str] = {}

        # -----------------------------------
        # Phase 1: Direct fs_tree resolution
        # -----------------------------------
        # Build probe directories from the importing binary's installPath parents.
        # This mirrors the legacy behavior (Windows DLL search: "application directory").
        probedirs: List[str] = []
        if isinstance(sw.installPath, Iterable):
            for ipath in sw.installPath or []:
                # Extract the parent directory in normalized POSIX form
                parent_dir = pathlib.PureWindowsPath(ipath).parent.as_posix()
                probedirs.append(parent_dir)
        logger.debug(f"[PE][import] probedirs for '{fname}': {probedirs}")

        for directory in probedirs:
            full_path = normalize_path(directory, fname)
            match = sbom.get_software_by_path(
                full_path,
                case_insensitive=True,  # Windows DLL resolution should be case-insensitive
            )
            ok = bool(match and match.UUID != dependent_uuid)
            logger.debug(
                f"[PE][fs_tree] {full_path} -> {'UUID=' + match.UUID if ok else 'no match'}"
            )
            if ok:
                matched_uuids.add(match.UUID)
                used_method[match.UUID] = "fs_tree"

        # ----------------------------------------
        # Phase 2: legacy fallback (installPath-only)
        # Mirrors legacy by delegating to find_installed_software().
        # ----------------------------------------
        if not matched_uuids:
            for e in find_installed_software(sbom, probedirs, fname):
                logger.debug(f"[PE][legacy] {fname} -> UUID={e.UUID}")
                matched_uuids.add(e.UUID)
                used_method[e.UUID] = "legacy_installPath"

        # ----------------------------------------
        # Emit final relationships (if any found)
        # ----------------------------------------
        if matched_uuids:
            for uuid in matched_uuids:
                rel = Relationship(dependent_uuid, uuid, "Uses")
                if rel not in relationships:
                    method = used_method.get(uuid, "unknown")
                    logger.debug(
                        f"[PE][final] {dependent_uuid} Uses {fname} -> UUID={uuid} [{method}]"
                    )
                    relationships.append(rel)
        else:
            logger.debug(f"[PE][final] {dependent_uuid} Uses {fname} -> no match")

    return relationships
