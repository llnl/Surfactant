# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
"""Surfactant plugin that uses angr to extract loader/symbol binary metadata.

This plugin is scoped to the things angr + CLE do best and cheaply: loader and
architecture facts, imported/exported symbols, import-to-library resolution
(which powers the ``Uses`` relationships between binaries), a section map, and
ELF versioned-symbol minimums useful for CVE/version matching.

Structural code analysis that Binary Ninja does with higher fidelity (function
recovery, the call graph, notable-API cross-references, typed prototypes) is
deliberately left to the ``binaryninja_info`` plugin so the two produce
complementary, non-overlapping records on the same binary.

The metadata is grouped under the ``angrExpanded`` key on each software entry.
"""

from pathlib import Path
from typing import Any

import angr
from cle import CLECompatibilityError, CLEError
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.gnuversions import GNUVerNeedSection
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software

# Every ``except Exception`` below is intentional: analyzing a possibly-malformed or
# untrusted binary must never abort SBOM generation for the rest of the corpus.
# pylint: disable=broad-exception-caught

# Top-level key the metadata object is stored under in the software entry.
_METADATA_KEY = "angrExpanded"

# Settings base name for this plugin.
_SETTINGS_SECTION = "angr_expanded"


def supports_file(filetype: list[str]) -> bool:
    """Return True for file types that angr's loader can analyze."""
    return any(t in filetype for t in ("ELF", "PE", "MACHOFAT", "MACHO"))


def _hex(value: Any) -> Any:
    """Render integer addresses as hex strings, pass everything else through."""
    if isinstance(value, int):
        return hex(value)
    return value


def _collect_loader_info(project: "angr.Project") -> dict[str, Any]:
    """Collect cheap loader/architecture facts that don't require code analysis."""
    loader = project.loader
    main = loader.main_object
    arch = project.arch

    endianness = "little" if getattr(arch, "memory_endness", "") == "Iend_LE" else "big"

    info: dict[str, Any] = {
        "arch": getattr(arch, "name", None),
        "bits": getattr(arch, "bits", None),
        "endianness": endianness,
        "entryPoint": _hex(getattr(project, "entry", None)),
        "imageBase": _hex(getattr(main, "linked_base", None)),
        "mappedBase": _hex(getattr(main, "mapped_base", None)),
        "minAddr": _hex(main.min_addr) if hasattr(main, "min_addr") else None,
        "maxAddr": _hex(main.max_addr) if hasattr(main, "max_addr") else None,
        "positionIndependent": bool(getattr(main, "pic", False)),
        "executableStack": bool(getattr(main, "execstack", False)),
        "relocatable": bool(getattr(main, "is_main_bin", True) is False)
        or bool(getattr(main, "pic", False)),
        "linkingType": getattr(main, "linking", None),
        "objectFormat": type(main).__name__,
    }

    # Direct shared-library dependencies as recorded by the loader.
    deps = getattr(main, "deps", None)
    info["linkedLibraries"] = sorted(str(d) for d in deps) if deps else []

    # Statically linked binaries have no recorded dynamic dependencies and are not
    # marked as dynamically linked by cle.
    linking = getattr(main, "linking", None)
    if linking is not None:
        info["staticallyLinked"] = linking == "static"
    else:
        info["staticallyLinked"] = not info["linkedLibraries"]

    return info


def _collect_symbols(project: "angr.Project") -> dict[str, Any]:
    """Collect imported/exported symbols with import-to-library resolution."""
    main = project.loader.main_object

    imported: list[dict[str, Any]] = []
    exported: list[dict[str, Any]] = []
    seen_imports: set[tuple[str, Any]] = set()
    seen_exports: set[str] = set()

    for symbol in getattr(main, "symbols", []):
        name = getattr(symbol, "name", None)
        if not name:
            continue
        if getattr(symbol, "is_import", False):
            # PE binaries record the providing DLL per-symbol; ELF imports are
            # resolved at runtime so library is usually None.
            library = getattr(symbol, "libname", None)
            key = (name, library)
            if key in seen_imports:
                continue
            seen_imports.add(key)
            imported.append(
                {
                    "name": name,
                    "library": library,
                    "isFunction": bool(getattr(symbol, "is_function", False)),
                }
            )
        elif getattr(symbol, "is_export", False):
            if name in seen_exports:
                continue
            seen_exports.add(name)
            exported.append(
                {
                    "name": name,
                    "address": _hex(getattr(symbol, "rebased_addr", None)),
                    "isFunction": bool(getattr(symbol, "is_function", False)),
                }
            )

    imported.sort(key=lambda s: s["name"])
    exported.sort(key=lambda s: s["name"])
    return {
        "importedFunctions": imported,
        "exportedFunctions": exported,
        "importedFunctionCount": len(imported),
        "exportedFunctionCount": len(exported),
    }


def _parse_symbol_version(version: str) -> tuple[str, tuple[int, ...] | None]:
    """Split a versioned symbol tag into a (prefix, numeric version) pair.

    Examples:
        ``GLIBC_2.34`` -> (``GLIBC``, (2, 34))
        ``GLIBCXX_3.4.29`` -> (``GLIBCXX``, (3, 4, 29))
        ``LIBSELINUX_1.0`` -> (``LIBSELINUX``, (1, 0))
        ``GLIBC_PRIVATE`` -> (``GLIBC``, None)  # non-numeric, not comparable
    """
    prefix, _, rest = version.rpartition("_")
    if not prefix:
        return version, None
    parts = rest.split(".")
    if parts and all(p.isdigit() for p in parts):
        return prefix, tuple(int(p) for p in parts)
    return prefix, None


def _collect_symbol_versions(filename: str) -> dict[str, Any]:
    """Extract ELF versioned-symbol requirements and derive minimum library versions.

    Reads the ``.gnu.version_r`` (version needs) section using pyelftools and
    computes, for each needed library and version prefix (e.g. ``GLIBC``), the
    highest version required by any imported symbol. That highest value is the
    *minimum* library version the binary can run against, which is useful for
    dependency resolution and narrowing CVE/version matching.

    Returns an empty dict for non-ELF files or files without version needs.
    """
    needs: dict[str, list[str]] = {}
    minimums: dict[str, dict[str, str]] = {}
    best: dict[str, dict[str, tuple[int, ...]]] = {}

    try:
        with Path(filename).open("rb") as f:
            elf = ELFFile(f)
            for section in elf.iter_sections():
                if not isinstance(section, GNUVerNeedSection):
                    continue
                for verneed, aux_iter in section.iter_versions():
                    libname = verneed.name
                    for aux in aux_iter:
                        version = aux.name
                        needs.setdefault(libname, [])
                        if version not in needs[libname]:
                            needs[libname].append(version)
                        prefix, numeric = _parse_symbol_version(version)
                        if numeric is None:
                            continue
                        lib_best = best.setdefault(libname, {})
                        if prefix not in lib_best or numeric > lib_best[prefix]:
                            lib_best[prefix] = numeric
    except (OSError, ELFError):
        return {}

    if not needs:
        return {}

    for libname, prefixes in best.items():
        minimums[libname] = {
            prefix: ".".join(str(n) for n in numeric)
            for prefix, numeric in sorted(prefixes.items())
        }

    for versions in needs.values():
        versions.sort()

    return {
        "minimumLibraryVersions": minimums,
        "symbolVersionNeeds": needs,
    }


def _collect_sections(project: "angr.Project") -> list[dict[str, Any]]:
    """Summarize the loaded sections (name, address, size, permissions)."""
    main = project.loader.main_object
    sections: list[dict[str, Any]] = []
    for section in getattr(main, "sections", []) or []:
        sections.append(
            {
                "name": getattr(section, "name", None),
                "vaddr": _hex(getattr(section, "vaddr", None)),
                "size": getattr(section, "memsize", None),
                "isExecutable": bool(getattr(section, "is_executable", False)),
                "isWritable": bool(getattr(section, "is_writable", False)),
                "isReadable": bool(getattr(section, "is_readable", False)),
            }
        )
    return sections


@surfactant.plugin.hookimpl(specname="extract_file_info")
def angr_expanded(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    """Extract expanded angr binary analysis metadata for the SBOM.

    Args:
        sbom (SBOM): The SBOM the software entry belongs to.
        software (Software): The software entry the metadata will be attached to.
        filename (str): Full path to the file to analyze.
        filetype (List[str]): File type hints based on magic bytes.

    Returns:
        object: A metadata dict stored under ``angrExpanded``, or None if the file
            is not a supported binary or could not be loaded.
    """
    if not supports_file(filetype):
        return None

    path = Path(filename)
    if not path.exists():
        logger.warning(f"angr_expanded: file does not exist: {filename}")
        return None

    try:
        project = angr.Project(path.as_posix(), auto_load_libs=False)
    except (CLECompatibilityError, CLEError) as e:
        logger.info(f"angr_expanded could not load {filename}: {e}")
        return None
    except Exception as e:  # noqa: BLE001 - loading untrusted binaries can raise anything
        logger.warning(f"angr_expanded unexpected error loading {filename}: {e}")
        return None

    metadata: dict[str, Any] = {}
    try:
        metadata.update(_collect_loader_info(project))
        metadata.update(_collect_symbols(project))
        metadata.update(_collect_symbol_versions(path.as_posix()))
        # ELF sections are already emitted by Surfactant's built-in elf_file
        # extractor, so only add them here for formats it does not cover (PE,
        # Mach-O). This keeps angr_expanded from duplicating the native ELF output.
        if "ELF" not in filetype:
            metadata["sections"] = _collect_sections(project)
    except Exception as e:  # noqa: BLE001 - keep SBOM generation resilient
        logger.warning(f"angr_expanded partial extraction for {filename}: {e}")

    if not metadata:
        return None

    logger.info(f"angr_expanded extracted metadata for {path.name}")
    return {_METADATA_KEY: metadata}


# Cache mapping id(sbom) -> {export_symbol_name: set(software UUID)}. Exports do
# not change during the relationship phase, so the index is built once per SBOM.
_EXPORT_INDEX_CACHE: dict[int, dict[str, set[str]]] = {}


def _iter_angr_metadata(software: Software) -> Any:
    """Yield each ``angrExpanded`` metadata dict attached to a software entry."""
    for entry in getattr(software, "metadata", None) or []:
        if isinstance(entry, dict) and _METADATA_KEY in entry:
            value = entry[_METADATA_KEY]
            if isinstance(value, dict):
                yield value


def _build_export_index(sbom: SBOM) -> dict[str, set[str]]:
    """Build (and cache) a map of exported function name -> set of exporter UUIDs."""
    cached = _EXPORT_INDEX_CACHE.get(id(sbom))
    if cached is not None:
        return cached

    index: dict[str, set[str]] = {}
    for sw in getattr(sbom, "software", None) or []:
        for md in _iter_angr_metadata(sw):
            for exp in md.get("exportedFunctions", []):
                name = exp.get("name") if isinstance(exp, dict) else None
                if name:
                    index.setdefault(name, set()).add(sw.UUID)
    _EXPORT_INDEX_CACHE[id(sbom)] = index
    return index


def _basenames(paths: Any) -> set[str]:
    """Return the set of lowercased basenames for a list of file names/paths."""
    result: set[str] = set()
    for p in paths or []:
        if p:
            result.add(Path(str(p)).name.lower())
    return result


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata: object
) -> list[Relationship] | None:
    """Link a binary's imported functions to SBOM entries that export them.

    For each imported function in this software's ``angrExpanded`` metadata, find
    other software entries in the SBOM whose ``angrExpanded`` exports that symbol
    and emit a ``Uses`` relationship. To keep matches high-confidence, when the
    importer records ``linkedLibraries`` the exporter must also match one of those
    library file names; otherwise a plain symbol match is used as a fallback.

    Args:
        sbom (SBOM): The SBOM being processed.
        software (Software): The importing software entry.
        metadata (object): One metadata value from the software entry; only the
            ``angrExpanded`` value is handled.

    Returns:
        Optional[List[Relationship]]: ``Uses`` relationships, or None if this
            metadata value is not an ``angrExpanded`` block with imports.
    """
    if not isinstance(metadata, dict) or _METADATA_KEY not in metadata:
        return None
    data = metadata[_METADATA_KEY]
    if not isinstance(data, dict):
        return None

    imported = data.get("importedFunctions") or []
    if not imported:
        return None

    export_index = _build_export_index(sbom)
    if not export_index:
        return None

    linked_libs = _basenames(data.get("linkedLibraries"))

    # Map candidate exporter UUID -> set of matched symbol names (for logging).
    matches: dict[str, set[str]] = {}
    for imp in imported:
        name = imp.get("name") if isinstance(imp, dict) else None
        if not name:
            continue
        for exporter_uuid in export_index.get(name, set()):
            if exporter_uuid == software.UUID:
                continue
            if linked_libs:
                exporter = (
                    sbom.get_software(exporter_uuid) if hasattr(sbom, "get_software") else None
                )
                exporter = exporter or next(
                    (s for s in (sbom.software or []) if s.UUID == exporter_uuid), None
                )
                if exporter is not None and not _basenames(exporter.fileName) & linked_libs:
                    continue
            matches.setdefault(exporter_uuid, set()).add(name)

    relationships: list[Relationship] = []
    for exporter_uuid, symbols in matches.items():
        relationships.append(
            Relationship(xUUID=software.UUID, yUUID=exporter_uuid, relationship="Uses")
        )
        logger.debug(
            f"angr_expanded: {software.UUID} Uses {exporter_uuid} ({len(symbols)} matched symbols)"
        )

    return relationships or None


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    """Short name used to enable/disable and reference this plugin."""
    return "angr_expanded"


@surfactant.plugin.hookimpl
def settings_name() -> str | None:
    """Base name used for reading/writing this plugin's Surfactant settings."""
    return _SETTINGS_SECTION
