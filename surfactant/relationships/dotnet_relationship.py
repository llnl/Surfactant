import pathlib
from collections.abc import Iterable
from typing import List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.relationships._internal.windows_utils import (
    find_installed_software,
    get_dotnet_probedirs,
)
from surfactant.sbomtypes import SBOM, Relationship, Software
from surfactant.utils.paths import normalize_path

# -------------------------------------------------------------------------
# Legacy Documentation
# -------------------------------------------------------------------------
# Unmanaged (.dll/.so/.dylib) resolution background
#
# Reference:
#   https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/loading-unmanaged
#
# The .NET runtime resolves unmanaged/native libraries through a multistage
# search process:
#
# 1. Check the active AssemblyLoadContext cache.
#
# 2. Invoke any resolver registered via SetDllImportResolver().
#    - Example using SetDllImportResolver:
#        https://learn.microsoft.com/en-us/dotnet/standard/native-interop/native-library-loading
#    - Behavior:
#        * Checks the PInvoke or Assembly-level DefaultDllImportSearchPathsAttribute,
#          then the assembly's directory, then calls LoadLibraryEx with the
#          LOAD_WITH_ALTERED_SEARCH_PATH flag (on Windows).
#    - DefaultDllImportSearchPathsAttribute notes:
#        * Has no effect on non-Windows platforms / Mono runtime.
#        * API reference:
#            https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.defaultdllimportsearchpathsattribute?view=net-7.0
#        * Its "Paths" property is a bitwise combination of values from:
#            https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportsearchpath?view=net-7.0
#
# 3. The active AssemblyLoadContext calls its LoadUnmanagedDll function
#    (default behavior is effectively the same as assembly reference probing).
#    - a. This method can be overridden to provide custom unmanaged library
#         resolution logic.
#         * The default implementation returns IntPtr.Zero, which tells the
#           runtime to continue using its normal unmanaged library resolution
#           policy.
#    - b. API reference:
#         https://learn.microsoft.com/en-us/dotnet/api/system.runtime.loader.assemblyloadcontext.loadunmanageddll?view=net-7.0
#
# 4. Run default unmanaged library probing logic by parsing *.deps.json
#    probing properties.
#    - a. If the json file isn't present, assume the calling assembly's
#         directory contains the library.
#    - b. Reference:
#         https://learn.microsoft.com/en-us/dotnet/core/dependency-loading/default-probing#unmanaged-native-library-probing
#
# 5. Platform-specific probing notes:
#    - On Linux, if the libname ends with ".so" or contains ".so.", the
#      runtime attempts version variations such as:
#         libfoo.so
#         libfoo.so.1
#         libfoo.so.1.2.3
#      (Legacy code references Issue #79 indicating regex-based matching for
#       version variations was needed but not yet implemented.)
#
# 6. Legacy Surfactant unmanaged resolution logic:
#    - Construct a list of candidate filenames following the rules outlined
#      earlier in SetDllImportResolver behavior.
#    - Candidate list includes:
#         refName
#         refName.dll
#         refName.exe
#         refName.so
#         refName.dylib
#         lib<refName>.so
#         lib<refName>.dylib
#         lib<refName>
#    - This list corresponds to the combinations described in (2.a).
#      (Legacy comments reference Issue #80, noting the need to verify that
#       these candidate combinations behave correctly across platforms.)
#    - Versioned ".so" variations were NOT evaluated.
#      (Related to Issue #79 — regex matching needed for versioned .so names.)
#    - Determine probing directories by taking the parent directory of each
#      entry in software.installPath.
#    - Search for all candidate filenames using find_installed_software().
#
# 7. Absolute-path unmanaged imports:
#    - If the DllImport / PInvoke name is an absolute Windows path:
#         * Convert to PureWindowsPath.
#         * Compare this absolute path against every installPath entry of every
#           software node in the SBOM.
#         * A relationship is created only if an exact match is found.
#    - When an absolute path is used, no probing or filename variants are
#      attempted.
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Managed (.dll/.exe) assembly resolution background
#
# Reference:
#   https://learn.microsoft.com/en-us/dotnet/framework/deployment/how-the-runtime-locates-assemblies
#
# The .NET runtime locates managed assemblies using the following steps:
#
# 1. Determine the correct assembly version using configuration files
#    (binding redirects, code location, culture, version, etc.).
#
# 2. Check whether the assembly name has already been bound; if so, the runtime
#    uses the previously loaded assembly instead of probing.
#
# 3. Check the Global Assembly Cache (GAC)
#    - %WINDIR%\Microsoft.NET\assembly   (used by .NET Framework 4 and later)
#    - %WINDIR%\assembly                 (used by earlier .NET Framework versions)
#
# 4. Probe for assembly:
#
#    a. Check for a <codeBase> element in the app configuration file.
#       - If <codeBase href="..."> is present, the runtime checks the specified
#         location for the assembly.
#       - If the assembly is found, probing stops entirely.
#       - If the assembly is not found, the runtime fails without performing
#         any further probing.
#       - The href may be:
#           * http:// or https://
#           * file://
#           * a relative path (interpreted as relative to the application's
#             base directory, i.e., the parent of installPath).
#
#    b. If there is no <codeBase> element, begin standard probing:
#       - Search application base + culture + assembly name directories.
#       - Search privatePath directories from a <probing> element, combined
#         with culture / application base / assembly name.
#         (privatePath directories are evaluated before standard probing
#          locations.)
#       - The location of the calling assembly may be used as a hint for where
#         to find the referenced assembly.
#
# 5. Standard probing when no <codeBase> element is present:
#
#    Application-base probing:
#        [appBase] / <assemblyName>.dll
#        [appBase] / <assemblyName> / <assemblyName>.dll
#
#    Culture-specific probing:
#        [appBase] / <culture> / <assemblyName>.dll
#        [appBase] / <culture> / <assemblyName> / <assemblyName>.dll
#
#    Probing via <probing privatePath="bin;lib;...">:
#        - privatePath values are split on ";" (Windows convention).
#        - For each privatePath:
#            * [appBase] / <privatePath> / <assemblyName>.dll
#            * [appBase] / <privatePath> / <assemblyName> / <assemblyName>.dll
#
#    Calling-assembly influence:
#        - The location of the calling assembly may be used as a hint for
#          where to find the referenced assembly.
#        - The legacy implementation approximated this by probing the
#          parent directory of each installPath entry.
#
# 6. Missing assemblies:
#        - The legacy implementation intentionally did not log assemblies that
#          were not found, because such messages would overwhelmingly consist of
#          unresolved system/core .NET assemblies and produce excessive noise.
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Probing directory construction rules (legacy logic)
#
# For each software.installPath entry:
#     install_basepath = dirname(installPath)
#
# For each referenced assembly:
#
#   If Culture is None or empty ("neutral"):
#       Add directories corresponding to:
#           [application base] / [assembly name].dll
#           [application base] / [assembly name] / [assembly name].dll
#
#       If dnProbingPaths (from <probing privatePath="...">) exists:
#           For each binPath in dnProbingPaths:
#               [application base] / [binpath] / [assembly name].dll
#               [application base] / [binpath] / [assembly name] / [assembly name].dll
#
#   If Culture is specified:
#       Add directories corresponding to:
#           [application base] / [culture] / [assembly name].dll
#           [application base] / [culture] / [assembly name] / [assembly name].dll
#
#       If dnProbingPaths exists:
#           For each binPath in dnProbingPaths:
#               [application base] / [binpath] / [culture] / [assembly name].dll
#               [application base] / [binpath] / [culture] / [assembly name] / [assembly name].dll
#
# Notes:
#   * dnProbingPaths is derived from:
#       appConfigFile.runtime.assemblyBinding.probing.privatePath
#     and is split on ";" (Windows convention).
#   * These directory patterns mirror the .NET Framework probing rules
#     documented in:
#       https://learn.microsoft.com/en-us/dotnet/framework/deployment/how-the-runtime-locates-assemblies
# -------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Absolute-path unmanaged imports behavior (legacy)
#
#   def is_absolute_path(fname: str) -> bool:
#       return PureWindowsPath(fname).is_absolute()
#
# Example:
#     <DllImport("C:\\path\\to\\foo.dll")>
#
# Legacy logic:
#   - If the import Name is an absolute path:
#       * Convert to PureWindowsPath.
#       * For each software entry in the SBOM:
#             For each installPath of that entry:
#                 If the absolute path exactly matches installPath:
#                     → Create a Relationship(dependent_uuid, match.UUID, "Uses")
#
#   - If absolute, no probing or variant-name construction occurs.
#
#   - If not absolute:
#       → Apply unmanaged probing behavior:
#            * Candidate filename list (dll/so/dylib/lib variants)
#            * Search installer directories via find_installed_software()
# -------------------------------------------------------------------------


def has_required_fields(metadata) -> bool:
    """
    Check whether the metadata includes .NET assembly references.
    """
    return "dotnetAssemblyRef" in metadata


def is_absolute_path(fname: str) -> bool:
    givenpath = pathlib.PureWindowsPath(fname)
    return givenpath.is_absolute()


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """
    SurfActant plugin: Establish 'Uses' relationships for .NET assembly dependencies.

    Implements a 3-phase resolution strategy for managed (.dll/.exe) assemblies:

    1. Primary (fs_tree exact-path resolution):
        - Construct concrete probe paths using legacy .NET probing rules
        (get_dotnet_probedirs).
        - Resolve each candidate path via sbom.get_software_by_path(), leveraging the fs_tree + symlink edges.
        - (COMMENTED OUT) Apply identity filters (version and culture) when metadata is present.
        - This phase provides the most precise resolution.

    2. Secondary (legacy full scan fallback):
        - Executed only if Phase 1 finds no matches.
        - Reproduces legacy behavior exactly:
            * Probe the same legacy probing directories.
            * Match strictly on refName + ".dll".
            * Use find_installed_software() without version or culture filtering.
        - This phase intentionally prioritizes compatibility over precision.

    3. Finalization:
        - Deduplicate matches and emit 'Uses' relationships.
        - Record which resolution method produced each match for debugging.

    Also supports:
    - Resolving unmanaged/native libraries via dotnetImplMap:
        * Absolute-path fast path (fs_tree-aware)
        * Legacy filename variants (.dll/.so/.dylib/lib*)
        * Directory-based probing
    - Honoring .NET app.config <probing privatePath="..."> rules
    - Honoring <codeBase href="..."> relative paths
    - Avoiding self-dependencies

    Args:
        sbom (SBOM): The current SBOM graph.
        software (Software): The importing software.
        metadata (dict): Parsed metadata for .NET imports.

    Returns:
        Optional[List[Relationship]]: A list of 'Uses' relationships, or None if
        no applicable .NET metadata is present.
    """

    if not has_required_fields(metadata):
        logger.debug(f"[.NET] Skipping: No usable .NET metadata for {software.UUID}")
        return None

    relationships: List[Relationship] = []
    dependent_uuid = software.UUID

    # The following variables declared in legacy but never used and are kept for potential future use
    dnName = None
    dnCulture = None
    dnVersion = None
    if "dotnetAssembly" in metadata:
        dnAssembly = metadata["dotnetAssembly"]
        if "Name" in dnAssembly:
            dnName = dnAssembly["Name"]
        if "Culture" in dnAssembly:
            dnCulture = dnAssembly["Culture"]
        if "Version" in dnAssembly:
            dnVersion = dnAssembly["Version"]

    # --- Extract appConfig metadata ---
    # get additional probing paths if they exist
    dnProbingPaths = None
    dnDependentAssemblies = None

    windowsAppConfig = None
    windowsManifest = None  # This variable was declared in legacy but never used and is kept for potential future use
    if "manifestFile" in metadata:
        windowsManifest = metadata["manifestFile"]
    if "appConfigFile" in metadata:
        windowsAppConfig = metadata["appConfigFile"]

    if windowsAppConfig:
        if "runtime" in windowsAppConfig:
            wac_runtime = windowsAppConfig["runtime"]
            if "assemblyBinding" in wac_runtime:
                wac_asmbinding = wac_runtime["assemblyBinding"]
                if "dependentAssembly" in wac_asmbinding:
                    dnDependentAssemblies = wac_asmbinding["dependentAssembly"]
                if "probing" in wac_asmbinding:
                    wac_probing = wac_asmbinding["probing"]
                    if "privatePath" in wac_probing:
                        wac_paths = wac_probing["privatePath"]
                        for path in wac_paths.split(";"):
                            if dnProbingPaths is None:
                                dnProbingPaths = []
                            dnProbingPaths.append(pathlib.PureWindowsPath(path).as_posix())

    # --- Handle unmanaged libraries from dotnetImplMap ---
    if "dotnetImplMap" in metadata:
        for asmRef in metadata["dotnetImplMap"]:
            if "Name" not in asmRef:
                continue
            refName = asmRef["Name"]

            # Absolute path fast path (restores legacy behavior, but fs_tree-aware)
            #
            # Legacy did:
            #   - If Name is an absolute Windows path, compare that absolute path
            #     directly against all Software.installPath entries.
            #   - If it matches, emit Uses and skip probing entirely.
            #
            # New behavior:
            #   - Normalize the absolute path to POSIX style.
            #   - Use sbom.get_software_by_path(norm) so we benefit from fs_tree
            #   - Skip self (dependent_uuid) to avoid self-loops.

            if is_absolute_path(refName):
                norm = normalize_path(refName)
                # 1) Graph-first: fs_tree + symlink edges
                match = sbom.get_software_by_path(norm, case_insensitive=True)
                if match and match.UUID != dependent_uuid:
                    logger.debug(
                        f"[.NET][unmanaged][abs] {refName} (norm={norm}) → UUID={match.UUID}"
                    )
                    relationships.append(Relationship(dependent_uuid, match.UUID, "Uses"))
                    continue

                # 2) Legacy fallback: strict PureWindowsPath equality across all installPath entries
                ref_abspath = pathlib.PureWindowsPath(refName)
                legacy_found = False
                for e in sbom.software:
                    if e.installPath is None or e.UUID == dependent_uuid:
                        continue
                    if isinstance(e.installPath, Iterable) and not isinstance(
                        e.installPath, (str, bytes)
                    ):
                        for ifile in e.installPath:
                            if ref_abspath == pathlib.PureWindowsPath(ifile):
                                logger.debug(
                                    f"[.NET][unmanaged][abs] {refName} → UUID={e.UUID} [legacy_fallback]"
                                )
                                relationships.append(Relationship(dependent_uuid, e.UUID, "Uses"))
                                legacy_found = True

                if not legacy_found:
                    logger.debug(f"[.NET][unmanaged][abs] {refName} (norm={norm}) → no match")

                # Legacy behavior: absolute path means no probing/variants
                continue

            # Probe directories from this software's installPath
            probedirs = []
            if isinstance(software.installPath, Iterable):
                for ipath in software.installPath:
                    probedirs.append(pathlib.PureWindowsPath(ipath).parent.as_posix())
            logger.debug(f"[.NET][unmanaged] probedirs for {refName}: {probedirs}")

            # Build candidate filenames for unmanaged imports (legacy behavior)
            # Construct a list of combinations specified in (2)
            # Refer to Issue #80 - Need to verify that this conforms with cross-platform behavior
            logger.debug(f"[.NET][unmanaged] resolving import: {refName}")
            combinations = [refName]
            if not (refName.endswith(".dll") or refName.endswith(".exe")):
                combinations.append(f"{refName}.dll")
            combinations.extend(
                [
                    f"{refName}.so",
                    f"{refName}.dylib",
                    f"lib{refName}.so",
                    f"lib{refName}.dylib",
                    f"lib{refName}",
                ]
            )
            logger.debug(f"[.NET][unmanaged] candidates for {refName}: {combinations}")

            found = False
            # On Linux, if the libname ends with .so or has .so. then version variations are tried
            # Refer to Issue #79 - Need regex matching for version variations
            for e in find_installed_software(sbom, probedirs, combinations):
                if e and e.UUID != dependent_uuid:
                    dependency_uuid = e.UUID
                    logger.debug(f"[.NET][unmanaged] {refName} → UUID={dependency_uuid}")
                    relationships.append(Relationship(dependent_uuid, dependency_uuid, "Uses"))
                    found = True

            if not found:
                logger.debug(f"[.NET][unmanaged] {refName} → no match")

    if "dotnetAssemblyRef" in metadata:
        logger.debug(
            f"[.NET][import] {software.UUID} importing {len(metadata['dotnetAssemblyRef'])} assemblies"
        )
        for asmRef in metadata["dotnetAssemblyRef"]:
            refName = None
            refVersion = None  # This variable was declared in legacy but never used and is kept for potential future use
            refCulture = None
            if "Name" in asmRef:
                refName = asmRef["Name"]
            else:
                continue  # no name means we have no assembly to search for
            if "Culture" in asmRef:
                refCulture = asmRef["Culture"]
            if "Version" in asmRef:
                refVersion = asmRef["Version"]
            logger.debug(
                f"[.NET][import] resolving {refName} (version={refVersion}, culture={refCulture})"
            )

            fname_variants = [refName + ".dll"]

            # Check if codeBase element exists for this assembly in appconfig
            if dnDependentAssemblies is not None:
                for depAsm in dnDependentAssemblies:
                    # dependent assembly object contains info on assembly id and binding redirects that with a better internal SBOM
                    # representation could be used to also verify the right assembly is being found
                    if "codeBase" in depAsm:
                        if "href" in depAsm["codeBase"]:
                            codebase_href = depAsm["codeBase"]["href"]
                            # strong named assembly can be anywhere on intranet or Internet
                            if (
                                codebase_href.startswith("http://")
                                or codebase_href.startswith("https://")
                                or codebase_href.startswith("file://")
                            ):
                                # codebase references a url; interesting for manual analysis/gathering additional files, but not supported by surfactant yet
                                pass
                            else:
                                # most likely a private assembly, so path must be relative to application's directory
                                if isinstance(software.installPath, Iterable):
                                    for install_filepath in software.installPath:
                                        install_basepath = pathlib.PureWindowsPath(
                                            install_filepath
                                        ).parent.as_posix()
                                        cb_fullpath = normalize_path(
                                            install_basepath, codebase_href
                                        )
                                        # 1) Graph-first: resolve via fs_tree
                                        match = sbom.get_software_by_path(
                                            cb_fullpath, case_insensitive=True
                                        )
                                        if match and match.UUID != dependent_uuid:
                                            logger.debug(
                                                f"[.NET][codeBase] {codebase_href} → UUID={match.UUID} [graph]"
                                            )
                                            relationships.append(
                                                Relationship(dependent_uuid, match.UUID, "Uses")
                                            )
                                        else:
                                            # 2) Legacy fallback: directory+filename scan (matches legacy behavior)
                                            cb_filepath = pathlib.PureWindowsPath(cb_fullpath)
                                            cb_file = cb_filepath.name
                                            cb_path = [cb_filepath.parent.as_posix()]

                                            legacy_found = False
                                            for e in find_installed_software(
                                                sbom, cb_path, cb_file
                                            ):
                                                if e and e.UUID != dependent_uuid:
                                                    logger.debug(
                                                        f"[.NET][codeBase] {codebase_href} → UUID={e.UUID} [legacy_fallback]"
                                                    )
                                                    relationships.append(
                                                        Relationship(dependent_uuid, e.UUID, "Uses")
                                                    )
                                                    legacy_found = True

                                            if not legacy_found:
                                                logger.debug(
                                                    f"[.NET][codeBase] {codebase_href} → no match"
                                                )

            # --- Build probing dirs (legacy patterns + fs_tree) ---
            #   - base dir
            #   - base/refName
            #   - culture subdirs
            #   - privatePath combinations
            # This reproduces legacy layout coverage, but we will still resolve
            # through the fs_tree via sbom.get_software_by_path().
            # continue on to probing even if codebase element was found, since we can't guarantee the assembly identity required by the codebase element
            # get the list of paths to probe based on locations software is installed, assembly culture, assembly name, and probing paths from appconfig file
            probedirs: list[str] = []
            probedirs = get_dotnet_probedirs(
                software=software,
                refCulture=refCulture,
                refName=refName,
                dnProbingPaths=dnProbingPaths or None,
            )

            logger.debug(f"[.NET][import] probing dirs for {refName}: {probedirs}")

            matched_uuids = set()
            used_method = {}

            # def is_valid_match(sw: Software, refVersion=refVersion, refCulture=refCulture) -> bool:
            #     """
            #     Apply identity-based filters to ensure that a candidate assembly
            #     truly corresponds to the referenced assembly.

            #     A match is rejected when:
            #     • The candidate is the dependent software itself (avoid self-loops).
            #     • Version metadata exists on both sides and the versions differ.
            #     • Culture metadata exists on both sides and the cultures differ.

            #     Only explicit mismatches are filtered out; if metadata is absent on
            #     either side, the function allows the match to proceed so that other
            #     phases may evaluate it.
            #     """
            #     # Do not match the importing software to itself
            #     if sw.UUID == dependent_uuid:
            #         return False

            #     # Check version and culture metadata when present
            #     for md in sw.metadata or []:
            #         asm = md.get("dotnetAssembly")
            #         if asm:
            #             sw_version = asm.get("Version")
            #             sw_culture = asm.get("Culture")

            #             # Version mismatch
            #             if refVersion and sw_version and sw_version != refVersion:
            #                 logger.debug(
            #                     f"[.NET][filter] skipping {sw.UUID}: version {sw_version} ≠ {refVersion}"
            #                 )
            #                 return False

            #             # Culture mismatch
            #             if refCulture and sw_culture and sw_culture != refCulture:
            #                 logger.debug(
            #                     f"[.NET][filter] skipping {sw.UUID}: culture {sw_culture} ≠ {refCulture}"
            #                 )
            #                 return False
            #     return True

            # Phase 1: fs_tree lookup
            #
            # Construct fully qualified candidate paths by combining each probing
            # directory with each allowed filename variant. Each constructed path
            # is resolved through sbom.get_software_by_path(), which uses the
            # filesystem graph (fs_tree+ symlink edges)
            #
            # A match is accepted only when:
            #   • A software entry exists at the resolved path, and
            #   • It satisfies version and culture filters (is_valid_match).
            #
            # This phase provides the most precise form of resolution because it
            # operates on concrete filesystem paths derived from .NET probing rules.
            for probe_dir in sorted(set(probedirs)):
                for fname in fname_variants:
                    path = normalize_path(probe_dir, fname)
                    match = sbom.get_software_by_path(path, case_insensitive=True)
                    # ok = bool(match and is_valid_match(match))
                    logger.debug(
                        f"[.NET][fs_tree] {path} → {'UUID=' + match.UUID if match else 'no match'}"
                    )
                    if match and match.UUID != dependent_uuid:
                        matched_uuids.add(match.UUID)
                        used_method[match.UUID] = "fs_tree"

            # Phase 2: Legacy probe
            if not matched_uuids:
                for e in find_installed_software(sbom, probedirs, refName + ".dll"):
                    if e.UUID != dependent_uuid:
                        logger.debug(f"[.NET][legacy_phase2] {refName} → UUID={e.UUID}")
                        matched_uuids.add(e.UUID)
                        used_method[e.UUID] = "legacy_full_scan"

            # Phase 3: Finalize relationships
            for uuid in matched_uuids:
                rel = Relationship(dependent_uuid, uuid, "Uses")
                if rel not in relationships:
                    method = used_method.get(uuid, "unknown")
                    logger.debug(
                        f"[.NET][final] {dependent_uuid} Uses {refName} → UUID={uuid} [{method}]"
                    )
                    relationships.append(rel)
                    # logging assemblies not found would be nice but is a lot of noise as it mostly just prints system/core .NET libraries

            if not matched_uuids:
                logger.debug(f"[.NET][final] {dependent_uuid} Uses {refName} → no match")

    return relationships
