# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import List, Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software

from ._internal.posix_utils import posix_normpath


def has_required_fields(metadata) -> bool:
    """
    Checks if the metadata contains the required `elfDependencies` field.

    This function determines whether the `elfDependencies` field exists in the provided
    metadata. This field indicates the necessary
    dependency information to establish relationships.

    Args:
        metadata: The metadata provided to determine the presence of elfDependencies.

    Returns:
        bool: True if the `elfDependencies` field exists in the metadata, False otherwise.

    Raises:
        None
    """
    # no elfDependencies info, can't establish relationships
    return "elfDependencies" in metadata


# Information on loading dynamic libraries from ld.so man page:
# 1. if dependency string contains a slash, it is interpreted as a (relative or absolute) pathname and shared object is loaded using that
# 2. if no slash, search in the following order:
# - use dirs in DT_RPATH if present and DT_RUNPATH doesn't exist (deprecated)
# - use LD_LIBRARY_PATH unless being run in secure-execution mode (in which case ignored)
# - use dirs in DT_RUNPATH if present; only searched to find objects required by DT_NEEDED (direct dependencies) and don't apply to objects' children which must have their own DT_RUNPATH entries (this differs from DT_RPATH, which applies to searches for all children in the dependency tree)
# - from /etc/ld.so.cache, unless binary linked with -z nodeflib linker option then shared objects in the default paths are skipped (shared objects in hardware capability dirs are preferred over other shared objects)
# - in default path /lib, and then /usr/lib (/lib64 and /usr/lib64 maybe for 64-bit libraries); skipped if binary was linked with -z nodeflib linker option
# some strings are expanded; $ORIGIN, $LIB, $PLATFORM
# /etc/ld.so.conf can be used to configure the dynamic loader to search for other directories (such as /usr/local/lib or /opt/lib) as well; format is separate lines naming additional directories, and include <path> statement that can use wildcards to include paths from additional files, such as /etc/ld.so.conf.d/*.conf
# secure execution mode if AT_SECURE entry in auxiliary vector has nonzero value (process real & effective user IDs differ, or real & effectived group IDs differ; process with non-root user ID executed a binary that conferred capabilities to the process; nonzero value set by a Linux Security Module)
# hardware capability directories can be cascaded
# ----- hardware capabilities, recognized names -----
# Alpha: ev4, ev5, ev56, ev6, ev67
# MIPS: loongson2e, loongson2f, octeon, octeon2
# PowerPC: 4xxmac, altivec, arch_2_05, arch_2_06, booke, cellbe, dfp, efpdouble, efpsingle, fpu, ic_snoop, mmu, notb, pa6t, power4, power5, power5+, power6x, ppc32, ppc601, ppc64, smt, spe, ucache, vsx
# SPARC: flush, muldiv, stbar, swap, ultra3, v9, v9v, v9v2
# s390: dfp, eimm, esan3, etf3enh, g5, highgprs, hpage, ldisp, msa, stfle, z900, z990, z9-109, z10, zarch
# x86 (32-bit only): acpi, apic, clflush, cmov, cx8, dts, fxsr, ht, i386, i486, i586, i686, mca, mmx, mtrr, pat, pbe, pge, pn, pse36, sep, ss, sse, sse2, tm


@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """
    Establish `Uses` relationships between a software item and its ELF-declared
    dependencies.

    This function resolves dependencies listed in `metadata["elfDependencies"]`
    by computing the set of possible runtime file paths for each dependency and
    attempting to match them against software entries in the SBOM. Resolution
    proceeds in two stages:

        1. **fs_tree-based lookup**
           Fully-qualified dependency paths (absolute or constructed from
           runpaths, RPATH, RUNPATH, and $ORIGIN substitutions) are checked
           against the SBOM filesystem graph. This lookup is symlink-aware.

        2. **Legacy installPath fallback**
           If no fs_tree match is found, the function falls back to a strict
           legacy rule: a candidate software entry must advertise the same
           filename *and* must contain an exact installPath equal to one of the
           computed dependency paths.

    No heuristic directory-level inference is performed. Dependencies are only
    matched when the SBOM contains a resolvable path or an exact legacy
    installPath entry.

    Args:
        sbom (SBOM): The software bill of materials containing all discovered
            software entries and the filesystem graph.
        software (Software): The software entry whose dependencies are being
            resolved.
        metadata: Metadata extracted from the ELF file. Must contain the
            `"elfDependencies"` field to participate in relationship inference.

    Returns:
        Optional[List[Relationship]]:
            A list of `Relationship(dependent, dependency, "Uses")` entries.
            Returns `None` if the metadata does not contain `elfDependencies`.

    Notes:
        - Dependency paths may originate from:
            • absolute paths in metadata
            • relative paths joined against each installPath
            • computed runpaths (RPATH/RUNPATH) and default library paths
        - Duplicate relationships are suppressed.
        - Self-dependencies are not emitted.

    Example:
        relationships = establish_relationships(sbom, software, metadata)
        for rel in relationships or []:
            print(f"{rel.xUUID} uses {rel.yUUID}")
    """
    if not has_required_fields(metadata):
        return None

    relationships: List[Relationship] = []
    dependent_uuid = software.UUID
    default_search_paths = generate_search_paths(software, metadata)
    logger.debug(f"[ELF][search] default paths: {[p.as_posix() for p in default_search_paths]}")

    # Each entry in metadata["elfDependencies"] is a DT_NEEDED-style string
    # extracted from the ELF dynamic section. These can be:
    #   • Bare filenames, e.g. "libc.so.6"
    #   • Relative paths, e.g. "subdir/libfoo.so"
    #   • Absolute paths, e.g. "/opt/lib/libbar.so"
    #
    # The dynamic loader interprets these differently, and the resolution logic
    # below mirrors that behavior. We normalize each dependency into candidate
    # full paths ("fpaths") that represent where the loader *could* reasonably
    # locate the referenced library within the captured filesystem snapshot.
    #
    # Notes:
    #   - posix_normpath() removes "..", ".", and duplicate separators to keep
    #     path comparisons consistent with fs_tree key normalization.
    #   - No directory inference or fuzzy matching occurs: all candidate paths
    #     must be derived strictly from ELF semantics (slashes vs. bare names)
    #     and from the calling software’s installPath or runpath metadata.
    for dep in metadata["elfDependencies"]:
        dep_str = dep
        fpaths = []
        dep = posix_normpath(dep_str)
        fname = dep.name  # e.g., 'libfoo.so'

        # Determine all candidate filesystem paths where this dependency *might*
        # reside. ELF dependency strings come in two forms:
        #
        #   Case 1: The string contains a slash (e.g., "somedir/libfoo.so")
        #           → The dynamic loader interprets this as a literal path.
        #             - If absolute, the path is used directly.
        #             - If relative, it is resolved relative to each installPath
        #               of the referencing software. This mirrors runtime behavior
        #               where a DT_NEEDED entry containing "subdir/libX.so" is
        #               interpreted relative to the binary's directory.
        #
        #   Case 2: Bare filename (e.g., "libfoo.so")
        #           → The loader searches a sequence of directories:
        #             runpaths, rpaths, LD_LIBRARY_PATH, cache entries,
        #             and system defaults. Here we approximate that search by
        #             joining the filename onto the generated search paths
        #             (generate_search_paths), which already expands RPATH,
        #             RUNPATH, $ORIGIN, and default library paths unless disabled.
        #
        # Together, these two branches generate the list `fpaths`, representing
        # all plausible full paths that could correspond to this dependency.
        # Later phases attempt to match these paths against the SBOM via fs_tree
        # or exact installPath equality.

        # Case 1: Dependency has slash — treat as direct path
        if "/" in dep_str:
            if dep.is_absolute():
                fpaths = [dep.as_posix()]
            else:
                if isinstance(software.installPath, Iterable):
                    for ipath in software.installPath:
                        ipath_posix = posix_normpath(ipath)
                        combined = posix_normpath(str(ipath_posix.parent.joinpath(dep))).as_posix()
                        fpaths.append(combined)

        # Case 2: Bare filename — use runpaths and fallback paths
        else:
            fpaths = [p.joinpath(fname).as_posix() for p in default_search_paths]

        # Phase 1: fs_tree lookup
        #
        # Attempt to resolve each dependency path directly against the SBOM's
        # filesystem graph. This is the most accurate resolution method and
        # mirrors how the file would be found at runtime:
        #
        #   - Paths are normalized and checked for a software UUID attached to
        #     the corresponding fs_tree node.
        #   - If the exact node is not a software installPath, the resolver
        #     follows recorded filesystem symlinks (file- and directory-level)
        #     using BFS until a software entry is reached.
        #
        # This phase yields only concrete, evidence-based matches—no inference.
        # A match is accepted only if:
        #   - The target resolves through the fs_tree to a software entry, AND
        #   - The dependency is not self-referential.
        matched_uuids = set()
        used_method = {}

        for path in fpaths:
            match = sbom.get_software_by_path(path)
            ok = bool(match and match.UUID != software.UUID)
            logger.debug(f"[ELF][fs_tree] {path} → {'UUID=' + match.UUID if ok else 'no match'}")
            if ok:
                matched_uuids.add(match.UUID)
                used_method[match.UUID] = "fs_tree"

        # Phase 2: Legacy installPath fallback
        #
        # This stage preserves the historical (pre-fs_tree) resolution behavior:
        # a dependency is considered matched only if:
        #   - the candidate software entry advertises the same fileName, AND
        #   - one of its installPath entries exactly matches one of the fully
        #     constructed dependency paths in `fpaths`.
        #
        # Unlike the fs_tree lookup, this method does NOT resolve symlinks,
        # It requires a literal, explicit installPath match. This ensures:
        #   - No directory-level inference (removed with Phase 3),
        #   - No fallback guesses when the SBOM lacks a concrete path,
        #   - Behavior consistent with the older relationship engine.
        #
        # This phase only runs if fs_tree matching failed.
        if not matched_uuids:
            # Look for a software entry with a file name and install path that matches the dependency that would be loaded
            for item in sbom.software:
                # Check if the software entry has a name matching the dependency first as a quick check to rule out non-matches
                if isinstance(item.fileName, Iterable) and fname not in item.fileName:
                    continue

                # Check for exact installPath equivalence with any computed dep path
                for fp in fpaths:
                    if isinstance(item.installPath, Iterable) and fp in (item.installPath or []):
                        # software matching requirements to be the loaded dependency was found
                        if item.UUID != software.UUID:
                            dependency_uuid = item.UUID
                            logger.debug(f"[ELF][legacy] {fname} in {fp} → UUID={item.UUID}")
                            matched_uuids.add(dependency_uuid)
                            used_method[dependency_uuid] = "legacy_installPath"

        # Emit final relationships
        if matched_uuids:
            for dependency_uuid in matched_uuids:
                if dependency_uuid == software.UUID:
                    continue
                rel = Relationship(dependent_uuid, dependency_uuid, "Uses")
                if rel not in relationships:
                    relationships.append(rel)
                    method = used_method.get(dependency_uuid, "unknown")
                    logger.debug(
                        f"[ELF][final] {dependent_uuid} Uses {fname} → UUID={dependency_uuid} [{method}]"
                    )
        else:
            logger.debug(f"[ELF][final] {dependent_uuid} Uses {fname} → no match")

    logger.debug(f"[ELF][final] emitted {len(relationships)} relationships")
    return relationships


def generate_search_paths(sw: Software, md) -> List[pathlib.PurePosixPath]:
    """
    Generates a list of search paths for locating runtime libraries.

    This function constructs a list of search paths leveraging the `generate_runpaths`
    function, which generates runtime paths for the given software using PurePosixPath formatting. If the
    metadata specifies the `DF_1_NODEFLIB` flag in `elfDynamicFlags1`, it skips
    default library paths (`/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`) to comply with
    the `-z nodeflib` linker option.

    Args:
        sw (Software): An object representing the software to generate search
            paths for.
        md: Metadata associated with the software, which may include dynamic
            flags (`elfDynamicFlags1`) to determine if default library paths should
            be excluded.

    Returns:
        List[pathlib.PurePosixPath]: A list of `PurePosixPath` objects representing
        the search paths for runtime library resolution. This includes paths from
        `generate_runpaths`, along with default library paths if `DF_1_NODEFLIB` is
        not set.

    Notes:
        - The `DT_RPATH` dynamic tag has been deprecated.
        - Default library paths are included only if the `-z nodeflib` linker option
          is not specified through the `DF_1_NODEFLIB` flag in `elfDynamicFlags1`.
    """
    # 1. Search using directories in DT_RPATH if present and no DT_RUNPATH exists (use of DT_RPATH is deprecated)
    # 2. Use LD_LIBRARY_PATH environment variable; ignore if suid/sgid binary (nothing to do, we don't have this information w/o running on a live system)
    # 3. Search using directories in DT_RUNPATH if present
    paths = generate_runpaths(sw, md)  # May include $ORIGIN etc., already substituted

    # Check for the DF_1_NODEFLIB dynamic flag: disables default library search
    # 4. From /etc/ld.so.cache (/var/run/ld.so.hints on FreeBSD) list of compiled candidate libraries previously found in augmented library path; if binary was linked with -z nodeflib linker option, libraries in default library paths are skipped
    # /etc/ld.so.conf can be used to add additional directories to defaults (e.g. /usr/local/lib or /opt/lib), but we don't necessarily have a way to gather this info
    # Search in default path /lib, then /usr/lib; skip if binary was linked with -z nodeflib option
    nodeflib = False
    if "elfDynamicFlags1" in md and "DF_1_NODEFLIB" in md["elfDynamicFlags1"]:
        nodeflib = md["elfDynamicFlags1"]["DF_1_NODEFLIB"]

    # If DF_1_NODEFLIB is not set, include default system paths
    if not nodeflib:
        defaults = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        logger.debug(f"[ELF][runpath] DF_1_NODEFLIB not set; adding defaults: {defaults}")
        paths.extend([pathlib.PurePosixPath(p) for p in defaults])

    # Ensure all entries are PurePosixPath objects (in case runpaths included strings)
    return [p if isinstance(p, pathlib.PurePosixPath) else pathlib.PurePosixPath(p) for p in paths]


def generate_runpaths(sw: Software, md) -> List[pathlib.PurePosixPath]:
    # rpath and runpath are lists of strings (just in case an ELF file has several, though that is probably an invalid ELF file)
    rp_to_use = []
    rpath = None
    runpath = None
    if "elfRpath" in md and md["elfRpath"]:
        rpath = md["elfRpath"]
    if "elfRunpath" in md and md["elfRunpath"]:
        runpath = md["elfRunpath"]

    # 1. Search using directories in DT_RPATH if present and no DT_RUNPATH exists (use of DT_RPATH is deprecated)
    # 3. Search using directories in DT_RUNPATH if present
    if rpath and not runpath:
        rp_to_use = rpath
    elif runpath:
        rp_to_use = runpath

    results = [
        sp  # append path with DSTs replaced to the list
        for rp in rp_to_use  # iterate through all possible runpath entries
        for p in rp.split(":")  # iterate through all components (paths) in each runpath entry
        if p != ""  # if the path entry is not empty
        for sp in substitute_all_dst(sw, md, p)  # substitute DSTs in the path
    ]

    logger.debug(f"[ELF][runpath] expanded: {results}")
    return results


def replace_dst(origstr, dvar, newval) -> str:
    """
    Replaces placeholders in a string with a new value.

    This function replaces occurrences of `$dvar` and `${dvar}` in the input
    string `origstr` with the value specified by `newval`.

     Args:
         origstr (str): The original string.
         dvar (str): The variable name to look for in origstr.
         newval (str): The value to replace occurrences of dvar with.

     Returns:
         str: A new string with all occurrences of `$dvar` and `${dvar}` replaced
         by `newval`.

     Typical Usage Example:
         >>> origstr = "The variable $name and ${name} are placeholders."
         >>> replace_dst(origstr, "name", "Alice")
         'The variable Alice and Alice are placeholders.'

    Raises:
         None

    """
    return origstr.replace("$" + dvar, newval).replace("${" + dvar + "}", newval)


def substitute_all_dst(sw: Software, md, path) -> List[pathlib.PurePosixPath]:
    """
    Expands dynamic string tokens (DSTs) in ELF search paths like $ORIGIN, $LIB, $PLATFORM.

    Background and References:
    --------------------------
    The dynamic linker (`ld.so`) performs these substitutions for several contexts:
        - Environment variables: LD_LIBRARY_PATH, LD_PRELOAD, and LD_AUDIT
        - Dynamic section tags: DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_AUDIT, and DT_DEPAUDIT
        - Arguments to ld.so: --audit, --library-path, and --preload
        - Filename arguments to dlopen() and dlmopen()

    More details:
        See the “Dynamic string tokens” section of:
        https://man7.org/linux/man-pages/man8/ld.so.8.html

    Token behavior summary:
        $ORIGIN / ${ORIGIN}:
            Replaced with the absolute directory containing the program or shared object
            (with symlinks resolved and no ../ or ./ components).
            For SUID/SGID binaries, the resolved path must lie in a trusted directory.
            References:
              - glibc: elf/dl-load.c#L356-L357
              - glibc: elf/dl-load.c#L297-L316

        $LIB / ${LIB}:
            Expands to either "lib" or "lib64" depending on architecture
            (e.g. x86-64 → lib64, x86-32 → lib).

        $PLATFORM / ${PLATFORM}:
            Expands to the CPU type string (e.g. "x86_64").
            On some architectures this comes from AT_PLATFORM in the auxiliary vector.
            Implementing full substitution would require target-specific enumeration
            of possible platform values (from glibc or musl sources), which is nontrivial
            and rarely used — similar to hardware capability (hwcaps) subfolder searching.
            For now, such paths are discarded if unresolved.

    Returns a list of expanded paths; if no supported tokens are present, returns an empty list.

    Parameters:
        sw (Software): The software object (used for $ORIGIN resolution).
        md (dict): ELF metadata.
        path (str): The raw path string to process.

    Returns:
        List[pathlib.PurePosixPath]: All normalized, substituted search paths.
    """
    pathlist: List[pathlib.PurePosixPath] = []

    has_origin = "$ORIGIN" in path or "${ORIGIN}" in path
    has_lib = "$LIB" in path or "${LIB}" in path
    has_platform = "$PLATFORM" in path or "${PLATFORM}" in path

    # ----------------------
    # PLATFORM not supported
    # ----------------------
    if has_platform:
        # No way to resolve this reliably (varies by CPU/platform).
        # Returning empty disables unresolved PLATFORM paths.
        return []

    # No tokens → keep path as-is
    if not (has_origin or has_lib):
        return [posix_normpath(path)]

    # ----------------------
    # ORIGIN token expansion
    # ----------------------
    if has_origin and isinstance(sw.installPath, Iterable):
        for ipath in sw.installPath:
            origin = pathlib.PurePosixPath(ipath).parent.as_posix()
            pathlist.append(pathlib.PurePosixPath(replace_dst(path, "ORIGIN", origin)))

    # ------------------
    # LIB token expansion
    # ------------------
    if has_lib:
        if not pathlist:
            # nothing in the original pathlist, use the original path passed in
            pathlist.append(pathlib.PurePosixPath(replace_dst(path, "LIB", "lib")))
            pathlist.append(pathlib.PurePosixPath(replace_dst(path, "LIB", "lib64")))
        else:
            pathlist = [
                newp
                for p in pathlist
                for newp in (
                    pathlib.PurePosixPath(replace_dst(p.as_posix(), "LIB", "lib")),
                    pathlib.PurePosixPath(replace_dst(p.as_posix(), "LIB", "lib64")),
                )
            ]

    # -------------------------
    # Normalize all paths
    # -------------------------
    return [posix_normpath(p.as_posix()) for p in pathlist]
