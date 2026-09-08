# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
"""Surfactant plugin that uses Binary Ninja for control-flow graph extraction.

This plugin is intentionally scoped to the one thing Binary Ninja does *better*
than angr: high-fidelity function recovery and the per-function control-flow
graph (basic blocks + edges). It loads the binary in Binary Ninja's
``controlFlow`` analysis mode, which recovers functions and CFGs without running
the far more expensive data-flow / IL / decompilation passes.

It deliberately does **not** duplicate the loader/symbol/dependency work owned by
the ``angr_expanded`` plugin, so the two produce complementary (not overlapping)
records on the same binary. The metadata is grouped under the ``binaryNinja`` key.

Because the Binary Ninja Python API usually lives outside ``site-packages`` and
requires a license, it is imported lazily. If it cannot be imported the plugin
registers but simply skips analysis (logging a warning), so SBOM generation is
never blocked by a missing Binary Ninja install.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime here
    import binaryninja as bn

    from surfactant.sbomtypes import SBOM, Software

# ``except Exception`` guards and the lazy Binary Ninja import below are intentional:
# a missing/unlicensed install or a malformed binary must never abort SBOM generation.
# pylint: disable=broad-exception-caught,import-outside-toplevel

# Top-level key the metadata object is stored under in the software entry.
_METADATA_KEY = "binaryNinja"

# Settings section and keys (read via Surfactant's ConfigManager).
_SETTINGS_SECTION = "binary_ninja"
_SETTINGS_MAX_FUNCTIONS = "max_functions"
_SETTINGS_MIN_BASIC_BLOCKS = "min_basic_blocks"
_SETTINGS_EXCLUDE_LIBRARY = "exclude_library_functions"

# Cap on how many per-function records are emitted so a single large binary
# (e.g. a statically-linked busybox with thousands of functions) cannot bloat
# the SBOM without bound. Aggregate statistics are always computed over *all*
# functions regardless of this cap.
_DEFAULT_MAX_FUNCTIONS = 5000

# Minimum basic-block count for a function to be emitted in the CFG ``functions``
# list. A single-block function has no control flow worth serializing, and such
# stubs (PLT thunks, trivial wrappers) otherwise dominate the output. They are
# still counted in the aggregate stats. Set to 1 to emit every function.
_DEFAULT_MIN_BASIC_BLOCKS = 2

# GCC/Clang emit helper "clones" — cold-path splits and interprocedural
# specializations — whose standalone CFG carries little analytic value and which
# heavily inflate the output. They are excluded from the emitted ``functions``
# list (still counted in aggregate stats). Matched as substrings of the name.
_CLONE_MARKERS = (".cold", ".isra", ".constprop", ".part")

# C++ runtime/library namespaces whose functions are rarely the analysis target
# and which dominate the CFG of any C++ binary. When library exclusion is on
# (default), functions whose name starts with one of these markers are dropped
# from the emitted ``functions`` list (still counted in aggregate stats). Both
# Itanium-mangled prefixes (e.g. ``_ZNSt`` for ``std::``) and demangled
# ``namespace::`` prefixes are matched so it works regardless of BN's naming.
_DEFAULT_LIBRARY_MARKERS = (
    "_ZNSt",  # std:: (nested)
    "_ZSt",  # std:: (free function)
    "_ZNKSt",  # std:: (const method)
    "_ZN9__gnu_cxx",  # __gnu_cxx::
    "_ZN3fmt",  # fmt::
    "_ZN6spdlog",  # spdlog::
    "_ZN7cxxopts",  # cxxopts::
    "_ZN8nlohmann",  # nlohmann::
    "std::",
    "__gnu_cxx::",
    "fmt::",
    "spdlog::",
    "cxxopts::",
    "nlohmann::",
)


def supports_file(filetype: list[str]) -> bool:
    """Return True for executable formats Binary Ninja can load."""
    return any(t in filetype for t in ("ELF", "PE", "MACHOFAT", "MACHO"))


# ELF ``e_type`` values kept for analysis: ET_EXEC (executables) and ET_DYN
# (shared objects / PIE executables). ET_REL (relocatable objects, which is what
# Linux kernel modules ``.ko`` and ``.o`` files are) and ET_CORE are excluded so
# Binary Ninja only analyzes true loadable executables/libraries.
_ELF_ANALYZABLE_ETYPES = frozenset({2, 3})  # ET_EXEC, ET_DYN


def _is_true_executable(path: Path, filetype: list[str]) -> bool:
    """Return True only for genuine loadable binaries.

    For ELF, this reads ``e_type`` and rejects relocatable objects (``.ko``
    kernel modules, ``.o`` files) and core dumps. Non-ELF supported formats
    (PE, Mach-O) are executables/dylibs already and are allowed through.
    """
    if "ELF" not in filetype:
        return True
    try:
        with path.open("rb") as f:
            header = f.read(18)
    except OSError:
        return False
    if len(header) < 18 or header[:4] != b"\x7fELF":
        return False
    # EI_DATA (byte 5): 1 = little-endian, 2 = big-endian.
    endian = "big" if header[5] == 2 else "little"
    e_type = int.from_bytes(header[16:18], endian)
    return e_type in _ELF_ANALYZABLE_ETYPES


def _get_bool_setting(key: str, default: bool) -> bool:
    """Read a boolean plugin setting, never raising on lookup failure."""
    try:
        return bool(ConfigManager().get(_SETTINGS_SECTION, key, default))
    except Exception:  # noqa: BLE001 - config lookup must never break extraction
        return default


def _get_int_setting(key: str, default: int) -> int:
    """Read an integer plugin setting, never raising on lookup failure."""
    try:
        value = ConfigManager().get(_SETTINGS_SECTION, key, default)
        return int(value)
    except Exception:  # noqa: BLE001 - config lookup must never break extraction
        return default


def _load_binaryninja() -> bn | None:
    """Import the Binary Ninja API lazily; return the module or None."""
    try:
        import binaryninja as bn  # noqa: PLC0415 - intentional lazy import
    except Exception as e:  # noqa: BLE001 - missing/broken install must not crash
        logger.warning(
            "binaryninja_info: Binary Ninja Python API not importable "
            f"({type(e).__name__}: {e}); skipping structural analysis"
        )
        return None
    return bn


def _open_view(bn: bn, path: str) -> Any | None:
    """Open an analyzed BinaryView for ``path`` (headless) in ``controlFlow`` mode.

    ``controlFlow`` recovers only functions and basic blocks, which is all the
    CFG extraction needs -- it skips the far more expensive data-flow / IL /
    decompilation passes.
    """
    try:
        view = bn.load(path, options={"analysis.mode": "controlFlow"})
    except Exception as e:  # noqa: BLE001 - loading untrusted binaries can raise anything
        logger.info(f"binaryninja_info could not load {path}: {e}")
        return None
    if view is None:
        return None
    try:
        # ``load`` normally runs analysis already; this is a cheap no-op if so and
        # guarantees the CFG is populated before we read it.
        view.update_analysis_and_wait()
    except Exception as e:  # noqa: BLE001 - analysis can fail on malformed input
        logger.warning(f"binaryninja_info analysis incomplete for {path}: {e}")
    return view


def _collect_header(bn: bn, view: Any) -> dict[str, Any]:
    """Collect BN-unique provenance/platform header fields.

    Loader facts that angr already owns (``arch``, ``endianness``, ``entryPoint``,
    ``objectFormat``, image base, sections, ...) are intentionally *not* repeated
    here to keep the two plugins non-redundant. ``platform`` is kept because it is
    a Binary Ninja concept that folds in the OS/ABI dimension angr does not report
    (e.g. ``linux-aarch64``).
    """
    platform = getattr(view, "platform", None)
    return {
        "coreVersion": bn.core_version(),
        "platform": getattr(platform, "name", None),
    }


def _basic_block_record(block: Any) -> dict[str, Any]:
    """Build a structure-only record for one basic block (no disassembly text)."""
    edges: list[dict[str, str]] = []
    for edge in getattr(block, "outgoing_edges", []):
        target = getattr(edge, "target", None)
        if target is None:
            continue
        edges.append(
            {
                "target": hex(target.start),
                "type": getattr(edge.type, "name", str(edge.type)),
            }
        )
    return {
        "start": hex(block.start),
        "end": hex(block.end),
        "instructionCount": getattr(block, "instruction_count", 0),
        "edges": edges,
    }


def _iter_control_flow(
    view: Any, limit: int, min_basic_blocks: int, library_markers: tuple = ()
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Single pass over functions: build a filtered CFG list + full-corpus stats.

    Returns ``(functions, stats)``. ``functions`` holds compact per-function
    control-flow records (basic blocks + edges), excluding thunks, functions
    with fewer than ``min_basic_blocks`` blocks (which carry no control flow),
    compiler-generated clones, and — when ``library_markers`` is non-empty —
    functions whose name starts with a C++ runtime/library marker. Records are
    capped at ``limit``. ``stats`` aggregates over *every* recovered function
    regardless of those filters.
    """
    functions: list[dict[str, Any]] = []
    total_functions = 0
    total_basic_blocks = 0
    total_instructions = 0
    thunk_count = 0
    capped = False

    for func in view.functions:
        total_functions += 1
        basic_blocks = func.basic_blocks
        bb_count = len(basic_blocks)
        insn_count = 0
        for block in basic_blocks:
            insn_count += getattr(block, "instruction_count", 0)
        total_basic_blocks += bb_count
        total_instructions += insn_count

        is_thunk = bool(getattr(func, "is_thunk", False))
        if is_thunk:
            thunk_count += 1

        # Drop analytically-empty or off-target records to cut bloat: thunks
        # (pure forwarders), compiler-generated clones, functions with no real
        # control flow, and — when enabled — C++ runtime/library functions. All
        # are still counted in the aggregate stats above.
        name = func.name
        if (
            is_thunk
            or bb_count < min_basic_blocks
            or any(marker in name for marker in _CLONE_MARKERS)
            or any(name.startswith(prefix) for prefix in library_markers)
        ):
            continue
        if len(functions) >= limit:
            capped = True
            continue

        functions.append(
            {
                "name": func.name,
                "address": hex(func.start),
                "basicBlockCount": bb_count,
                "instructionCount": insn_count,
                "isThunk": is_thunk,
                "basicBlocks": [_basic_block_record(block) for block in basic_blocks],
            }
        )

    stats = {
        "functionCount": total_functions,
        "basicBlockCount": total_basic_blocks,
        "instructionCount": total_instructions,
        "thunkCount": thunk_count,
        "emittedFunctionCount": len(functions),
        "controlFlowTruncated": capped,
    }
    return functions, stats


@surfactant.plugin.hookimpl(specname="extract_file_info")
def binaryninja_info(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    """Extract Binary Ninja control-flow-graph metadata for the SBOM.

    Args:
        sbom (SBOM): The SBOM the software entry belongs to.
        software (Software): The software entry the metadata will be attached to.
        filename (str): Full path to the file to analyze.
        filetype (List[str]): File type hints based on magic bytes.

    Returns:
        object: A metadata dict stored under ``binaryNinja``, or None if the file
            is unsupported or Binary Ninja could not analyze it.
    """
    # pylint: disable=too-many-return-statements
    if not supports_file(filetype):
        return None

    path = Path(filename)
    if not path.exists():
        logger.warning(f"binaryninja_info: file does not exist: {filename}")
        return None

    if not _is_true_executable(path, filetype):
        logger.info(
            "binaryninja_info: skipping non-executable ELF "
            f"(relocatable object / kernel module / core): {path.name}"
        )
        return None

    bn = _load_binaryninja()
    if bn is None:
        return None

    view = _open_view(bn, path.as_posix())
    if view is None:
        return None

    max_functions = _get_int_setting(_SETTINGS_MAX_FUNCTIONS, _DEFAULT_MAX_FUNCTIONS)
    min_basic_blocks = _get_int_setting(_SETTINGS_MIN_BASIC_BLOCKS, _DEFAULT_MIN_BASIC_BLOCKS)
    library_markers = (
        _DEFAULT_LIBRARY_MARKERS if _get_bool_setting(_SETTINGS_EXCLUDE_LIBRARY, True) else ()
    )
    metadata: dict[str, Any] = {}
    try:
        metadata.update(_collect_header(bn, view))
        functions, stats = _iter_control_flow(
            view, max_functions, min_basic_blocks, library_markers
        )
        metadata.update(stats)
        metadata["functions"] = functions
    except Exception as e:  # noqa: BLE001 - keep SBOM generation resilient
        logger.warning(f"binaryninja_info partial extraction for {filename}: {e}")
    finally:
        with contextlib.suppress(Exception):  # best-effort cleanup
            view.file.close()

    if not metadata:
        return None

    logger.info(f"binaryninja_info extracted metadata for {path.name}")
    return {_METADATA_KEY: metadata}


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    """Short name used to enable/disable and reference this plugin."""
    return "binaryninja_info"


@surfactant.plugin.hookimpl
def settings_name() -> str | None:
    """Base name used for reading/writing this plugin's Surfactant settings."""
    return _SETTINGS_SECTION
