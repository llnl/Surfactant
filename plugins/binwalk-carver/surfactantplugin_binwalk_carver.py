# SPDX-License-Identifier: MIT
"""Surfactant plugin that carves regions embedded at non-zero offsets with binwalk.

The OFRAK unpacker (``ofrak_unpacker``) and Surfactant's built-in decompressor are
the primary extractors: they identify a container/filesystem by the magic bytes at
offset 0 and unpack it properly. What they cannot see is an artifact embedded
*partway* into an opaque blob -- a vendor-headered firmware image that wraps an
LZMA kernel at one offset and a SquashFS root filesystem at another, none of whose
magic sits at offset 0.

That gap is the only thing this plugin fills. It shells out to ``binwalk`` (the
signature scanner) to locate embedded regions, carves each region that starts at a
**non-zero** offset into its own file (so its magic now sits at offset 0), and
pushes a ``ContextEntry`` for it onto Surfactant's ``context_queue``. Each carved
region then re-enters the pipeline where OFRAK / the native decompressor identify
and unpack it exactly as they would a stand-alone artifact.

The plugin only carves; it never analyzes contents and never unpacks. Regions at
offset 0, files Surfactant already analyzes natively (ELF/PE/Mach-O), and embedded
ELF signatures are all skipped -- those are handled directly by OFRAK and the
native extractors, so carving them only duplicates work (and produces truncated
fragments). binwalk is an optional runtime dependency: if it is not on PATH the
plugin logs a warning once and does nothing.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import tempfile
from typing import TYPE_CHECKING, Any

from loguru import logger

import surfactant.plugin
from surfactant import ContextEntry
from surfactant.configmanager import ConfigManager

if TYPE_CHECKING:
    from queue import Queue

    from surfactant.sbomtypes import Software

_METADATA_KEY = "binwalkCarver"
_SETTINGS_SECTION = "binwalk_carver"

# File types that Surfactant already analyzes natively (via their own info
# extractors), so the carver must never scan or carve them. These are standalone
# executables/objects -- not firmware containers -- and running binwalk on them
# only produces truncated, unparseable fragments (e.g. a carved ELF whose section
# table points past the end of the carved bytes). The carver is meant for outer
# firmware images (.img, etc.) that wrap filesystems, not for artifacts that can
# be parsed directly.
_SKIP_INPUT_FILETYPES = frozenset({"ELF", "PE", "MACHOFAT", "MACHO32", "MACHO64"})

# binwalk signature names that must never be carved into standalone files. An ELF
# embedded in a firmware image is recovered by the filesystem unpacker and then
# analyzed directly, so carving its raw signature only yields truncated fragments.
_NON_CARVE_SIGNATURES = frozenset({"elf"})

# Map binwalk signature names (the lowercase ``name`` field in its file_map) to a
# standard file extension so carved regions are named like the artifact they are.
# Some downstream plugins (and the built-in file_decompression / extension
# identifier) key off the extension. Names not listed fall back to ``.bin``.
_EXTENSION_MAP: dict[str, str] = {
    # Archives / compression streams
    "gzip": ".gz",
    "bzip2": ".bz2",
    "xz": ".xz",
    "lzma": ".lzma",
    "lzop": ".lzo",
    "zstd": ".zst",
    "tarball": ".tar",
    "tar": ".tar",
    "sevenzip": ".7z",
    "7z": ".7z",
    "rar": ".rar",
    "cpio": ".cpio",
    # Filesystems
    "squashfs": ".squashfs",
    "cramfs": ".cramfs",
    "jffs2": ".jffs2",
    "ubi": ".ubi",
    "ubifs": ".ubifs",
    "yaffs": ".yaffs",
    "romfs": ".romfs",
    "ext": ".ext",
    "iso9660": ".iso",
    # Firmware / boot containers
    "uimage": ".uimage",
    "trx": ".trx",
    "dtb": ".dtb",
    "uefi": ".fv",
}


def _extension_for(name: str) -> str:
    """Return the standard file extension for a binwalk signature name."""
    return _EXTENSION_MAP.get(name.lower(), ".bin")


# sha256 -> carve output directory, so identical bytes are only carved once.
# Directories are intentionally kept (not auto-deleted) so their contents can be
# inspected and reused, mirroring Surfactant's built-in file_decompression.
_CARVE_DIRS: dict[str, str] = {}


def _get(key: str, default: Any) -> Any:
    return ConfigManager().get(_SETTINGS_SECTION, key, default)


def _binwalk_path() -> str | None:
    configured = _get("binwalk_path", "binwalk")
    return shutil.which(configured)


def _make_carve_dir() -> str:
    base = _get("extract_dir", tempfile.gettempdir())
    pathlib.Path(base).mkdir(parents=True, exist_ok=True)
    return tempfile.mkdtemp(prefix="surfactant-binwalk-", dir=base)


def _run_binwalk(filepath: str) -> list[dict[str, Any]]:
    """Run a binwalk signature scan and return its ``file_map`` entries.

    Uses binwalk's JSON log output (``-l``) with stdout suppressed (``-q``) and
    performs no extraction. Returns an empty list on any failure so a single bad
    scan never aborts SBOM generation.
    """
    binwalk = _binwalk_path()
    if binwalk is None:
        return []

    timeout = int(_get("timeout", 300))
    search_all = bool(_get("search_all", False))
    exclude = _get("exclude_signatures", [])

    with tempfile.TemporaryDirectory(prefix="surfactant-binwalk-log-") as log_dir:
        log_path = str(pathlib.Path(log_dir) / "binwalk.json")
        cmd = [binwalk, "-q", "-l", log_path]
        if search_all:
            cmd.append("-a")
        if exclude:
            for sig in exclude:
                cmd += ["-x", str(sig)]
        cmd.append(filepath)

        try:
            subprocess.run(  # noqa: S603 - args are built from config + a file path
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning(f"binwalk scan of {filepath} failed: {exc}")
            return []

        try:
            with pathlib.Path(log_path).open(encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

    entries: list[dict[str, Any]] = []
    if isinstance(data, list):
        for top in data:
            if isinstance(top, dict):
                analysis = top.get("Analysis", {})
                file_map = analysis.get("file_map", []) if isinstance(analysis, dict) else []
                if isinstance(file_map, list):
                    entries.extend(e for e in file_map if isinstance(e, dict))
    return entries


def _compute_carve_regions(
    entries: list[dict[str, Any]], file_size: int, min_carve_size: int
) -> list[dict[str, Any]]:
    """Turn binwalk ``file_map`` entries into concrete byte ranges to carve.

    Only regions embedded at a **non-zero** offset are carved: anything at offset 0
    has its magic where OFRAK and the native identifiers already look, so they
    handle it directly (this is what keeps the carver from duplicating OFRAK's
    work and from re-carving a file that is already the artifact). When binwalk
    reports no size for a signature, the region is extended to the next
    signature's offset (or end of file). Signatures Surfactant analyzes natively
    (e.g. ELF) are skipped.
    """
    ordered = sorted(
        (e for e in entries if isinstance(e.get("offset"), int)),
        key=lambda e: e["offset"],
    )

    regions: list[dict[str, Any]] = []
    for i, entry in enumerate(ordered):
        name = str(entry.get("name", "data"))
        if name.lower() in _NON_CARVE_SIGNATURES:
            continue

        offset = int(entry["offset"])
        # Skip offset-0 (and invalid) regions; OFRAK / native identifiers own those.
        if offset <= 0 or offset >= file_size:
            continue

        size = entry.get("size")
        if not isinstance(size, int) or size <= 0:
            next_offset = int(ordered[i + 1]["offset"]) if i + 1 < len(ordered) else file_size
            size = max(next_offset - offset, 0)

        end = min(offset + size, file_size)
        length = end - offset
        if length < min_carve_size:
            continue

        regions.append(
            {
                "offset": offset,
                "length": length,
                "name": name,
                "description": str(entry.get("description", "")),
            }
        )
    return regions


def _carve_range(src_path: str, offset: int, length: int, dest_path: str) -> int:
    """Copy ``length`` bytes starting at ``offset`` from ``src_path`` to ``dest_path``."""
    written = 0
    with pathlib.Path(src_path).open("rb") as src, pathlib.Path(dest_path).open("wb") as out:
        src.seek(offset)
        remaining = length
        while remaining > 0:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                break
            out.write(chunk)
            written += len(chunk)
            remaining -= len(chunk)
    return written


def _existing_carved_files(out_dir: str) -> list[str]:
    return [str(p) for p in sorted(pathlib.Path(out_dir).glob("carved_*")) if p.is_file()]


# pylint: disable=too-many-positional-arguments
@surfactant.plugin.hookimpl
def extract_file_info(
    software: Software,
    filename: str,
    filetype: list[str],
    context_queue: Queue[ContextEntry],
    current_context: ContextEntry | None,
    omit_unrecognized_types: bool = False,
) -> dict[str, Any] | None:
    """Carve non-zero-offset embedded regions out of ``filename`` and queue them."""
    # pylint: disable=too-many-return-statements
    if _binwalk_path() is None:
        return None

    # Skip files Surfactant already analyzes natively (ELF/PE/Mach-O). Carving
    # these only yields truncated fragments; the carver is for firmware images.
    if filetype and any(ft in _SKIP_INPUT_FILETYPES for ft in filetype):
        return None

    # Don't scan files too small to plausibly contain an embedded filesystem.
    min_file_size = int(_get("min_file_size", 4096))
    try:
        file_size = pathlib.Path(filename).stat().st_size
    except OSError:
        return None
    if file_size < min_file_size:
        return None

    # Avoid re-carving a container we're already processing the contents of.
    if current_context and current_context.archive == filename and current_context.extractPaths:
        return None

    install_prefix = current_context.installPrefix if current_context else ""

    # Reuse a previous carve of identical bytes.
    out_dir = _CARVE_DIRS.get(software.sha256)
    reused = bool(out_dir and pathlib.Path(out_dir).exists())

    if reused:
        carved_files = _existing_carved_files(out_dir)
        if not carved_files:
            return None
        for path in carved_files:
            context_queue.put(
                ContextEntry(
                    archive=filename,
                    installPrefix=install_prefix,
                    extractPaths=[path],
                    skipProcessingArchive=True,
                    omitUnrecognizedTypes=omit_unrecognized_types,
                )
            )
        return {
            _METADATA_KEY: {
                "carved": True,
                "cached": True,
                "extractPath": out_dir,
                "regionCount": len(carved_files),
            }
        }

    entries = _run_binwalk(filename)
    if not entries:
        return None

    min_carve_size = int(_get("min_carve_size", 512))
    regions = _compute_carve_regions(entries, file_size, min_carve_size)
    if not regions:
        return None
    regions.sort(key=lambda r: r["offset"])

    out_dir = _make_carve_dir()
    _CARVE_DIRS[software.sha256] = out_dir

    carved: list[dict[str, Any]] = []
    for idx, region in enumerate(regions):
        ext = _extension_for(region["name"])
        dest = str(
            pathlib.Path(out_dir)
            / f"carved_{idx:03d}_0x{region['offset']:08x}_{region['name']}{ext}"
        )
        try:
            written = _carve_range(filename, region["offset"], region["length"], dest)
        except OSError as exc:
            logger.warning(f"Failed to carve region at 0x{region['offset']:x} of {filename}: {exc}")
            continue
        if written <= 0:
            continue

        carved.append(
            {
                "offset": region["offset"],
                "length": written,
                "signature": region["name"],
                "description": region["description"],
                "path": dest,
            }
        )
        context_queue.put(
            ContextEntry(
                archive=filename,
                installPrefix=install_prefix,
                extractPaths=[dest],
                skipProcessingArchive=True,
                omitUnrecognizedTypes=omit_unrecognized_types,
            )
        )

    if not carved:
        return None

    covered = sum(int(c["length"]) for c in carved)
    logger.info(f"binwalk_carver carved {len(carved)} region(s) from '{filename}' -> {out_dir}")
    return {
        _METADATA_KEY: {
            "carved": True,
            "extractPath": out_dir,
            "imageSize": file_size,
            "coveragePercent": round(covered / file_size * 100, 2) if file_size else None,
            "regions": carved,
        }
    }


@surfactant.plugin.hookimpl
def short_name() -> str:
    return "binwalk_carver"


@surfactant.plugin.hookimpl
def settings_name() -> str:
    return _SETTINGS_SECTION


@surfactant.plugin.hookimpl
def init_hook(command_name: str | None = None) -> None:
    """Warn once if binwalk is unavailable before extraction runs."""
    if command_name not in (None, "generate"):
        return
    if _binwalk_path() is None:
        logger.warning(
            "binwalk_carver: the 'binwalk' executable was not found on PATH; embedded "
            "regions at non-zero offsets will not be carved. Install binwalk to enable "
            "carving (e.g. 'cargo install binwalk' or 'pip install binwalk')."
        )
