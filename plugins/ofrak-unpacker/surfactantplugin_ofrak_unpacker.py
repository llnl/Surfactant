# SPDX-License-Identifier: MIT
"""Surfactant plugin that unpacks non-native firmware/container formats with OFRAK.

Surfactant natively decompresses common archives (ZIP/TAR/GZIP/BZIP2/XZ/RAR) via
``file_decompression.py``. This plugin extends that idea to firmware and embedded
container formats that OFRAK knows how to unpack (SquashFS, CramFS, JFFS2, UBI/UBIFS,
ext filesystems, U-Boot uImage, OpenWrt TRX, 7-Zip, ISO 9660, UEFI firmware volumes,
UF2, CPIO, zstd/lzop streams, etc.).

It works exactly like the built-in decompressor: it unpacks the container to a
temporary directory and pushes ``ContextEntry`` objects onto Surfactant's
``context_queue`` so the extracted artifacts are re-processed by the *entire* plugin
pipeline (ELF/PE extractors, checksec, angr-expanded, relationship builders, ...).
This plugin therefore does not analyze the contents itself; it only unpacks.

OFRAK is an optional dependency. If it is not installed, ``identify_file_type`` still
works (so the firmware type is still recorded), and ``extract_file_info`` logs a
warning and skips unpacking.
"""

from __future__ import annotations

import asyncio
import atexit
import importlib.util
import pathlib
import shutil
import tempfile
import threading
from typing import TYPE_CHECKING, Any

from loguru import logger

import surfactant.plugin
from surfactant import ContextEntry
from surfactant.configmanager import ConfigManager

if TYPE_CHECKING:
    from queue import Queue

    from surfactant.sbomtypes import SBOM, Software

# ``except Exception`` guards and the lazy ``ofrak`` imports below are intentional:
# OFRAK is an optional dependency and unpacking untrusted firmware must never abort
# SBOM generation for the rest of the corpus.
# pylint: disable=broad-exception-caught,import-outside-toplevel

# ---------------------------------------------------------------------------
# File-type identification (magic bytes)
# ---------------------------------------------------------------------------

# Each entry maps a Surfactant file-type label to a (offset, signatures) pair.
# ``signatures`` is a tuple of byte strings; a match at ``offset`` for any of them
# identifies the type. These are the non-native container formats that OFRAK can
# unpack but Surfactant does not handle on its own.
#
# ROMFS and Android boot images were intentionally dropped: OFRAK's core has no
# unpacker for them, so identifying them here only produced empty extractions.
# Device tree blobs (DTB) were also dropped: they describe hardware, contain no
# software artifacts for the SBOM, and OFRAK's DtbUnpacker crashes on some of them.
_MAGIC_SIGNATURES: dict[str, tuple[int, tuple[bytes, ...]]] = {
    # SquashFS: "hsqs" (little-endian) or "sqsh" (big-endian) at offset 0
    "SQUASHFS": (0, (b"hsqs", b"sqsh")),
    # CramFS: 0x28cd3d45 stored little-endian at offset 0
    "CRAMFS": (0, (b"\x45\x3d\xcd\x28",)),
    # JFFS2: 0x1985 as either endianness at offset 0
    "JFFS2": (0, (b"\x85\x19", b"\x19\x85")),
    # UBI volume ("UBI#") and UBIFS at offset 0
    "UBI": (0, (b"UBI#",)),
    "UBIFS": (0, (b"\x31\x18\x10\x06",)),
    # U-Boot legacy uImage: magic 0x27051956 at offset 0
    "UIMAGE": (0, (b"\x27\x05\x19\x56",)),
    # OpenWrt TRX firmware: magic "HDR0" (0x30524448 little-endian) at offset 0
    "OPENWRT_TRX": (0, (b"HDR0",)),
    # CPIO archives (newc/crc ASCII and old binary)
    "CPIO": (0, (b"070701", b"070702", b"070707", b"\xc7\x71")),
    # YAFFS2 object header (first record is typically a directory named for the root)
    "YAFFS": (0, (b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff",)),
    # 7-Zip archive (not decompressed natively by Surfactant): magic at offset 0
    "SEVENZIP": (0, (b"7z\xbc\xaf\x27\x1c",)),
    # UF2 flashing format: first-block magic 0x0A324655 ("UF2\n") at offset 0
    "UF2": (0, (b"\x55\x46\x32\x0a",)),
    # Zstandard frame: magic 0xFD2FB528 stored little-endian at offset 0
    "ZSTD": (0, (b"\x28\xb5\x2f\xfd",)),
    # lzop (.lzo): magic \x89LZO\x00\r\n\x1a\n at offset 0
    "LZOP": (0, (b"\x89\x4c\x5a\x4f\x00\x0d\x0a\x1a\x0a",)),
    # UEFI firmware volume: "_FVH" signature at offset 0x28
    "UEFI": (0x28, (b"_FVH",)),
    # GPT-partitioned disk image: "EFI PART" at LBA 1 (offset 0x200)
    "GPT": (0x200, (b"EFI PART",)),
}

# ext2/3/4 superblock magic 0xEF53 lives at offset 0x438, handled specially.
_EXT_MAGIC_OFFSET = 0x438
_EXT_MAGIC = b"\x53\xef"

# ISO 9660 primary volume descriptor: "CD001" at offset 0x8001, handled specially
# because it sits far past the header read used for the offset-0 signatures.
_ISO_MAGIC_OFFSET = 0x8001
_ISO_MAGIC = b"CD001"

# MBR-partitioned disk image: 0x55AA boot signature at offset 0x1FE with at least
# one non-empty partition table entry (checked specially to reduce false positives).
_MBR_SIG_OFFSET = 0x1FE
_MBR_SIG = b"\x55\xaa"
_MBR_PART_TABLE_OFFSET = 0x1BE

# The set of labels this plugin knows how to unpack.
_SUPPORTED_TYPES = frozenset(_MAGIC_SIGNATURES) | {"EXT", "DISK_IMAGE", "ISO9660", "IHEX"}

_METADATA_KEY = "ofrakUnpacker"
_SETTINGS_SECTION = "ofrak_unpacker"

# External CLI tools that OFRAK unpackers shell out to for the formats this plugin
# detects (verified against ``python -m ofrak deps``). These must be present on
# PATH for extraction of the corresponding formats to succeed. Package hints are
# for Debian/Ubuntu. Maps tool -> (formats, install hint).
_EXTERNAL_TOOLS: dict[str, tuple[str, str]] = {
    "unsquashfs": ("SQUASHFS", "apt install squashfs-tools"),
    "jefferson": ("JFFS2", "pip install jefferson"),
    "debugfs": ("EXT", "apt install e2fsprogs"),
    "7zz": ("SEVENZIP/CRAMFS/ISO9660", "apt install 7zip (or download from 7-zip.org)"),
    "lzop": ("LZOP", "apt install lzop"),
    "zstd": ("ZSTD", "apt install zstd"),
    "uefiextract": ("UEFI", "download from https://github.com/LongSoft/UEFITool/releases"),
}

# Python modules certain OFRAK unpackers import directly (not PATH tools).
# Maps importable module name -> (formats, install hint).
_PYTHON_DEPS: dict[str, tuple[str, str]] = {
    "lzo": ("UBI/UBIFS", "apt install liblzo2-dev && pip install python-lzo"),
}

# ---------------------------------------------------------------------------
# Extraction bookkeeping
# ---------------------------------------------------------------------------

# sha256 -> extracted directory path, so repeated files are only unpacked once.
# sha256 -> extracted directory path, so repeated files are only unpacked once.
# Extraction directories are intentionally kept (not auto-deleted) so their
# contents can be inspected and reused, mirroring Surfactant's built-in
# file_decompression extractor.
_EXTRACT_DIRS: dict[str, str] = {}

_SECTOR_SIZE = 512
# Extended-partition container types hold logical partitions rather than a
# filesystem, so they are skipped (their logical partitions would be carved
# separately in a fuller implementation).
_EXTENDED_PART_TYPES = {0x05, 0x0F, 0x85}


def _make_extract_dir() -> str:
    base = ConfigManager().get(_SETTINGS_SECTION, "extract_dir", tempfile.gettempdir())
    pathlib.Path(base).mkdir(parents=True, exist_ok=True)
    return tempfile.mkdtemp(prefix="surfactant-ofrak-", dir=base)


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


def _mbr_partitions(header: bytes, file_size: int) -> list[dict[str, int]]:
    """Parse the four primary MBR partition-table entries."""
    parts: list[dict[str, int]] = []
    table = header[_MBR_PART_TABLE_OFFSET : _MBR_PART_TABLE_OFFSET + 64]
    for i in range(4):
        entry = table[i * 16 : (i + 1) * 16]
        if len(entry) < 16:
            break
        ptype = entry[4]
        lba_start = int.from_bytes(entry[8:12], "little")
        num_sectors = int.from_bytes(entry[12:16], "little")
        if ptype == 0 or num_sectors == 0 or ptype in _EXTENDED_PART_TYPES:
            continue
        offset = lba_start * _SECTOR_SIZE
        if offset <= 0 or offset >= file_size:
            continue
        length = min(num_sectors * _SECTOR_SIZE, file_size - offset)
        parts.append({"index": i, "type": ptype, "offset": offset, "length": length})
    return parts


def _gpt_partitions(src_path: str, file_size: int) -> list[dict[str, int]]:
    """Parse the GPT partition entry array (header at LBA 1)."""
    parts: list[dict[str, int]] = []
    with pathlib.Path(src_path).open("rb") as f:
        f.seek(_SECTOR_SIZE)
        hdr = f.read(_SECTOR_SIZE)
        if hdr[:8] != b"EFI PART":
            return parts
        part_entry_lba = int.from_bytes(hdr[72:80], "little")
        num_entries = int.from_bytes(hdr[80:84], "little")
        entry_size = int.from_bytes(hdr[84:88], "little")
        if entry_size < 128 or num_entries == 0 or num_entries > 512:
            return parts
        f.seek(part_entry_lba * _SECTOR_SIZE)
        table = f.read(num_entries * entry_size)
    for i in range(num_entries):
        entry = table[i * entry_size : (i + 1) * entry_size]
        if len(entry) < 56:
            break
        if entry[0:16] == b"\x00" * 16:  # unused entry (zero type GUID)
            continue
        first_lba = int.from_bytes(entry[32:40], "little")
        last_lba = int.from_bytes(entry[40:48], "little")
        if last_lba < first_lba:
            continue
        offset = first_lba * _SECTOR_SIZE
        if offset >= file_size:
            continue
        length = min((last_lba - first_lba + 1) * _SECTOR_SIZE, file_size - offset)
        parts.append({"index": i, "type": 0xEE, "offset": offset, "length": length})
    return parts


def _carve_partitions(filename: str, out_dir: str) -> list[dict[str, Any]]:
    """Carve each partition of an MBR/GPT disk image into ``out_dir``."""
    file_size = pathlib.Path(filename).stat().st_size
    with pathlib.Path(filename).open("rb") as f:
        header = f.read(1088)

    partitions: list[dict[str, int]] = []
    if header[0x200:0x208] == b"EFI PART":
        partitions = _gpt_partitions(filename, file_size)
    if not partitions:
        partitions = _mbr_partitions(header, file_size)

    results: list[dict[str, Any]] = []
    for p in partitions:
        dest = str(pathlib.Path(out_dir) / f"partition_{p['index']}_type_0x{p['type']:02x}.img")
        written = _carve_range(filename, p["offset"], p["length"], dest)
        results.append(
            {
                "index": p["index"],
                "partitionType": f"0x{p['type']:02x}",
                "offset": p["offset"],
                "length": written,
                "path": dest,
            }
        )
    return results


def _existing_partition_files(out_dir: str) -> list[dict[str, Any]]:
    return [
        {"path": str(p), "length": p.stat().st_size}
        for p in sorted(pathlib.Path(out_dir).glob("partition_*.img"))
    ]


def supports_file(filetype: list[str] | None) -> list[str] | None:
    """Return the subset of ``filetype`` labels this plugin can unpack."""
    if not filetype:
        return None
    supported = [ft for ft in filetype if ft in _SUPPORTED_TYPES]
    return supported or None


def _looks_like_ihex(header: bytes) -> bool:
    """Validate that ``header`` begins with a well-formed Intel HEX record.

    Intel HEX is ASCII, so a bare ``:`` prefix is far too weak. This parses the
    first record and verifies its length field, record type, and checksum to
    avoid misidentifying arbitrary text files that happen to start with a colon.
    """
    if not header.startswith(b":"):
        return False
    line = header[1:].split(b"\n", 1)[0].rstrip(b"\r")
    if len(line) < 10 or len(line) % 2 != 0:
        return False
    try:
        raw = bytes.fromhex(line.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return False
    byte_count = raw[0]
    record_type = raw[3]
    if record_type > 0x05 or len(raw) != byte_count + 5:
        return False
    return sum(raw) & 0xFF == 0


@surfactant.plugin.hookimpl
def identify_file_type(filepath: str, context: ContextEntry | None = None) -> list[str] | None:
    """Identify non-native firmware/container formats by magic bytes."""
    try:
        with pathlib.Path(filepath).open("rb") as f:
            header = f.read(1088)  # covers all offset-0 sigs plus the ext superblock
            # ISO 9660's primary volume descriptor sits far past the header read,
            # so grab just its signature separately (empty read past EOF is fine).
            f.seek(_ISO_MAGIC_OFFSET)
            iso_window = f.read(len(_ISO_MAGIC))
    except OSError:
        return None

    matches: list[str] = []
    for label, (offset, signatures) in _MAGIC_SIGNATURES.items():
        window = header[offset : offset + max(len(s) for s in signatures)]
        if any(window.startswith(sig) for sig in signatures):
            matches.append(label)

    if header[_EXT_MAGIC_OFFSET : _EXT_MAGIC_OFFSET + 2] == _EXT_MAGIC:
        matches.append("EXT")

    if iso_window == _ISO_MAGIC:
        matches.append("ISO9660")

    if _looks_like_ihex(header):
        matches.append("IHEX")

    # MBR disk image: boot signature plus a partition table entry with a non-zero
    # partition type byte (offset +4 within a 16-byte entry). GPT protective MBRs
    # also match, which is fine since GPT is detected separately above.
    if header[_MBR_SIG_OFFSET : _MBR_SIG_OFFSET + 2] == _MBR_SIG:
        part_types = [header[_MBR_PART_TABLE_OFFSET + i * 16 + 4] for i in range(4)]
        if any(pt != 0 for pt in part_types):
            matches.append("DISK_IMAGE")

    return matches or None


# ---------------------------------------------------------------------------
# OFRAK unpacking
# ---------------------------------------------------------------------------


def _ofrak_available() -> bool:
    return importlib.util.find_spec("ofrak") is not None


class _OfrakSession:
    """A single long-lived OFRAK context shared across every file in a run.

    Building an OFRAK context (service discovery, license verification, component
    registration) takes several seconds. The plugin previously paid that cost
    once *per file* via ``ofrak.OFRAK().run()``, which dominated runtime on
    firmware images that expand into thousands of extractable containers.

    This session starts one context on a dedicated background event loop and
    reuses it for every unpack. Access is serialized with a lock because a single
    OFRAK context (and its asyncio loop) is not safe to drive concurrently, and
    OFRAK itself only allows one live context per process.
    """

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._context: Any = None
        self._lock = threading.Lock()

    def _ensure_started(self) -> None:
        if self._context is not None:
            return
        import ofrak  # noqa: PLC0415 - lazy so the plugin loads without OFRAK installed

        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, name="ofrak-session", daemon=True)
        thread.start()
        future = asyncio.run_coroutine_threadsafe(ofrak.OFRAK().create_ofrak_context(), loop)
        self._context = future.result()
        self._loop = loop
        self._thread = thread
        atexit.register(self.shutdown)

    def run(self, coro_factory: Any) -> Any:
        """Run ``coro_factory(context)`` on the shared context and return its result."""
        with self._lock:
            self._ensure_started()
            future = asyncio.run_coroutine_threadsafe(coro_factory(self._context), self._loop)
            return future.result()

    def shutdown(self) -> None:
        with self._lock:
            if self._context is None:
                return
            try:
                future = asyncio.run_coroutine_threadsafe(
                    self._context.shutdown_context(), self._loop
                )
                future.result(timeout=30)
            except Exception:  # noqa: BLE001
                pass
            self._context = None
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._loop.stop)
                self._loop = None
            self._thread = None


# Module-level singleton so every ``extract_file_info`` call reuses one context.
_OFRAK_SESSION = _OfrakSession()


async def _mapped_coverage(root_resource: Any) -> tuple[int, float] | None:
    """Return ``(image_size, covered_fraction)`` for an unpacked OFRAK resource.

    Coverage is the fraction of the original image's bytes that OFRAK mapped to
    child resources. Only byte-mapped children are counted: content that OFRAK
    decodes/decompresses into a separate data space (e.g. files inside a
    compressed filesystem) is not mapped back onto the image, so an image that is
    itself a single recognized container reports full (1.0) coverage. Unidentified
    gaps (padding, unknown blobs) are left uncovered and lower the fraction.
    """
    try:
        image_size = await root_resource.get_data_length()
    except Exception:  # noqa: BLE001
        return None
    if not image_size:
        return None

    intervals: list[tuple[int, int]] = []

    async def _walk(res: Any, base: int) -> None:
        try:
            children = await res.get_children()
        except Exception:  # noqa: BLE001
            return
        for child in children:
            try:
                rng = await child.get_data_range_within_parent()
            except Exception:  # noqa: BLE001
                continue
            # A zero-length range marks an unmapped (decoded) child that lives in
            # its own data space, so it contributes no original-image bytes.
            if rng.length() <= 0:
                continue
            start = base + rng.start
            end = base + rng.end
            if start < 0 or end > image_size or end <= start:
                continue
            intervals.append((start, end))
            await _walk(child, start)

    await _walk(root_resource, 0)

    if not intervals:
        # No mapped sub-regions: the whole image is one recognized container.
        return image_size, 1.0

    intervals.sort()
    covered = 0
    cur_start, cur_end = intervals[0]
    for start, end in intervals[1:]:
        if start > cur_end:
            covered += cur_end - cur_start
            cur_start, cur_end = start, end
        else:
            cur_end = max(cur_end, end)
    covered += cur_end - cur_start
    return image_size, covered / image_size


def _unpack_fs_with_ofrak(filename: str, out_dir: str) -> dict[str, Any]:
    """Unpack a single filesystem/container ``filename`` into ``out_dir`` with OFRAK.

    OFRAK is asyncio-based, so the async work is wrapped and run to completion.
    A recursive unpack gives the best coverage but can crash on a spurious match
    (e.g. a false-positive device-tree blob inside an extracted file). Such
    errors are tolerated: whatever filesystem trees were recovered are still
    flushed to disk, and a single-level unpack is used as a fallback.
    """
    from ofrak.core.filesystem import FilesystemRoot  # noqa: PLC0415 - optional dependency

    summary: dict[str, Any] = {"extractedFileCount": 0, "filesystemCount": 0}

    async def _run(ofrak_context: Any) -> None:
        root = await ofrak_context.create_root_resource_from_file(filename)
        try:

            async def _collect_fs_roots() -> list[Any]:
                found: list[Any] = []
                if root.has_tag(FilesystemRoot):
                    found.append(root)
                for descendant in await root.get_descendants():
                    if descendant.has_tag(FilesystemRoot):
                        found.append(descendant)
                return found

            # Shallow unpack first: for a resource that is itself a filesystem (e.g. an
            # ext partition), a single-level unpack runs its dedicated unpacker and
            # populates the whole tree quickly, without recursing into every extracted
            # file. Recursing eagerly is both slow and prone to crashing on a spurious
            # match inside one of the extracted files, which previously left the
            # filesystem tagged-but-empty.
            try:
                await root.unpack()
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"OFRAK shallow unpack of {filename} failed: {exc}")

            fs_resources = await _collect_fs_roots()
            have_populated = False
            for fsr in fs_resources:
                try:
                    if list(await fsr.get_children()):
                        have_populated = True
                        break
                except Exception:  # noqa: BLE001
                    continue

            # Only dig deeper when the shallow unpack did not already yield a populated
            # filesystem. This handles wrapper formats (uImage/TRX/etc.) that must be
            # peeled back a few layers before a filesystem is exposed. A crashing
            # sub-unpacker here is tolerated.
            if not have_populated:
                try:
                    await root.unpack_recursively()
                except Exception as exc:  # noqa: BLE001 - tolerate crashing sub-unpackers
                    logger.warning(f"OFRAK recursive unpack of {filename} hit an error: {exc}")
                fs_resources = await _collect_fs_roots()

            # A crashing sub-unpacker can abort a recursive pass *after* a filesystem
            # was identified (tagged) but *before* its dedicated unpacker populated it,
            # leaving an empty tree. Explicitly unpack any filesystem that still has no
            # children so its contents are recovered (e.g. ext via debugfs), tolerating
            # per-resource errors so one bad filesystem can't block the others.
            for fsr in fs_resources:
                try:
                    if not list(await fsr.get_children()):
                        await fsr.unpack()
                except Exception as exc:  # noqa: BLE001
                    logger.warning(f"OFRAK failed to populate a filesystem in {filename}: {exc}")

            # Re-collect: populating a filesystem may have exposed nested filesystem roots.
            fs_resources = await _collect_fs_roots()

            for idx, fsr in enumerate(fs_resources):
                dest = pathlib.Path(out_dir) / f"filesystem_{idx}"
                dest.mkdir(parents=True, exist_ok=True)
                try:
                    view = await fsr.view_as(FilesystemRoot)
                    await view.flush_to_disk(str(dest))
                except Exception as exc:  # noqa: BLE001
                    logger.warning(f"OFRAK failed to flush filesystem_{idx} of {filename}: {exc}")

            summary["filesystemCount"] = len(fs_resources)
            summary["extractedFileCount"] = sum(
                1 for p in pathlib.Path(out_dir).rglob("*") if p.is_file()
            )

            coverage = await _mapped_coverage(root)
            if coverage is not None:
                image_size, fraction = coverage
                summary["imageSize"] = image_size
                summary["coveragePercent"] = round(fraction * 100, 2)
        finally:
            # The OFRAK context is shared across every file in the run, so the
            # resource tree for this file must be released once it has been
            # flushed to disk; otherwise the whole firmware image's worth of
            # unpacked filesystems would pile up in memory.
            try:
                await root.delete()
                await root.save()
            except Exception:  # noqa: BLE001
                pass

    _OFRAK_SESSION.run(_run)
    return summary


# pylint: disable=too-many-positional-arguments,too-many-return-statements
@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: list[str],
    context_queue: Queue[ContextEntry],
    current_context: ContextEntry | None,
    omit_unrecognized_types: bool = False,
) -> dict[str, Any] | None:
    supported = supports_file(filetype)
    if not supported:
        # ``identify_file_type`` is a ``firstresult=True`` hook, so only the first
        # plugin to return a non-None result wins and that single label list is
        # what gets passed here. The built-in magic identifier runs ``tryfirst``
        # and may win with a label this plugin does not use (e.g. "ZSTANDARD" vs
        # "ZSTD", "ISO_9660_CD" vs "ISO9660") or return nothing for formats it
        # doesn't know (e.g. MBR disk images), which would shadow our own
        # detection. Re-run our own magic-based identification on the file so we
        # still unpack any format we support, regardless of who won the race.
        supported = supports_file(identify_file_type(filename))
    if not supported:
        return None

    # Avoid re-extracting an archive we're already inside of.
    if current_context and current_context.archive == filename and current_context.extractPaths:
        return None

    # Inherit the install prefix from the parent context, if any.
    install_prefix = current_context.installPrefix if current_context else ""
    is_disk_image = any(t in ("DISK_IMAGE", "GPT") for t in supported)

    # Reuse a previous extraction of identical bytes.
    out_dir = _EXTRACT_DIRS.get(software.sha256)
    reused = bool(out_dir and pathlib.Path(out_dir).exists())
    if not reused:
        out_dir = _make_extract_dir()
        _EXTRACT_DIRS[software.sha256] = out_dir

    if is_disk_image:
        # Partition carving is pure-Python; OFRAK has no MBR/GPT unpacker.
        try:
            partitions = (
                _existing_partition_files(out_dir)
                if reused
                else _carve_partitions(filename, out_dir)
            )
        except Exception as exc:  # noqa: BLE001
            logger.opt(exception=True).error(f"Failed to carve partitions from {filename}: {exc}")
            return {
                _METADATA_KEY: {
                    "detectedFormats": supported,
                    "unpacked": False,
                    "error": str(exc),
                }
            }

        if not partitions:
            logger.warning(f"No partitions carved from disk image {filename}")
            return {_METADATA_KEY: {"detectedFormats": supported, "unpacked": False}}

        for part in partitions:
            context_queue.put(
                ContextEntry(
                    archive=filename,
                    installPrefix=install_prefix,
                    extractPaths=[part["path"]],
                    skipProcessingArchive=True,
                    omitUnrecognizedTypes=True,
                )
            )
        logger.info(
            f"Carved {len(partitions)} partition(s) from {supported} '{filename}' -> {out_dir}"
        )
        image_size = pathlib.Path(filename).stat().st_size
        covered = sum(int(p.get("length", 0)) for p in partitions)
        coverage_percent = round(covered / image_size * 100, 2) if image_size else None
        return {
            _METADATA_KEY: {
                "detectedFormats": supported,
                "unpacked": True,
                "extractPath": out_dir,
                "partitions": partitions,
                "imageSize": image_size,
                "coveragePercent": coverage_percent,
            }
        }

    # Filesystem/container formats require OFRAK.
    if not _ofrak_available():
        logger.warning(
            f"OFRAK is not installed; cannot unpack {supported} file {filename}. "
            "Install with 'pip install ofrak' to enable extraction."
        )
        return {_METADATA_KEY: {"detectedFormats": supported, "unpacked": False}}

    if reused:
        summary: dict[str, Any] = {"cached": True}
    else:
        try:
            summary = _unpack_fs_with_ofrak(filename, out_dir)
        except Exception as exc:  # noqa: BLE001 - surface OFRAK errors without crashing
            logger.opt(exception=True).error(f"OFRAK failed to unpack {filename}: {exc}")
            return {
                _METADATA_KEY: {
                    "detectedFormats": supported,
                    "unpacked": False,
                    "error": str(exc),
                }
            }

    context_queue.put(
        ContextEntry(
            archive=filename,
            installPrefix=install_prefix,
            extractPaths=[out_dir],
            skipProcessingArchive=True,
            omitUnrecognizedTypes=True,
        )
    )
    logger.info(f"OFRAK unpacked {supported} '{filename}' -> {out_dir}")

    return {
        _METADATA_KEY: {
            "detectedFormats": supported,
            "unpacked": True,
            "extractPath": out_dir,
            **summary,
        }
    }


@surfactant.plugin.hookimpl
def short_name() -> str:
    return "ofrak_unpacker"


@surfactant.plugin.hookimpl
def settings_name() -> str:
    return _SETTINGS_SECTION


@surfactant.plugin.hookimpl
def init_hook(command_name: str | None = None) -> None:
    """Warn once about missing OFRAK dependencies before extraction runs.

    Only the ``generate`` command performs extraction, so the checks are skipped
    for unrelated commands to avoid spurious warnings.
    """
    if command_name not in (None, "generate"):
        return

    if not _ofrak_available():
        logger.warning(
            "ofrak_unpacker: OFRAK is not installed; firmware/container formats "
            "will still be identified but cannot be unpacked. Install with "
            "'pip install ofrak' to enable extraction."
        )
        return

    missing = [
        f"{tool} [{fmt}] (install: {hint})"
        for tool, (fmt, hint) in _EXTERNAL_TOOLS.items()
        if shutil.which(tool) is None
    ]
    missing += [
        f"{module} [{fmt}] (install: {hint})"
        for module, (fmt, hint) in _PYTHON_DEPS.items()
        if importlib.util.find_spec(module) is None
    ]
    if missing:
        logger.warning(
            "ofrak_unpacker: the following OFRAK unpacking dependencies were not "
            "found; the corresponding formats cannot be extracted: " + ", ".join(missing)
        )
    else:
        logger.info("ofrak_unpacker: OFRAK and all checked unpacking dependencies are available.")
