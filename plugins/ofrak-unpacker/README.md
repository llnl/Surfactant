# surfactantplugin-ofrak-unpacker

A Surfactant plugin that unpacks **non-native firmware and embedded container
formats** using [OFRAK](https://ofrak.com/), then hands the extracted artifacts
back to Surfactant so the rest of the plugin pipeline (ELF/PE extractors,
checksec, `angr-expanded`, relationship builders, ...) analyzes them.

## Why

Surfactant already decompresses common archives (ZIP, TAR, GZIP, BZIP2, XZ, RAR)
via its built-in `file_decompression` extractor. Firmware images, however, use
container formats that Surfactant does not handle natively. OFRAK knows how to
unpack these, so this plugin bridges the two.

This plugin **only unpacks** — it does not analyze the contents. It unpacks the
container to a temporary directory and pushes a `ContextEntry` onto Surfactant's
`context_queue`, which causes every other extractor to run on the extracted
files automatically. Container provenance (`archive`, `installPrefix`) is
preserved so `Contains` relationships and install paths appear in the SBOM.

## Supported formats

Detected by magic bytes in `identify_file_type`:

| Label         | Format                                | Magic offset |
| ------------- | ------------------------------------- | ------------ |
| `SQUASHFS`    | SquashFS filesystem                   | `0x0`        |
| `CRAMFS`      | CramFS filesystem                     | `0x0`        |
| `JFFS2`       | JFFS2 filesystem                      | `0x0`        |
| `UBI`         | UBI volume                            | `0x0`        |
| `UBIFS`       | UBIFS filesystem                      | `0x0`        |
| `EXT`         | ext2/3/4 filesystem                   | `0x438`      |
| `YAFFS`       | YAFFS2 filesystem                     | `0x0`        |
| `ISO9660`     | ISO 9660 disc image                   | `0x8001`     |
| `UIMAGE`      | U-Boot legacy uImage                  | `0x0`        |
| `OPENWRT_TRX` | OpenWrt TRX firmware container        | `0x0`        |
| `UEFI`        | UEFI firmware volume                  | `0x28`       |
| `CPIO`        | CPIO archive (initramfs, etc.)        | `0x0`        |
| `SEVENZIP`    | 7-Zip archive                         | `0x0`        |
| `UF2`         | UF2 flashing image                    | `0x0`        |
| `ZSTD`        | Zstandard-compressed stream           | `0x0`        |
| `LZOP`        | lzop (`.lzo`) compressed stream       | `0x0`        |
| `IHEX`        | Intel HEX                             | (text scan) |
| `DISK_IMAGE`  | MBR-partitioned disk image            | `0x1FE`      |
| `GPT`         | GPT-partitioned disk image            | `0x200`      |

## How it works

1. `identify_file_type` tags the file with one of the labels above.
2. `extract_file_info` runs OFRAK (`unpack_recursively`), flushing recovered
   filesystem trees (or leaf resources) into a temporary directory.
3. A `ContextEntry(archive=<file>, extractPaths=[<temp dir>],
   skipProcessingArchive=True)` is queued so Surfactant re-processes the
   extracted files with all extractors.
4. Metadata about the unpacking is added to the archive's software entry under
   the `ofrakUnpacker` key.

## Metadata

```json
{
  "ofrakUnpacker": {
    "detectedFormats": ["SQUASHFS"],
    "unpacked": true,
    "extractPath": "/tmp/surfactant-ofrak-xxxx",
    "extractedFileCount": 128,
    "resourceTags": ["File", "Folder", "SquashfsFilesystem"]
  }
}
```

If OFRAK is not installed, the entry records `"unpacked": false` and unpacking is
skipped (file-type identification still happens).

## Installation

OFRAK is an **optional** dependency because it is large and relies on external
unpacker tooling. Install the plugin, then OFRAK separately if you want
extraction:

```bash
# Enable extraction (heavy; may require system tools / Docker image deps):
pip install ofrak
# Once installed you must specify the license being used (community or pro)
ofrak license
```

## Configuration

| Section          | Key           | Default        | Meaning                                  |
| ---------------- | ------------- | -------------- | ---------------------------------------- |
| `ofrak_unpacker` | `extract_dir` | system tempdir | Base directory for extraction scratch    |

## Notes / caveats

- OFRAK is asyncio-based; the plugin wraps the async work internally.
- OFRAK relies on external unpackers for many formats (often provided via its
  Docker image). Those must be present in the environment for extraction to
  succeed.
- Extractions are cached by SHA-256, and temp directories are cleaned up at exit.
