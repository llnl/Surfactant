# surfactant-plugin-binwalk-carver

A vendor-agnostic Surfactant plugin that uses [binwalk](https://github.com/ReFirmLabs/binwalk)
to carve embedded regions out of a file and feed each one back into the Surfactant
processing pipeline.

## Why

Surfactant's built-in decompressor and the OFRAK unpacker only recognize a format
when its magic bytes sit at a **fixed offset** (usually 0). Real firmware images
are frequently proprietary outer containers -- vendor headers, padding, and
concatenated blobs -- that wrap standard artifacts (an LZMA kernel, a
SquashFS/JFFS2/UBIFS root filesystem, etc.) at **arbitrary, non-zero offsets**. A
filesystem that starts partway into the image is therefore never seen.

For example, a TP-Link OpenWrt `factory.bin` starts with a TP-Link header at
offset 0 and places the SquashFS root filesystem at offset `0x1102FC`. Nothing in
the default pipeline detects it.

## What it does

1. Runs a `binwalk` signature scan (JSON output, no extraction) on each file.
2. Turns every region binwalk recognizes at a **non-zero offset** into a concrete
   byte range.
3. Carves each such region into a standalone file in a temp directory.
4. Pushes a `ContextEntry` for each carved file onto Surfactant's `context_queue`.

Each carved region then re-enters the **entire** plugin pipeline. Because its
magic now sits at offset 0 of the carved file, the native extractors, the
file-decompression plugin, and the OFRAK unpacker identify and process it exactly
as they would a stand-alone artifact.

The plugin only *carves*; it never analyzes contents itself and does not use
binwalk's own extraction (`-e`). **OFRAK (`ofrak_unpacker`) and the built-in
decompressor are the primary extractors** — this plugin exists only to expose the
embedded artifacts they cannot see because those artifacts don't start at offset 0.

### Scope / duplication safety

- **Only non-zero-offset regions are carved.** Anything whose magic is at offset
  0 is already visible to OFRAK and the native identifiers, so it is left to them
  — this is what keeps the carver from duplicating OFRAK's work or re-copying a
  carved filesystem forever.
- **Files Surfactant analyzes natively are skipped** (`ELF`, `PE`, `MACHO32`,
  `MACHO64`, `MACHOFAT`). Carving a standalone executable only produces truncated,
  unparseable fragments; the carver is meant for outer firmware images.
- **ELF signatures are never carved**, even inside an image — the filesystem
  unpacker recovers the ELF and it is then analyzed directly.
- Results are de-duplicated by SHA-256, so identical bytes are only carved once.
- Files already being processed as a container's contents are skipped.

## Requirements

- The `binwalk` executable must be on `PATH`. If it is missing, the plugin logs a
  warning once and does nothing (SBOM generation still succeeds).
- Install binwalk via `cargo install binwalk` (v3, Rust) or `pip install binwalk`.

## Install

```bash
pip install -e plugins/binwalk-carver
```

## Configuration

Settings live under the `[binwalk_carver]` section of the Surfactant config
(`surfactant config` / `~/.config/surfactant/config.toml`):

| Key | Default | Description |
| --- | --- | --- |
| `binwalk_path` | `binwalk` | Name or path of the binwalk executable. |
| `extract_dir` | system temp | Base directory for carved output. |
| `min_file_size` | `4096` | Files smaller than this are not scanned. |
| `min_carve_size` | `512` | Regions smaller than this are not carved. |
| `search_all` | `false` | Pass `-a` to binwalk (search all signatures at all offsets). |
| `exclude_signatures` | `[]` | binwalk signature names to skip (passed as `-x`). |
| `timeout` | `300` | Per-file binwalk timeout, in seconds. |

## Usage

Once installed it runs automatically during `surfactant generate`:

```bash
surfactant generate firmware.bin out.json
```
