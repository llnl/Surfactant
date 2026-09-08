# surfactantplugin-binaryninja-info

A Surfactant plugin that uses **Binary Ninja** for lightweight *control-flow
graph* extraction and embeds the results into the generated SBOM under the
`binaryNinja` metadata key.

It is designed to be **complementary** to the `angr_expanded` plugin, not
overlapping. Each tool focuses on what it does best:

| Concern | Owned by | Why |
|---------|----------|-----|
| Loader/architecture, PIC, sections | `angr_expanded` (angr/CLE) | angr's loader is fast and authoritative |
| Imported/exported symbols | `angr_expanded` | drives dependency resolution |
| Import → library resolution, `Uses` relationships | `angr_expanded` | CLE resolves providers |
| Minimum library versions (CVE matching) | `angr_expanded` | pyelftools version-needs |
| **Function inventory (accurate recovery)** | **`binaryninja_info`** | BN recovers more/cleaner functions on stripped code |
| **Per-function control-flow graph (blocks + edges)** | **`binaryninja_info`** | BN's CFG recovery is high fidelity and cheap in `controlFlow` mode |

The binary is always loaded in Binary Ninja's **`controlFlow`** analysis mode, so
only function and basic-block recovery runs — the heavier data-flow / IL /
decompilation passes are skipped. This keeps the plugin fast and its output
scoped to the one thing Binary Ninja does best.

## Metadata schema (`binaryNinja`)

```jsonc
{
  "coreVersion": "5.3.9757",
  "platform": "linux-aarch64",   // BN OS/ABI concept (arch/endianness/entryPoint
                                  // are owned by angrExpanded, not repeated here)
  "functionCount": 1234,          // over ALL functions
  "basicBlockCount": 9876,
  "instructionCount": 54321,
  "thunkCount": 42,
  "emittedFunctionCount": 611,    // functions actually in functions[] (post-filter)
  "controlFlowTruncated": false,  // true if functions[] was capped by max_functions
  "functions": [                  // capped at max_functions; excludes thunks,
                                  // clones, library funcs, and < min_basic_blocks
    {
      "name": "main",
      "address": "0x...",
      "basicBlockCount": 12,
      "instructionCount": 130,
      "isThunk": false,
      "basicBlocks": [            // structure only, no disassembly text
        {"start": "0x...", "end": "0x...", "instructionCount": 8,
         "edges": [{"target": "0x...", "type": "TrueBranch"},
                   {"target": "0x...", "type": "FalseBranch"}]}
      ]
    }
  ]
}
```

## Settings

Read via Surfactant's `ConfigManager`, section `binary_ninja`:

| Key | Default | Effect |
|-----|---------|--------|
| `max_functions` | `5000` | Cap on emitted `functions[]` / analyzed-function count |
| `min_basic_blocks` | `2` | Minimum blocks for a function to appear in `functions[]`; set to `1` to emit every function (incl. straight-line stubs) |
| `exclude_library_functions` | `true` | Drop C++ runtime/library functions (`std::`, `__gnu_cxx::`, `fmt::`, `spdlog::`, `cxxopts::`, `nlohmann::`) from `functions[]`; set to `false` to include them |

Aggregate statistics (`functionCount`, etc.) are always computed over **all**
functions regardless of `max_functions`, `min_basic_blocks`, and
`exclude_library_functions`. To cut bloat, the emitted `functions[]` CFG excludes
thunks, functions with no real control flow (fewer than `min_basic_blocks` basic
blocks), compiler-generated clones (`.cold`/`.isra`/`.constprop`/`.part`), and —
unless disabled — C++ runtime/library functions matched by mangled or demangled
name prefix. Those stubs and library internals otherwise dominate the output.

## How it works

1. `supports_file` limits analysis to `ELF`, `PE`, `MACHO`, `MACHOFAT`. For ELF,
   an additional `e_type` check restricts analysis to **true loadable
   executables** — `ET_EXEC` and `ET_DYN` (shared objects / PIE) — and
   **excludes** `ET_REL` relocatable objects, which is what Linux kernel modules
   (`.ko`) and `.o` files are, as well as core dumps.
2. Binary Ninja is imported **lazily**. If the API is not importable (not on
   `sys.path`, unlicensed, etc.) the plugin logs a warning and skips — SBOM
   generation is never blocked.
3. `binaryninja.load(path, options={"analysis.mode": "controlFlow"})` produces
   the `BinaryView`. The plugin walks `view.functions` once to build the
   aggregate stats and the filtered per-function CFG.

## Environment

The Binary Ninja Python API and a valid license must be available to the Python
interpreter running Surfactant. Typical options:

- Run Binary Ninja's `scripts/install_api.py` once to drop a `.pth` into the
  active environment, **or**
- Add the API directory to `PYTHONPATH` (e.g.
  `.../binaryninja/python`).

No environment setup is performed by this plugin.
