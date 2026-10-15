# surfactantplugin-binaryninja-info

A Surfactant plugin that uses **Binary Ninja** to recover function structure,
rank likely points of interest, and embed the results into the generated SBOM
under the `binaryNinja` metadata key.

It is designed to be **complementary** to the `angr_expanded` plugin, not
overlapping. Each tool focuses on what it does best:

| Concern | Owned by | Why |
|---------|----------|-----|
| Loader/architecture, PIC, sections | `angr_expanded` (angr/CLE) | angr's loader is fast and authoritative |
| Imported/exported symbols | `angr_expanded` | drives dependency resolution |
| Import → library resolution, `Uses` relationships | `angr_expanded` | CLE resolves providers |
| Minimum library versions (CVE matching) | `angr_expanded` | pyelftools version-needs |
| **POI candidate ranking for triage** | **`binaryninja_info`** | BN recovers enough structural context to score interesting functions cheaply |
| **Optional per-function CFG (blocks + edges)** | **`binaryninja_info`** | Available when you explicitly switch to `full_cfg` output |

The binary is always loaded in Binary Ninja's **`controlFlow`** analysis mode, so
only function and basic-block recovery runs — the heavier data-flow / IL /
decompilation passes are skipped. By default, that recovered structure is used
to produce a compact, score-ranked POI list for fast triage. A fuller per-
function CFG dump is still available as an opt-in profile when you need it.

## Metadata schema (`binaryNinja`)

The default output profile is `poi_fast`:

```jsonc
{
  "coreVersion": "5.3.9757",
  "platform": "linux-aarch64",   // BN OS/ABI concept (arch/endianness/entryPoint
                                  // are owned by angrExpanded, not repeated here)
  "outputProfile": "poi_fast",
  "functionCount": 1234,          // over ALL functions
  "basicBlockCount": 9876,
  "instructionCount": 54321,
  "thunkCount": 42,
  "emittedFunctionCount": 50,     // POIs actually emitted in poiCandidates[]
  "controlFlowTruncated": true,   // true if scored candidates exceeded poi_count
  "poiScoringVersion": "1",
  "poiCandidateCount": 187,
  "poiCandidates": [              // score-ranked, filtered POI list
    {
      "name": "verify_firmware_signature",
      "address": "0x...",
      "score": 6.45,
      "reasons": ["keyword_match:firmware|verify|signature", "many_callers"],
      "metrics": {
        "instructionCount": 130,
        "basicBlockCount": 12,
        "outgoingEdgeCount": 18,
        "callerCount": 9,
        "calleeCount": 6
      }
    }
  ]
}
```

If you set `output_profile = full_cfg`, the plugin emits `functions[]` instead
of `poiCandidates[]`, containing the per-function basic-block and edge list.

## Settings

Read via Surfactant's `ConfigManager`, section `binary_ninja`:

| Key | Default | Effect |
|-----|---------|--------|
| `output_profile` | `poi_fast` | Default compact POI output; set to `full_cfg` for per-function CFG export |
| `poi_count` | `50` | Maximum number of POI candidates emitted in `poiCandidates[]` |
| `poi_min_score` | `1.0` | Minimum score a function must reach to be emitted as a POI |
| `poi_keywords` | built-in list | Comma-separated keyword overrides used to boost semantically-interesting function names |
| `min_basic_blocks` | `2` | Minimum blocks for a function to be considered for POI emission or `functions[]`; set to `1` to include straight-line stubs |
| `exclude_library_functions` | `true` | Drop C++ runtime/library functions (`std::`, `__gnu_cxx::`, `fmt::`, `spdlog::`, `cxxopts::`, `nlohmann::`) from emitted POIs / CFG records |
| `max_functions` | `5000` | Cap on emitted `functions[]` when `output_profile = full_cfg` |

Aggregate statistics (`functionCount`, etc.) are always computed over **all**
functions regardless of profile-specific emission limits and filters. To keep
the output focused, emitted POIs and CFG records exclude thunks, functions with
no real control flow (fewer than `min_basic_blocks` basic blocks), compiler-
generated clones (`.cold`/`.isra`/`.constprop`/`.part`), and — unless disabled —
C++ runtime/library functions matched by mangled or demangled name prefix.

The `poi_fast` scorer uses a lightweight combination of structural signals and
name heuristics, including:

- instruction count and basic-block count
- CFG edge density
- caller and callee counts
- keyword matches in recovered function names

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
  the `BinaryView`. The plugin walks `view.functions` once to build aggregate
  stats and then either:

  - scores and ranks compact POI candidates for `poi_fast`, or
  - emits the filtered per-function CFG for `full_cfg`.

## Environment

The Binary Ninja Python API and a valid license must be available to the Python
interpreter running Surfactant. Typical options:

- Run Binary Ninja's `scripts/install_api.py` once to drop a `.pth` into the
  active environment, **or**
- Add the API directory to `PYTHONPATH` (e.g.
  `.../binaryninja/python`).

No environment setup is performed by this plugin.
