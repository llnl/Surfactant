# angr-expanded — Expanded angr Binary Analysis Plugin for Surfactant

A Surfactant plugin that uses the [angr](https://github.com/angr/angr) binary
analysis framework to extract **expanded** metadata from ELF, PE, and Mach-O
binaries and embed it **directly into the generated SBOM** (not in a separate
side-car file).

Where the original `angrimportfinder` plugin only records imported/exported
function names (to an external JSON file), this plugin adds a richer
`angrExpanded` metadata object to each software entry.

## What information it adds

All data is stored on the software entry's metadata under the `angrExpanded` key:

- **Loader / architecture facts** (cheap, always collected)
  - `arch`, `bits`, `endianness`
  - `entryPoint`, `imageBase`, `mappedBase`, `minAddr`, `maxAddr`
  - `positionIndependent` (PIE/PIC), `executableStack`, `relocatable`
  - `linkingType`, `staticallyLinked`, `objectFormat`
  - `linkedLibraries` — direct shared-library dependencies from the loader
- **Symbols with import→library resolution**
  - `importedFunctions` — each with `name`, providing `library` (populated for PE
    imports; ELF imports resolve at runtime), and `isFunction`
  - `exportedFunctions` — each with `name`, `address`, `isFunction`
  - `importedFunctionCount`, `exportedFunctionCount`
- **Minimum library versions** (ELF, cheap)
  - `minimumLibraryVersions` — per needed library, the highest required version
    per prefix (e.g. `{"libc.so.6": {"GLIBC": "2.34"}}`). This is the *minimum*
    library version the binary can run against, derived from the `.gnu.version_r`
    section. Useful for dependency resolution and narrowing CVE/version matching.
  - `symbolVersionNeeds` — the full list of versioned symbol tags per library
- **Section map** (non-ELF only)
  - `sections` — `name`, `vaddr`, `size`, and `isExecutable`/`isWritable`/`isReadable`.
    Emitted for **PE and Mach-O** only; ELF section data is already produced by
    Surfactant's built-in `elf_file` extractor, so it is not duplicated here.

## Relationships

The plugin also implements `establish_relationships`. After metadata is gathered,
it links each binary's **imported functions** to other SBOM entries that **export**
those functions, emitting `Uses` relationships. When the importer records
`linkedLibraries`, matches are restricted to exporters whose file name matches one
of those libraries to keep the edges high-confidence.

### Example SBOM metadata

```json
{
  "angrExpanded": {
    "arch": "AMD64",
    "bits": 64,
    "endianness": "little",
    "entryPoint": "0x401660",
    "imageBase": "0x400000",
    "positionIndependent": false,
    "executableStack": false,
    "staticallyLinked": false,
    "linkedLibraries": ["libc.so.6"],
    "importedFunctions": [
      {"name": "printf", "library": null, "isFunction": true}
    ],
    "exportedFunctions": [],
    "importedFunctionCount": 1,
    "exportedFunctionCount": 0,
    "sections": [
      {"name": ".text", "vaddr": "0x401000", "size": 1234, "isExecutable": true,
       "isWritable": false, "isReadable": true}
    ]
  }
}
```

> Note: `sections` is present for PE and Mach-O only. For ELF binaries, section
> data comes from Surfactant's built-in `elf_file` extractor instead.

## Quickstart

In the same virtual environment that Surfactant is installed in:

```bash
cd plugins/angr-expanded
pip install .          # or: surfactant plugin install .
```

For development (editable install):

```bash
pip install -e .
```

Then generate an SBOM as usual; ELF/PE/Mach-O entries will include the
`angrExpanded` metadata:

```bash
surfactant plugin list          # confirm "angr_expanded" is enabled
surfactant generate config.json out.json
```

## Enable / disable the whole plugin

The plugin registers with the short name `angr_expanded`:

```bash
surfactant plugin disable angr_expanded
surfactant plugin enable angr_expanded
```

## Uninstalling

```bash
pip uninstall surfactantplugin-angr-expanded
```
