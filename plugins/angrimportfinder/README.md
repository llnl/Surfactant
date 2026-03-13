# Imported and Exported function name extractor Plugin for SBOM Surfactant

A plugin for Surfactant that uses the [angr](https://github.com/angr/angr)
Python library to extract the imported and exported function names from ELF and PE files.

## Quickstart

In the same virtual environment that Surfactant was installed in, install this plugin with `pip install .`.

For developers making changes to this plugin, install it with `pip install -e .`.

After installing the plugin, run Surfactant to generate an SBOM as usual and entries for ELF
and PE files will generate additional json files in the working directory that contain the list of imported and exported functions in the executable files.
If there are duplicate hashed files the extractor will skip the entry.
Example:

`Output Filename: $(sha256hash)_additional_metadata.json`

```json
{
  "sha256hash": "",
  "filename": [],
  "imported function names": [],
  "exported function names": []
}
```

Surfactant features for controlling which plugins are enabled/disabled can be used to control
whether or not this plugin will run using the plugin name `surfactantplugin_angrimportfinder.py` (the name given in
`pyproject.toml` under the `project.entry-points."surfactant"` section).

## Uninstalling

The plugin can be uninstalled with `pip uninstall surfactantplugin_angrimportfinder.py`.
