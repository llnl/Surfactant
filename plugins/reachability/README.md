# Import Reachability Plugin for SBOM Surfactant

A plugin for Surfactant that checks the reachability of imported functions within exported functions to narrow down reachable code and reduse the amount of deadcode analysts are having to view.

## Quickstart

To install this plugin within the same virtual environment as Surfactant, use the command `pip install .`.

For developers modifying the plugin, the editable installation can be achieved with `pip install -e .`.

After installing the plugin, run Surfactant to generate an SBOM as usual and entries for ELF
and PE files will contain a metadata object with the information that checksec.py was able
to get about security related features.

After the plugin installation, run Surfactant as you normally would to create an SBOM. For binary files analyzed by this plugin, additional JSON files will be generated containing vulnerability data extracted from the binaries. If there are duplicate hashed files, the extractor will check if they have the exported functions entries and skip remaking the output file if so.

Example:
Output Filename: `reachability.json`

```json
{
  "filename": {
    "exp_func": {
      "library": [
        "imp_func1",
        "imp_func2"
      ]
    }
  }
}
```

The plugin's functionality can be toggled via Surfactant's plugin management features, using the plugin name `surfactantplugin_reachability.py` as defined in the `pyproject.toml` under the `project.entry-points."surfactant"` section.

## Uninstalling

Remove the plugin from your environment with `pip uninstall surfactantplugin_reachability`.

## Important Licensing Information
Main Project License (Surfactant): MIT License.

Plugin License: MIT License, but it includes and uses cve-bin-tool, which is GPL-3.0 licensed.
