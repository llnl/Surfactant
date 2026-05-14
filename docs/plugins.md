# Plugins

The surfactant plugin system uses the [pluggy](https://pluggy.readthedocs.io/en/stable) module. This module is used by projects such as pytest and tox for their plugin systems; installing and writing plugins for surfactant is a similar to using plugins for those projects. Most of the core surfactant functionality is also implemented as plugins (see [surfactant/output](https://github.com/LLNL/Surfactant/tree/main/surfactant/output), [surfactant/infoextractors](https://github.com/LLNL/Surfactant/tree/main/surfactant/infoextractors), [surfactant/filetypeid](https://github.com/LLNL/Surfactant/tree/main/surfactant/filetypeid), and [surfactant/relationships](https://github.com/LLNL/Surfactant/tree/main/surfactant/relationships)).

## Managing Plugins

Surfactant provides several subcommands for managing plugins:

### List Plugins

View all installed plugins and their status:
```bash
surfactant plugin list
```

### Install Plugin

Install a plugin from a local path or PyPI:
```bash
surfactant plugin install <plugin_name_or_path>
```

### Uninstall Plugin

Remove an installed plugin:
```bash
surfactant plugin uninstall <plugin_name>
```

### Enable/Disable Plugins

Temporarily enable or disable plugins without uninstalling them:
```bash
surfactant plugin enable <plugin_name>
surfactant plugin disable <plugin_name>
```

### Update Plugin Database

Some plugins maintain pattern databases that need to be kept up-to-date. Update the database for a specific plugin or all plugins:
```bash
# Update a specific plugin's database
surfactant plugin update-db <plugin_name>

# Update all plugin databases
surfactant plugin update-db --all

# Force update regardless of whether upstream has changed
surfactant plugin update-db <plugin_name> --force
surfactant plugin update-db --all --force
```

The `--force` option bypasses the check for whether the upstream database has changed and forces a re-download and update. This is useful when you need to ensure the latest database is installed or when troubleshooting database-related issues.

## Creating a Plugin

### Step 1: Write Plugin

In order to create a plugin, you will need to write your implementation for one or more of the functions in the [hookspecs.py](https://github.com/LLNL/Surfactant/tree/main/surfactant/plugin/hookspecs.py) file. Which functions you implement will depend on the goals of your plugin.

#### Brief overview of functions
[identify_file_type](https://github.com/LLNL/Surfactant/tree/main/surfactant/plugin/hookspecs.py#L18)
- Return a string or list of strings representing the type of file passed in

[extract_file_info](https://github.com/LLNL/Surfactant/tree/main/surfactant/plugin/hookspecs.py#L40)
- Determine how file info is supposed to be extracted and return a metadata object for the software entry

[establish_relationships](https://github.com/LLNL/Surfactant/tree/main/surfactant/plugin/hookspecs.py#L88)
- Determines how to establish relationships between the software/metadata that has been passed to it

[write_sbom](https://github.com/LLNL/Surfactant/tree/main/surfactant/plugin/hookspecs.py#L111)
- Determine what format to write the SBOM to file

[read_sbom](https://github.com/LLNL/Surfactant/tree/main/surfactant/plugin/hookspecs.py#L122)
- If reading from input SBOMs, specifies what format the input SBOMs are

### Step 2. Write pyproject.toml File

Once you have written your plugin, you will need to write a pyproject.toml file. Include any relevant project metadata/dependencies for your plugin, as well as an entry-point specification (example below) to make the plugin discoverable by surfactant. Once you write your .toml file, you can `surfactant plugin install <path to plugin's folder>` to install your plugin. Alternatively, you can `pip install <path to plugin's folder>` your plugin.

More information on entry points can be found [here](https://setuptools.pypa.io/en/latest/userguide/entry_point.html#entry-points-syntax)

#### Example

#### sampleplugin.py
```python
import surfactant.plugin
from surfactant.sbomtypes import SBOM

@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
  outfile.write(sbom.to_json(indent=10))
```
#### pyproject.toml
```toml
... generic pyproject info ...
[project.entry-points."surfactant"]
sampleplugin = "sampleplugin"
```
Run `surfactant plugin install <path to plugin's folder>` to install the plugin. Surfactant will automatically load and use the plugin. Alternatively, from the same folder as your sampleplugin files, run `pip install .`.

Consider uploading your plugin to PyPI for easy sharing and to enable installation using the PyPI package name of the plugin. If the package is on PyPI, run `surfactant plugin install <plugin name>`.

Another example can be found in the [plugins/checksec.py](https://github.com/LLNL/Surfactant/tree/main/plugins/checksec.py) folder. There you can see the [pyproject.toml](https://github.com/LLNL/Surfactant/tree/main/plugins/checksec.py/pyproject.toml) file with the `[project.entry-points."surfactant"]` entry. In the [surfactantplugin_checksec.py](https://github.com/LLNL/Surfactant/tree/main/plugins/checksec.py/surfactantplugin_checksec.py) file, you can identify the hooked functions with the `@surfactant.plugin.hookimpl` hook.
