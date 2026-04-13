# QilingExec Plugin for SBOM Surfactant

A plugin for Surfactant that uses [Qiling](https://github.com/qilingframework/qiling) to identify software packages from executable binary files by running any binaries found under Qiling. By default, this plugin expects to load libraries from your system and that the python environment running this plugin to have an OS and Architecture matching that of the executables being emulated. Do not use this plugin on binaries you do not trust.

## Overview

The QilingExec plugin enhances Surfactant's SBOM generation by identifying which version number and package name are associated with a given

## Features

- **Executable-level package detection**: Determines the package name and version from output to `stdout` when executed

## Installation

In the same virtual environment that Surfactant was installed in, install this plugin:

```bash
# From PyPI (when available)
pip install surfactantplugin-qilingexec

# From GitHub
pip install git+https://github.com/LLNL/Surfactant#subdirectory=plugins/qilingexec

# For developers making changes to this plugin
git clone https://github.com/LLNL/Surfactant.git
cd Surfactant/plugins/qilingexec
pip install -e .
```


## Output Format

The plugin adds version information and the 1st line of stdout from running the executable to the metadata field of software entries in the SBOM. For each binary file, it provides:

```json
{
   "qilingexec": {
      "stdout": "GNU ld (GNU Binutils for Ubuntu) 2.38",
      "version": "2.38",
      "help_stdout": [
        "Usage: /usr/bin/ld [options] file...",
        "Options:",
        "  -a KEYWORD                  Shared library control for HP/UX compatibility",
        "  -A ARCH, --architecture ARCH",
        "                              Set architecture",
        "  -b TARGET, --format TARGET  Specify target for following input files",
        "  -c FILE, --mri-script FILE  Read MRI format linker script",
        "  -d, -dc, -dp                Force common symbols to be defined",
        "  --dependency-file FILE      Write dependency file",
        "  --force-group-allocation    Force group members out of groups"
      ]
    }
}
```

### Key Fields

- **stdout**: 1st line of text sent to stdout
- **version**: Identified version number

## Configuration

### Context File

Here is a basic example context file:
```json
[
  {
    "extractPaths": [
      "/usr/bin/ld"
    ],
    "pluginConf": {
      "surfactantplugin_qilingexec": {
        "mount_prefix": "/"
      }
    }
  }
]
```

#### Key Fields

- **mount_prefix**: Base folder to look for libraries from. If using Surfactant on an extracted filesystem please specify the equivalent of the `/` or `C:\` folders.
- **arch_type**: ISA of the executable. By default, this is set to x86_64.
- **os_type**: What type of Operating System does the executable run under? By default, this is set to Linux.
- **timeout**: How long (in microseconds) should executables be given to run before timing out? By default, this is set to 150000 or 15/100th of a second. Sometimes executables need longer to load their libraries into memory and begin execution. If you are running into issues (i.e. Invalid memory fetches), this is a good field to play with.
- **regex**: Regular expression to match against when searching through the output of `--version` and other options.

### Enabling/Disabling

The plugin can be controlled using Surfactant's plugin management features with the plugin name `surfactantplugin_qilingexec` (defined in `pyproject.toml`).

```bash
# Disable the plugin
surfactant plugin disable surfactantplugin_qilingexec

# Enable the plugin
surfactant plugin enable surfactantplugin_qilingexec
```


## Supported File Types

Currently supported:
- **ELF files** (Linux binaries): `.o`, and extensionless executables

Planned support:
- **PE files** (Windows binaries): `.dll`, `.exe`, `.sys`


## Uninstalling

Remove the plugin with:
```bash
pip uninstall surfactantplugin-qilingexec
```

If pipx was used:
```bash
pipx uninject surfactant surfactantplugin-qilingexec
```

## Important Licensing Information
Main Project License (Surfactant): MIT License.

Plugin License: MIT License, but it includes and uses qiling, which is GPL-2.0+ licensed.

## Additional Resources
- [Qiling installation instructions](https://docs.qiling.io/en/latest/install/)
- [Qiling Documentation](https://docs.qiling.io/en/latest/)
- [Qiling GitHub Repository](https://github.com/qilingframework/qiling/)
- [Surfactant Documentation](https://surfactant.readthedocs.io)
