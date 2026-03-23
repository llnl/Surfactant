# QilingExec Plugin for SBOM Surfactant

A plugin for Surfactant that uses [Qiling](https://github.com/qilingframework/qiling) to identify software packages from executable binary files by running any binaries found under Qiling.

## Overview

The QilingExec plugin enhances Surfactant's SBOM generation by identifying which version number and package name are associated with a given

## Features

- **Executable-level package detection**: Determines the package name and version from output to `stdout` when executed

## Prerequisites

### Install QilingExec and 



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

The plugin adds package information to the metadata field of software entries in the SBOM. For each binary file, it provides:

```json
{
   "dapper_packages": [
            {
              "package_name": "libssl3",
              "package_dataset": "ubuntu-jammy",
              "original_name": "libssl.so.3",
              "file_path": "usr/lib/x86_64-linux-gnu/libssl.so.3",
              "normalized_name": "libssl.so",
              "version": null,
              "soabi": "3"
            },
            {
              "package_name": "libssl3t64",
              "package_dataset": "ubuntu-noble",
              "original_name": "libssl.so.3",
              "file_path": "usr/lib/x86_64-linux-gnu/libssl.so.3",
              "normalized_name": "libssl.so",
              "version": null,
              "soabi": "3"
            }
          ]
}
```

### Key Fields

- **package_name**: Short package name (e.g., "libssl3")
- **full_package_name**: Complete package identifier with version
- **package_dataset**: Source dataset/distribution
- **normalized_name**: Normalized filename used for matching
- **original_output**: Original output of running `<executable> --version` as found
- **file_path**: Installation path within the package

## Configuration

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
- **PE files** (Windows binaries): `.dll`, `.exe`, `.sys` (pending NuGet dataset availability)


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
