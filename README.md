<p align="center">
<picture>
<source srcset="https://user-images.githubusercontent.com/3969255/290751328-fe11d1de-c2a9-4602-a7cd-b0e34bfce728.png#gh-dark-mode-only" media="(prefers-color-scheme: dark)" width="250" alt="Blue magnifying glass Surfactant logo">
<img src="https://user-images.githubusercontent.com/3969255/290751330-77003e89-944a-4269-9821-843abe35fe4a.png#gh-light-mode-only" width="250" alt="Blue magnifying glass Surfactant logo">
</picture>
</p>

# Surfactant


A modular framework to gather file information for SBOM generation and dependency analysis.

[![CI Test Status](https://github.com/LLNL/Surfactant/actions/workflows/pytest.yml/badge.svg)](https://github.com/LLNL/Surfactant/actions/workflows/pytest.yml)
[![PyPI](https://img.shields.io/pypi/v/surfactant)](https://pypi.org/project/Surfactant/)
[![Python Versions](https://img.shields.io/pypi/pyversions/surfactant.svg)](https://pypi.org/project/Surfactant/)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/LLNL/Surfactant/blob/main/LICENSE)
[![Documentation Status](https://readthedocs.org/projects/surfactant/badge/?version=latest)](https://surfactant.readthedocs.io/en/latest/?badge=latest)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/LLNL/Surfactant/main.svg)](https://results.pre-commit.ci/latest/github/LLNL/Surfactant/main)

[Documentation](https://surfactant.readthedocs.io/en/latest/)

## Description

Surfactant can be used to gather information from a set of files to generate an SBOM, along with manipulating SBOMs and analyzing the information in them. It pulls information from recognized file types (such as PE, ELF, or MSI files) contained within a directory structure corresponding to an extracted software package. By default, the information is "surface-level" metadata contained in the files that does not require running the files
or decompilation.

## Installation

### For Users:

For ease of use, we recommend using [pipx](https://github.com/pypa/pipx) since it transparently handles creating and using Python virtual environments, which helps avoid dependency conflicts with other installed Python apps. Install `pipx` by following [their installation instructions](https://github.com/pypa/pipx#install-pipx).

1. Install Surfactant using `pipx install` (with python >= 3.10)

```bash
pipx install surfactant
```

> Note: Mach-O file support requires installing Surfactant with the `macho` optional dependencies, and Java file support requires installing with the `java` optional dependencies (e.g. `pipx install surfactant[macho,java]`).

2. Install plugins using `pipx inject surfactant`. As an example, this is how the fuzzy hashing plugin could be installed from a git repository (PyPI package names, local source directories, or wheel files can also be used).

```bash
pipx inject surfactant git+https://github.com/LLNL/Surfactant#subdirectory=plugins/fuzzyhashes
```

If for some reason manually managing virtual environments is desired, the following steps can be used instead:

1. Create a virtual environment with python >= 3.10 and activate it [Optional, but highly recommended over a global install]

```bash
python -m venv venv
source venv/bin/activate
```

2. Install Surfactant with `pip install`

```bash
pip install surfactant
```

3. Install plugins using `pip install`. As an example, this is how the fuzzy hashing plugin could be installed from a git repository (PyPI package names, local source directories, or wheel files can also be used).

```bash
pip install git+https://github.com/LLNL/Surfactant#subdirectory=plugins/fuzzyhashes
```

### For Developers:

1. Create a virtual environment with python >= 3.10 [Optional, but recommended]

```bash
python -m venv venv
source venv/bin/activate
```

2. Clone sbom-surfactant

```bash
git clone git@github.com:LLNL/Surfactant.git
```

3. Create an editable surfactant install (changes to code will take effect immediately):

```bash
pip install -e .
```

To install optional dependencies required for running pytest and pre-commit:

```bash
pip install -e ".[test,dev]"
```

`pip install` with the `-e` or `--editable` option can also be used to install Surfactant plugins for development.

```bash
pip install -e plugins/fuzzyhashes
```

## Quick Start: Generating an SBOM

Surfactant supports several subcommands that can be shown using `surfactant --help`. The main one for creating an SBOM is the `generate` subcommand, which takes the following arguments:

```bash
surfactant generate [OPTIONS] SPECIMEN_CONTEXT SBOM_OUTFILE [INPUT_SBOM]
```

The two required arguments are a specimen context, and the output SBOM file name. For a simple case of generating an SBOM for a single directory or file, it is enough to just use the path to the directory or file for the specimen configuration. For example, the following command will generate an SBOM file called `output.json` with software entries for all files found in the folder `mysoftware`:

```bash
surfactant generate /usr/local/mysoftware output.json
```

In the generated SBOM, there will be software entries for each file. The install paths captured will say where individual files are located within `/usr/local/mysoftware` -- if instead a relative path had been given such as `surfactant generate local/mysoftware output.json`, all of the install paths for files would appear to be under the relative path `local/mysoftware` instead of an absolute path.

For more control over the options used to create software entries and relationships, or for capturing information from multiple directories, see the following section on how to write a [Surfactant specimen context file](#build-context-file-for-sample). This context file is a JSON file can then be given to Surfactant for the `SPECIMEN_CONTEXT` argument.

NOTE: When using a Surfactant speciment context JSON file, it is recommended that it end in a `.json` file extension; otherwise, you'll have to use a special prefix (`context:`) for the `SPECIMEN_CONTEXT` argument to tell Surfactant that it should interpret the given file that doesn't end in `.json` as a specimen configuration file rather than to generate an SBOM that only contains details on that one file.

## Settings

Surfactant settings can be changed using the `surfactant config` subcommand, or by hand editing the settings configuration file (this is not the same as the JSON file used to configure settings for a particular sample that is described later). The [settings documentation page](https://surfactant.readthedocs.io/en/latest/settings.html) has a list of available options that are built-into Surfactant.

### Command Line

Using `surfactant config` is very similar to the basic use of `git config`. The key whose value is being accessed will be in the form `section.option` where `section` is typically a plugin name or `core`, and `option` is the option to set. As an example, the `core.author_name` and `core.author_type` options can be used to configure the author recorded in generated SBOMs.

Setting these options for LLNL as an organization could be done with the following commands:

```bash
surfactant config core.author_name LLNL
surfactant config core.author_type organization
```

Getting the currently set values for the options would then be done with:

```bash
surfactant config core.author_name
surfactant config core.author_type
```

Another example of a setting you might want to change is `docker.enable_docker_scout`, which controls whether Docker Scout is enabled. To disable Docker Scout (which also suppresses the warning message about installing Docker Scout), set this option to `false`:

```bash
surfactant config docker.enable_docker_scout false
```

### Manual Editing

If desired, the settings config file can also be manually edited. The location of the file will depend on your platform.
On Unix-like platforms (including macOS), the XDG directory specification is followed and settings will be stored in
`${XDG_CONFIG_HOME}/surfactant/config.toml`. If the `XDG_CONFIG_HOME` environment variable is not set, the location defaults
to `~/.config`. On Windows, the file is stored in the Roaming AppData folder at `%APPDATA%\\surfactant\\config.toml`.

The file itself is a TOML file, and for the previously mentioned author settings may look something like this:

```toml
[core]
author_name = "LLNL"
author_type = "organization"
```

## Usage

### Identify sample file

In order to test out surfactant, you will need a sample file/folder to generate an SBOM for. If you don't have one on hand, you can download and use the portable .zip file from <https://github.com/ShareX/ShareX/releases> or the Linux .tar.gz file from <https://github.com/GMLC-TDC/HELICS/releases>.

### Build context file for sample

A JSON context file for a sample contains the information about the sample to gather information from. Example JSON context files can be found in the examples folder of this repository.

- **extractPaths**: (required) the absolute path or relative path from location of current working directory that `surfactant` is being run from to the files or folders to gather information on. Note that even on Windows, Unix style `/` directory separators should be used in paths.
- **archive**: (optional) the full path, including file name, of the zip, exe installer, or other archive file that the files or folders in `extractPaths` were extracted from. This is used to collect metadata about the overall sample and will be added as a "Contains" relationship to all software entries found in the various `extractPaths`.
- **installPrefix**: (optional) where the files in `extractPaths` would be if installed correctly on an actual system i.e. "C:/", "C:/Program Files/", etc. Note that even on Windows, Unix style `/` directory separators should be used in the path. If not given then the `extractPaths` will be used as the install prefixes.
- **omitUnrecognizedTypes**: (optional) If set to True, files with unrecognized types will be omitted from the generated SBOM.
- **includeFileExts**: (optional) A list of file extensions to include, even if not recognized by Surfactant. `omitUnrecognizedTypes` must be set to True for this to take effect.
- **excludeFileExts**: (optional) A list of file extensions to exclude, even if recognized by Surfactant. Note that if both `omitUnrecognizedTypes` and `includeFileExts` are set, the specified extensions in `includeFileExts` will still be included.
- **skipProcessingArchive**: (optional) Skip processing the given archive file with info extractors. Software entry for the archive file will only contain basic information such as hashes. Default setting is False.

#### Create context file using the TUI

The Surfactant TUI has a "Context" tab that can be used to create a context file. Launch the TUI with `surfactant tui` and then navigate to the TUI tab to get to the editor for creating and modifying context files. This is the easiest way for new users to create a context file from scratch. The following sections will walkthrough what the context files look like, and the resulting SBOM with different options set in the context file entries.

#### Example context file

Let's say you have a .tar.gz file that you want to run surfactant on. For this example, we will be using the HELICS release .tar.gz example. In this scenario, the absolute path for this file is `/home/samples/helics.tar.gz`. Upon extracting this file, we get a helics folder with 4 sub-folders: bin, include, lib64, and share.

##### Example 1: Simple Context File

If we want to include only the folders that contain binary files to analyze, our most basic context file would be:

```json
[
  {
    "extractPaths": ["/home/samples/helics/bin", "/home/samples/helics/lib64"]
  }
]
```

The resulting SBOM would be structured like this:

```json
{
  "software": [
    {
      "UUID": "abc1",
      "fileName": ["helics_binary"],
      "installPath": ["/home/samples/helics/bin/helics_binary"],
      "containerPath": null
    },
    {
      "UUID": "abc2",
      "fileName": ["lib1.so"],
      "installPath": ["/home/samples/helics/lib64/lib1.so"],
      "containerPath": null
    }
  ],
  "relationships": [
    {
      "xUUID": "abc1",
      "yUUID": "abc2",
      "relationship": "Uses"
    }
  ]
}
```

##### Example 2: Detailed Context File

A more detailed context file might look like the example below. The resulting SBOM would have a software entry for the helics.tar.gz with a "Contains" relationship to all binaries found to in the extractPaths. Providing the install prefix of `/` and an extractPaths as `/home/samples/helics` will allow to surfactant correctly assign the install paths in the SBOM for binaries in the subfolders as `/bin` and `/lib64`.

```json
[
  {
    "archive": "/home/samples/helics.tar.gz",
    "extractPaths": ["/home/samples/helics"],
    "installPrefix": "/"
  }
]
```

The resulting SBOM would be structured like this:

```json
{
  "software": [
    {
      "UUID": "abc0",
      "fileName": ["helics.tar.gz"],
      "installPath": null,
      "containerPath": null
    },
    {
      "UUID": "abc1",
      "fileName": ["helics_binary"],
      "installPath": ["/bin/helics_binary"],
      "containerPath": ["abc0/bin/helics_binary"]
    },
    {
      "UUID": "abc2",
      "fileName": ["lib1.so"],
      "installPath": ["/lib64/lib1.so"],
      "containerPath": ["abc0/lib64/lib1.so"]
    }
  ],
  "relationships": [
    {
      "xUUID": "abc0",
      "yUUID": "abc1",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc0",
      "yUUID": "abc2",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc1",
      "yUUID": "abc2",
      "relationship": "Uses"
    }
  ]
}
```

##### Example 3: Adding Related Binaries

If our sample helics tar.gz file came with a related tar.gz file to install a plugin extension module (extracted into a helics_plugin folder that contains bin and lib64 subfolders), we could add that information to the context file as well:

```json
[
  {
    "archive": "/home/samples/helics.tar.gz",
    "extractPaths": ["/home/samples/helics"],
    "installPrefix": "/"
  },
  {
    "archive": "/home/samples/helics_plugin.tar.gz",
    "extractPaths": ["/home/samples/helics_plugin"],
    "installPrefix": "/"
  }
]
```

The resulting SBOM would be structured like this:

```json
{
  "software": [
    {
      "UUID": "abc0",
      "fileName": ["helics.tar.gz"],
      "installPath": null,
      "containerPath": null
    },
    {
      "UUID": "abc1",
      "fileName": ["helics_binary"],
      "installPath": ["/bin/helics_binary"],
      "containerPath": ["abc0/bin/helics_binary"]
    },
    {
      "UUID": "abc2",
      "fileName": ["lib1.so"],
      "installPath": ["/lib64/lib1.so"],
      "containerPath": ["abc0/lib64/lib1.so"]
    },
    {
      "UUID": "abc3",
      "fileName": ["helics_plugin.tar.gz"],
      "installPath": null,
      "containerPath": null
    },
    {
      "UUID": "abc4",
      "fileName": ["helics_plugin"],
      "installPath": ["/bin/helics_plugin"],
      "containerPath": ["abc3/bin/helics_plugin"]
    },
    {
      "UUID": "abc5",
      "fileName": ["lib_plugin.so"],
      "installPath": ["/lib64/lib_plugin.so"],
      "containerPath": ["abc3/lib64/lib_plugin.so"]
    }
  ],
  "relationships": [
    {
      "xUUID": "abc1",
      "yUUID": "abc2",
      "relationship": "Uses"
    },
    {
      "xUUID": "abc4",
      "yUUID": "abc5",
      "relationship": "Uses"
    },
    {
      "xUUID": "abc5",
      "yUUID": "abc2",
      "relationship": "Uses"
    },
    {
      "xUUID": "abc0",
      "yUUID": "abc1",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc0",
      "yUUID": "abc2",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc3",
      "yUUID": "abc4",
      "relationship": "Contains"
    },
    {
      "xUUID": "abc3",
      "yUUID": "abc5",
      "relationship": "Contains"
    }
  ]
}
```

NOTE: These examples have been simplified to show differences in output based on the context file provided.

### Run Surfactant

The Surfactant TUI for generating and merging SBOMs, as well as working with specimen context files, can be launched with the following command:

```bash
$  surfactant tui
```

While the TUI provides access to most of the options for generating SBOMs, there are times when it may be necessary to run the generate command directly to access certain extra command line options, or in environments where a TUI can't be used:

```bash
$  surfactant generate [OPTIONS] SPECIMEN_CONTEXT SBOM_OUTFILE [INPUT_SBOM]
```

**SPECIMEN_CONTEXT**: (required) the context file created earlier that contains the information on specimens to include in an SBOM, or the path to a specific file/directory to generate an SBOM for with some implied default context options\
**SBOM OUTPUT**: (required) the desired name of the output file\
**INPUT_SBOM**: (optional) a base sbom, should be used with care as relationships could be messed up when files are installed on different systems\
**--skip_gather**: (optional) skips the gathering of information on files and adding software entires\
**--skip_relationships**: (optional) skips the adding of relationships based on metadata\
**--skip_install_path**: (optional) skips including an install path for the files discovered. This may cause "Uses" relationships to also not be generated\
**--author_name**: (optional) the name of the BOM author. Must be supplied together with `--author_type`\
**--author_type**: (optional) the type of BOM author, such as `name`, `organization`, or `program`. Must be supplied together with `--author_name`\
**--output_format**: (optional) changes the output format for the SBOM (given as full module name of a surfactant plugin implementing the `write_sbom` hook)\
**--input_format**: (optional) specifies the format of the input SBOM if one is being used (default: cytrics) (given as full module name of a surfactant plugin implementing the `read_sbom` hook)\
**--help**: (optional) show the help message and exit

## Understanding the SBOM Output

### Software

This section contains a list of entries relating to each piece of software found in the sample. Metadata including file size, vendor, version, etc are included in this section along with a uuid to uniquely identify the software entry.

### Relationships

This section contains information on how each of the software entries in the previous section are linked.

**Uses**: this relationship type means that x software uses y software i.e. y is a helper module to x\
**Contains**: this relationship type means that x software contains y software (often x software is an installer or archive such as a zip file)

### Observations:

This section contains information about notable observations about individual software components. This could be vulnerabilities, observed features, etc

## Merging SBOMs


A folder containing multiple separate SBOM JSON files can be combined using merge_sbom.py with a command such the one below that gets a list of files using ls, and then uses xargs to pass the resulting list of files to merge_sbom.py as arguments.

`ls -d ~/Folder_With_SBOMs/Surfactant-* | xargs -d '\n' surfactant merge --config_file=merge_config.json --sbom_outfile combined_sbom.json`

If the merge config file option is given, a top-level system entry will be created that all other software entries are tied to (directly or indirectly based on other relationships). Specifying an empty UUID will make a random UUID get generated for the new system entry, otherwise it will use the one provided.

Details on the merge command can be found in the docs page [here](./docs/basic_usage.md#merging-sboms).

## Plugins

Surfactant supports using plugins to add additional features. Users can install plugins with `surfactant plugin install` and disable or enable them with `surfactant plugin disable` and `surfactant plugin enable` respectively. `surfactant plugin install` detects the active virtual environment and runs the appropriate command i.e. `pipx` or `pip`. Alternatively, users can manually manage their environments with `pipx inject surfactant` when using pipx or `pip install`.

Detailed information on configuration options for the plugin system and how to develop new plugins can be found [here](./docs/plugins.md).

## Support

Full user guides for Surfactant are available [online](https://surfactant.readthedocs.io)
and in the [docs](./docs) directory.

For questions or support, please create a new discussion on [GitHub Discussions](https://github.com/LLNL/Surfactant/discussions/categories/q-a),
or [open an issue](https://github.com/LLNL/Surfactant/issues/new/choose) for bug reports and feature requests.

## Contributing

Contributions are welcome. Bug fixes or minor changes are preferred via a
pull request to the [Surfactant GitHub repository](https://github.com/LLNL/Surfactant).
For more information on contributing see the [CONTRIBUTING](./CONTRIBUTING.md) file.

## License

Surfactant is released under the MIT license. See the [LICENSE](./LICENSE)
and [NOTICE](./NOTICE) files for details. All new contributions must be made
under this license.

SPDX-License-Identifier: MIT

LLNL-CODE-850771
