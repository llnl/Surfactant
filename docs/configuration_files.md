# Configuration Files

There are several files for configuring different aspects of Surfactant functionality based on the subcommand used.
This page currently describes specimen context files, and the Surfactant settings configuration file. The specimen context file is used to generate an SBOM for a particular software/firmware sample, and will be the one users are most likely to have to create and edit. The Surfactant settings configuration file is used to turn on and off various Surfactant features, including settings for controlling functionality in Surfactant plugins.

## Settings Configuration File

Surfactant settings can be changed using the `surfactant config` subcommand, or by hand editing the settings configuration file (this is not the same as the JSON file used to configure settings for a particular sample that is described later). See the [settings page](settings.md) for a list of available config settings to control functionality that comes with Surfactant.

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

## Specimen Context File

A specimen context file contains the information about the sample to gather information from. Example JSON specimen context files can be found in the examples folder of this repository.

The `Context` tab in the Surfactant TUI (launched with the `surfactant tui` command) provides an interface for creating and modifying specimen context files. Most of the options described can be set using the TUI, however there may be less frequently used options that require modifying the context file by hand.

- **extractPaths**: (required) the absolute path or relative path from location of current working directory that `surfactant` is being run from to the files or folders to gather information on. Note that even on Windows, Unix style `/` directory separators should be used in paths.
- **archive**: (optional) the full path, including file name, of the zip, exe installer, or other archive file that the files or folders in `extractPaths` were extracted from. This is used to collect metadata about the overall sample and will be added as a "Contains" relationship to all software entries found in the various `extractPaths`.
- **installPrefix**: (optional) where the files in `extractPaths` would be if installed correctly on an actual system i.e. "C:/", "C:/Program Files/", etc. Note that even on Windows, Unix style `/` directory separators should be used in the path. If not given then the `extractPaths` will be used as the install prefixes.
- **omitUnrecognizedTypes**: (optional) If set to True, files with unrecognized types will be omitted from the generated SBOM.
- **includeFileExts**: (optional) A list of file extensions to include, even if not recognized by Surfactant. `omitUnrecognizedTypes` must be set to True for this to take effect.
- **excludeFileExts**: (optional) A list of file extensions to exclude, even if recognized by Surfactant. Note that if both `omitUnrecognizedTypes` and `includeFileExts` are set, the specified extensions in `includeFileExts` will still be included.
- **skipProcessingArchive**: (optional) Skip processing the given archive file with info extractors. Software entry for the archive file will still appear in the SBOM with basic info such as hashes, but no information extraction plugins will run to pull out extra file type specific info. Default setting is False.

## Example context files

Lets say you have a .tar.gz file that you want to run surfactant on. For this example, we will be using the HELICS release .tar.gz example. In this scenario, the absolute path for this file is /home/samples/helics.tar.gz. Upon extracting this file, we get a helics folder with 4 sub-folders: bin, include, lib64, and share.

### Example 1: Simple Context File

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

### Example 2: Detailed Context File

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

### Example 3: Adding Related Binaries

If our sample helics tar.gz file came with a related tar.gz file to install a plugin extension module (extracted into a helics_plugin folder that contains bin and lib64 subfolders), we could add that into the context file as well:

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
