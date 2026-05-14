# Basic Usage

The `surfactant` command has many _subcommands_. Typically you'll only need a subset of them. `surfactant --help` will list
available subcommands, and `surfactant <subcommand> --help` can be used to get usage information on individual subcommands.

## Identify Sample File

In order to test out surfactant, you will need a sample file/folder. If you don't have one on hand, you can download and use the portable .zip file from <https://github.com/ShareX/ShareX/releases> or the Linux .tar.gz file from <https://github.com/GMLC-TDC/HELICS/releases>.

## Running Surfactant

Most of the functionality for the generate and merge subcommands can be accessed via the Surfactant TUI, which can be launched using the following command:

```bash
$  surfactant tui
```

The TUI also provides a convenient interface for creating a specimen context JSON file for more complex SBOM generation use cases, and will also soon provide options for changing Surfactant configuration settings and managing plugins.

While the TUI provides access to most of the options for generating SBOMs, there are times when it may be necessary to run the generate command directly to access certain extra command line options, or in environments where a TUI can't be used.


## Generating SBOMs

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
**--install_prefix**: (optional) specifies a SBOM install prefix\
**--help**: (optional) show the help message and exit


## Merging SBOMs

A folder containing multiple separate SBOM JSON files can be combined using merge_sbom.py with a command such the one below that gets a list of files using ls, and then uses xargs to pass the resulting list of files to merge_sbom.py as arguments.

`ls -d ~/Folder_With_SBOMs/Surfactant-* | xargs -d '\n' surfactant merge --config_file=merge_config.json --sbom_outfile combined_sbom.json`

If the config file option is given, a top-level system entry will be created that all other software entries are tied to (directly or indirectly based on other relationships). Specifying an empty UUID will make a random UUID get generated for the new system entry, otherwise it will use the one provided.
