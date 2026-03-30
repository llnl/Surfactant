import hashlib
import sys
from pathlib import Path

import click
from loguru import logger

from surfactant.cmd.cli_commands import Load, Save
from surfactant.configmanager import ConfigManager
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.sbomtypes._relationship import Relationship
from surfactant.sbomtypes._sbom import SBOM
from surfactant.sbomtypes._software import Software

from surfactant.utils.capture_time import validate_capture_time


@click.argument("sbom", type=click.File("r"), required=True)
@click.option(
    "--input_format",
    is_flag=False,
    default=ConfigManager().get(
        "core", "input_format", fallback="surfactant.input_readers.cytrics_reader"
    ),
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=[cytrics|cyclonedx|spdx]",
)
@click.command("load")
def handle_cli_load(sbom, input_format):
    "CLI command to load supplied SBOM into cli"
    Load(input_format=input_format).execute(sbom)


@click.argument("sbom", type=click.File("r"), required=True)
@click.option("--file", is_flag=False, help="File of the entry to find")
@click.option("--sha256", is_flag=False, type=str, help="sha256 hash of the entry to find")
@click.option("--uuid", is_flag=False, type=str, help="uuid of the entry to find")
@click.option(
    "--installPath",
    is_flag=False,
    type=str,
    help="Matches all entries with an install path or partial install path match",
)
@click.option(
    "--containerPath",
    is_flag=False,
    type=str,
    help="Matches all entries with a container path or partial container path match",
)
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, options=[cytrics|csv|spdx|cyclonedx]",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=[cytrics|cyclonedx|spdx]",
)
@click.command("find")
def handle_cli_find(sbom, output_format, input_format, **kwargs):
    "CLI command to find specific entry(s) within a supplied SBOM"
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")
    in_sbom = input_reader.read_sbom(sbom)

    # Remove None values
    filtered_kwargs = dict({(k, v) for k, v in kwargs.items() if v is not None})
    out_sbom = cli_find().execute(in_sbom, **filtered_kwargs)
    if not out_sbom.software:
        logger.warning("No software matches found with given parameters.")
    output_writer.write_sbom(out_sbom, sys.stdout)


@click.argument("sbom", required=True)
@click.option(
    "--output",
    default=None,
    is_flag=False,
    help="Specifies the file to output new sbom. Default replaces the input file.",
)
@click.option("--file", is_flag=False, help="Adds entry for file to sbom")
@click.option("--relationship", is_flag=False, type=str, help="Adds relationship to sbom")
@click.option("--entry", is_flag=False, type=str, help="Adds software entry to sbom")
@click.option(
    "--installPath",
    is_flag=False,
    type=str,
    nargs=2,
    help="Adds new installPath by finding and replacing a containerPath prefix (1st arg) with a new prefix (2nd arg)",
)
@click.option(
    "--output_format",
    is_flag=False,
    default="surfactant.output.cytrics_writer",
    help="SBOM output format, options=[cytrics|csv|spdx|cyclonedx]",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, options=[cytrics|cyclonedx|spdx]",
)
@click.command("add")
def handle_cli_add(sbom, output, output_format, input_format, **kwargs):
    "CLI command to add specific entry(s) to a supplied SBOM"
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")
    with open(Path(sbom), "r") as f:
        in_sbom = input_reader.read_sbom(f)
    # Remove None values
    filtered_kwargs = dict({(k, v) for k, v in kwargs.items() if v is not None})
    out_sbom = cli_add().execute(in_sbom, **filtered_kwargs)
    # Write to the input file if no output specified
    if output is None:
        with open(Path(sbom), "w") as f:
            output_writer.write_sbom(out_sbom, f)
    else:
        try:
            with open(Path(output), "w") as f:
                output_writer.write_sbom(out_sbom, f)
        except OSError as e:
            logger.error(f"Could not open file {output} in write mode - {e}")


@click.argument("sbom", type=click.File("r"), required=True)
@click.command("edit")
def handle_cli_edit(sbom, output_format, input_format, **kwargs):
    "CLI command to edit specific entry(s) in a supplied SBOM"


@click.argument("outfile", type=click.File("w"), required=True)
@click.option(
    "--output_format",
    is_flag=False,
    default=ConfigManager().get(
        "core", "output_format", fallback="surfactant.output.cytrics_writer"
    ),
    help="SBOM output format, options=[cytrics|csv|spdx|cyclonedx]",
)
@click.command("save")
def handle_cli_save(outfile, output_format):
    "CLI command to save SBOM to a user specified file"
    Save(output_format=output_format).execute(outfile)


class cli_add:
    """
    A class that implements the surfactant cli add functionality

    Attributes:
    match_functions         A dictionary of functions that provide matching functionality for given SBOM fields (i.e. uuid, sha256, installpath, etc)
    camel_case_conversions  A dictionary of string conversions from all lowercase to camelcase. Used to convert python click options to match the SBOM attribute's case
    sbom                    An internal record of sbom entries the class adds to as it finds more matches.
    """

    camel_case_conversions: dict
    match_functions: dict
    sbom: SBOM

    def __init__(self):
        """Initializes the cli_add class"""
        self.match_functions = {
            "relationship": self.add_relationship,
            "file": self.add_file,
            "installPath": self.add_installpath,
            "entry": self.add_entry,
        }
        self.camel_case_conversions = {
            "uuid": "UUID",
            "filename": "fileName",
            "installpath": "installPath",
            "capturetime": "captureTime",
            "relationshipassertion": "relationshipAssertion",
        }

    def handle_kwargs(self, kwargs: dict) -> dict:
        converted_kwargs = {}
        for k, v in kwargs.items():  # Convert key values to camelcase where appropriate
            key = self.camel_case_conversions[k] if k in self.camel_case_conversions else k
            converted_kwargs[key] = v
        return converted_kwargs

    def execute(self, input_sbom: SBOM, **kwargs):
        """Executes the main functionality of the cli_find class
        param: input_sbom   The sbom to add entries to
        param: kwargs:      Dictionary of key/value pairs indicating what features to match on
        """
        converted_kwargs = self.handle_kwargs(kwargs)
        self.sbom = input_sbom

        for key, value in converted_kwargs.items():
            if key in self.match_functions:
                self.match_functions[key](value)
            else:
                logger.warning(f"Paramter {key} is not supported")
        return self.sbom

    def add_relationship(self, value: dict) -> bool:
        self.sbom.add_relationship(Relationship(**value))

    def add_file(self, path):
        self.sbom.software.append(Software.create_software_from_file(path))

    def add_entry(self, entry):
        """Add a software entry, validating captureTime fields before deserialization."""
        # Validate top-level software captureTime
        if "captureTime" in entry:
            entry["captureTime"] = validate_capture_time(entry["captureTime"], nullable=True)

        # Validate nested software component captureTime values
        components = entry.get("components")
        if isinstance(components, list):
            for component in components:
                if isinstance(component, dict) and "captureTime" in component:
                    component["captureTime"] = validate_capture_time(
                        component["captureTime"],
                        nullable=True,
                        field_name="components[].captureTime",
                    )

        self.sbom.software.append(Software.from_dict(entry))

    def add_installpath(self, prefixes: tuple):
        """Add installPath values by rewriting matching containerPath prefixes."""
        cleaned_prefixes = (p.rstrip("/") for p in prefixes)
        containerPathPrefix, installPathPrefix = cleaned_prefixes

        for sw in self.sbom.software:
            if not sw.containerPath:
                continue

            if sw.installPath is None:
                sw.installPath = []

            for path in sw.containerPath:
                if containerPathPrefix in path:
                    new_path = path.replace(containerPathPrefix, installPathPrefix)
                    if new_path not in sw.installPath:
                        sw.installPath.append(new_path)


class cli_find:
    """
    A class that implements the surfactant cli find functionality

    Attributes:
    match_functions         A dictionary of functions that provide matching functionality for given SBOM fields (i.e. uuid, sha256, installpath, etc)
    camel_case_conversions  A dictionary of string conversions from all lowercase to camelcase. Used to convert python click options to match the SBOM attribute's case
    sbom                    An internal record of sbom entries the class adds to as it finds more matches.
    """

    match_functions: dict
    camel_case_conversions: dict
    sbom: SBOM

    def __init__(self):
        """Initializes the cli_find class"""
        self.match_functions = {
            int: self.match_single_value,
            str: self.match_single_value,
            list: self.match_array_value,
            dict: self.match_dict_value,
            float: self.match_none_or_unhandled,
            tuple: self.match_none_or_unhandled,
            type(None): self.match_none_or_unhandled,
        }
        self.camel_case_conversions = {
            "uuid": "UUID",
            "filename": "fileName",
            "containerpath": "containerPath",
            "installpath": "installPath",
            "capturetime": "captureTime",
            "relationshipassertion": "relationshipAssertion",
        }
        self.sbom = SBOM()

    def handle_kwargs(self, kwargs: dict) -> dict:
        converted_kwargs = {}
        for k, v in kwargs.items():  # Convert key values to camelcase where appropriate
            if k == "file":
                sha256, sha1, md5 = self._calculate_hashes(v, sha256=True, sha1=True, md5=True)
                v = {"sha256": sha256, "sha1": sha1, "md5": md5}
            key = self.camel_case_conversions[k] if k in self.camel_case_conversions else k
            converted_kwargs[key] = v
        return converted_kwargs

    def execute(self, input_sbom: SBOM, **kwargs):
        """Executes the main functionality of the cli_find class
        param: input_sbom   The sbom to find matches within
        param: kwargs:      Dictionary of key/value pairs indicating what features to match on
        """
        converted_kwargs = self.handle_kwargs(kwargs)

        for sw in input_sbom.software:
            match = True
            for k, v in converted_kwargs.items():
                if k == "file":
                    entry_value = {"sha256": sw.sha256, "sha1": sw.sha1, "md5": sw.md5}
                else:
                    entry_value = vars(sw)[k] if k in vars(sw) else None
                if not self.match_functions[type(entry_value)](entry_value, v):
                    match = False
                    break
            if match:
                self.sbom.add_software(sw)
        return self.sbom

    def match_single_value(self, first, second) -> bool:
        """Matches sbom entry on single value
        param: first   The entry value to match
        param: second: The value to match first to
        returns:       bool, True if a match, False if not
        """
        if first == second:
            return True
        return False

    def match_array_value(self, array, value) -> bool:
        """Matches sbom entry on array value. Will match if value is contained in any of the array values.
        param: entry    The entry array to match
        param: value:   The value to find in array
        returns:        bool, True if a match, False if not
        """
        if any(value in entry for entry in array):
            return True
        return False

    def match_dict_value(self, d1: dict, d2: dict) -> bool:
        """Matches dictonary values. Will match if two dictionaries have any k,v pairs in common. Used for file hash comparison.
        param: d1       The first dictionary of values
        param: d2:      The 2nd dictionary of values to find
        returns:        bool, True if a match, False if not
        """
        if set(d1.items()).intersection(set(d2.items())):
            return True
        return False

    def match_none_or_unhandled(self, value, match):
        """Default match function if no key value found in SBOM or match type unknown/unhandled
        param: value    Should only be None
        param: match:   Value that would have been matched
        returns:        False
        """
        logger.debug(f"SBOM entry_value of type={type(value)} is not currently handled.")
        return False

    def _calculate_hashes(self, file, sha256=False, sha1=False, md5=False):
        """Helper function to calculate hashes on a given file.
        param: file      The file to calculate hashes on
        param: sha256:   Bool to decide if sha256 hash should be calculated
        param: sha1:     Bool to decide if sha1 hash should be calculated
        param: md5:      Bool to decide if md5 hash should be calculated
        returns:         str, str, str, Hashes calculated, None for those that aren't calculated
        """
        sha256_hash, sha1_hash, md5_hash = None, None, None
        with open(file, "rb") as f:
            if sha256:
                sha256_hash = hashlib.sha256(f.read()).hexdigest()
                f.seek(0)
            if sha1:
                sha1_hash = hashlib.sha1(f.read()).hexdigest()
                f.seek(0)
            if md5:
                md5_hash = hashlib.md5(f.read()).hexdigest()
        return sha256_hash, sha1_hash, md5_hash
