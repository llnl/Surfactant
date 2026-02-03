import json
import uuid as uuid_module
from typing import Tuple

import click
import networkx as nx
from loguru import logger

from surfactant.configmanager import ConfigManager
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager
from surfactant.sbomtypes._sbom import SBOM
from surfactant.sbomtypes._system import System


@click.argument("sbom_outfile", envvar="SBOM_OUTPUT", type=click.File("w"), required=True)
@click.argument("input_sboms", type=click.File("r"), required=True, nargs=-1)
@click.option(
    "--config_file",
    type=click.File("r"),
    required=False,
    help="Config file for controlling some aspects of the merged SBOM, primarily the creation of a new top-level system object (settings here will typically take precedence over command line options)",
)
@click.option(
    "--output_format",
    is_flag=False,
    default=ConfigManager().get(
        "core", "output_format", fallback="surfactant.output.cytrics_writer"
    ),
    help="SBOM output format, options=surfactant.output.[cytrics|csv|spdx]_writer",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="SBOM input format, assumes that all input SBOMs being merged have the same format, options=surfactant.input_readers.[cytrics|cyclonedx|spdx]_reader",
)
@click.option(
    "--system_uuid",
    is_flag=False,
    help="System UUID to use for relationships to a top-level system object",
)
@click.option(
    "--system_relationship",
    is_flag=False,
    default="Contains",
    show_default=True,
    help="Relationship type between merged SBOM contents to a top-level system object",
)
@click.option(
    "--add_system/--no_add_system",
    default=False,
    show_default=True,
    help="Create a top-level system entry for tying together the merged SBOM components. When disabled, relationships will still be created to a provided system UUID",
)
@click.command("merge")
# pylint: disable-next=too-many-positional-arguments
def merge_command(
    input_sboms,
    sbom_outfile,
    config_file,
    output_format,
    input_format,
    system_uuid,
    system_relationship,
    add_system,
):
    """Merge two or more INPUT_SBOMS together into SBOM_OUTFILE.

    An optional CONFIG_FILE can be supplied to specify a root system entry
    """
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")

    sboms = []
    for sbom in input_sboms:
        sboms.append(input_reader.read_sbom(sbom))
    config = None
    if config_file:
        config = json.load(config_file)
    merge(sboms, sbom_outfile, config, output_writer, system_uuid, system_relationship, add_system)


# pylint: disable-next=too-many-positional-arguments
def merge(
    input_sboms,
    sbom_outfile,
    config,
    output_writer,
    system_uuid=None,
    system_relationship="Contains",
    add_system=False,
):
    """Merge two or more SBOMs, then optionally wrap in a top‐level system."""
    # Merge all input SBOMs into the first one
    merged_sbom = input_sboms[0]
    for sbom_m in input_sboms[1:]:
        merged_sbom.merge(sbom_m)

    # Find root nodes: those with zero incoming edges
    roots = [
        n
        for n, deg in merged_sbom.graph.in_degree()
        if deg == 0 and merged_sbom.graph.nodes.get(n, {}).get("type") != "Path"
    ]
    logger.info(f"ROOT NODES: {roots}")

    # Detect any directed cycles
    cycles = list(nx.simple_cycles(merged_sbom.graph))
    if cycles:
        logger.warning(f"SBOM CYCLE(S) DETECTED: {cycles}")
    else:
        logger.info("No cycles detected in SBOM graph")

    # Prepare (or suppress) the top‐level system entry
    if config and "system" in config and "UUID" in config["system"]:
        if any(s.UUID == config["system"]["UUID"] for s in merged_sbom.systems):
            add_system = False

    system_obj, using_random = create_system_object(merged_sbom, config, system_uuid)
    if add_system:
        merged_sbom.systems.append(system_obj)

    # Attach a system‐to‐root relationship for each root
    if not using_random or add_system:
        if config and "systemRelationship" in config:
            system_relationship = config["systemRelationship"]
        for root_uuid in roots:
            if merged_sbom.graph.nodes.get(root_uuid, {}).get("type") == "Path":
                continue
            merged_sbom.create_relationship(system_obj.UUID, root_uuid, system_relationship)
    else:
        logger.warning(
            "No top‐level system relationships added; "
            "either specify --add_system or provide a system UUID."
        )

    # Write out
    output_writer.write_sbom(merged_sbom, sbom_outfile)


def create_system_object(sbom: SBOM, config=None, system_uuid=None) -> Tuple[System, bool]:
    """Function to create an accurate system object

    Positional arguments:
        sbom (SBOM): The SBOM the system object is being created for.
        config: The user specified config json (Optional).

    Returns:
        Tuple[System, bool]: The created system object and a boolean indicating if a random UUID was used.
    """

    system = {}
    using_random_uuid = False
    if config and "system" in config:
        system = config["system"]

    # system_uuid supplied via command line overrides config file UUID
    if system_uuid:
        system["UUID"] = system_uuid
    elif "UUID" not in system:
        # No UUID, generate a random one...
        using_random_uuid = True
        system["UUID"] = str(uuid_module.uuid4())
    # check if the UUID appears valid based on the CyTRICS schema
    elif not sbom.is_valid_uuid4(system["UUID"]):
        invalid_uuid = system["UUID"]
        logger.error(f"Invalid uuid4 given ({invalid_uuid}) for the system")

    if "name" not in system:
        system["name"] = ""
    captureStart = -1
    captureEnd = -1
    for sw in sbom.software:
        if captureStart and sw.captureTime:
            if captureStart == -1 or sw.captureTime < captureStart:
                captureStart = sw.captureTime
        if captureEnd and sw.captureTime:
            if captureEnd == -1 or sw.captureTime > captureEnd:
                captureEnd = sw.captureTime
    if "captureStart" not in system or not system["captureStart"]:
        system["captureStart"] = captureStart
    if "captureEnd" not in system or not system["captureEnd"]:
        system["captureEnd"] = captureEnd
    return System(**system), using_random_uuid
