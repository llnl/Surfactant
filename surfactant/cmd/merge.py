import click
import networkx as nx
from loguru import logger

from surfactant.configmanager import ConfigManager
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager


@click.argument("sbom_outfile", envvar="SBOM_OUTPUT", type=click.File("w"), required=True)
@click.argument("input_sboms", type=click.File("r"), required=True, nargs=-1)
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
@click.command("merge")
# pylint: disable-next=too-many-positional-arguments
def merge_command(
    input_sboms,
    sbom_outfile,
    output_format,
    input_format,
):
    """Merge two or more INPUT_SBOMS together into SBOM_OUTFILE."""
    pm = get_plugin_manager()
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")

    sboms = []
    for sbom in input_sboms:
        sboms.append(input_reader.read_sbom(sbom))

    try:
        merge(sboms, sbom_outfile, output_writer)
    except ValueError as err:
        raise click.ClickException(str(err)) from err


def merge(
    input_sboms,
    sbom_outfile,
    output_writer,
):
    """Merge two or more SBOMs and write the merged result."""
    # Merge all input SBOMs into the first one
    merged_sbom = input_sboms[0]
    for sbom_m in input_sboms[1:]:
        merged_sbom.merge(sbom_m)

    # Find root nodes: those with zero incoming edges
    roots = [
        n
        for n, deg in merged_sbom.graph.in_degree()
        if deg == 0 and merged_sbom.graph.nodes.get(n, {}).get("type") != "path"
    ]
    logger.info(f"ROOT NODES: {roots}")

    # Detect any directed cycles
    cycles = list(nx.simple_cycles(merged_sbom.graph))
    if cycles:
        logger.warning(f"SBOM CYCLE(S) DETECTED: {cycles}")
    else:
        logger.info("No cycles detected in SBOM graph")

    # Write out
    output_writer.write_sbom(merged_sbom, sbom_outfile)
