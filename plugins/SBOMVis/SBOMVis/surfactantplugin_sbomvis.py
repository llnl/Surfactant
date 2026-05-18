from pathlib import Path

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM

from . import visualization as vis


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    htmlName = Path(outfile.name).stem + ".html"

    logger.info(f"Generating visualization: {htmlName}")
    g = vis.generate_dependency_graph({"sbom": sbom, "sbomFileName": outfile.name})
    vis.generate_pyvis_graph(g, htmlName)

    logger.info("Writing CyTRICS format")
    outfile.write(sbom.to_json(indent=2))


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    return "sbomvis"
