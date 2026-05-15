# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from typing import Optional

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    # outfile is a file pointer, not a file name
    logger.debug("writing SBOM")
    outfile.write(sbom.to_json(indent=2))


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "cytrics"
