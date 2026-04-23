# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT


import surfactant.plugin
from surfactant.sbomtypes import SBOM


@surfactant.plugin.hookimpl
def read_sbom(infile) -> SBOM:
    return SBOM.from_json(infile.read())


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    return "cytrics"
