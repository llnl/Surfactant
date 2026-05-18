# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from pathlib import Path

from checksec.__main__ import checksec_file
from checksec.elf import ELFChecksecData
from checksec.pe import PEChecksecData

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    if not ("ELF" in filetype or "PE" in filetype):
        return None
    checksec_data = checksec_file(Path(filename))
    data = {}
    if isinstance(checksec_data, ELFChecksecData):
        data["checksecDataType"] = "ELF"
        data["checksec"] = {
            "relro": checksec_data.relro.name,
            "canary": checksec_data.canary,
            "nx": checksec_data.nx,
            "pie": checksec_data.pie.name,
            "rpath": checksec_data.rpath,
            "runpath": checksec_data.runpath,
            "symbols": checksec_data.symbols,
            "fortify_source": checksec_data.fortify_source,
            "fortified": checksec_data.fortified,
            "fortify-able": checksec_data.fortifiable,
            "fortify_score": checksec_data.fortify_score,
        }
    elif isinstance(checksec_data, PEChecksecData):
        data["checksecDataType"] = "PE"
        data["checksec"] = {
            "nx": checksec_data.nx,
            "canary": checksec_data.canary,
            "aslr": checksec_data.aslr,
            "dynamic_base": checksec_data.dynamic_base,
            "high_entropy_va": checksec_data.high_entropy_va,
            "isolation": checksec_data.isolation,
            "seh": checksec_data.seh,
            "safe_seh": checksec_data.safe_seh,
            "authenticode": checksec_data.authenticode,
            "guard_cf": checksec_data.guard_cf,
            "force_integrity": checksec_data.force_integrity,
        }
    return data
