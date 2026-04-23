# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype: list[str]) -> bool:
    return "COFF" in filetype


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    if not supports_file(filetype):
        return None
    return extract_coff_out_info(filename)


# Machine types:
# https://github.com/file/file/blob/master/magic/Magdir/coff
COFF_MAGIC_TARGET_NAME = {
    0x014C: "Intel 80386",
    0x0500: "Hitachi SH big-endian",
    0x0550: "Hitachi SH little-endian",
    0x0200: "Intel ia64",
    0x8664: "Intel amd64",
    0xAA64: "Aarch64",
    0x01C0: "ARM",
    0xA641: "ARM64EC",
    0x01C2: "ARM Thumb",
    0x01C4: "ARMv7 Thumb",
}


def extract_coff_out_info(filename: str) -> object:
    try:
        with open(filename, "rb") as f:
            magic_bytes = f.read(4)
            magic_int = int.from_bytes(magic_bytes, byteorder="little", signed=False)
            if magic_int in COFF_MAGIC_TARGET_NAME:
                return {"coffMachineType": COFF_MAGIC_TARGET_NAME[magic_int]}
            return None
    except FileNotFoundError:
        return None
