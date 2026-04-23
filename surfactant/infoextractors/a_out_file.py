# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype: list[str]) -> bool:
    supported_types = ("A.OUT little", "A.OUT big")
    for ft in filetype:
        if ft in supported_types:
            return True
    return False


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    if not supports_file(filetype):
        return None
    return extract_a_out_info(filetype, filename)


# Machine ID/types can be found in various OS source files (+ file magic patterns) - some are ambiguous
# https://github.com/file/file/tree/master/magic/Magdir
# https://github.com/openbsd/src/blob/master/sys/sys/exec.h#L259-L291
# https://github.com/haiku/haiku/blob/master/src/tools/elf2aout.c#L70-L111
# https://github.com/KimLoanSA/mimuw/blob/main/sem4/so/abrams/zadania/zad6/minix_source/usr/include/sys/aout_mids.h#L36-L67
_A_OUT_TARGET_NAME = {
    0x00: "Unknown",
    0x01: "M68010",
    0x02: "M68020",
    0x03: "SPARC",
    0x04: "R3000",
    0x40: "NS32032",
    0x45: "NS32532",
    0x64: "386",
    0x65: "AMD 29K",
    0x66: "386 DYNIX",
    0x67: "ARM",
    0x68: "IBM RT (ROMP AOS)",
    0x83: "Sparclet",
    0x86: "NetBSD/i386",
    0x87: "NetBSD/m68k",
    0x88: "NetBSD/m68k4k",
    0x89: "NetBSD/ns32532",
    0x8A: "NetBSD/SPARC",
    0x8B: "NetBSD/pmax",
    0x8C: "NetBSD/vax 1k",
    0x8D: "NetBSD/alpha",
    0x8E: "NetBSD/mips",
    0x8F: "NetBSD/arm32",
    0x91: "SH3",
    0x94: "PowerPC 64",
    0x95: "NetBSD/powerpc",
    0x96: "NetBSD/vax 4k",
    0x97: "MIPS R2000/R3000",
    0x98: "MIPS R4000/R6000",
    0x99: "OpenBSD/m88k",
    0x9A: "OpenBSD/HPPA",
    0x9B: "SuperH 64-bit",
    0x9C: "NetBSD/sparc64",
    0x9D: "NetBSD/amd64",
    0x9E: "SuperH 32-bit",
    0x9F: "Itanium",
    0xB7: "ARM AARCH64",
    0xB8: "OpenRISC 1000",
    0xB9: "RISC-V",
    0xFF: "Axis ETRAX CRIS",
}


def extract_a_out_info(filetype: list[str], filename: str) -> object:
    try:
        with open(filename, "rb") as f:
            magic_bytes = f.read(4)
            target = get_target_type(filetype, magic_bytes)
            if target is None:
                return None
            return {"aoutMachineType": target}
    except FileNotFoundError:
        return None


def get_target_type(filetype: list[str], magic_bytes: bytes) -> str | None:
    if "A.OUT big" in filetype:
        big_endian_magic = (
            int.from_bytes(magic_bytes[:4], byteorder="big", signed=False) >> 16
        ) & 0xFF
        if big_endian_magic in _A_OUT_TARGET_NAME:
            return _A_OUT_TARGET_NAME[big_endian_magic]
    if "A.OUT little" in filetype:
        little_endian_magic = (
            int.from_bytes(magic_bytes[:4], byteorder="little", signed=False) >> 16
        ) & 0xFF
        if little_endian_magic in _A_OUT_TARGET_NAME:
            return _A_OUT_TARGET_NAME[little_endian_magic]
    return None
