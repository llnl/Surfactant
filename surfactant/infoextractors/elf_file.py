# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import struct
from pathlib import Path
from typing import Any

from elftools.common.exceptions import ELFError, ELFParseError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_DT_FLAGS, ENUM_DT_FLAGS_1
from elftools.elf.sections import NoteSection
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype: list[str]) -> bool:
    return "ELF" in filetype


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    if not supports_file(filetype):
        return None
    return extract_elf_info(filename)


_EI_OSABI_NAME = {
    "ELFOSABI_SYSV": "System V",
    "ELFOSABI_HPUX": "HP-UX",
    "ELFOSABI_NETBSD": "NetBSD",
    "ELFOSABI_LINUX": "Linux",
    "ELFOSABI_HURD": "GNU/Hurd",
    "ELFOSABI_SOLARIS": "Solaris",
    "ELFOSABI_AIX": "AIX",
    "ELFOSABI_IRIX": "IRIX",
    "ELFOSABI_FREEBSD": "FreeBSD",
    "ELFOSABI_TRU64": "TRUE64",
    "ELFOSABI_MODESTO": "Novell Modesto",
    "ELFOSABI_OPENBSD": "OpenBSD",
    "ELFOSABI_OPENVMS": "OpenVMS",
    "ELFOSABI_NSK": "HP Non-Stop Kernel",
    "ELFOSABI_AROS": "AROS",
    "ELFOSABI_FENIXOS": "Fenix OS",
    "ELFOSABI_CLOUD": "Nuxi CloudABI",
    "ELFOSABI_SORTIX": "Sortix",
    "ELFOSABI_ARM_AEABI": "ARM EABI",
    "ELFOSABI_ARM": "ARM",
    "ELFOSABI_CELL_LV2": "CellOS Lv-2",
    "ELFOSABI_STANDALONE": "Standalone",
}


def extract_elf_info(filename: str) -> object:
    with Path(filename).open("rb") as f:  # noqa: F821
        try:
            elf = ELFFile(f)
        except (OSError, ELFError):
            return {}

        # Don't assume OS is Linux, map e_ident EI_OSABI value to an OS name
        file_details: dict[str, Any] = {"OS": ""}
        file_details["elfIdent"] = get_elf_ident_from_file_header(f, elf.little_endian)
        file_details["elfDependencies"] = set()
        file_details["elfRpath"] = []
        file_details["elfRunpath"] = []
        file_details["elfSoname"] = []
        file_details["elfInterpreter"] = []
        file_details["elfDynamicFlags"] = []
        file_details["elfDynamicFlags1"] = []
        file_details["elfGnuRelro"] = False
        file_details["elfComment"] = []
        file_details["elfNote"] = []
        file_details["elfOsAbi"] = elf["e_ident"]["EI_OSABI"]
        file_details["elfHumanArch"] = elf.get_machine_arch()
        file_details["elfArchNumber"] = file_details["elfIdent"]["E_MACHINE"]
        file_details["elfArchitecture"] = elf["e_machine"]

        # Get a human readable name for the OS
        file_details["OS"] = _EI_OSABI_NAME.get(file_details["elfOsAbi"], "")
        try:
            for section in elf.iter_sections():
                if section.name == ".interp":
                    file_details["elfInterpreter"].append(section.data().rstrip(b"\x00").decode())
                if section.name == ".comment":
                    for v in section.data().rstrip(b"\x00").split(b"\x00"):
                        file_details["elfComment"].append(v.decode())
                if isinstance(section, NoteSection):
                    for note in section.iter_notes():
                        # Info on contents of NetBSD and PaX notes: https://www.netbsd.org/docs/kernel/elf-notes.html
                        # Heuristics used by Avast RetDec to identify compiler/OS: https://github.com/avast/retdec/commit/d55b541c26fb110381b2203dc7baa50928e3f473
                        note_info = {}
                        note_info["sectionName"] = section.name
                        note_info["name"] = note.n_name
                        note_info["type"] = note.n_type
                        if note.n_name == "GNU":
                            if note.n_type == "NT_GNU_ABI_TAG":
                                note_info["os"] = note.n_desc.abi_os
                                note_info["abi"] = (
                                    f"{note.n_desc.abi_major}.{note.n_desc.abi_minor}.{note.n_desc.abi_tiny}"
                                )
                            elif note.n_type in ("NT_GNU_BUILD_ID", "NT_GNU_GOLD_VERSION"):
                                note_info["desc"] = note.n_desc
                            else:
                                note_info["descdata"] = note.n_descdata.decode("unicode_escape")
                        else:
                            note_info["descdata"] = note.n_descdata.decode("unicode_escape")
                        file_details["elfNote"].append(note_info)
                if isinstance(section, DynamicSection):
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            # Shared libraries
                            file_details["elfDependencies"].add(tag.needed)
                        elif tag.entry.d_tag == "DT_RPATH":
                            # Library rpath
                            file_details["elfRpath"].append(tag.rpath)
                        elif tag.entry.d_tag == "DT_RUNPATH":
                            # Library runpath
                            file_details["elfRunpath"].append(tag.runpath)
                        elif tag.entry.d_tag == "DT_SONAME":
                            # Library soname (for linking)
                            file_details["elfSoname"].append(tag.soname)
                        elif tag.entry.d_tag == "DT_FLAGS":
                            # Dynamic Flags, DT_FLAGS
                            dt_flags_entry: dict[str, Any] = {}
                            dt_flags_entry["value"] = hex(tag.entry.d_val)
                            # $ORIGIN processing is required
                            dt_flags_entry["DF_ORIGIN"] = bool(
                                tag.entry.d_val & ENUM_DT_FLAGS["DF_ORIGIN"]
                            )
                            # Perform complete relocation processing (part of Full RELRO)
                            dt_flags_entry["DF_BIND_NOW"] = bool(
                                tag.entry.d_val & ENUM_DT_FLAGS["DF_BIND_NOW"]
                            )
                            file_details["elfDynamicFlags"].append(dt_flags_entry)
                        elif tag.entry.d_tag == "DT_FLAGS_1":
                            # Dynamic Flags, DT_FLAGS_1 (custom entry first added by binutils)
                            dt_flags_1_entry: dict[str, Any] = {}
                            dt_flags_1_entry["value"] = hex(tag.entry.d_val)
                            # Position-Independent Executable file
                            dt_flags_1_entry["DF_1_PIE"] = bool(
                                tag.entry.d_val & ENUM_DT_FLAGS_1["DF_1_PIE"]
                            )
                            # Perform complete relocation processing
                            dt_flags_1_entry["DF_1_NOW"] = bool(
                                tag.entry.d_val & ENUM_DT_FLAGS_1["DF_1_NOW"]
                            )
                            # $ORIGIN processing is required
                            dt_flags_1_entry["DF_1_ORIGIN"] = bool(
                                tag.entry.d_val & ENUM_DT_FLAGS_1["DF_1_ORIGIN"]
                            )
                            # Ignore the default library search path
                            dt_flags_1_entry["DF_1_NODEFLIB"] = bool(
                                tag.entry.d_val & ENUM_DT_FLAGS_1["DF_1_NODEFLIB"]
                            )
                            file_details["elfDynamicFlags1"].append(dt_flags_1_entry)
        except ELFParseError as e:
            logger.warning(f"Error while parsing ELF sections in {filename}: {e!r}")

        # Check for presence of special segments (e.g. PT_GNU_RELRO)
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_GNU_RELRO":
                file_details["elfGnuRelro"] = True
            elif segment["p_type"] == "PT_DYNAMIC":
                for tag in segment.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        # Shared libraries
                        file_details["elfDependencies"].add(tag.needed)

        # Ensure the set of dependencies is JSON-encodable, and has a stable ordering
        file_details["elfDependencies"] = sorted(file_details["elfDependencies"])

        if elf["e_type"] == "ET_EXEC":
            file_details["elfIsExe"] = True
        else:
            file_details["elfIsExe"] = False

        if elf["e_type"] == "ET_DYN":
            file_details["elfIsLib"] = True
        else:
            file_details["elfIsLib"] = False

        if elf["e_type"] == "ET_REL":
            file_details["elfIsRel"] = True
        else:
            file_details["elfIsRel"] = False

        if elf["e_type"] == "ET_CORE":
            file_details["elfIsCore"] = True
        else:
            file_details["elfIsCore"] = False

        return file_details


def get_elf_ident_from_file_header(f, little_endian) -> dict:
    # Details on ELF header information/format:
    # https://man7.org/linux/man-pages/man5/elf.5.html
    # https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#File_header
    e_ident = {}

    # EI_CLASS (32 or 64-bit architecture)
    f.seek(4)
    e_ident["EI_CLASS"] = struct.unpack("B", f.read(1))[0]
    # EI_DATA (file encoding/endianness)
    f.seek(5)
    e_ident["EI_DATA"] = struct.unpack("B", f.read(1))[0]
    # EI_VERSION (version number of ELF specification)
    f.seek(6)
    e_ident["EI_VERSION"] = struct.unpack("B", f.read(1))[0]
    # EI_OSABI
    f.seek(7)
    e_ident["EI_OSABI"] = struct.unpack("B", f.read(1))[0]
    # EI_ABIVERSION
    f.seek(8)
    e_ident["EI_ABIVERSION"] = struct.unpack("B", f.read(1))[0]
    # E_MACHINE
    f.seek(18)
    isa_data = f.read(2)
    if little_endian:
        e_ident["E_MACHINE"] = struct.unpack("<H", isa_data)[0]
    else:
        e_ident["E_MACHINE"] = struct.unpack(">H", isa_data)[0]

    return e_ident
