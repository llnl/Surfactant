# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

# TODO: Ensure all the relevant information available is extracted from here
# https://lief.re/doc/stable/api/python/macho.html

"""
Config Options:
    include_bindings_exports(bool): Include bindings/exports information for Mach-O files.
    include_signature_content(bool): Include signature content for Mach-O files.
"""

from sys import modules
from typing import Any

from loguru import logger

try:
    import lief
except ModuleNotFoundError:
    pass

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.infoextractors.__macho_cpuSubtypes import get_cpu_subtype_name, get_cpu_type_name
from surfactant.sbomtypes import SBOM, Software

__config_manager = ConfigManager()

__include_bindings_exports = __config_manager.get("macho", "include_bindings_exports", False)
__include_signature_content = __config_manager.get("macho", "include_signature_content", False)


def supports_file(filetype: list[str]) -> bool:
    supported_types = ("MACHOFAT", "MACHOFAT64", "MACHO32", "MACHO64")
    for ft in filetype:
        if ft in supported_types:
            return True
    return False


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    if not supports_file(filetype):
        return None
    if "lief" not in modules:
        logger.warning("LIEF not installed - Skipped extracting Mach-O file info.")
        return None
    return extract_mach_o_info(filename)


def extract_mach_o_info(filename: str) -> object:
    try:
        binaries = lief.MachO.parse(filename)
    except OSError:
        return {}

    file_details: dict[str, Any] = {"OS": "MacOS", "numBinaries": binaries.size, "binaries": []}

    # Iterate over all binaries in the FAT binary
    for binary in binaries:
        header = binary.header
        details = {
            "format": binary.format.__name__,
            "header": {
                "cpuType": get_cpu_type_name(header.cpu_type.value),
                "cpuTypeValue": header.cpu_type.value,
                "cpuSubtype": get_cpu_subtype_name(header.cpu_type.value, 20 + header.cpu_subtype),
                "cpuSubtypeValue": header.cpu_subtype,
                "fileType": header.file_type.__name__,
                "fileTypeValue": header.file_type.value,
                "flags": [flag.__name__ for flag in header.flags_list],
                "numCommands": header.nb_cmds,
            },
            "build": {},
            "signature": {},
            "dependencies": [],
            "rpaths": [],
            "dyld": {},
            "encryption": {},
        }

        # Extract info from build version
        if binary.has_build_version:
            build = binary.build_version
            details["build"] = {
                "platform": build.platform.__name__,
                "platformValue": build.platform.value,
                "minOSVersion": ".".join(map(str, build.minos)),
                "sdkVersion": ".".join(map(str, build.sdk)),
                "tools": [],
            }
            for tool in build.tools:
                details["build"]["tools"].append(
                    {"tool": tool.tool.__name__, "version": ".".join(map(str, tool.version))}
                )

        # Extract info from code signature
        if binary.has_code_signature or binary.has_code_signature_dir:
            if binary.has_code_signature:
                signature = binary.code_signature
                signature_type = "Default"
            else:
                signature = binary.code_signature_dir
                signature_type = "LC_DYLIB_CODE_SIGN_DRS"

            details["signature"] = {
                "offset": signature.data_offset,
                "size": signature.data_size,
                "type": signature_type,
            }

            # signature is a memoryview in lief, turn it into a hex string
            # this avoid serialization errors later when outputting an SBOM
            if __include_signature_content and hasattr(signature.content, "hex"):
                details["signature"]["content"] = signature.content.hex()
            else:
                details["signature"]["content"] = None

        # Extract library dependencies
        for library in binary.libraries:
            details["dependencies"].append(
                {
                    "name": library.name,
                    "currentVersion": ".".join(map(str, library.current_version)),
                    "compatibilityVersion": ".".join(map(str, library.compatibility_version)),
                }
            )

        # rpath info
        if binary.has_rpath:
            for rpath in binary.rpaths:
                details["rpaths"].append(rpath.path)

        # dyld info
        if binary.has_dylinker:
            details["dyld"]["linker"] = binary.dylinker.name
        if binary.has_dyld_environment:
            details["dyld"]["environment"] = binary.dyld_environment.__name__
            details["dyld"]["environmentValue"] = binary.dyld_environment.value
        # https://github.com/qyang-nj/llios/blob/main/dynamic_linking/chained_fixups.md
        if __include_bindings_exports:
            if binary.has_dyld_info:
                details["dyld"]["info"] = {
                    "bindings": [],
                    "exports": [],
                }
                bindings = get_bindings(binary.dyld_info.bindings)
                details["dyld"]["info"]["bindings"] = bindings
                for export in binary.dyld_info.exports:
                    details["dyld"]["info"]["exports"].append(
                        {"address": export.address, "kind": export.kind.__name__}
                    )
            elif binary.has_dyld_exports_trie and binary.has_dyld_chained_fixups:
                details["dyld"]["exports"] = []
                for export in binary.dyld_exports_trie.exports:
                    details["dyld"]["exports"].append(
                        {"address": export.address, "kind": export.kind.__name__}
                    )
                fixups = binary.dyld_chained_fixups
                details["dyld"]["chainedFixups"] = {"chainedStartsInSegment": [], "bindings": []}
                for chainedStarts in fixups.chained_starts_in_segments:
                    details["dyld"]["chainedFixups"]["chainedStartsInSegment"].append(
                        {
                            "maxValidPointer": chainedStarts.max_valid_pointer,
                            "pageSize": chainedStarts.page_size,
                            "pointerFormat": chainedStarts.pointer_format.__name__,
                            "pointerFormatValue": chainedStarts.pointer_format.value,
                            "segment": chainedStarts.segment.name,
                        }
                    )
                bindings = get_bindings(fixups.bindings)
                details["dyld"]["chainedFixups"]["bindings"] = bindings

        # encryption info
        if binary.has_encryption_info:
            encryption = binary.encryption_info
            details["encryption"] = {
                "system": encryption.crypt_id,
                "offset": encryption.crypt_offset,
                "size": encryption.crypt_size,
            }
        file_details["binaries"].append(details)

    return file_details


def get_bindings(bindings):
    bindings_info = []
    for binding in bindings:
        # ChainedFixups and dyld info store bindings in the same format in LIEF
        info = {
            "addend": binding.addend,
            "address": binding.address,
            "isWeakImport": binding.weak_import,
        }
        if binding.has_library:
            info["library"] = binding.library.name
        if binding.has_segment:
            info["segment"] = binding.segment.name
        bindings_info.append(info)
    return bindings_info


@surfactant.plugin.hookimpl
def settings_name() -> str | None:
    return "macho"
