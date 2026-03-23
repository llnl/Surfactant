# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT


# from pathlib import Path
import io
import platform
import re
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

import surfactant.plugin
from surfactant.context import ContextEntry
from surfactant.sbomtypes import SBOM, Software

try:
    from qiling import Qiling
    from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
    from qiling.extensions import pipe

    QILING_AVAILABLE = True
except ImportError:
    QILING_AVAILABLE = False
    logger.warning("qiling not installed. QilingExec plugin will be disabled.")

# Regex for version checking is currently looking
# for 1+ alphanumeric character(s), followed by a
# period, followed by 1+ alphanumeric character(s).
# This is only being done on line 1 of stdout.
versionRegex = re.compile(r"[a-zA-Z0-9]+\.[a-zA-Z0-9]+")


def grab_version(fd: io.BytesIO, regex: re.Pattern[str]) -> Optional[Tuple[str, str]]:
    """Returns a tuple of the word in the first line of fd that matches the given regex pattern and the entire first line"""
    output = fd.getvalue().decode()
    lines = output.splitlines()
    words = lines[0].split(" ")
    for j in words:
        if versionRegex.search(j):
            return (j, lines[0])
    return ("", lines[0])


def env_mismatch(filetype: str, os: QL_OS) -> bool:
    if "PE" in filetype and os != QL_OS.WINDOWS:
        return True
    if "ELF" in filetype and os in (QL_OS.WINDOWS, QL_OS.DOS):
        return True
    return False


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: List[str],
    software_field_hints: List[Tuple[str, object, int]],
    current_context: Optional[ContextEntry],
) -> Optional[Dict[str, Any]]:
    """Extracts information from the given file to add to the given software entry. Return an
    object to be included as part of the metadata field, and potentially used as part of
    selecting default values for other Software entry fields. Returning `None` will not add
    anything to the Software entry metadata.

    Args:
        sbom (SBOM): The SBOM that the software entry is part of. Can be used to add observations or analysis data.
        software (Software): The software entry the gathered information will be added to.
        filename (str): The full path to the file to extract information from.
        filetype (List[str]): File type information based on magic bytes and other heuristics.
        context_queue (Queue[ContextEntry]): Modifiable queue of entries typically initialized from the input specimen
            config file. Plugins can add new entries to the queue to make Surfactant process additional files/folders.
            Existing plugins should still work without adding this parameter.
        current_context (Optional[ContextEntry]): The ContextEntry object from the queue whose files are currently being
            processed (modifying it is considered undefined behavior and should be avoided). Most plugins do not need to
            use this parameter.
        children (List[Software]): List of additional software entries to include in the SBOM. Plugins can add
            additional entries, though if the plugin extracts files to a temporary directory, the context argument
            should be used to have Surfactant process the files instead.
        software_field_hints (List[tuple[str, str]]): List of tuples containing the name of a software entry field,
            a suggested value for it, and a confidence level. Plugins can use this information to suggest values for
            software entry fields by adding entries to this list. The one with the highest confidence level for a
            field will be selected.
        omit_unrecognized_types (bool): Whether files with types that are not recognized by Surfactant should be
            left out of the SBOM. When a plugin is adding additional context entries to the queue, it should typically
            default to propagating this value to the new context entries that it creates.

    Returns:
        object: An object to be added to the metadata field for the software entry. May be `None` to add no metadata.
    """
    # Stop if Qiling is unavailable or the file type isn't some variety of executable
    if not QILING_AVAILABLE or not ("ELF" in filetype or "PE" in filetype):
        return None
    # If there is no current context, create one so that the get_pconf function can be used
    if not current_context:
        current_context = ContextEntry()
    # Set up configuration
    (def_mount, def_os) = (r"/", r"Linux") if platform.system() == "Linux" else ("C:\\", "Windows")
    mountPoint = current_context.get_pconf(__name__, "mountPrefix", def_mount)
    arch = current_context.get_pconf(__name__, "arch_type", QL_ARCH.X8664)
    os = current_context.get_pconf(__name__, "os_type", QL_OS.LINUX)

    # Prevent running binaries when environment doesn't match
    if env_mismatch(filetype, os):
        return None

    fd = pipe.SimpleStringBuffer()
    ql = Qiling(
        argv=[filename, "--version"],
        rootfs=mountPoint,
        archtype=arch,
        ostype=os,
        verbose=QL_VERBOSE.OFF,
    )
    ql.os.stdout = fd
    # Emulate executable
    ql.run(timeout=100000)
    file_details: Dict[str, Any] = {"qilingexec": {}}
    (version, file_details["qilingexec"]["stdout"]) = grab_version(fd, versionRegex)
    if version:
        software_field_hints.append(("version", version, 80))
        file_details["qilingexec"]["version"] = version
    return file_details
