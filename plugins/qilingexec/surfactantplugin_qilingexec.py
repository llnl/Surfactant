# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT


# from pathlib import Path
import io
import platform
import re
from typing import Any

from loguru import logger

import surfactant.plugin
from surfactant.context import ContextEntry
from surfactant.sbomtypes import SBOM, Software

try:
    from qiling import Qiling
    from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
    from qiling.exception import QlErrorBase
    from qiling.extensions import pipe
    from unicorn import UcError  # , UC_ERR_FETCH_UNMAPPED

    QILING_AVAILABLE = True
except ImportError:
    QILING_AVAILABLE = False
    logger.warning("qiling not installed. QilingExec plugin will be disabled.")


def parse_stdout(fd: io.BytesIO, regex: re.Pattern[str]) -> tuple[str, str] | None:
    """Returns a tuple of the words in fd that match the given regex pattern with either the line the match was found or the first line if no match was found.

    Args:
        fd (io.BytesIO): File descriptor used as stdout or stderr when running an executable
        regex (re.Pattern[str]): Regular expression to check for matches against
    Returns:
        object(Optional[Tuple[str,str]]): If a match to the supplied regex is found in fd,
            returns the 'words' that match the regex and the line from fd where the match was found.
            If no match is found, returns an empty string and the first line from fd.
    """
    if fd and regex:
        stdout = fd.getvalue().decode().splitlines()
        if stdout:
            for line in stdout:
                if regex.search(line):
                    # Grab the first occurrence
                    ret_val = regex.search(line).group(0)
                    return (ret_val, line)
            return ("", stdout[0])
    return None


def handle_help(fd: io.BytesIO) -> list[str] | None:
    """Returns a string if there is anything in the input file descriptor

    Args:
        fd (io.BytesIO): File descriptor used as stdout or stderr when running an executable
    """
    if fd:
        lines = fd.getvalue().decode().splitlines()
        line_num = min(10, len(lines))
        return lines[:line_num]
    return None


def env_mismatch(filetype: str, os: QL_OS) -> bool:
    if "PE" in filetype and os != QL_OS.WINDOWS:
        return True
    if "ELF" in filetype and os in (QL_OS.WINDOWS, QL_OS.DOS):
        return True
    return False


def get_os_arch(context: ContextEntry, filetype: str, def_os) -> tuple[QL_OS, QL_ARCH] | None:
    """Returns a tuple of the OS and architecture to use for the binary associated with the current ContextEntry and checks that the current filetype matches the OS being used."""
    operating_system = context.get_pconf(__name__, "os_type", def_os)
    arch = context.get_pconf(__name__, "arch_type", "x64")

    os_conversion = {
        "linux": QL_OS.LINUX,
        "freebsd": QL_OS.FREEBSD,
        "macos": QL_OS.MACOS,
        "windows": QL_OS.WINDOWS,
        "uefi": QL_OS.UEFI,
        "dos": QL_OS.DOS,
        "evm": QL_OS.EVM,
        "qnx": QL_OS.QNX,
        "mcu": QL_OS.MCU,
        "blob": QL_OS.BLOB,
    }

    arch_conversion = {
        "x64": QL_ARCH.X8664,
        "x86": QL_ARCH.X86,
        "a8086": QL_ARCH.A8086,
        "arm32": QL_ARCH.ARM,
        "cortex_m": QL_ARCH.CORTEX_M,
        "aarch64": QL_ARCH.ARM64,
        "mips": QL_ARCH.MIPS,
        "evm": QL_ARCH.EVM,
        "riscv": QL_ARCH.RISCV,
        "riscv64": QL_ARCH.RISCV64,
        "ppc": QL_ARCH.PPC,
    }

    if not (operating_system in os_conversion and arch in arch_conversion):
        logger.error("QilingExec: OS or Arch not in expected values")
        return None
    # Prevent running binaries when environment doesn't match
    if env_mismatch(filetype, os_conversion[operating_system]):
        logger.warning(f"Trying to run qilingexec on {filetype} when OS is: {operating_system}")
        return None
    return (os_conversion[operating_system], arch_conversion[arch])


@surfactant.plugin.hookimpl
def extract_file_info(  # pylint: disable=too-many-positional-arguments
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: list[str],
    software_field_hints: list[tuple[str, object, int]],
    current_context: ContextEntry | None,
) -> dict[str, Any] | None:
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
    # Stop if Qiling is unavailable or the file type isn't some type of executable
    if not QILING_AVAILABLE or not ("ELF" in filetype or "PE" in filetype):
        return None
    # Set up configuration
    (def_mount, def_os) = (
        (r"/", r"linux") if platform.system() == "Linux" else (r"C:\\", r"windows")
    )
    mountPoint = current_context.get_pconf(__name__, "mount_prefix", def_mount)
    ver_arg_list = current_context.get_pconf(
        __name__, "ver_arg_list", ["--version", "-v", "-V", "version"]
    )
    os_arch_ret = get_os_arch(current_context, filetype, def_os)
    if os_arch_ret:
        (os, arch) = os_arch_ret
    else:
        return None
    timeout = current_context.get_pconf(__name__, "timeout", 150000)
    args_help = [filename, "--help"]
    reg_string = current_context.get_pconf(
        __name__, "regex", r"[0-9a-zA-Z\(\)]+( \([0-9a-zA-Z ]*\))? [0-9]+\.[0-9]+"
    )

    # Set up static variables for emulation
    regex = re.compile(reg_string)
    file_details: dict[str, Any] = {"qilingexec": {}}

    # Loop through all the potential version args
    for arg in ver_arg_list:
        # print(arg) # For debugging
        args_version = [filename, arg]
        out_version_fd = pipe.SimpleStringBuffer()
        err_version_fd = pipe.SimpleStringBuffer()
        ql_version = Qiling(
            argv=args_version,
            rootfs=mountPoint,
            archtype=arch,
            ostype=os,
            verbose=QL_VERBOSE.OFF,
            multithread=True,
        )
        ql_version.os.stdout = out_version_fd
        ql_version.os.stderr = err_version_fd
        # Emulate executable
        try:
            ql_version.run(timeout=timeout)
        except UcError as error:
            # This error occurs even during normal emulation
            logger.error(f"qilingexec ran into a(n) {error} exception when trying to run {arg}")
        except (QlErrorBase, NotImplementedError, AttributeError) as error:
            logger.error(f"qilingexec ran into a(n) {error} exception when trying to run {arg}")
            return None
        # If text was sent to stderr instead of stdout, use stderr for parsing
        result = parse_stdout(out_version_fd, regex) or parse_stdout(err_version_fd, regex)
        (match, file_details["qilingexec"]["stdout"]) = result or (None, None)
        if match:  # pylint: disable=no-else-break
            match_arr = match.split(" ")
            name = match_arr[0]
            version = match_arr[-1]
            software_field_hints.append(("version", version, 80))
            software_field_hints.append(("name", name, 10))
            file_details["qilingexec"]["version"] = version
            file_details["qilingexec"]["name"] = name
            break
        logger.info(f'No version information returned by {args_version} with "{arg}"')
        if not file_details["qilingexec"]["stdout"] and arg == ver_arg_list[-1]:
            return None

    out_help_fd = pipe.SimpleStringBuffer()
    err_help_fd = pipe.SimpleStringBuffer()
    ql_help = Qiling(
        argv=args_help,
        rootfs=mountPoint,
        archtype=arch,
        ostype=os,
        verbose=QL_VERBOSE.OFF,
        multithread=True,
    )
    ql_help.os.stdout = out_help_fd
    ql_help.os.stderr = err_help_fd
    # Emulate executable
    try:
        ql_help.run(timeout=timeout)
    except UcError as error:
        # This error occurs even during normal emulation
        logger.error(f"qilingexec ran into a(n) {error} exception when trying to run {args_help}")
    except (QlErrorBase, NotImplementedError, AttributeError) as error:
        logger.error(f"qilingexec ran into a(n) {error} exception when trying to run {args_help}")
        return None
    help_result = handle_help(out_help_fd) or handle_help(err_help_fd)
    file_details["qilingexec"]["help_stdout"] = help_result
    return file_details
