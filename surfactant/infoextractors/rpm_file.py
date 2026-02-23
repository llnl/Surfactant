# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# import struct
# from pathlib import Path
# from queue import Queue                       # Present for use in future extraction implementation
from typing import Any, Dict, List, Optional, Tuple

import rpmfile
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software

# from surfactant.context import ContextEntry   # Present for use in future extraction implementation


def supports_file(filetype) -> bool:
    """Returns if filetype contains "RPM Package" """
    return "RPM Package" in filetype


# Currently unused, keeping in case we'd like to use the filedigestalgo field instead of hash length
def algo_from_id(algo_identifier: int) -> str:
    """Grabs the hashing algorithm used for payload files.

    Args:
        algo_identifier (int): Integer in RPM file associated with a hashing algorithm
    """
    if algo_identifier == 0:
        return "md5"
    if algo_identifier == 8:
        return "sha256"
    return f"Unknown: {algo_identifier}"


def algo_from_len(input_hash: bytes) -> Optional[str]:
    """Grabs hashing algorithm from length. Do not use when sha3 hashes are a possibility

    Args:
        length (int): Length of hashing algorithm
    """
    length = len(input_hash.decode())
    if length == 0:
        return None
    if length == 36:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    if length == 128:
        return "sha512"
    raise ValueError(f"case for: {input_hash.decode()} not implemented for algo_from_len")


def get_files(
    directories: List[bytes], files: List[bytes], indicies: List[int], hashes: List[bytes]
) -> Tuple[Dict[Any, Any], Optional[str]]:
    """Extracts files from the given directories and files list.

    Args:
        directories (List[bytes]): List of directory paths in bytes.
        files (List[bytes]): List of file names in bytes.
        indicies (List[bytes]): Directory associated with current file.
        hashes: (List[bytes]): Hash for each file
    Returns:
        List of extracted file paths and the hash used for them.
    """
    extracted_files = {}
    index = 0
    hash_used = None
    # If there is only one index, return as an integer, not a list of integers
    if isinstance(indicies, int):
        directory = directories[indicies].decode()
        file_name = files[index].decode()
        file_hash = hashes[index].decode()
        extracted_files[f"{directory}{file_name}"] = file_hash
        hash_used = algo_from_len(hashes[index])
    else:
        while index < len(indicies):
            directory = directories[indicies[index]].decode()
            file_name = files[index].decode()
            file_hash = hashes[index].decode()
            extracted_files[f"{directory}{file_name}"] = file_hash
            if not hash_used:
                hash_used = algo_from_len(hashes[index])
            index += 1
    return (extracted_files, hash_used)


def combine_lists(key_list: List[bytes], value_list: List[bytes]) -> Dict:
    """Combines 2 lists into a single dictionary - matching on index.

    Args:
        key_list (List[bytes]): List to use as key.
        value_list (List[bytes]): List to use as value.
    Returns:
        Combined dictionary.
    """
    result = {}
    if not key_list or not value_list or len(key_list) != len(value_list):
        return result
    index = 0
    while index < len(key_list):
        name = key_list[index].decode()
        version = value_list[index].decode()
        result[name] = version
        index += 1
    return result


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: List[str],
    software_field_hints: List[Tuple[str, object, int]],
    # context_queue: "Queue[ContextEntry]",     # Present for use in future extraction implementation
    # current_context: Optional[ContextEntry],
) -> object:
    if not supports_file(filetype):
        return None
    rpm_info = extract_rpm_info(filename)

    for key in rpm_info["rpm"]:
        software_field_hints.append((key, rpm_info["rpm"][key], 80))
    return rpm_info


def extract_rpm_info(filename: str) -> Dict[str, Any]:
    """Extracts fields from the header of an RPM Package.

    Args:
        filename: Path to file to extract information from.
    Returns:
        A dictionary of all fields found in the RPM header.
    """
    file_details: Dict[str, Any] = {}
    with rpmfile.open(filename) as rpm:
        header = rpm.headers
        file_details["rpm"] = {}
        # If any additional fields are desired that have values of single strings, just add the field to this list
        simple_keys = [
            "name",
            "sourcerpm",
            "version",
            "release",
            "summary",
            "description",
            "rpmversion",
            "copyright",
            "os",
            "arch",
            "target",
            "url",
            "archive_format",
            "archive_compression",
            "optflags",
            "sha256",
        ]
        for key in simple_keys:
            if key in header:
                file_details["rpm"][key] = header[key].decode()
        # Handle sections that aren't simple strings
        complex_keys = {
            "requirename": "requireversion",
            "conflict": "conflictversion",
            "obsoletes": "obsoleteversion",
            "enhancename": "enhanceversion",
            "suggestname": "suggestversion",
            "recommendname": "recommendversion",
            "supplementname": "supplementversion",
            "provides": "provideversion",
        }
        for key, value in complex_keys.items():
            if key in header:
                file_details["rpm"][key] = combine_lists(header[key], header[value])
        # md5 field in rpm file may be a different algorithm
        try:
            md5_algo = algo_from_len(header["md5"])
        except ValueError as e:
            logger.error(
                f"Issue when extracting top-level md5 hash for rpm package: {filename}\nError raised: {e}"
            )
        if isinstance(md5_algo, str):
            file_details["rpm"][md5_algo] = header["md5"].decode()
        if "buildtime" in header:
            file_details["rpm"]["buildtime"] = header["buildtime"]
        if "basenames" in header:
            file_hash_location = ""
            if "filedigests" in header:
                file_hash_location = "filedigests"
            else:
                file_hash_location = "filemd5s"
            # Handling error here so filename can be included in error output
            try:
                # Storing which algorithm is used for the file hashes
                file_algo = ""
                (file_details["rpm"]["associated_files"], file_algo) = get_files(
                    header["dirnames"],
                    header["basenames"],
                    header["dirindexes"],
                    header[file_hash_location],
                )
                file_details["rpm"]["file_algo"] = file_algo
            except ValueError as e:
                logger.error(
                    f"Error when extracting hash algo from payload files from {filename}\nError: {e}"
                )
        return file_details
