# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
import string
from typing import List, Optional

import surfactant.plugin
from surfactant import ContextEntry


def check_motorola(current_line):
    current_line = current_line.strip()
    if len(current_line) < 1:
        return False
    if current_line[0] != "S" and current_line[0] != "s":
        return False
    for x in range(1, len(current_line)):
        if current_line[x] not in string.hexdigits:
            return False
    return True


def check_intel(current_line):
    current_line = current_line.strip()
    if len(current_line) < 1:
        return False
    if current_line[0] != ":":
        return False
    for x in range(1, len(current_line)):
        if current_line[x] not in string.hexdigits:
            return False
    return True


# extensions from:
# https://en.wikipedia.org/wiki/Intel_HEX
# - not included: all p00 to pff extensions
# https://en.wikipedia.org/wiki/SREC_(file_format)
hex_file_extensions = [
    ".hex",
    ".mcs",
    ".h86",
    ".hxl",
    ".hxh",
    ".obl",
    ".obh",
    ".ihex",
    ".ihe",
    ".ihx",
    ".a43",
    ".a90",
    ".s-record",
    ".srecord",
    ".s-rec",
    ".srec",
    ".s19",
    ".s28",
    ".s37",
    ".s",
    ".s1",
    ".s2",
    ".s3",
    ".sx",
    ".exo",
    ".mot",
    ".mxt",
]


@surfactant.plugin.hookimpl
def identify_file_type(
    filepath: str, context: Optional[ContextEntry] = None
) -> Optional[List[str]]:
    file_suffix = pathlib.Path(filepath).suffix.lower()
    # quick exit based on file extension
    if file_suffix not in hex_file_extensions:
        return None
    try:
        with open(filepath, "r") as f:
            percent_intel = 0
            percent_motorola = 0
            for _ in range(100):
                curr = f.readline()
                if not curr:
                    break
                if check_motorola(curr):
                    percent_motorola += 1
                elif check_intel(curr):
                    percent_intel += 1
            if percent_intel > percent_motorola:
                return ["INTEL_HEX"]
            if percent_motorola > percent_intel:
                return ["MOTOROLA_SREC"]
            return None

    except (FileNotFoundError, UnicodeDecodeError):
        return None
