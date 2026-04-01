# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass
from typing import Optional


@dataclass
class Tool:
    toolName: str
    version: str = ""
    externalReference: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.toolName, str):
            raise TypeError("toolName must be a string")

        if not isinstance(self.version, str):
            raise TypeError("version must be a string")

        if not isinstance(self.externalReference, str):
            raise TypeError("externalReference must be a string")