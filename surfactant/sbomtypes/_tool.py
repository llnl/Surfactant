# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass


@dataclass
class Tool:
    toolName: str
    version: str = ""
    externalReference: str = ""

    def validate(self) -> None:
        if not isinstance(self.toolName, str):
            raise TypeError("toolName must be a string")

        if not isinstance(self.version, str):
            raise TypeError("version must be a string")

        if not isinstance(self.externalReference, str):
            raise TypeError("externalReference must be a string")
