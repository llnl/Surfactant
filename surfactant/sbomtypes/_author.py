# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass


@dataclass
class Author:
    authorType: str = ""
    authorName: str = ""

    def validate(self) -> None:
        if not isinstance(self.authorType, str):
            raise TypeError("authorType must be a string")

        if not isinstance(self.authorName, str):
            raise TypeError("authorName must be a string")
