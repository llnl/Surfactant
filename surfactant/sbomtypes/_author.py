# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass

@dataclass
class Author:
    authorType: str = ""
    authorName: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.authorType, str):
            raise TypeError("authorType must be a string")

        if not isinstance(self.authorName, str):
            raise TypeError("authorName must be a string")