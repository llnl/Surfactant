# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass

# pylint: disable=too-many-instance-attributes


@dataclass
class File:
    filePath: str
    description: str
    category: str
    capturedBy: str
    captureTime: str
    source: str
    methodOfAcquisition: list[str] | None = None
