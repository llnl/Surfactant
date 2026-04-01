# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass
from typing import List, Optional

from ..utils.capture_time import validate_capture_time

# pylint: disable=too-many-instance-attributes


@dataclass
class File:
    filePath: str
    captureTime: str
    description: str = ""
    category: str = ""
    capturedBy: str = ""
    source: str = ""
    methodOfAcquisition: Optional[List[str]] = None

    def __post_init__(self) -> None:
        """Validate against the CyTRICS file schema requirements."""

        if not isinstance(self.filePath, str):
            raise TypeError("filePath must be a string")

        if len(self.filePath) < 5:
            raise ValueError("filePath must be at least 5 characters long")

        string_fields = ["description", "category", "capturedBy", "source"]
        for field_name in string_fields:
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string")

        if not isinstance(self.captureTime, str):
            raise TypeError("captureTime must be a string")

        self.captureTime = validate_capture_time(self.captureTime, nullable=False)

        if self.methodOfAcquisition is not None:
            if not isinstance(self.methodOfAcquisition, list):
                raise TypeError("methodOfAcquisition must be a list or None")
            for item in self.methodOfAcquisition:
                if not isinstance(item, str):
                    raise TypeError("All items in methodOfAcquisition must be strings")
