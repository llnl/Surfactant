# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..utils.capture_time import validate_capture_time
from ._comment import CommentEntry
from ._file import File
from ._name import NameEntry

# pylint: disable=too-many-instance-attributes


@dataclass
class Hardware:
    UUID: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: Optional[List[NameEntry]] = None
    captureTime: Optional[str] = None
    countryOfOrigin: Optional[List[str]] = None
    countryOfOriginSource: Optional[str] = None
    quantity: Optional[int] = None
    description: Optional[str] = None
    vendor: Optional[List[str]] = None
    identifiers: Optional[List[str]] = None
    hardwareType: Optional[List[str]] = None
    comments: Optional[List[CommentEntry]] = None
    metadata: List[Dict[str, Any]] = field(default_factory=list)
    supplementaryFiles: Optional[List[File]] = None
    packageType: Optional[str] = None
    boardLocation: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate captureTime against the CyTRICS hardware schema requirement."""

        # Validate UUID format
        try:
            uuid.UUID(self.UUID)
        except (ValueError, TypeError):
            raise ValueError(f"UUID must be a valid UUID string; got {self.UUID!r}")

        self.captureTime = validate_capture_time(self.captureTime, nullable=True)

        if self.name is not None:
            if not isinstance(self.name, list):
                raise TypeError("name must be a list or None")
            for item in self.name:
                if not isinstance(item, NameEntry):
                    raise TypeError("All items in name must be NameEntry objects")

        if (self.countryOfOrigin is None) != (self.countryOfOriginSource is None):
            raise ValueError(
                "countryOfOrigin and countryOfOriginSource must both be set or both be None"
            )

        if self.quantity is not None and not isinstance(self.quantity, int):
            raise TypeError("quantity must be a number or None")

        if self.countryOfOrigin is not None:
            if not isinstance(self.countryOfOrigin, list):
                raise TypeError("countryOfOrigin must be a list of strings")
            if not all(isinstance(c, str) for c in self.countryOfOrigin):
                raise TypeError("countryOfOrigin must be a list of strings")
            if len(self.countryOfOrigin) < 1:
                raise ValueError("countryOfOrigin must contain at least one item when provided")

        string_fields = ["countryOfOriginSource", "description", "packageType"]
        for field_name in string_fields:
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string or None")

        list_string_fields = [
            "vendor",
            "identifiers",
            "hardwareType",
            "boardLocation",
        ]

        for field_name in list_string_fields:
            value = getattr(self, field_name)
            if value is not None:
                if not isinstance(value, list):
                    raise TypeError(f"{field_name} must be a list")
                for item in value:
                    if not isinstance(item, str):
                        raise TypeError(f"All items in {field_name} must be strings")

        if self.comments is not None:
            if not isinstance(self.comments, list):
                raise TypeError("comments must be a list or None")
            for item in self.comments:
                if not isinstance(item, CommentEntry):
                    raise TypeError("All items in comments must be CommentEntry objects")

        if self.supplementaryFiles is not None:
            if not isinstance(self.supplementaryFiles, list):
                raise TypeError("supplementaryFiles must be a list or None")
            for item in self.supplementaryFiles:
                if not isinstance(item, File):
                    raise TypeError("All items in supplementaryFiles must be File objects")

        if not isinstance(self.metadata, list):
            raise TypeError("metadata must be a list")

        for item in self.metadata:
            if not isinstance(item, dict):
                raise TypeError("All items in metadata must be objects (dicts)")
