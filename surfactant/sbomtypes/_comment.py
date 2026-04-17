# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional

from ..utils.capture_time import validate_capture_time


@dataclass
class CommentEntry:
    comment: str
    fieldName: Optional[str] = None
    author: Optional[str] = None
    timestamp: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate timestamp against the CyTRICS comment schema requirement."""
        if not isinstance(self.comment, str):
            raise ValueError("comment must be a string")

        if self.fieldName is not None and not isinstance(self.fieldName, str):
            raise TypeError("fieldName must be a string or None")

        if self.author is not None and not isinstance(self.author, str):
            raise TypeError("author must be a string or None")

        if self.timestamp is not None:
            if not isinstance(self.timestamp, str):
                raise TypeError("timestamp must be a string or None")

            self.timestamp = validate_capture_time(self.timestamp, nullable=True)

    @classmethod
    def from_hint(cls, value: Any) -> "CommentEntry":
        if isinstance(value, cls):
            return value

        if isinstance(value, str):
            return cls(comment=value)

        if isinstance(value, Mapping):
            if "comment" not in value:
                raise TypeError("comment hint mappings must contain 'comment'")
            return cls(**dict(value))

        raise TypeError("comment hints must be CommentEntry, mapping, or string")
