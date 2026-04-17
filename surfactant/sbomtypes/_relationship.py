# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import uuid
from dataclasses import dataclass
from typing import List, Optional

from ._comment import CommentEntry


def validate_uuid(value: str) -> str:
    try:
        uuid.UUID(value)
    except (ValueError, TypeError) as err:
        raise ValueError(f"Invalid UUID: {value!r}") from err

    return value


@dataclass
class Relationship:
    xUUID: str
    yUUID: str
    relationship: str
    comments: Optional[List[CommentEntry]] = None

    def __post_init__(self) -> None:
        validate_uuid(self.xUUID)
        validate_uuid(self.yUUID)

        if not isinstance(self.relationship, str):
            raise TypeError("relationship must be a string")

        if self.comments is not None:
            if not isinstance(self.comments, list):
                raise TypeError("comments must be a list or None")
            for item in self.comments:
                if not isinstance(item, CommentEntry):
                    raise TypeError("All items in comments must be CommentEntry objects")

    def __hash__(self) -> int:
        return hash(repr(self))
