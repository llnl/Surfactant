# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field, fields

from ._provenance import SystemProvenance

# pylint: disable=too-many-instance-attributes


@dataclass
class System:
    UUID: str = field(default_factory=lambda: str(uuid.uuid4()))
    captureStart: int | None = None
    captureEnd: int | None = None
    name: str | None = None
    officialName: str | None = None
    vendor: list[str] | None = None
    description: str | None = None
    provenance: list[SystemProvenance] = field(default_factory=list)

    def merge(self, sy: System):
        if sy and self != sy:
            # leave UUID and captureTime the same
            single_value_fields = [
                "captureStart",
                "captureEnd",
                "name",
                "officialName",
                "description",
            ]
            array_fields = ["vendor", "provenance"]
            for fld in fields(self):
                if fld.name in single_value_fields:
                    current_value = getattr(self, fld.name)
                    new_value = getattr(sy, fld.name)
                    update = None
                    # If field is captureStart or captureEnd, replace if increasing time bounds
                    if fld.name == "captureStart":
                        update = new_value if new_value < current_value else current_value
                    elif fld.name == "captureEnd":
                        update = new_value if new_value > current_value else current_value
                    else:
                        update = new_value if new_value != current_value else current_value
                    self._update_field(fld.name, update)
                # for lists, append new values that we don't currently have
                if fld.name in array_fields:
                    current_arr = getattr(self, fld.name)
                    new_arr = getattr(sy, fld.name)
                    # if the multi-value fields differ, the one with new values *must* be Iterable
                    if current_arr != new_arr and isinstance(new_arr, Iterable):
                        # if our field is not iterable, initialize it as a new list
                        if current_arr is None:
                            setattr(self, fld.name, [])
                            current_arr = getattr(self, fld.name)
                        for new_value in new_arr:
                            # special case, UUID in containerPaths need updating to match our UUID
                            if new_value not in current_arr:
                                current_arr.append(new_value)
        return self.UUID, sy.UUID
