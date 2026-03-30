# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import platform
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field, fields
from typing import Any, List, Optional

from dataclasses_json import dataclass_json

from surfactant.fileinfo import calc_file_hashes, get_file_info

from ..utils.capture_time import utc_now_rfc3339, validate_capture_time
from ._file import File
from ._provenance import SoftwareComponentProvenance, SoftwareProvenance

# pylint: disable=too-many-instance-attributes


@dataclass_json
@dataclass
class SoftwareComponent:
    name: str
    captureTime: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[List[str]] = None
    description: Optional[str] = None
    comments: Optional[str] = None
    metadata: Optional[List[object]] = None
    supplementaryFiles: Optional[List[File]] = None
    provenance: Optional[List[SoftwareComponentProvenance]] = None
    recordedInstitution: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate captureTime against the software component schema requirement."""
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)


@dataclass_json
@dataclass
class Software:
    UUID: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: Optional[str] = None
    size: Optional[int] = None
    fileName: Optional[List[str]] = None
    installPath: Optional[List[str]] = None
    containerPath: Optional[List[str]] = None
    captureTime: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[List[str]] = None
    description: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    relationshipAssertion: Optional[str] = (
        None  # enum: Unknown, Root, Partial, Known; default=Unknown
    )
    comments: Optional[str] = None
    metadata: Optional[List[object]] = None
    supplementaryFiles: Optional[List[File]] = None
    provenance: Optional[List[SoftwareProvenance]] = None
    recordedInstitution: Optional[str] = None
    components: Optional[List[SoftwareComponent]] = None

    def __post_init__(self) -> None:
        """Validate captureTime against the software schema requirement."""
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)

    def _update_field(self, field_name: str, value: Any):
        if value in ["", " ", None]:
            return

        if field_name == "captureTime":
            value = validate_capture_time(value, nullable=True, field_name=field_name)

        setattr(self, field_name, value)

    @staticmethod
    def create_software_from_file(filepath) -> Software:
        file_hashes = calc_file_hashes(filepath)
        stat_file_info = get_file_info(filepath)

        # add basic file info, and information on what collected the information listed for the file to aid later processing
        collection_info = {
            "collectedBy": "Surfactant",
            "collectionPlatform": platform.platform(),
            "fileInfo": {
                "mode": stat_file_info["filemode"],
                "hidden": stat_file_info["filehidden"],
            },
        }

        sw = Software(
            sha1=file_hashes["sha1"],
            sha256=file_hashes["sha256"],
            md5=file_hashes["md5"],
            fileName=[pathlib.Path(filepath).name],
            installPath=[],
            containerPath=[],
            size=stat_file_info["size"],
            captureTime=utc_now_rfc3339(),
            version="",
            vendor=[],
            description="",
            relationshipAssertion="Unknown",
            comments="",
            metadata=[collection_info],
            supplementaryFiles=[],
            provenance=None,
            components=[],
        )
        return sw

    # TODO: figure out how to handle merging an SBOM with manual additions
    def merge(self, sw: Software):
        # hashes should be confirmed to match before calling this function
        # check to make sure entry isn't an exact duplicate
        if sw and self != sw:
            # leave UUID and captureTime the same
            single_value_fields = [
                "name",
                "comments",
                "version",
                "description",
                "relationshipAssertion",
                "recordedInstitution",
            ]
            array_fields = [
                "containerPath",
                "fileName",
                "installPath",
                "vendor",
                "provenance",
                "metadata",
                "supplementaryFiles",
                "components",
            ]
            for fld in fields(self):
                if fld.name in single_value_fields:
                    current_value = getattr(self, fld.name)
                    new_value = getattr(sw, fld.name)
                    if current_value != new_value:
                        self._update_field(fld.name, new_value)
                # for lists, append new values that we don't currently have
                if fld.name in array_fields:
                    current_arr = getattr(self, fld.name)
                    new_arr = getattr(sw, fld.name)
                    # if the multi-value fields differ, the one with new values *must* be Iterable
                    if current_arr != new_arr and isinstance(new_arr, Iterable):
                        # if our field is not iterable, initialize it as a new list
                        if current_arr is None:
                            setattr(self, fld.name, [])
                            current_arr = getattr(self, fld.name)
                        for new_value in new_arr:
                            # special case, UUID in containerPaths need updating to match our UUID
                            if fld.name == "containerPath":
                                if new_value.startswith(sw.UUID):
                                    new_value = new_value.replace(sw.UUID, self.UUID)
                            if new_value not in current_arr:
                                current_arr.append(new_value)

        return self.UUID, sw.UUID

    @staticmethod
    def check_for_hash_collision(soft1: Optional[Software], soft2: Optional[Software]) -> bool:
        if not soft1 or not soft2:
            return False
        # A hash collision occurs if one or more but less than all hashes match or
        # any hash matches but the filesize is different
        collision = False
        if soft1.sha256 == soft2.sha256 or soft1.sha1 == soft2.sha1 or soft1.md5 == soft2.md5:
            # Hashes can be None; make sure they aren't before checking for inequality
            if soft1.sha256 and soft2.sha256 and soft1.sha256 != soft2.sha256:
                collision = True
            elif soft1.sha1 and soft2.sha1 and soft1.sha1 != soft2.sha1:
                collision = True
            elif soft1.md5 and soft2.md5 and soft1.md5 != soft2.md5:
                collision = True
            elif soft1.size != soft2.size:
                collision = True
        return collision
