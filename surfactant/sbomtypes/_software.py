# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from __future__ import annotations

import pathlib
import platform
import uuid
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any, Dict, List, Optional

from dataclasses_json import dataclass_json

from surfactant.fileinfo import calc_file_hashes, get_file_info

from ..utils.capture_time import utc_now_rfc3339, validate_capture_time
from ._comment import CommentEntry
from ._file import File
from ._name import NameEntry

# pylint: disable=too-many-instance-attributes


class RelationshipAssertion(str, Enum):
    UNKNOWN = "Unknown"
    ROOT = "Root"
    PARTIAL = "Partial"
    KNOWN = "Known"


@dataclass_json
@dataclass
class Software:
    UUID: str = field(default_factory=lambda: str(uuid.uuid4()))
    softwareType: Optional[List[str]] = None
    name: Optional[List[NameEntry]] = None
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
    notHashable: Optional[bool] = None
    relationshipAssertion: Optional["RelationshipAssertion"] = RelationshipAssertion.UNKNOWN
    comments: Optional[List[CommentEntry]] = None
    metadata: List[Dict[str, Any]] = field(default_factory=list)
    supplementaryFiles: Optional[List[File]] = None

    def __post_init__(self) -> None:
        """Validate fields against the CyTRICS software schema requirements."""
        self._validate_capture_time()
        self._validate_uuid()
        self._validate_scalar_fields()
        self._normalize_relationship_assertion()
        self._validate_hash_fields()
        self._enforce_hash_requirement()

        for field_name in (
            "softwareType",
            "fileName",
            "installPath",
            "containerPath",
            "vendor",
        ):
            self._validate_optional_string_list_field(field_name)

        self._validate_optional_typed_list_field("name", NameEntry)
        self._validate_optional_typed_list_field("comments", CommentEntry)
        self._validate_optional_typed_list_field("supplementaryFiles", File)
        self._validate_metadata()

    def _validate_capture_time(self) -> None:
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)

    def _validate_uuid(self) -> None:
        try:
            parsed_uuid = uuid.UUID(self.UUID)
        except (ValueError, AttributeError, TypeError) as err:
            raise ValueError(f"UUID must be a valid UUID string; got {self.UUID!r}") from err

        if parsed_uuid.version != 4:
            raise ValueError(
                f"UUID must be a valid RFC 4122 version 4 UUID string; got {self.UUID!r}"
            )

    def _validate_scalar_fields(self) -> None:
        if self.notHashable is not None and not isinstance(self.notHashable, bool):
            raise TypeError("notHashable must be a bool or None")

        if self.size is not None and not isinstance(self.size, int):
            raise TypeError("size must be an int or None")

        for field_name in ("version", "description"):
            self._validate_optional_string_field(field_name)

    def _validate_optional_string_field(self, field_name: str) -> None:
        value = getattr(self, field_name)
        if value is not None and not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string or None")

    def _normalize_relationship_assertion(self) -> None:
        if self.relationshipAssertion is not None and not isinstance(
            self.relationshipAssertion, RelationshipAssertion
        ):
            self.relationshipAssertion = RelationshipAssertion(self.relationshipAssertion)

    def _validate_hash_fields(self) -> None:
        for field_name in ("sha1", "sha256", "md5"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError(
                    f"{field_name} must be a string or None; got {type(value).__name__}"
                )

    def _enforce_hash_requirement(self) -> None:
        if not self.notHashable:
            if not any(isinstance(v, str) for v in (self.sha1, self.sha256, self.md5)):
                raise ValueError("At least one hash must be a string unless notHashable is True")

    def _validate_optional_string_list_field(self, field_name: str) -> None:
        value = getattr(self, field_name)
        if value is None:
            return

        if not isinstance(value, list):
            raise TypeError(f"{field_name} must be a list or None")

        for item in value:
            if not isinstance(item, str):
                raise TypeError(f"All items in {field_name} must be strings")

    def _validate_optional_typed_list_field(self, field_name: str, entry_type: type) -> None:
        value = getattr(self, field_name)
        if value is None:
            return

        if not isinstance(value, list):
            raise TypeError(f"{field_name} must be a list or None")

        if not all(isinstance(item, entry_type) for item in value):
            raise TypeError(f"All items in {field_name} must be {entry_type.__name__} objects")

    def _validate_metadata(self) -> None:
        if not isinstance(self.metadata, list):
            raise TypeError("metadata must be a list")

        for item in self.metadata:
            if not isinstance(item, dict):
                raise TypeError("All items in metadata must be objects (dicts)")

    def update_field(self, field_name: str, value: Any) -> None:
        """Public helper to update a field while preserving validation semantics."""
        self._update_field(field_name, value)

    def _update_field(self, field_name: str, value: Any) -> None:
        if value in ("", " ", None):
            return

        original_value = getattr(self, field_name)

        setattr(self, field_name, value)

        try:
            self.__post_init__()
        except Exception:
            setattr(self, field_name, original_value)
            raise

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
            comments=[],
            metadata=[collection_info],
            supplementaryFiles=[],
        )
        return sw

    # TODO: figure out how to handle merging an SBOM with manual additions
    def merge(self, sw: Software):
        # hashes should be confirmed to match before calling this function
        # check to make sure entry isn't an exact duplicate
        if sw and self != sw:
            # leave UUID and captureTime the same
            single_value_fields = [
                "version",
                "description",
                "relationshipAssertion",
                "size",
                "sha1",
                "sha256",
                "md5",
                "notHashable",
            ]
            array_fields = [
                "softwareType",
                "name",
                "comments",
                "containerPath",
                "fileName",
                "installPath",
                "vendor",
                "metadata",
                "supplementaryFiles",
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

                    if current_arr != new_arr and isinstance(new_arr, list):
                        merged_arr = list(current_arr) if current_arr is not None else []

                        for new_value in new_arr:
                            # special case, UUID in containerPaths need updating to match our UUID
                            if fld.name == "containerPath" and isinstance(new_value, str):
                                if new_value.startswith(sw.UUID):
                                    new_value = new_value.replace(sw.UUID, self.UUID)

                            if new_value not in merged_arr:
                                merged_arr.append(new_value)

                        self._update_field(fld.name, merged_arr)

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
