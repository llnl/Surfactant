# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import uuid
from dataclasses import dataclass, field

from ._file import File
from ._provenance import HardwareProvenance

# pylint: disable=too-many-instance-attributes


@dataclass
class Hardware:
    UUID: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str | None = None
    captureTime: int | None = None
    officialName: str | None = None
    countryOfOrigin: list[str] | None = None
    countryOfOriginSource: str | None = None
    quantity: int | None = None
    description: str | None = None
    vendor: list[str] | None = None
    identifiers: list[str] | None = None
    hardwareType: list[str] | None = None
    comments: str | None = None
    metadata: list[object] | None = None
    supplementaryFiles: list[File] | None = None
    packageType: str | None = None
    boardLocation: list[str] | None = None
    provenance: list[HardwareProvenance] | None = None
    recordedInstitution: str | None = None
