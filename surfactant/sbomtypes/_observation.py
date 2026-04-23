# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import uuid
from dataclasses import dataclass, field

from ._file import File
from ._provenance import ObservationProvenance

# pylint: disable=too-many-instance-attributes


@dataclass
class Observation:
    UUID: str = field(default_factory=lambda: str(uuid.uuid4()))
    flag: str | None = None
    CWEClass: str | None = None
    targetEnvironmentOrDevice: str | None = None
    potentialEffectOrImpact: str | None = None
    CVE: str | None = None
    CVSS: int | None = None
    analystInfo: str | None = None
    discovery: str | None = None
    files: list[File] | None = None
    toRecreate: str | None = None
    mitigationSuggestions: str | None = None
    confidenceLevel: str | None = None  # enum: none, low, medium, high, critical
    provenance: list[ObservationProvenance] | None = None
