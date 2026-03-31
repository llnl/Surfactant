# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from ._file import File

# pylint: disable=too-many-instance-attributes


@dataclass
class Observation:
    UUID: str = field(default_factory=lambda: str(uuid.uuid4()))
    flag: Optional[str] = None
    CWEClass: Optional[str] = None
    targetEnvironmentOrDevice: Optional[str] = None
    potentialEffectOrImpact: Optional[str] = None
    CVE: Optional[str] = None
    CVSS: Optional[int] = None
    analystInfo: Optional[str] = None
    discovery: Optional[str] = None
    files: Optional[List[File]] = None
    toRecreate: Optional[str] = None
    mitigationSuggestions: Optional[str] = None
    confidenceLevel: Optional[str] = None  # enum: none, low, medium, high, critical
