# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import uuid
from dataclasses import dataclass, field

from ._file import File
from ._provenance import AnalysisDataProvenance

# pylint: disable=too-many-instance-attributes


@dataclass
class AnalysisData:
    # origin, testName, and testVersion are not optional
    # user must provide the info, not really a "safe" default value
    origin: str
    testName: str
    testVersion: str
    UUID: str = field(default_factory=lambda: str(uuid.uuid4()))
    specificEnvironment: str | None = None
    files: list[File] | None = None
    linksToKnownVulnerabilities: str | None = None
    provenance: list[AnalysisDataProvenance] | None = None
