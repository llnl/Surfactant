# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass
from typing import List, Optional

from ..utils.capture_time import validate_capture_time

# pylint: disable=too-many-instance-attributes


@dataclass
class SystemProvenance:
    fieldName: str  # enum: captureStart, captureEnd, name, officialName, vendor, description
    capturedBy: Optional[str] = None
    captureTime: Optional[str] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None

    def __post_init__(self) -> None:
        """Validate captureTime against the provenance schema requirement."""
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)


@dataclass
class HardwareProvenance:
    fieldName: str  # enum: name, captureTime, officialName, countryOfOrigin, countryOfOriginSource, quantity, description, vendor, identifiers, hardwareType, comments, metadata, packageType, boardLocation, recordedInstitution
    capturedBy: Optional[str] = None
    captureTime: Optional[str] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None

    def __post_init__(self) -> None:
        """Validate captureTime against the provenance schema requirement."""
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)


@dataclass
class SoftwareComponentProvenance:
    fieldName: str  # enum: name, captureTime, version, vendor, description, comments, metadata, recordedInstitution
    capturedBy: Optional[str] = None
    captureTime: Optional[str] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None

    def __post_init__(self) -> None:
        """Validate captureTime against the provenance schema requirement."""
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)


@dataclass
class SoftwareProvenance:
    fieldName: str  # enum: name, size, fileName, installPath, containerPath, captureTime, version, vendor, description, sha1, sha256, md5, relationshipAssertion, comments, metadata, recordedInstitution
    capturedBy: Optional[str] = None
    captureTime: Optional[str] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None

    def __post_init__(self) -> None:
        """Validate captureTime against the provenance schema requirement."""
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)


@dataclass
class AnalysisDataProvenance:
    fieldName: (
        str  # enum: origin, testName, testVersion, specificEnvironment, linksToKnownVulnerabilities
    )
    capturedBy: Optional[str] = None
    captureTime: Optional[str] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None

    def __post_init__(self) -> None:
        """Validate captureTime against the provenance schema requirement."""
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)


@dataclass
class ObservationProvenance:
    fieldName: str  # enum: flag, CWEClass, targetEnvironmentOrDevice, potentialEffectOrImpact, CVE, CVSS, analystInfo, discovery, toRecreate, mitigationSuggestions, confidenceLevel
    capturedBy: Optional[str] = None
    captureTime: Optional[str] = None
    source: Optional[str] = None
    methodOfAcquisition: Optional[List[str]] = None

    def __post_init__(self) -> None:
        """Validate captureTime against the provenance schema requirement."""
        self.captureTime = validate_capture_time(self.captureTime, nullable=True)
