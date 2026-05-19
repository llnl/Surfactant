# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Relationship, Software


def has_required_fields(metadata) -> bool:
    # no elfDependencies info, can't establish relationships
    return "rpm" in metadata


@surfactant.plugin.hookimpl
def establish_relationships(sbom: SBOM, software: Software, metadata) -> list[Relationship] | None:
    if not has_required_fields(metadata):
        return None
    # Current file is a RPM package with associated_files and file_algo sections
    relationships: list[Relationship] = []
    parent_uuid = software.UUID
    # Check what kind of hash the RPM uses for its associated files and act accordingly. If the hash doesn't match the implemented hash algorithms then print a warning
    if "sha256" == metadata["rpm"]["file_algo"]:
        for _key, value in metadata["rpm"]["associated_files"].items():
            if value:
                child_software = sbom.find_software(value)
                if child_software:
                    rel = Relationship(parent_uuid, child_software.UUID, "Installs")
                    if rel not in relationships:
                        relationships.append(rel)
    elif "md5" == metadata["rpm"]["file_algo"]:
        for _key, value in metadata["rpm"]["associated_files"].items():
            if value:
                child_uuid = find_md5_match(value, sbom.software)
                if child_uuid:
                    rel = Relationship(parent_uuid, child_uuid, "Installs")
                    if rel not in relationships:
                        relationships.append(rel)
    else:
        logger.warning(
            f"RPM Package File: {software.fileName} uses {metadata['rpm']['file_algo']} for its internal file hashes, which has not been implemented"
        )
    return relationships


def find_md5_match(search_md5: str, sList: list[Software]) -> str | None:
    """Searches through the SBOM software db for md5 hash matches

    Args:
        search_md5 (str): MD5 hash to match against
        sList (List[Software]): List of software found in the search space
    Returns:
        **UUID** of the first match found, **None** if no matches were found
    """
    for entry in sList:
        if search_md5 == entry.md5:
            return entry.UUID
    return None
