import json
import uuid

# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from typing import Dict, List, Optional, Tuple

from cyclonedx.model import HashAlgorithm
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.vulnerability import Vulnerability

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Observation, Software, SoftwareComponent


@surfactant.plugin.hookimpl
def read_sbom(infile) -> SBOM:
    """Reads the contents of the CycloneDX SBOM to the CyTRICS format.

    The read_sbom hook for the cyclonedx_reader makes a best-effort attempt
    to map the information gathered from the CycloneDX file to a valid
    internal SBOM representation.

    Args:
        infile: The input file handle to read the CycloneDX SBOM from.
    """
    # NOTE eventually informat should be user settable
    informat = "json"

    bom = Bom.from_json(data=json.loads(infile.read()))
    sbom = SBOM()

    # Keep track of dependecies
    # bom_ref -> xuuid, dependencies -> yuuids
    # Keep track of which generated UUIDs map to which bom refs
    uuids = {}

    for xdependency in bom.dependencies:
        xbomref = xdependency.ref.value
        if xbomref not in uuids:
            new_uuid = str(uuid.uuid4())
            uuids[xbomref] = new_uuid
        xuuid = uuids[xbomref]
        xuuid = xbomref  # Comment this line if you want the uuid to look like the CyTRICS uuid, uncomment if you want the uuid to match the bom-ref

        for ydependency in xdependency.get("dependsOn", []):
            ybomref = ydependency.ref.value
            if ybomref not in uuids:
                new_uuid = str(uuid.uuid4())
                uuids[ybomref] = new_uuid
            yuuid = uuids[ybomref]
            yuuid = ybomref  # Comment this line if you want the uuid to look like the CyTRICS uuid, uncomment if you want the uuid to match the bom-ref

            # TODO
            # # Relationship: xbomref "depends on" ybomref
            # rel_type = "DependsOn"
            # cytrics_rel = Relationship(xUUID=xbomref, yUUID=ybomref, relationship=rel_type)
            # sbom.add_relationship(cytrics_rel)

            # for provided_bomref in xdependency.get("provides", []):
            #     rel_type = "Provides"
            #     cytrics_rel = Relationship(
            #         xUUID=xbomref, yUUID=provided_bomref, relationship=rel_type
            #     )
            #     sbom.add_relationship(cytrics_rel)

    # Create a CyTRICS software entry for each CycloneDX component
    for component in bom.components:
        # If a component detail can be mapped to a detail in a software entry, then add to software entry details
        # Otherwise, add detail to software entry's metadata section

        # Add CycloneDX metadata section to metadata section of each software entry
        c_uuid, sw = convert_cyclonedx_component_to_software(component, uuids)
        sbom.add_software(sw)
        if component.bom_ref.value:
            uuids[component.bom_ref.value] = c_uuid

    # Do the same thing for the component from the CycloneDX metadata section (if there is one) because its bom-ref can appear in the dependencies
    if bom.metadata.component:
        mc_uuid, msw = convert_cyclonedx_component_to_software(bom.metadata.component, uuids)
        sbom.add_software(msw)
        if bom.metadata.component.bom_ref.value:
            uuids[bom.metadata.component.bom_ref.value] = mc_uuid

    # Add vulnerabilities from the CycloneDX SBOM to the observations section in the CyTRICS SBOM
    if bom.vulnerabilities:
        for vuln in bom.vulnerabilities:
            observation = convert_cyclonedx_vulnerability_to_observation(vuln)
            sbom.observations.append(observation)

    return sbom


@surfactant.plugin.hookimpl
def short_name() -> Optional[str]:
    return "cyclonedx"


def convert_cyclonedx_component_to_software(
    component: Component, uuids: Dict
) -> Tuple[str, Software]:
    """Converts a component entry in the CycloneDX SBOM to a CyTRICS software entry

    Args:
        component (Component): The CycloneDX component to convert to a CyTRICS software entry.
        uuids (Dict): A Python dictionary that keeps track of which CycloneDX bom-refs have already been assigned UUIDs

    Returns:
        Tuple[str, Software]: A tuple containing the UUID of the Component that was
        converted into a Software, and the Software object that was created.
    """

    print(component.bom_ref)
    bomref = component.bom_ref.value
    if (not bomref) or (bomref not in uuids.keys()):
        cytrics_uuid = str(uuid.uuid4())
    else:
        cytrics_uuid = uuids[bomref]
        cytrics_uuid = bomref  # Comment this line if you want the uuid to look like the CyTRICS uuid, uncomment if you want the uuid to match the bom-ref

    name = component.name
    description = component.description

    # CycloneDX only supports one supplier, so the vendor list will only contain one vendor
    vendor = [component.supplier]
    version = component.version
    hashes = {"SHA-1": None, "SHA-256": None, "MD5": None}
    for c_hash in component.hashes:
        if c_hash.alg == HashAlgorithm.SHA_1:
            hashes.update({"SHA-1": c_hash.content})
        elif c_hash.alg == HashAlgorithm.SHA_256:
            hashes.update({"SHA-256": c_hash.content})
        elif c_hash.alg == HashAlgorithm.MD5:
            hashes.update({"MD5": c_hash.content})

    # Convert subcomponents of CycloneDX components into components of the corresponding CyTRICS software entry
    sw_components: List[SoftwareComponent] = []
    for subcomp in component.components:
        sw_comp = convert_cyclonedx_subcomponent_to_software_components(subcomp)
        sw_components.append(sw_comp)

    # Add remaining data that is exclusive to CycloneDX component entries into the metadata section of the CyTRICS software entry
    metadata = {}
    if component.type:
        metadata["type"] = component.type
    if component.mime_type:
        metadata["mime_type"] = component.mime_type
    if component.publisher:
        metadata["publisher"] = component.publisher
    if component.group:
        metadata["group"] = component.group

    if component.scope:
        # scope is an enum (of string) so need to make it serializable
        metadata["scope"] = component.scope.value

    if hasattr(component, "licenses") and component.licenses:
        metadata["licenses"] = []
        for license_obj in component.licenses:
            license_dict = {}
            license_id = getattr(license_obj, "id", None)
            if license_id:
                license_dict["id"] = license_id
            license_url = getattr(license_obj, "url", None)
            if license_url:
                license_dict["url"] = str(license_url)
            license_name = getattr(license_obj, "name", None)
            if license_name:
                license_dict["name"] = license_name
            metadata["licenses"].append(license_dict)

    if component.copyright:
        metadata["copyright"] = component.copyright

    # isn't purl already a string-- do we need to construct it like below?
    if component.purl:
        purl = (
            "pkg:"
            + component.purl.type
            + "/"
            + component.purl.namespace
            + "/"
            + component.purl.name
            + "@"
            + component.purl.version
        )
        if component.purl.qualifiers:
            purl = purl + "?"
            first = True
            for qualifier in component.purl.qualifiers:
                if first:
                    purl = purl + qualifier + "=" + component.purl.qualifiers[qualifier]
                else:
                    purl = purl + "&" + qualifier + "=" + component.purl.qualifiers[qualifier]
        if component.purl.subpath:
            purl = purl + "#" + component.purl.subpath

        metadata["purl"] = purl

    if hasattr(component, "external_references") and component.external_references:
        metadata["externalReferences"] = []
        for ext_ref in component.external_references:
            ext_dict = {}
            # .type is an enum, get its string value
            if hasattr(ext_ref, "type") and ext_ref.type:
                ext_dict["type"] = str(ext_ref.type).lower()
            if hasattr(ext_ref, "url") and ext_ref.url:
                ext_dict["url"] = str(ext_ref.url)
            if hasattr(ext_ref, "comment") and ext_ref.comment:
                ext_dict["comment"] = ext_ref.comment
            metadata["externalReferences"].append(ext_dict)

    if component.properties:  # is array of objects
        metadata["properties"] = [prop.to_dict() for prop in component.properties]

    if component.release_notes:  # is an object with one required field
        metadata["releaseNotes"] = {"type": component.release_notes.type}

    if component.cpe:
        metadata["cpe"] = component.cpe

    if component.swid:  # is an object
        swid_obj = component.swid
        metadata["swid"] = {}
        if getattr(swid_obj, "tagId", None):
            metadata["swid"]["tagId"] = swid_obj.tagId
        if getattr(swid_obj, "name", None):
            metadata["swid"]["name"] = swid_obj.name

    # if component.pedigree:
    # *** Not JSON serializable on its own despite being a serializable class.
    # TODO: Create a proper conversion of the object into a serializable format
    #    metadata["pedigree"] = component.pedigree

    # if component.evidence:
    # *** Not JSON serializable on its own despite being a serializable class.
    # TODO: Create a proper conversion of the object into a serializable format
    #    metadata["evidence"] = component.evidence

    if component.modified:
        metadata["modified"] = component.modified
    if component.manufacturer:
        metadata["manufacturer"] = component.manufacturer

    if component.authors:  # list of objects
        authors_list = []
        for author in component.authors:
            author_dict = {}
            if getattr(author, "bom_ref", None):
                author_dict["bom-ref"] = author.bom_ref
            if getattr(author, "name", None):
                author_dict["name"] = author.name
            if getattr(author, "email", None):
                author_dict["email"] = author.email
            if getattr(author, "phone", None):
                author_dict["phone"] = author.phone
            authors_list.append(author_dict)
        metadata["authors"] = authors_list

    # if component.omnibor_ids:
    # Need to see some examples of this property in use
    # TODO: Create a proper conversion of the object into a serializable format
    #    metadata["omnibor_ids"] = component.omnibor_ids

    if component.swhid:  # array of strings
        metadata["swhid"] = component.swhid

    # if component.crypto_properties:
    # Need to see some examples of this property in use
    # TODO: Create a proper conversion of the object into a serializable format
    #    metadata["crypto_properties"] = component.crypto_properties

    if component.tags:  # tags is an array of strings
        metadata["tags"] = component.tags

    # TODO: Distinguish CycloneDX files from containers

    sw_entry = Software(
        UUID=cytrics_uuid,
        name=name,
        fileName="",
        installPath=[""],
        containerPath=[""],
        version=version,
        vendor=vendor,
        description=description,
        sha1=hashes["SHA-1"],
        sha256=hashes["SHA-256"],
        md5=hashes["MD5"],
        metadata=metadata,
        components=sw_components,
    )

    return cytrics_uuid, sw_entry


def convert_cyclonedx_subcomponent_to_software_components(
    component: Component,
) -> SoftwareComponent:
    """Converts a subcomponent of a CycloneDX component into a component of the corresponding CyTRICS software entry

    Args:
        component (Component): The subcomponent of the CycloneDX component to convert to a CyTRICS component in the CyTRICS software entry.

    Returns:
        SoftwareComponent: The Software object that was created.
    """
    name = component.name
    description = component.description
    # CycloneDX only supports one supplier, so vendor list will only contain one vendor
    vendor = [component.supplier]
    version = component.version

    sw_component = SoftwareComponent(
        name=name, version=version, vendor=vendor, description=description
    )

    return sw_component


def convert_cyclonedx_vulnerability_to_observation(vulnerability: Vulnerability) -> Observation:
    """Convert a CycloneDX Vulnerability object into a CyTRICS Observation object

    Args:
        vulnerability (Vulnerability): The vulnerability entry from the CycloneDX SBOM to convert to an observation entry in the CyTRICS SBOM.

    Returns:
        Observation: The Observation object that was created.
    """

    vbomref = vulnerability.bom_ref.value
    v_uuid = str(uuid.uuid4())
    if vbomref:
        v_uuid = vbomref  # Comment this if statement if you want the uuid to look like the CyTRICS uuid, uncomment if you want the uuid to match the bom-ref
    cve = vulnerability.id
    cvss: int
    for rating in vulnerability.ratings:
        cvss = rating.score
        break
    cwe = vulnerability.cwes
    description = vulnerability.description
    mitigations = vulnerability.recommendation
    url = str(vulnerability.source.url)

    sw_observation = Observation(
        UUID=v_uuid,
        CWEClass=cwe,
        potentialEffectOrImpact=description,
        CVE=cve,
        CVSS=cvss,
        toRecreate=url,
        mitigationSuggestions=mitigations,
    )

    return sw_observation
