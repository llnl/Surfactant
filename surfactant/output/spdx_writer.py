# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import hashlib
import pathlib
import random
import string
import sys
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone

import spdx_tools.spdx.writer.json.json_writer as jsonwriter
import spdx_tools.spdx.writer.tagvalue.tagvalue_writer as tvwriter
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.checksum import Checksum, ChecksumAlgorithm
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.file import File, FileType
from spdx_tools.spdx.model.package import Package
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.spdx_element_utils import calculate_package_verification_code

import surfactant.plugin
from surfactant import __version__ as surfactant_version
from surfactant.sbomtypes import SBOM, Software, System


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    """Writes the contents of the SBOM to a SPDX file.

    The write_sbom hook for the spdx_writer makes a best-effort attempt
    to map the information gathered from the internal SBOM representation
    to a valid SPDX file. Currently the spdx-tools library used for validating
    and writing a SPDX file has an unstable API which can at times lead
    to things not working.

    Args:
        sbom (SBOM): The SBOM to write to the output file.
        outfile: The output file handle to write the SBOM to.
    """
    outformat = "json"
    spdx_doc = create_spdx_doc()

    # Build UUID → SPDX ID map
    uuid_to_spdxid: dict[str, list[str]] = {}

    # Add system packages
    for system in sbom.systems:
        system_uuid, pkg = convert_system_to_spdx_package(system)
        spdx_doc.packages.append(pkg)
        uuid_to_spdxid.setdefault(system_uuid, []).append(pkg.spdx_id)

    # Track container paths for files
    container_path_relationships: dict[str, str] = {}

    # Add software as packages or files
    for software in sbom.software:
        if sbom.get_children(software.UUID, rel_type="Contains"):
            software_uuid, pkgs = convert_software_to_spdx_packages(software)
            for pkg in pkgs:
                spdx_doc.packages.append(pkg)
                uuid_to_spdxid.setdefault(software_uuid, []).append(pkg.spdx_id)
        else:
            for parent_uuid, software_uuid, file in convert_software_to_spdx_files(software):
                spdx_doc.files.append(file)
                if parent_uuid:
                    container_path_relationships[file.spdx_id] = parent_uuid
                if software_uuid:
                    uuid_to_spdxid.setdefault(software_uuid, []).append(file.spdx_id)

    # Document DESCRIBES relationships
    if spdx_doc.packages:
        for pkg in spdx_doc.packages:
            spdx_doc.relationships.append(
                Relationship(
                    spdx_element_id=spdx_doc.creation_info.spdx_id,
                    relationship_type=RelationshipType.DESCRIBES,
                    related_spdx_element_id=pkg.spdx_id,
                )
            )
    else:
        spdx_doc.relationships.append(
            Relationship(
                spdx_element_id=spdx_doc.creation_info.spdx_id,
                relationship_type=RelationshipType.DESCRIBES,
                related_spdx_element_id=SpdxNoAssertion(),
            )
        )

    # Iterate with keys=True to get each distinct relationship key
    for parent_uuid, child_uuid, rel_type in sbom.graph.edges(keys=True):
        rel_type = rel_type.upper()

        # skip duplicate CONTAINS for container-path dedupe
        if (
            rel_type == "CONTAINS"
            and child_uuid in container_path_relationships
            and parent_uuid != container_path_relationships[child_uuid]
        ):
            continue

        if parent_uuid not in uuid_to_spdxid or child_uuid not in uuid_to_spdxid:
            continue

        for x_spdxid in uuid_to_spdxid[parent_uuid]:
            for y_spdxid in uuid_to_spdxid[child_uuid]:
                comment = None
                try:
                    rel_enum = RelationshipType[rel_type]
                except KeyError:
                    comment = f"Type: {rel_type}"
                    rel_enum = RelationshipType.OTHER

                spdx_doc.relationships.append(
                    Relationship(
                        spdx_element_id=x_spdxid,
                        relationship_type=rel_enum,
                        related_spdx_element_id=y_spdxid,
                        comment=comment,
                    )
                )

    # Compute package verification codes
    for pkg in spdx_doc.packages:
        # gather files that pkg contains or is contained by
        related_ids = {
            rel.related_spdx_element_id
            for rel in spdx_doc.relationships
            if rel.relationship_type == RelationshipType.CONTAINS
            and rel.spdx_element_id == pkg.spdx_id
        } | {
            rel.spdx_element_id
            for rel in spdx_doc.relationships
            if rel.relationship_type == RelationshipType.CONTAINED_BY
            and rel.related_spdx_element_id == pkg.spdx_id
        }

        files_for_verification = [f for f in spdx_doc.files if f.spdx_id in related_ids]
        pkg.verification_code = calculate_package_verification_code(files_for_verification)

    # Write out
    if outformat == "json":
        try:
            jsonwriter.write_document_to_stream(spdx_doc, outfile)
        except ValueError as e:
            sys.stderr.write(str(e))
    else:  # tagvalue
        try:
            tvwriter.write_document_to_stream(spdx_doc, outfile)
        except ValueError as e:
            sys.stderr.write(str(e))


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    return "spdx"


def convert_system_to_spdx_package(system: System) -> tuple[str, Package]:
    """Converts a system entry in the SBOM to a SPDX Package.

    If a system entry has multiple vendors, only the first one is chosen as the
    supplier for the SPDX Package (due to limitations of the SPDX format).

    Args:
        system (System): The SBOM system to convert to a SPDX Package.

    Returns:
        Tuple[str, Package]: A tuple containing the UUID of the system that was
        converted into a Package, and the SPDX Package object that was created.
    """
    # Pick the best name for the package
    name = system.officialName
    if not name and system.name:
        name = system.name

    # Pick a vendor to use as the supplier
    supplier = None
    if system.vendor:
        # assume Organization, not enough info to distinguish People
        supplier = Actor(name=system.vendor[0], actor_type=ActorType.ORGANIZATION)

    return system.UUID, create_spdx_package(name, system.description, supplier)


def convert_software_to_spdx_packages(software: Software) -> tuple[str, list[Package]]:
    """Converts a software entry in the SBOM to one or more SPDX Packages.

    A SPDX Package is created for each file name that the software can have. If
    a software entry has multiple vendors, only the first one is chosen as the
    supplier for the SPDX Package (due to limitations of the SPDX format).

    Args:
        software (Software): The SBOM software entry to convert to SPDX Packages.

    Returns:
        Tuple[str, List[Package]]: A tuple containing the UUID of the software that was
        converted into Packages, and a list of the SPDX Package objects that were created.
    """
    packages: list[Package] = []
    for fname in software.fileName:
        name = software.name
        if not name:
            # No name, fall-back to the file name
            name = fname
        # Pick a vendor to use as the supplier
        supplier = None
        if software.vendor:
            # assume Organization, not enough info to distinguish People
            supplier = Actor(name=software.vendor[0], actor_type=ActorType.ORGANIZATION)
        packages.append(
            create_spdx_package(
                name,
                software.description,
                supplier,
                file_name=fname,
                version=software.version,
                sha1=software.sha1,
                sha256=software.sha256,
                md5=software.md5,
            )
        )
    return software.UUID, packages


def convert_software_to_spdx_files(software: Software) -> list[tuple[str, str, File]]:
    """Converts a software entry in the SBOM to one or more SPDX Files.

    A SPDX File is created for each unique container path that the software has. If
    no container paths exist, each unique file name will be used instead. If a software
    entry has multiple vendors, only the first one is chosen as the supplier for the SPDX
    File (due to limitations of the SPDX format).

    Args:
        software (Software): The SBOM software entry to convert to SPDX Files.

    Returns:
        List[Tuple[str, str, File]]: A list of tuples that contains the UUID of the parent
        container for the software entry (or None if file names were used), the UUID of the
        software entry that was converted into a SPDX File, and the resulting SPDX File that
        was created.
    """
    files: list[tuple[str, str, File]] = []
    for cpathstr in software.containerPath:
        cpath = pathlib.PurePath(cpathstr)
        # Less than 2 parts would just be the container path uuid, or a file name
        if len(cpath.parts) > 1:
            # First entry in container path is the parent container UUID
            parent_uuid = cpath.parts[0]
            # Full path to file, relative to package root (starting with "./")
            file_path = "./" + "/".join(cpath.parts[1:])

            idstring = generate_file_idstring(software, cpath.parts[-1])
            file = create_spdx_file(idstring, file_path, software)
            files.append((parent_uuid, software.UUID, file))
    # Alternative if no container paths exist for a software entry
    if not software.containerPath:
        for fname in software.fileName:
            idstring = generate_file_idstring(software, fname)
            file = create_spdx_file(idstring, "./" + fname, software)
            files.append((None, software.UUID, file))
    return files


def create_spdx_doc() -> Document:
    """Creates a SPDX Document with some default values for required fields filled in.

    Returns:
        Document: The SPDX Document that was created.
    """
    # NOTE: The document namespace URI does not have to be accessible, it just provides a unique ID.
    # Format is: https://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]
    # spdx.org/spdxdocs can be used if the creator does not own their own website.
    doc_name = "SBOM - DRAFT"  # document name, as designated by the creator
    spdx_creationinfo = CreationInfo(
        spdx_version="SPDX-2.3",
        spdx_id="SPDXRef-DOCUMENT",
        name=doc_name,
        document_namespace=f"https://spdx.org/spdxdocs/{doc_name}-{str(uuid.uuid4())}",  # unique URI for this SPDX Document
        creators=[
            Actor(name=f"Surfactant-{surfactant_version}", actor_type=ActorType.TOOL)
        ],  # Organization or Person can also be added as creators (may use "anonymous")
        created=datetime.now(timezone.utc).replace(microsecond=0),
        creator_comment="This SPDX document was created by using Surfactant.",
        document_comment="This is a DRAFT SPDX document, and is incomplete.",
    )
    spdx_doc = Document(creation_info=spdx_creationinfo)
    return spdx_doc


def create_spdx_file(idstring: str, file_path: str, software: Software) -> File:
    """Creates a SPDX File from a software entry.

    At minimum, the software entry must have a valid 'sha1' checksum.

    Args:
        idstring (str): A unique SPDX ID string (consisting of only alphanumeric, '.', and '-' characters).
        file_path (str): The full path to the SPDX File (starting with './', relative to the package/container).
        software (Software): The SBOM software entry to convert to a SPDX File.

    Returns:
        File: A SPDX File with information filled in based on the provided software entry.
    """
    sw_checksums = [
        Checksum(ChecksumAlgorithm.SHA1, software.sha1.lower())
    ]  # SHA1 required, should probably error if doesn't exist
    if software.sha256:
        sw_checksums.append(Checksum(ChecksumAlgorithm.SHA256, software.sha256.lower()))
    if software.md5:
        sw_checksums.append(Checksum(ChecksumAlgorithm.MD5, software.md5.lower()))

    sw_copyright = (
        SpdxNoAssertion()
    )  # SPDXNone for nothing present, SpdxNoAssertion for no attempt to determine
    if cr_text := get_fileinfo_metadata(software, "LegalCopyright"):
        sw_copyright = cr_text  # free-form text field extracted from actual file identifying copyright holder and any dates present

    file = File(
        name=file_path,
        spdx_id=f"SPDXRef-{idstring}",
        checksums=sw_checksums,
        file_types=[
            FileType.BINARY
        ],  # One or more of: SOURCE | BINARY | ARCHIVE | APPLICATION | AUDIO | IMAGE | TEXT | VIDEO | DOCUMENTATION | SPDX | OTHER
        license_concluded=SpdxNoAssertion(),  # SPDXNone if no license available for file, SpdxNoAssertion if can't determine
        license_info_in_file=[
            SpdxNoAssertion()
        ],  # info in actual file (e.g. header, not external such as COPYING.txt); None for nothing, SpdxNoAssertion for did not look
        copyright_text=sw_copyright,
    )

    return file


def create_spdx_package(
    name: str,
    summary,
    supplier,
    *,  # all remaining arguments are keyword-only
    file_name: str | None = None,
    version: str | None = None,
    sha1: str | None = None,
    sha256: str | None = None,
    md5: str | None = None,
) -> Package:
    """Creates a SPDX Package from the provided information.

    If there is a checksum provided, at minimum the 'sha1' should be present.

    Args:
        name (str): Name of the SPDX package.
        summary: A concise summary of the function or use of the package.
        supplier: The vendor the package came from.
        file_name (Optional[str]): Actual file name or path to the directory that is being treated as a package (subdirectory is denoted with './').
        version (Optional[str]): Version identifier for the package.
        sha1 (Optional[str]): SHA1 checksum that uniquely identifies the package. If the package includes the SPDX file, this should NOT be present.
        sha256 (Optional[str]): SHA256 checksum that uniquely identifies the package. If the package includes the SPDX file, this should NOT be present.
        md5 (Optional[str]): MD5 checksum that uniquely identifies the package. If the package includes the SPDX file, this should NOT be present.

    Returns:
        Package: A SPDX Package with information filled in based on the provided information.
    """
    pkg_checksums = []
    if sha1:
        pkg_checksums.append(Checksum(ChecksumAlgorithm.SHA1, sha1.lower()))
    if sha256:
        pkg_checksums.append(Checksum(ChecksumAlgorithm.SHA256, sha256.lower()))
    if md5:
        pkg_checksums.append(Checksum(ChecksumAlgorithm.MD5, md5.lower()))

    idstring = generate_package_idstring(name, version, file_name)
    pkg = Package(
        spdx_id=f"SPDXRef-{idstring}",
        name=name,
        download_location=SpdxNoAssertion(),  # SPDXNone if there is no location whatsoever, not just that we "failed" or didn't try to locate one
        license_concluded=SpdxNoAssertion(),  # if different from declared license, must explain in comments why; SpdxNoAssertion prefer to have comment
        license_declared=SpdxNoAssertion(),  # licenses declared by authors of package, not 3rd party repo; SpdxNoAssertion since didn't attempt to determine
        license_info_from_files=[
            SpdxNoAssertion()
        ],  # SPDXNone if no license info detected, SpdxNoAssertion if didn't try to determine
        copyright_text=SpdxNoAssertion(),  # SPDXNone if no copyright info, SpdxNoAssertion if didn't try to determine; use any Cr text even if incomplete
        version=version if version else None,
        file_name=(
            file_name if file_name else None
        ),  # actual file name, or path to directory treated as package (subdirectory is denoted with ./)
        supplier=(
            supplier if supplier else SpdxNoAssertion()
        ),  # SpdxNoAssertion if can't determine (SPDX can't handle multiple vendors)
        originator=SpdxNoAssertion(),  # 3rd party who distributed package is different than the supplier/vendor
        checksums=pkg_checksums,
        summary=(
            summary if summary else None
        ),  # concise info on the function or use of package, without having to parse source code
        homepage=SpdxNoAssertion(),  # SPDXNone if none exists, SpdxNoAssertion if didn't try to find a homepage
    )
    # primary_package_purpose can be: APPLICATION | FRAMEWORK | LIBRARY | CONTAINER | OPERATING - SYSTEM |
    # DEVICE | FIRMWARE | SOURCE | ARCHIVE | FILE | INSTALL | OTHER

    return pkg


def generate_random_idstring(num_chars: int = 5) -> str:
    """Generate a unique random alphanumeric ID string.

    Args:
        num_chars (int): Number of characters (default=5) that should be in the generated id string.

    Returns:
        str: The randomly generated idstring.
    """
    return "".join(random.choices(string.ascii_letters + string.digits, k=num_chars))


def generate_file_idstring(software: Software, filename: str) -> str:
    """Generate a unique random alphanumeric ID string for a SPDX File.

    The generated id string will consist of the provided file name, software product name,
    software version, and a randomly generated string separated by '-'. Non-alphanumeric or
    '.' or '-' characters will be removed from those components, and empty components will
    be omitted.

    Args:
        software (Software): Software entry to get product name and version to use in the id string.
        filename (str): File name (one of possibly several in software) to include in the id string.

    Returns:
        str: The randomly generated idstring for a SPDX File.
    """
    # Filename
    idfilename = "".join(ch for ch in filename if (ch.isalnum() or ch in ".-"))
    # Product name
    idproductname = ""
    if software.name:
        idproductname = "".join(ch for ch in software.name if (ch.isalnum() or ch in ".-"))
    # Version
    idversion = ""
    if software.version:
        idversion = "".join(ch for ch in software.version if (ch.isalnum() or ch in ".-"))
    # Return id string with generated unique id appended to ensure no duplicate SPDXRefs for files
    # leaving out "fields" that are empty strings
    return "-".join(
        x for x in [idfilename, idversion, idproductname, generate_random_idstring()] if x
    )


def generate_package_idstring(name: str, version: str, file_name: str) -> str:
    """Generate a unique random alphanumeric ID string for a SPDX Package.

    The generated id string will consist of the provided name, file name, version, and a
    randomly generated string separated by '-'. Non-alphanumeric or '.' or '-' characters
    will be removed from those components, and empty components will be omitted.

    Args:
        name (str): Name to include in the id string.
        version (str): Version to include in the id string.
        file_name (str): File name to include in the id string.

    Returns:
        str: The randomly generated idstring for a SPDX Package.
    """
    # Package Name
    idname = ""
    if idname:
        idname = "".join(ch for ch in name if (ch.isalnum() or ch in ".-"))
    # File Name
    idfilename = ""
    if file_name:
        idfilename = "".join(ch for ch in file_name if (ch.isalnum() or ch in ".-"))
    # Package Version
    idversion = ""
    if version:
        idversion = "".join(ch for ch in version if (ch.isalnum() or ch in ".-"))
    # Return id string with generated unique id appended to ensure no duplicate SPDXRefs for files
    # leaving out "fields" that are empty strings
    return "-".join(x for x in [idname, idversion, idfilename, generate_random_idstring()] if x)


def get_fileinfo_metadata(software: Software, field: str) -> str | None:
    """Retrieves the value for a field in a 'FileInfo' metadata object in a software entry.

    Args:
        software (Software): The software entry to get the 'FileInfo' field from.
        field (str): The name of the 'FileInfo' field to get the value of.

    Returns:
        Optional[str]: The value of the 'FileInfo' metadata field request, or None.
    """
    if software.metadata and isinstance(software.metadata, Iterable):
        for entry in software.metadata:
            if "FileInfo" in entry and field in entry["FileInfo"]:
                return entry["FileInfo"][field]
    return None


def get_software_field(software: Software, field: str):
    """Retrieves the value for a field in a SBOM software entry.

    The field retrieved can be the name of an attribute in the Software dataclass,
    or if the field provided is 'Copyright' it will try to retrieve the copyright
    information from a 'FileInfo' metadata object.

    Args:
        software (Software): The software entry to read the field from.
        field (str): The name of the field to get the value of, or 'Copyright'.

    Returns:
        Optional[str]: The value of the requested field, or None.
    """
    if hasattr(software, field):
        return getattr(software, field)
    # Copyright field currently only gets populated from Windows PE file metadata
    if field == "Copyright":
        if software.metadata and isinstance(software.metadata, Iterable):
            for entry in software.metadata:
                if "FileInfo" in entry and "LegalCopyright" in entry["FileInfo"]:
                    return entry["FileInfo"]["LegalCopyright"]
    return None


def java_generate_package_verification_code(software: list[Software]) -> tuple[str, list[str]]:
    """Generate a SPDX package verif_code according to the method used by the Java SPDX Tools.

    This is not the algorithm defined in the SPDX specification. The implementation here is provided
    in case we need to support an SBOM with verification codes that are compatible with the Java tool.
    Based on: https://github.com/spdx/tools/blob/bc35e25/TestFiles/spdx-parser-source/org/spdx/rdfparser/VerificationCodeGenerator.java

    Args:
        software (List[Software]): The software entries to include in the generated verification code.

    Returns:
        Tuple[str, List[str]]: A tuple consisting of the generated package verification code, and a list of
        skipped file names.
    """
    skippedFileNames: list[str] = []
    fileNameAndChecksums: list[str] = collect_file_data(software)
    fileNameAndChecksums.sort()
    m = hashlib.sha1()
    for entry in fileNameAndChecksums:
        m.update(bytes(entry, "utf-8"))
    return m.hexdigest, skippedFileNames


def collect_file_data(software: list[Software]) -> list[str]:
    """Collect file checksums and paths as done by the Java SPDX Tools.

    Args:
        software (List[Software]): The software entries to include in the collected data.

    Returns:
        List[str]: A list of checksums and file paths, in the form "<checksum>||<filepath>".
    """
    file_data: list[str] = []
    for sw in software:
        # lower case sha1 hash without a leading 0x prefix
        checksum = sw.sha1.lower()
        for fpath in sw.installPath:
            # GitHub spdx/tools uses this format for checksumming file data: checksumValue+"||"+filePath+END_OF_LINE_CHAR
            file_data.append(checksum + "||" + normalize_file_path(fpath) + "\n")
    return file_data


def normalize_file_path(nonNormalizedFilePath: str) -> str:
    """Normalization of file paths as done by Java SPDX Tools (not part of the SPDX specification).

    NOTE: The Java GitHub spdx/tools seems to have several bugs. It uses a './' replacement method
    that is too liberal and will mess up directory names ending in a '.'; it also does not appear
    to correctly remove the previously added part of the a path when it encounters a '..' relative
    directory.

    Args:
        nonNormalizedFilePath (str): The file path to normalize.

    Returns:
        str: A normalized file path.
    """
    # replace backslashes with forward slash
    filePath = nonNormalizedFilePath.replace("\\", "/").strip()
    # this splits the filepath, and removes instances of "./"
    filePathParts = pathlib.Path(filePath).parts
    # move up to higher directories
    if ".." in filePathParts:
        normalizedFilePathParts = []
        for _, part in enumerate(filePathParts):
            if part == "..":
                # go up a directory by removing the last entry from filePathParts
                # going above the last directory could be considered an error
                if len(normalizedFilePathParts) > 0:
                    normalizedFilePathParts.pop()
            else:
                normalizedFilePathParts.append(part)
        filePath = "/".join(normalizedFilePathParts)
    filePath = "./" + filePath
    return filePath
