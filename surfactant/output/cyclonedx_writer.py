import pathlib
from collections.abc import Iterable

import cyclonedx.output
from cyclonedx.model import HashAlgorithm, HashType
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.tool import Tool

import surfactant.plugin
from surfactant import __version__ as surfactant_version
from surfactant.sbomtypes import SBOM, Software, System


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    """Writes the contents of the SBOM to a CycloneDX file.

    The write_sbom hook for the cyclonedx_writer makes a best-effort attempt
    to map the information gathered from the internal SBOM representation
    to a valid CycloneDX file.

    Args:
        sbom (SBOM): The SBOM to write to the output file.
        outfile: The output file handle to write the SBOM to.
    """
    outformat = "json"

    # Initialize BOM and metadata
    surfactant_tool = Tool(name="Surfactant", version=f"{surfactant_version}")
    bom_metadata = BomMetaData(tools=[surfactant_tool])
    bom = Bom(metadata=bom_metadata)

    # Add CycloneDX Components for systems
    for system in sbom.systems:
        _, comp = convert_system_to_cyclonedx_component(system)
        bom.components.add(comp)

    # Build container-path lookup for software
    container_path_relationships: dict[tuple[str, str]] = {}
    for software in sbom.software:
        if sbom.get_children(software.UUID, rel_type="Contains"):
            _, container_list = convert_software_to_cyclonedx_container_components(software)
            for container in container_list:
                bom.components.add(container)
        else:
            for parent_uuid, _, file in convert_software_to_cyclonedx_file_components(software):
                bom.components.add(file)
                if parent_uuid:
                    container_path_relationships[file.bom_ref.value] = parent_uuid

    # Build a map of Dependency objects keyed by UUID
    cdx_rels: dict[str, Dependency] = {}

    # Walk every edge, pulling the relationship out of the key
    for parent_uuid, child_uuid, rel_type in sbom.graph.edges(keys=True):
        rel_type = rel_type.upper()

        # skip duplicate CONTAINS if we've already mapped a container path
        if (
            rel_type == "CONTAINS"
            and child_uuid in container_path_relationships
            and parent_uuid != container_path_relationships[child_uuid]
        ):
            continue

        # ensure we have a Dependency entry for the parent
        if parent_uuid not in cdx_rels:
            cdx_rels[parent_uuid] = Dependency(ref=BomRef(parent_uuid))
        parent_dep = cdx_rels[parent_uuid]

        if rel_type == "CONTAINS":
            parent_dep.dependencies.add(Dependency(ref=BomRef(child_uuid)))
        elif rel_type in ("USES", "DEPENDS_ON", "REQUIRES"):
            parent_dep.add_scope_dependency(Dependency(ref=BomRef(child_uuid)), scope="runtime")
        else:
            parent_dep.add_scope_dependency(Dependency(ref=BomRef(child_uuid)), scope="unknown")

    # Attach all built dependencies to the BOM
    for dep in cdx_rels.values():
        bom.dependencies.add(dep)

    # Output the BOM in the requested format
    output_fmt = (
        cyclonedx.output.OutputFormat.JSON
        if outformat == "json"
        else cyclonedx.output.OutputFormat.XML
    )
    outputter: cyclonedx.output.BaseOutput = cyclonedx.output.make_outputter(
        bom=bom, output_format=output_fmt, schema_version=cyclonedx.schema.SchemaVersion.V1_5
    )
    outfile.write(outputter.output_as_string())


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    return "cyclonedx"


def convert_system_to_cyclonedx_component(system: System) -> tuple[str, Component]:
    """Converts a system entry in the SBOM to a CycloneDX Component.

    If a system entry has multiple vendors, only the first one is chosen as the
    supplier for the CycloneDX Component.

    Args:
        system (System): The SBOM system to convert to a CycloneDX Component.

    Returns:
        Tuple[str, Component]: A tuple containing the UUID of the system that was
        converted into a Component, and the CycloneDX Component object that was created.
    """
    # Pick the best name for the package
    name = system.officialName
    if not name and system.name:
        name = system.name

    # Pick a vendor to use as the supplier
    supplier = None
    if system.vendor:
        # assume organization, can only list one supplier
        supplier = OrganizationalEntity(name=system.vendor[0])

    system_component = Component(
        bom_ref=system.UUID,
        name=name,
        supplier=supplier,
        description=system.description,
        # components: Optional[Iterable['Component']]
        type=ComponentType.CONTAINER,
    )

    return system.UUID, system_component


def convert_software_to_cyclonedx_container_components(
    software: Software,
) -> tuple[str, list[Component]]:
    """Converts a software entry in the SBOM to one or more CycloneDX Components.

    A CycloneDX Component is created for each file name that the software can have. If
    a software entry has multiple vendors, only the first one is chosen as the
    supplier for the CycloneDX Component.

    Args:
        software (Software): The SBOM software entry to convert to CycloneDX Components.

    Returns:
        Tuple[str, List[Component]]: A tuple containing the UUID of the software that was
        converted into Components, and a list of the CycloneDX Component objects that were created.
    """
    containers: list[Component] = []
    for fname in software.fileName:
        name = software.name
        if not name:
            # No name, fall-back to the file name
            name = fname
        # Pick a vendor to use as the supplier
        supplier = None
        if software.vendor:
            # assume organization, can only list one supplier
            supplier = OrganizationalEntity(name=software.vendor[0])
        hashes = []
        if software.sha1:
            hashes.append(HashType(alg=HashAlgorithm.SHA_1, content=software.sha1))
        if software.sha256:
            hashes.append(HashType(alg=HashAlgorithm.SHA_256, content=software.sha256))
        if software.md5:
            hashes.append(HashType(alg=HashAlgorithm.MD5, content=software.md5))
        if not hashes:
            hashes = None
        containers.append(
            Component(
                bom_ref=software.UUID,
                name=name,
                version=software.version,
                supplier=supplier,
                description=software.description,
                hashes=hashes,
                # components: Optional[Iterable['Component']]
                type=ComponentType.CONTAINER,
            )
        )
    return software.UUID, containers


def convert_software_to_cyclonedx_file_components(
    software: Software,
) -> list[tuple[str, str, Component]]:
    """Converts a software entry in the SBOM to one or more CycloneDX FILE Components.

    A CycloneDX Component is created for each unique container path that the software has. If
    no container paths exist, each unique file name will be used instead. If a software
    entry has multiple vendors, only the first one is chosen as the supplier for the
    CycloneDX Component.

    Args:
        software (Software): The SBOM software entry to convert to CycloneDX Components.

    Returns:
        List[Tuple[str, str, Component]]: A list of tuples that contains the UUID of the parent
        container for the software entry (or None if file names were used), the UUID of the
        software entry that was converted into a CycloneDX Component, and the resulting CycloneDX
        Component that was created.
    """
    files: list[tuple[str, str, Component]] = []
    for cpathstr in software.containerPath:
        cpath = pathlib.PurePath(cpathstr)
        # Less than 2 parts would just be the container path uuid, or a file name
        if len(cpath.parts) > 1:
            # First entry in container path is the parent container UUID
            parent_uuid = cpath.parts[0]
            # Full path to file, relative to package root (starting with "./")
            file_path = "/".join(cpath.parts[1:])

            file = create_cyclonedx_file(file_path, software)
            files.append((parent_uuid, software.UUID, file))
    # Alternative if no container paths exist for a software entry
    if not software.containerPath:
        for fname in software.fileName:
            file = create_cyclonedx_file(fname, software)
            files.append((None, software.UUID, file))
    return files


def create_cyclonedx_file(file_path: str, software: Software) -> Component:
    """Creates a CycloneDX FILE Component from a software entry.

    Args:
        file_path (str): The path relative to the parent container for the CycloneDX FILE Component.
        software (Software): The SBOM software entry to convert to a CycloneDX FILE Component.

    Returns:
        Component: CycloneDX FILE Component with information filled in based on the provided software entry.
    """
    # Pick a vendor to use as the supplier
    supplier = None
    if software.vendor:
        # assume organization, can only list one supplier
        supplier = OrganizationalEntity(name=software.vendor[0])

    hashes = []
    if software.sha1:
        hashes.append(HashType(alg=HashAlgorithm.SHA_1, content=software.sha1))
    if software.sha256:
        hashes.append(HashType(alg=HashAlgorithm.SHA_256, content=software.sha256))
    if software.md5:
        hashes.append(HashType(alg=HashAlgorithm.MD5, content=software.md5))
    if not hashes:
        hashes = None

    copyright_text = None
    if cr_text := get_fileinfo_metadata(software, "LegalCopyright"):
        copyright_text = cr_text  # free-form text field extracted from actual file identifying copyright holder and any dates present

    if software.description == "":
        software.description = None

    if software.version == "":
        software.version = None

    return Component(
        bom_ref=software.UUID,
        name=file_path,
        version=software.version,
        supplier=supplier,
        description=software.description,
        hashes=hashes,
        copyright=copyright_text,
        # components: Optional[Iterable['Component']]
        type=ComponentType.FILE,
    )


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
