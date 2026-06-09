# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import pathlib
import queue
import re
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

import click
from loguru import logger
from networkx.exception import NetworkXError

from surfactant import ContextEntry
from surfactant.cmd.internal.generate_utils import SpecimenContextParamType
from surfactant.configmanager import ConfigManager
from surfactant.fileinfo import sha256sum
from surfactant.plugin.manager import call_init_hooks, find_io_plugin, get_plugin_manager
from surfactant.relationships import parse_relationships
from surfactant.sbomtypes import SBOM, Author, Software
from surfactant.sbomtypes._comment import CommentEntry
from surfactant.sbomtypes._name import NameEntry


# Converts from a true path to an install path
def real_path_to_install_path(root_path: str, install_path: str, filepath: str) -> str:
    # appending a "/" to root_path can cause problems if it is "" or already ends with "/"
    if root_path != "" and not root_path.endswith("/"):
        return re.sub("^" + root_path + "/", install_path, filepath)
    return re.sub("^" + root_path, install_path, filepath)


def _normalize_filetypes(value: Any, *, filepath: str) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [value]

    if isinstance(value, (list, tuple)):
        normalized: List[str] = []
        for item in value:
            if not isinstance(item, str):
                raise TypeError(
                    f"Invalid identify_file_type result for {filepath}: "
                    f"expected str items, got {type(item).__name__}"
                )
            if item not in normalized:
                normalized.append(item)
        return normalized

    raise TypeError(
        f"Invalid identify_file_type result for {filepath}: "
        f"expected str, list[str], or None; got {type(value).__name__}"
    )


def _normalize_name_hints(value: Any, *, filepath: str) -> List[NameEntry]:
    raw_items = value if isinstance(value, (list, tuple)) else [value]
    normalized: List[NameEntry] = []

    for item in raw_items:
        if item is None:
            continue

        try:
            normalized.append(NameEntry.from_hint(item))
        except (TypeError, ValueError) as err:
            raise TypeError(f"Invalid name field hint for {filepath}: {err}") from err

    return normalized


def _normalize_comment_hints(value: Any, *, filepath: str) -> List[CommentEntry]:
    raw_items = value if isinstance(value, (list, tuple)) else [value]
    normalized: List[CommentEntry] = []

    for item in raw_items:
        if item is None:
            continue

        try:
            normalized.append(CommentEntry.from_hint(item))
        except (TypeError, ValueError) as err:
            raise TypeError(f"Invalid comment field hint for {filepath}: {err}") from err

    return normalized


def _normalize_string_hint(field_name: str, value: Any, *, filepath: str) -> str:
    if not isinstance(value, str):
        raise TypeError(
            f"Invalid {field_name} field hint for {filepath}: "
            f"expected str, got {type(value).__name__}"
        )
    return value


def _normalize_vendor_hints(value: Any, *, filepath: str) -> List[str]:
    normalized: List[str] = []

    def _append_vendor(item: Any) -> None:
        if item is None:
            return

        if isinstance(item, (list, tuple)):
            for sub_item in item:
                _append_vendor(sub_item)
            return

        if not isinstance(item, str):
            raise TypeError(
                f"Invalid vendor field hint for {filepath}: expected str, got {type(item).__name__}"
            )

        if item not in normalized:
            normalized.append(item)

    _append_vendor(value)
    return normalized


def _normalize_software_type_hints(value: Any, *, filepath: str) -> List[str]:
    normalized: List[str] = []

    def _append_software_type(item: Any) -> None:
        if item is None:
            return

        if isinstance(item, (list, tuple)):
            for sub_item in item:
                _append_software_type(sub_item)
            return

        if not isinstance(item, str):
            raise TypeError(
                f"Invalid softwareType field hint for {filepath}: "
                f"expected str, got {type(item).__name__}"
            )

        if item not in normalized:
            normalized.append(item)

    _append_software_type(value)
    return normalized


def _normalize_author_value(value: Optional[str], option_name: str) -> Optional[str]:
    """Normalize an optional author CLI/config value."""
    if value is None:
        return None

    if not isinstance(value, str):
        raise click.ClickException(f"{option_name} must be a string")

    value = value.strip()
    return value or None


# pylint: disable-next=redefined-outer-name
def _set_sbom_author(sbom: SBOM, author_name: Optional[str], author_type: Optional[str]) -> None:
    """Set a generated SBOM author from CLI/config values."""
    author_name = _normalize_author_value(author_name, "--author_name")
    author_type = _normalize_author_value(author_type, "--author_type")

    if author_name is None and author_type is None:
        return

    if author_name is None or author_type is None:
        raise click.ClickException("--author_name and --author_type must be provided together")

    author = Author(authorType=author_type, authorName=author_name)
    if sbom.authors is None:
        sbom.authors = []

    if author not in sbom.authors:
        sbom.authors.append(author)


def get_software_entry(
    context_queue,
    current_context,
    pluginmanager,
    parent_sbom: SBOM,
    filepath,
    *,  # arguments past this point are keyword-only
    filetype: Optional[Union[str, List[str]]] = None,
    container_uuid=None,
    root_path=None,
    install_path=None,
    omit_unrecognized_types=False,
    skip_extraction=False,
    container_prefix=None,
) -> Tuple[Software, List[Software]]:
    sw_entry = Software.create_software_from_file(filepath)
    normalized_filetypes = _normalize_filetypes(filetype, filepath=filepath)
    if root_path is not None and install_path is not None:
        sw_entry.installPath = [real_path_to_install_path(root_path, install_path, filepath)]
    if root_path is not None and container_uuid is not None:
        # make sure there is a "/" separating container uuid and the filepath
        if root_path != "" and not root_path.endswith("/"):
            sw_entry.containerPath = [
                re.sub("^" + root_path, container_uuid + container_prefix, filepath)
            ]
        else:
            sw_entry.containerPath = [
                re.sub("^" + root_path, container_uuid + container_prefix + "/", filepath)
            ]
    sw_children: List[Software] = []
    sw_field_hints: List[Tuple[str, Any, int]] = []

    # for unsupported file types, details are just empty; this is the case for archive files (e.g. zip, tar, iso)
    # as well as intel hex or motorola s-rec files
    extracted_info_results: List[Any] = (
        pluginmanager.hook.extract_file_info(
            sbom=parent_sbom,
            software=sw_entry,
            filename=filepath,
            filetype=normalized_filetypes,
            context_queue=context_queue,
            current_context=current_context,
            children=sw_children,
            software_field_hints=sw_field_hints,
            omit_unrecognized_types=omit_unrecognized_types,
        )
        if not skip_extraction
        else []
    )
    # add metadata extracted from the file
    validated_metadata: List[Any] = []
    for file_details in extracted_info_results:
        # None as details doesn't add any useful info...
        if file_details is None:
            continue

        validated_metadata.append(file_details)

    if validated_metadata:
        sw_entry.update_field("metadata", [*(sw_entry.metadata or []), *validated_metadata])

    # set SBOM fields based on sw_field_hints
    field_confidence: Dict[str, Tuple[Any, int]] = {}
    name_hints: List[Tuple[Any, int]] = []
    vendor_hints: List[Any] = []
    software_type_hints: List[Any] = []
    comment_hints: List[Any] = []

    for field, value, confidence in sw_field_hints:
        # name values are confidence-ranked separately for each name type
        if field == "name":
            name_hints.append((value, confidence))
            continue

        # vendor values are aggregated across hints rather than confidence-ranked
        if field == "vendor":
            vendor_hints.append(value)
            continue

        # softwareType values are aggregated across hints rather than confidence-ranked
        if field == "softwareType":
            software_type_hints.append(value)
            continue

        # comment values are aggregated across hints rather than confidence-ranked
        if field == "comments":
            comment_hints.append(value)
            continue

        # for all other fields, keep only the value with the highest confidence
        if field not in field_confidence or confidence > field_confidence[field][1]:
            field_confidence[field] = (value, confidence)

    if name_hints:
        field_confidence["name"] = (name_hints, 0)

    if vendor_hints:
        field_confidence["vendor"] = (vendor_hints, 0)

    if software_type_hints:
        field_confidence["softwareType"] = (software_type_hints, 0)

    if comment_hints:
        field_confidence["comments"] = (comment_hints, 0)

    # set any fields that haven't been set yet (user/previously set fields take precedence)
    for field, (value, _) in field_confidence.items():
        if field == "name" and not sw_entry.name:
            selected_names: Dict[str, Tuple[NameEntry, int]] = {}
            for name_value, name_confidence in value:
                for name_entry in _normalize_name_hints(name_value, filepath=filepath):
                    name_type = name_entry.nameType if isinstance(name_entry.nameType, str) else ""
                    if (
                        name_type not in selected_names
                        or name_confidence > selected_names[name_type][1]
                    ):
                        selected_names[name_type] = (name_entry, name_confidence)

            normalized_names = [name_entry for name_entry, _ in selected_names.values()]
            if normalized_names:
                sw_entry.update_field("name", normalized_names)
        elif field == "version" and not sw_entry.version:
            normalized_version = _normalize_string_hint("version", value, filepath=filepath)
            sw_entry.update_field("version", normalized_version)
        elif field == "vendor":
            normalized_vendors = _normalize_vendor_hints(value, filepath=filepath)
            if normalized_vendors:
                merged_vendors = [*(sw_entry.vendor or [])]
                for vendor in normalized_vendors:
                    if vendor not in merged_vendors:
                        merged_vendors.append(vendor)
                sw_entry.update_field("vendor", merged_vendors)
        elif field == "softwareType":
            normalized_software_types = _normalize_software_type_hints(value, filepath=filepath)
            if normalized_software_types:
                merged_software_types = [*(sw_entry.softwareType or [])]
                for software_type in normalized_software_types:
                    if software_type not in merged_software_types:
                        merged_software_types.append(software_type)
                sw_entry.update_field("softwareType", merged_software_types)
        elif field == "description" and not sw_entry.description:
            normalized_description = _normalize_string_hint("description", value, filepath=filepath)
            sw_entry.update_field("description", normalized_description)
        elif field == "comments":
            merged_comments = [*(sw_entry.comments or [])]
            for comment_value in value:
                for comment in _normalize_comment_hints(comment_value, filepath=filepath):
                    if comment not in merged_comments:
                        merged_comments.append(comment)

            if merged_comments != (sw_entry.comments or []):
                sw_entry.update_field("comments", merged_comments)
    return (sw_entry, sw_children)


def print_output_formats(ctx, _, value):
    if not value or ctx.resilient_parsing:
        return
    pm = get_plugin_manager()
    for plugin in pm.get_plugins():
        if hasattr(plugin, "write_sbom"):
            if hasattr(plugin, "short_name"):
                print(plugin.short_name())
            else:
                print(pm.get_canonical_name(plugin))
    ctx.exit()


def print_input_formats(ctx, _, value):
    if not value or ctx.resilient_parsing:
        return
    pm = get_plugin_manager()
    for plugin in pm.get_plugins():
        if hasattr(plugin, "read_sbom"):
            if hasattr(plugin, "short_name"):
                print(plugin.short_name())
            else:
                print(pm.get_canonical_name(plugin))
    ctx.exit()


def determine_install_prefix(
    entry: Optional[ContextEntry] = None,
    extract_path: Optional[Union[str, pathlib.Path]] = None,
    skip_extract_path: bool = False,
) -> Optional[str]:
    """Determine the install prefix based on what is provided in the context entry, and the extract path for the file.

    Args:
        entry (Optional[ContextEntry]): The context entry to check for an install prefix.
        extract_path (Optional[str|pathlib.Path]): The extract path for the file to use as a potential fallback.
        skip_extract_path (bool): Whether the extract_path should be skipped if the entry does not specify an installPrefix.

    Returns:
            Optional[str]: The install prefix to use, or 'NoneType' if an install path shouldn't be listed.
    """
    install_prefix = None
    if entry and (entry.installPrefix or entry.installPrefix == ""):
        install_prefix = entry.installPrefix
    elif not skip_extract_path and extract_path is not None:
        # pathlib doesn't include the trailing slash
        epath = pathlib.Path(extract_path)
        if epath.is_file():
            install_prefix = epath.parent.as_posix() if len(epath.parts) > 1 else ""
        else:
            install_prefix = epath.as_posix()
        # add a trailing slash after last directory name
        if install_prefix != "" and not install_prefix.endswith("/"):
            install_prefix += "/"
    return install_prefix


def get_default_from_config(option: str, fallback: Optional[Any] = None) -> Any:
    """Retrive a core config option for use as default argument value.

    Args:
        option (str): The core config option to get.
        fallback (Optional[Any]): The fallback value if the option is not found.

    Returns:
            Any: The configuration value or 'NoneType' if the key doesn't exist.
    """
    config_manager = ConfigManager()
    return config_manager.get("core", option, fallback=fallback)


@click.command("generate")
@click.argument(
    "specimen_context",
    envvar="SPECIMEN_CONTEXT",
    type=SpecimenContextParamType(),
    required=True,
)
@click.argument("sbom_outfile", envvar="SBOM_OUTPUT", type=click.File("w"), required=True)
@click.argument("input_sbom", type=click.File("r"), required=False)
@click.option(
    "--skip_gather",
    is_flag=True,
    default=False,
    required=False,
    help="Skip gathering information on files and adding software entries",
)
@click.option(
    "--skip_relationships",
    is_flag=True,
    default=False,
    required=False,
    help="Skip adding relationships based on Linux/Windows/etc metadata",
)
@click.option(
    "--skip_install_path",
    is_flag=True,
    default=False,
    required=False,
    help="Skip including install path information if not given by configuration",
)
@click.option(
    "--output_format",
    is_flag=False,
    default=get_default_from_config("output_format", fallback="surfactant.output.cytrics_writer"),
    help="SBOM output format, see --list-output-formats for list of options; default is CyTRICS",
)
@click.option(
    "--list_output_formats",
    is_flag=True,
    callback=print_output_formats,
    expose_value=False,
    is_eager=True,
    help="List supported output formats",
)
@click.option(
    "--input_format",
    is_flag=False,
    default="surfactant.input_readers.cytrics_reader",
    help="Input SBOM format, see --list-input-formats for list of options; default is CyTRICS",
)
@click.option(
    "--author_name",
    is_flag=False,
    default=get_default_from_config("author_name"),
    help="Name of the BOM author.",
)
@click.option(
    "--author_type",
    is_flag=False,
    default=get_default_from_config("author_type"),
    help="Type of the BOM author, such as name, organization, or program.",
)
@click.option(
    "--list_input_formats",
    is_flag=True,
    callback=print_input_formats,
    expose_value=False,
    is_eager=True,
    help="List supported input formats",
)
@click.option(
    "--omit_unrecognized_types",
    is_flag=True,
    default=get_default_from_config("omit_unrecognized_types", fallback=False),
    required=False,
    help="Omit files with unrecognized types from the generated SBOM.",
)
@click.option(
    "--install_prefix",
    "install_prefix_arg",
    is_flag=False,
    default=None,
    help="SBOM install prefix",
)

# Disable positional argument linter check -- could make keyword-only, but then defaults need to be set
# pylint: disable-next=too-many-positional-arguments
def sbom(
    specimen_context: list,
    sbom_outfile: click.File,
    input_sbom: click.File,
    skip_gather: bool,
    skip_relationships: bool,
    skip_install_path: bool,
    output_format: str,
    input_format: str,
    author_name: Optional[str],
    author_type: Optional[str],
    omit_unrecognized_types: bool,
    install_prefix_arg: str,
):
    """Generate a sbom based on SPECIMEN_CONTEXT and output to SBOM_OUTPUT.

    An optional INPUT_SBOM can be supplied to use as a base for subsequent operations.
    """

    pm = get_plugin_manager()
    call_init_hooks(
        pm, hook_filter=["identify_file_type", "extract_file_info"], command_name="generate"
    )
    output_writer = find_io_plugin(pm, output_format, "write_sbom")
    input_reader = find_io_plugin(pm, input_format, "read_sbom")

    logger.info(
        f'Using SBOM output writer "{pm.get_canonical_name(output_writer)}" '
        f'for output_format="{output_format}"'
    )
    logger.info(
        f'Using SBOM input reader "{pm.get_canonical_name(input_reader)}" '
        f'for input_format="{input_format}"'
    )

    contextQ: queue.Queue[ContextEntry] = queue.Queue()

    for cfg_entry in specimen_context:
        contextQ.put(ContextEntry(**cfg_entry))

    # define the new_sbom variable type
    new_sbom: SBOM
    # Click has Sentinel.UNSET type that doesn't have READ attribute, which may appear when running regression test script
    if not input_sbom or not hasattr(input_sbom, "read"):
        logger.info("No input SBOM supplied; creating a new empty SBOM")
        new_sbom = SBOM()
    else:
        logger.info(f"Reading input SBOM from {getattr(input_sbom, 'name', '<stream>')}")
        new_sbom = input_reader.read_sbom(input_sbom)

        graph = getattr(new_sbom, "graph", None)
        fs_tree = getattr(new_sbom, "fs_tree", None)

        logger.info(
            "Loaded input SBOM: "
            f"software={len(getattr(new_sbom, 'software', []) or [])}, "
            f"relationships={len(getattr(new_sbom, '_loaded_relationships', []) or [])}, "
            f"graph_nodes={graph.number_of_nodes() if graph is not None else 'None'}, "
            f"graph_edges={graph.number_of_edges() if graph is not None else 'None'}, "
            f"fs_tree_nodes={fs_tree.number_of_nodes() if fs_tree is not None else 'None'}, "
            f"fs_tree_edges={fs_tree.number_of_edges() if fs_tree is not None else 'None'}"
        )

    _set_sbom_author(new_sbom, author_name, author_type)

    # gather metadata for files and add/augment software entries in the sbom
    if not skip_gather:
        # List of directory symlinks; 2-sized tuples with (source, dest)
        dir_symlinks: List[Tuple[str, str]] = []
        # List of file install path symlinks; keys are SHA256 hashes, values are source paths
        file_symlinks: Dict[str, List[str]] = {}
        # List of filename symlinks; keys are SHA256 hashes, values are file names
        filename_symlinks: Dict[str, List[str]] = {}
        while not contextQ.empty():
            entry: ContextEntry = contextQ.get()
            if entry.archive:
                logger.info(f"Processing parent container {entry.archive}")
                # TODO: if the parent archive has an info extractor that does unpacking interally, should the children be added to the SBOM?
                # current thoughts are (Syft) doesn't provide hash information for a proper SBOM software entry, so exclude these
                # extractor plugins meant to unpack files could be okay when used on an "archive", but then extractPaths should be empty
                parent_entry, _ = get_software_entry(
                    contextQ,
                    entry,
                    pm,
                    new_sbom,
                    entry.archive,
                    filetype=pm.hook.identify_file_type(filepath=entry.archive, context=entry)
                    or [],
                    skip_extraction=entry.skipProcessingArchive,
                    container_prefix=entry.containerPrefix,
                )
                archive_entry = new_sbom.find_software(parent_entry.sha256)
                if (
                    archive_entry
                    and parent_entry
                    and Software.check_for_hash_collision(archive_entry, parent_entry)
                ):
                    logger.warning(
                        f"Hash collision between {archive_entry.name} and {parent_entry.name}; unexpected results may occur"
                    )
                if archive_entry:
                    parent_entry = archive_entry
                else:
                    new_sbom.add_software(parent_entry)
                parent_uuid = parent_entry.UUID
            else:
                parent_entry = None
                parent_uuid = None

            # Replace entry install prefix with user specified value if given by cli args
            if install_prefix_arg:
                if entry.installPrefix:
                    logger.error(
                        f"Conflicting installPrefix definitions; Check configuration file ({entry.installPrefix}) and CLI argument ({install_prefix_arg})"
                    )
                    sys.exit(-1)

                entry.installPrefix = install_prefix_arg

            # If an installPrefix was given, clean it up some
            if entry.installPrefix:
                if not entry.installPrefix.endswith(("/", "\\")):
                    # Make sure the installPrefix given ends with a "/" (or Windows backslash path, but users should avoid those)
                    logger.warning("Fixing installPrefix (include the trailing /)")
                    entry.installPrefix += "/"
                if "\\" in entry.installPrefix:
                    # Using an install prefix with backslashes can result in a gradual reduction of the number of backslashes... and weirdness
                    # Ideally even on a Windows "/" should be preferred instead in file paths, but "\" can be a valid character in Linux folder names
                    logger.warning(
                        "Fixing installPrefix with Windows-style backslash path separator in config file (ideally use / as path separator instead of \\, even for Windows"
                    )
                    entry.installPrefix = entry.installPrefix.replace("\\", "\\\\")

            # Clean up the container prefix if needed
            entry.containerPrefix = (
                entry.containerPrefix.strip("/") if entry.containerPrefix is not None else ""
            )
            if entry.containerPrefix != "":
                entry.containerPrefix = "/" + entry.containerPrefix

            for epath_str in entry.extractPaths:
                # convert to pathlib.Path, ensures trailing "/" won't be present and some more consistent path formatting
                epath = pathlib.Path(epath_str)
                install_prefix = determine_install_prefix(
                    entry, epath, skip_extract_path=skip_install_path
                )
                logger.trace("Extracted Path: " + epath.as_posix())

                # variable used to track software entries to add to the SBOM
                entries: List[Software]

                # handle individual file case, since os.walk doesn't
                if epath.is_file():
                    entries = []
                    filepath = epath.as_posix()
                    try:
                        sw_parent, sw_children = get_software_entry(
                            contextQ,
                            entry,
                            pm,
                            new_sbom,
                            filepath,
                            filetype=pm.hook.identify_file_type(filepath=filepath, context=entry)
                            or [],
                            root_path=epath.parent.as_posix() if len(epath.parts) > 1 else "",
                            container_uuid=parent_uuid,
                            install_path=install_prefix,
                            container_prefix=entry.containerPrefix,
                        )
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        raise RuntimeError(f"Unable to process: {filepath}") from e
                    entries.append(sw_parent)
                    entries.extend(sw_children if sw_children else [])
                    # ------------------------------------------------------------------------
                    # (Optional - Early Injection) Inject symlink paths into each Software entry so SBOM helper handles them
                    # ------------------------------------------------------------------------
                    # Early injection: add symlinks gathered so far so fs_tree sees them
                    for sw in entries:
                        if sw.fileName is None:
                            sw.fileName = []
                        if sw.installPath is None:
                            sw.installPath = []
                        # Filename symlinks
                        for link in filename_symlinks.get(sw.sha256, []):
                            if link not in sw.fileName:
                                logger.debug(
                                    f"Injecting filename symlink '{link}' for SHA {sw.sha256}"
                                )
                                sw.fileName.append(link)
                        # Install-path symlinks
                        for link in file_symlinks.get(sw.sha256, []):
                            if link not in sw.installPath:
                                logger.debug(
                                    f"Injecting install-path symlink '{link}' for SHA {sw.sha256}"
                                )
                                sw.installPath.append(link)
                    new_sbom.add_software_entries(entries, parent_entry=parent_entry)
                    # epath was a file, no need to walk the directory tree
                    continue

                # epath is a directory, walk it
                for cdir, dirs, files in os.walk(epath):
                    logger.info(f"Processing {cdir}")

                    if entry.installPrefix:
                        for dir_ in dirs:
                            full_path = os.path.join(cdir, dir_)
                            if os.path.islink(full_path):
                                dest = resolve_link(
                                    full_path, cdir, epath.as_posix(), entry.installPrefix
                                )
                                if dest is not None:
                                    install_source = real_path_to_install_path(
                                        epath.as_posix(), entry.installPrefix, full_path
                                    )
                                    install_dest = real_path_to_install_path(
                                        epath.as_posix(), entry.installPrefix, dest
                                    )
                                    dir_symlinks.append((install_source, install_dest))
                                    # Reflect in fs_tree immediately
                                    try:
                                        new_sbom.record_symlink(
                                            install_source, install_dest, subtype="directory"
                                        )
                                        logger.debug(
                                            f"[fs_tree] (dir) {install_source} -> {install_dest}"
                                        )
                                    except (NetworkXError, ValueError) as e:
                                        logger.warning(
                                            f"Failed to record directory symlink in fs_tree: {install_source} -> {install_dest}: {e}"
                                        )

                    entries: List[Software] = []
                    for file in files:
                        # os.path.join will insert an OS specific separator between cdir and f
                        # need to make sure that separator is a / and not a \ on windows
                        filepath = pathlib.Path(cdir, file).as_posix()
                        logger.debug(f"Processing filepath: {filepath}")
                        # TODO: add CI tests for generating SBOMs in scenarios with symlinks... (and just generally more CI tests overall...)
                        # Record symlink details but don't run info extractors on them
                        if os.path.islink(filepath):
                            # NOTE: resolve_link function could print warning if symlink goes outside of extract path dir
                            true_filepath = resolve_link(
                                filepath, cdir, epath.as_posix(), entry.installPrefix
                            )
                            # Dead/infinite links will error so skip them
                            if true_filepath is None:
                                continue

                            # Compute sha256 hash of the file; skip if the file pointed by the symlink can't be opened
                            try:
                                true_file_sha256 = sha256sum(true_filepath)
                            except (FileNotFoundError, PermissionError):
                                logger.warning(
                                    f"Unable to open symlink {filepath} pointing to {true_filepath}"
                                )
                                continue

                            # Record both source and target paths under the same hash node
                            install_filepath = real_path_to_install_path(
                                epath.as_posix(), entry.installPrefix, filepath
                            )
                            install_dest = real_path_to_install_path(
                                epath.as_posix(), entry.installPrefix, true_filepath
                            )

                            try:
                                new_sbom.record_hash_node(install_filepath, true_file_sha256)
                                new_sbom.record_hash_node(install_dest, true_file_sha256)
                                logger.debug(
                                    f"[fs_tree] Linked symlink + target by hash: {install_filepath} <-> {install_dest}"
                                )
                            except Exception as e:  # pylint: disable=broad-exception-caught
                                logger.warning(
                                    f"[fs_tree] Failed to link symlink + target by hash for {filepath}: {e}"
                                )

                            # Record the symlink name to be added as a file name
                            # Dead links would appear as a file, so need to check the true path to see
                            # if the thing pointed to is a file or a directory
                            if os.path.isfile(true_filepath):
                                if true_file_sha256 and true_file_sha256 not in filename_symlinks:
                                    filename_symlinks[true_file_sha256] = []
                                symlink_base_name = pathlib.PurePath(filepath).name
                                if symlink_base_name not in filename_symlinks[true_file_sha256]:
                                    filename_symlinks[true_file_sha256].append(symlink_base_name)
                            # Record symlink install path if an install prefix is given
                            if entry.installPrefix:
                                install_filepath = real_path_to_install_path(
                                    epath.as_posix(), entry.installPrefix, filepath
                                )
                                install_dest = real_path_to_install_path(
                                    epath.as_posix(), entry.installPrefix, true_filepath
                                )
                                # A dead link shows as a file so need to test if it's a
                                # file or a directory once rebased
                                if os.path.isfile(true_filepath):
                                    if true_file_sha256 and true_file_sha256 not in file_symlinks:
                                        file_symlinks[true_file_sha256] = []
                                    file_symlinks[true_file_sha256].append(install_filepath)
                                else:
                                    dir_symlinks.append((install_filepath, install_dest))

                                # Reflect this symlink in fs_tree immediately
                                try:
                                    subtype = (
                                        "file" if os.path.isfile(true_filepath) else "directory"
                                    )
                                    new_sbom.record_symlink(
                                        install_filepath, install_dest, subtype=subtype
                                    )
                                    logger.debug(
                                        f"[fs_tree] ({subtype}) {install_filepath} -> {install_dest}"
                                    )
                                except (NetworkXError, ValueError) as e:
                                    logger.warning(
                                        f"Failed to record symlink in fs_tree: {install_filepath} -> {install_dest}: {e}"
                                    )
                            # NOTE Two cases that don't get recorded (but maybe should?) are:
                            # 1. If the file pointed to is outside the extract paths, it won't
                            # appear in the SBOM at all -- is that desirable? If it were included,
                            # should the true path also be included as an install path?
                            # 2. Does a symlink "exist" inside an archive/installer, or only after
                            # unpacking/installation?
                            continue

                        if os.path.isfile(filepath):
                            if not entry.includeFileExts:
                                entry.includeFileExts = []
                            if not entry.excludeFileExts:
                                entry.excludeFileExts = []

                            # file-type identification and SBOM entry creation
                            if (
                                (
                                    ftype := pm.hook.identify_file_type(
                                        filepath=filepath, context=entry
                                    )
                                )
                                or (not (omit_unrecognized_types or entry.omitUnrecognizedTypes))
                                or (
                                    os.path.splitext(filepath)[1].lower()
                                    in [ext.lower() for ext in entry.includeFileExts]
                                )
                            ) and os.path.splitext(filepath)[1].lower() not in [
                                ext.lower() for ext in entry.excludeFileExts
                            ]:
                                try:
                                    sw_parent, sw_children = get_software_entry(
                                        contextQ,
                                        entry,
                                        pm,
                                        new_sbom,
                                        filepath,
                                        filetype=ftype or [],
                                        root_path=epath.as_posix(),
                                        container_uuid=parent_uuid,
                                        install_path=install_prefix,
                                        omit_unrecognized_types=omit_unrecognized_types
                                        or entry.omitUnrecognizedTypes,
                                        container_prefix=entry.containerPrefix,
                                    )
                                except Exception as e:  # pylint: disable=broad-exception-caught
                                    raise RuntimeError(f"Unable to process: {filepath}") from e

                                entries.append(sw_parent)
                                entries.extend(sw_children if sw_children else [])
                    # ------------------------------------------------------------------------
                    # (Optional - Early Injection) Inject symlink paths into each Software entry so SBOM helper handles them
                    # ------------------------------------------------------------------------
                    # Early injection for batch (so fs_tree captures aliases)
                    for sw in entries:
                        if sw.fileName is None:
                            sw.fileName = []
                        if sw.installPath is None:
                            sw.installPath = []
                        # Filename symlinks
                        for link in filename_symlinks.get(sw.sha256, []):
                            if link not in sw.fileName:
                                logger.debug(
                                    f"Injecting filename symlink '{link}' for SHA {sw.sha256}"
                                )
                                sw.fileName.append(link)
                        # Install-path symlinks
                        for link in file_symlinks.get(sw.sha256, []):
                            if link not in sw.installPath:
                                logger.debug(
                                    f"Injecting install-path symlink '{link}' for SHA {sw.sha256}"
                                )
                                sw.installPath.append(link)
                    new_sbom.add_software_entries(entries, parent_entry=parent_entry)

        # ------------------------------------------------------------------
        # Expand deferred directory symlinks once fs_tree is fully populated
        # ------------------------------------------------------------------
        new_sbom.expand_pending_dir_symlinks()

        # ------------------------------------------------------------------
        # Expand deferred file symlinks after all installPath nodes are added
        # ------------------------------------------------------------------
        new_sbom.expand_pending_file_symlinks()

        # ------------------------------------------------------------------
        # Inject legacy-style symlink metadata (fileNameSymlinks and
        # installPathSymlinks) derived from fs_tree relationships
        # ------------------------------------------------------------------
        new_sbom.inject_symlink_metadata()

    else:
        logger.info("Skipping gathering file metadata and adding software entries")

    # add "Uses" relationships based on gathered metadata for software entries
    if not skip_relationships:
        parse_relationships(pm, new_sbom)
    else:
        logger.info("Skipping relationships based on imports metadata")

    # TODO should contents from different containers go in different SBOM files, so new portions can be added bit-by-bit with a final merge?
    logger.info(
        f"Calling output writer {pm.get_canonical_name(output_writer)} "
        f"for {getattr(sbom_outfile, 'name', '<stream>')}"
    )
    output_writer.write_sbom(new_sbom, sbom_outfile)
    logger.info(f"Finished writing SBOM output to {getattr(sbom_outfile, 'name', '<stream>')}")


def resolve_link(
    path: str, cur_dir: str, extract_dir: str, install_prefix: Optional[str] = None
) -> Union[str, None]:
    assert cur_dir.startswith(extract_dir)
    # Links seen before
    seen_paths = set()
    # os.readlink() resolves one step of a symlink
    current_path = path
    steps = 0
    while os.path.islink(current_path):
        # If we've already seen this then we're in an infinite loop
        if current_path in seen_paths:
            logger.warning(f"Resolving symlink {path} encountered infinite loop at {current_path}")
            return None
        seen_paths.add(current_path)
        dest = os.readlink(current_path)
        # Convert relative paths to absolute local paths
        if not pathlib.Path(dest).is_absolute():
            common_path = os.path.commonpath([cur_dir, extract_dir])
            local_path = os.path.join("/", cur_dir[len(common_path) :])
            dest = os.path.join(local_path, dest)
        # Convert to a canonical form to eliminate .. to prevent reading above extract_dir
        # NOTE: should consider detecting reading above extract_dir and warn the user about incomplete file system structure issues
        dest = os.path.normpath(dest)
        if install_prefix and dest.startswith(install_prefix):
            dest = dest[len(install_prefix) :]
        # We need to get a non-absolute path so os.path.join works as we want
        if pathlib.Path(dest).is_absolute():
            # TODO: Windows support, but how???
            dest = dest[1:]
        # Rebase to get the true location
        current_path = os.path.join(extract_dir, dest)
        cur_dir = os.path.dirname(current_path)
    if not os.path.exists(current_path):
        logger.warning(f"Resolved symlink {path} to a path that doesn't exist {current_path}")
        return None
    return os.path.normpath(current_path)
