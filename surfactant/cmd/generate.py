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
from surfactant.sbomtypes import SBOM, Software


# Converts from a true path to an install path
def real_path_to_install_path(root_path: str, install_path: str, filepath: str) -> str:
    # appending a "/" to root_path can cause problems if it is "" or already ends with "/"
    if root_path != "" and not root_path.endswith("/"):
        return re.sub("^" + root_path + "/", install_path, filepath)
    return re.sub("^" + root_path, install_path, filepath)


def get_software_entry(
    context_queue,
    current_context,
    pluginmanager,
    parent_sbom: SBOM,
    filepath,
    *,  # arguments past this point are keyword-only
    filetype=None,
    container_uuid=None,
    root_path=None,
    install_path=None,
    user_institution_name="",
    omit_unrecognized_types=False,
    skip_extraction=False,
    container_prefix=None,
) -> Tuple[Software, List[Software]]:
    sw_entry = Software.create_software_from_file(filepath)
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
    sw_entry.recordedInstitution = user_institution_name
    sw_children: List[Software] = []
    sw_field_hints: List[Tuple[str, Any, int]] = []

    # for unsupported file types, details are just empty; this is the case for archive files (e.g. zip, tar, iso)
    # as well as intel hex or motorola s-rec files
    extracted_info_results: List[object] = (
        pluginmanager.hook.extract_file_info(
            sbom=parent_sbom,
            software=sw_entry,
            filename=filepath,
            filetype=filetype,
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
    for file_details in extracted_info_results:
        # None as details doesn't add any useful info...
        if file_details is None:
            continue

        # ensure metadata exists for the software entry
        if sw_entry.metadata is None:
            sw_entry.metadata = []
        sw_entry.metadata.append(file_details)

    # set SBOM fields based on sw_field_hints
    field_confidence: Dict[str, Tuple[Any, int]] = {}
    for field, value, confidence in sw_field_hints:
        # special case since vendor can list multiple values
        if field == "vendor":
            if field not in field_confidence:
                field_confidence[field] = ([], 0)
            field_confidence[field][0].append(value)
        # otherwise, find the value for each field with the highest confidence
        elif field not in field_confidence or confidence > field_confidence[field][1]:
            field_confidence[field] = (value, confidence)

    # set any fields that haven't been set yet (user/previously set fields take precedence)
    for field, (value, _) in field_confidence.items():
        if field == "name" and not sw_entry.name:
            sw_entry.name = value
        elif field == "version" and not sw_entry.version:
            sw_entry.version = value
        elif field == "vendor":
            # make sure the vendor field is initialized
            if sw_entry.vendor is None:
                sw_entry.vendor = []
            # add any new vendors detected to the list
            for vendor in value:
                if vendor not in sw_entry.vendor:
                    sw_entry.vendor.append(vendor)
        elif field == "description" and not sw_entry.description:
            sw_entry.description = value
        elif field == "comments" and not sw_entry.comments:
            sw_entry.comments = value
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
    "--recorded_institution",
    is_flag=False,
    default=get_default_from_config("recorded_institution"),
    help="Name of user's institution",
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
    recorded_institution: str,
    output_format: str,
    input_format: str,
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

    contextQ: queue.Queue[ContextEntry] = queue.Queue()

    for cfg_entry in specimen_context:
        contextQ.put(ContextEntry(**cfg_entry))

    # define the new_sbom variable type
    new_sbom: SBOM
    # Click has Sentinel.UNSET type that doesn't have READ attribute, which may appear when running regression test script
    if not input_sbom or not hasattr(input_sbom, "read"):
        new_sbom = SBOM()
    else:
        new_sbom = input_reader.read_sbom(input_sbom)

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
                    user_institution_name=recorded_institution,
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
                            user_institution_name=recorded_institution,
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
                                            f"[fs_tree] (dir) {install_source} → {install_dest}"
                                        )
                                    except (NetworkXError, ValueError) as e:
                                        logger.warning(
                                            f"Failed to record directory symlink in fs_tree: {install_source} → {install_dest}: {e}"
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
                                    f"[fs_tree] Linked symlink + target by hash: {install_filepath} ↔ {install_dest}"
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
                                        f"[fs_tree] ({subtype}) {install_filepath} → {install_dest}"
                                    )
                                except (NetworkXError, ValueError) as e:
                                    logger.warning(
                                        f"Failed to record symlink in fs_tree: {install_filepath} → {install_dest}: {e}"
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
                                        user_institution_name=recorded_institution,
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
    output_writer.write_sbom(new_sbom, sbom_outfile)


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
