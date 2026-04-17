# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from queue import Queue
from typing import Any, Dict, List, Optional, Tuple, Union

from pluggy import HookspecMarker

from surfactant import ContextEntry
from surfactant.sbomtypes import SBOM, Relationship, Software

hookspec = HookspecMarker("surfactant")


@hookspec(firstresult=True)
def identify_file_type(
    filepath: str, context: Optional[ContextEntry]
) -> Optional[Union[str, List[str]]]:
    """Determine the type of file located at filepath.

    Implementations may return either a single file type string or a list of file
    type strings. Callers normalize the result to ``List[str]`` before passing it
    to file extraction plugins. Return ``None`` to indicate that the type was
    unable to be determined.

    Args:
        filepath (str): The path to the file to determine the type of.
        context (ContextEntry): The context entry for the file, may be context of parent archive.

    Returns:
        Optional[Union[str, List[str]]]: A file type string, a list of file type
            strings, or None if the file type could not be recognized.
    """


@hookspec
# pylint: disable-next=too-many-positional-arguments
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: List[str],
    context_queue: "Queue[ContextEntry]",
    current_context: Optional[ContextEntry],
    children: List[Software],
    software_field_hints: List[Tuple[str, Any, int]],
    omit_unrecognized_types: bool,
) -> Optional[Dict[str, Any]]:
    """Extract information from the given file and add it to the given software entry.

    Plugins may:
      - return a metadata object to append to ``software.metadata``
      - add child Software entries through ``children``
      - provide candidate field values through ``software_field_hints``

    The returned metadata value must be a ``dict`` representing a JSON object, or
    ``None`` if the plugin has no metadata to contribute for this file.

    Args:
        sbom (SBOM): The SBOM that the software entry is part of. Can be used to add observations or analysis data.
        software (Software): The software entry the gathered information will be added to.
        filename (str): The full path to the file to extract information from.
        filetype (List[str]): File type information based on magic bytes and other heuristics.
        context_queue (Queue[ContextEntry]): Modifiable queue of entries typically initialized from the input specimen
            config file. Plugins can add new entries to the queue to make Surfactant process additional files/folders.
            Existing plugins should still work without adding this parameter.
        current_context (Optional[ContextEntry]): The ContextEntry object from the queue whose files are currently being
            processed (modifying it is considered undefined behavior and should be avoided). Most plugins do not need to
            use this parameter.
        children (List[Software]): List of additional software entries to include in the SBOM. Plugins can add
            additional entries, though if the plugin extracts files to a temporary directory, the context argument
            should be used to have Surfactant process the files instead.
        software_field_hints (List[Tuple[str, Any, int]]): List of tuples containing the target software field name,
            a suggested value for that field, and a confidence level. Plugins can add entries to this list to suggest
            values for software entry fields. The value with the highest confidence for a field will be selected.
        omit_unrecognized_types (bool): Whether files with types that are not recognized by Surfactant should be
            left out of the SBOM. When a plugin is adding additional context entries to the queue, it should typically
            default to propagating this value to the new context entries that it creates.

    Returns:
        Optional[Dict[str, Any]]: A metadata object to append to ``software.metadata``, or ``None`` to add no metadata.
    """


@hookspec
def establish_relationships(
    sbom: SBOM, software: Software, metadata
) -> Optional[List[Relationship]]:
    """Called to add relationships to an SBOM after information has been gathered.

    The function will be called once for every metadata object in every software
    entry in the SBOM. Realistically, this means a plugin should not be trying to
    establish relationships for the entire SBOM before returning, just for the
    software/metadata object that has been passed to it.

    Returns a list of relationships to be added to the SBOM.

    Args:
        sbom (SBOM): The SBOM object that the Software is part of.
        software (Software): The Software entry that the metadata object is from.
        metadata: The metadata object to establish relationships based on.

    Returns:
        Optional[List[Relationship]]: A list of relationships to add to the SBOM.
    """


@hookspec
def write_sbom(sbom: SBOM, outfile) -> None:
    """Writes the contents of the SBOM to the given output file.

    Args:
        sbom (SBOM): The SBOM to write to the output file.
        outfile: The output file handle to write the SBOM to.
    """


@hookspec
# type: ignore[empty-body]
def read_sbom(infile) -> SBOM:
    """Reads the contents of the input SBOM from the given input SBOM file.

    Returns a SBOM object containing the input SBOM, which can be added to.

    Args:
        infile: The input file handle to read the SBOM from.
    """


@hookspec
def short_name() -> Optional[str]:
    """A short name to register the hook as.

    Returns:
        Optional[str]: The name to register the hook with.
    """


@hookspec
def update_db(force: bool = False) -> Optional[str]:
    """Updates the database for the plugin.

    This hook should be implemented by plugins that require a database update.
    The implementation should perform the necessary update operations.

    Args:
        force (bool): If True, forces the database to update regardless of whether the upstream source has changed.

    Returns:
        Optional[str]: A message indicating the result of the update operation, or None if no update was needed.
    """


@hookspec
def init_hook(command_name: Optional[str] = None) -> None:
    """Initialization hook for plugins.

    This hook is called to perform any necessary initialization for the plugin,
    such as loading databases or setting up resources.

    Args:
        command_name (Optional[str]): The name of the command invoking the initialization,
                                      which can be used to conditionally initialize based on the context.
    """


@hookspec
def settings_name() -> Optional[str]:
    """The setting base name to use for setting/retrieving settings"""
