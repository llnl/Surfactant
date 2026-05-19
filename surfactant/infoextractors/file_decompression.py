# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import atexit
import bz2
import gzip
import json
import lzma
import pathlib
import shutil
import tarfile
import tempfile
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import rarfile
from loguru import logger

import surfactant.plugin
from surfactant import ContextEntry
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software
from surfactant.utils import exit_hook

if TYPE_CHECKING:
    from queue import Queue

EXTRACT_DIR = pathlib.Path(
    ConfigManager().get("decompression", "extract_dir", tempfile.gettempdir())
)
EXTRACT_DIRS_PREFIX = ConfigManager().get("decompression", "extract_prefix", "surfactant-temp")
EXTRACT_DIR.mkdir(parents=True, exist_ok=True)

# Global list to track extracted dirs
# Hash -> Path to extracted directory & Result of array of 2-tuples (install_prefix, extract_path)
EXTRACT_DIRS = {}
EXTRACT_DIRS_PATH = EXTRACT_DIR / ".surfactant_extracted_dirs.json"

RAR_SUPPORT = {"enabled": False}


def supports_file(filetype: list[str]) -> list[str] | None:
    if filetype is None:
        return None
    supported_types = {"TAR", "GZIP", "ZIP", "BZIP2", "XZ"}
    supported = []
    # Filter out non-archive types
    for ft in filetype:
        if ft in supported_types or ft == "RAR" and RAR_SUPPORT["enabled"]:
            supported.append(ft)
    if supported:
        return supported

    return None


# pylint: disable=too-many-positional-arguments
@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: list[str],
    context_queue: "Queue[ContextEntry]",
    current_context: ContextEntry | None,
) -> dict[str, Any] | None:
    # Check if the file is compressed and get its format
    compression_format = supports_file(filetype)

    if compression_format:
        for fmt in compression_format:
            create_extraction(
                filename,
                software,
                context_queue,
                current_context,
                lambda f, t, format=fmt: decompress_to(f, t, format),
            )


def create_extraction(
    filename: str,
    software: Software,
    context_queue: "Queue[ContextEntry]",
    current_context: ContextEntry | None,
    decompress: Callable[[str, str], bool | list[tuple[str, str]]],
):
    """Create extraction context entries for decompressed archive files.

    Args:
        filename (str): Path to the archive file to be extracted
        software (Software): Software object to associated with the file; used to skip extraction if already processed
        context_queue (Queue[ContextEntry]): Queue to add new context entries for extracted content
        current_context (Optional[ContextEntry]): Current context entry being processed
        decompress (Callable[[str, str], Union[bool, List[Tuple[str, str]]]]): Function that performs
            the actual decompression. Takes filename and output folder, returns True/False for success
            or a list of tuples containing (install_prefix, extract_path) pairs for multiple entries
    """

    install_prefix = ""

    # Check that archive key exists and filename is same as archive file
    if current_context and current_context.archive and current_context.archive == filename:
        if current_context.extractPaths is not None and current_context.extractPaths != []:
            logger.info(
                f"Already extracted, skipping extraction for archive: {current_context.archive}"
            )
            return

        # Inherit the context entry install prefix for the extracted files
        install_prefix = current_context.installPrefix

    if (
        software.sha256 in EXTRACT_DIRS
        and EXTRACT_DIRS[software.sha256]["result"]
        and Path(EXTRACT_DIRS[software.sha256]["path"]).exists()
    ):
        entries = EXTRACT_DIRS[software.sha256]["result"]
        logger.info(f"Using cached extraction entries for {filename}")
    else:
        # Create a temporary directory for extraction
        temp_folder = create_extract_dir()
        EXTRACT_DIRS[software.sha256] = {"path": temp_folder, "result": None}

        # Decompress the file
        entries = decompress(filename, temp_folder)

        # Simple case where the decompressor doesn't need multiple entries
        if entries is True:
            entries = [(None, temp_folder)]

        # If False or an empty list
        if not entries:
            logger.error(f"Failed to decompress {filename}. No entries created.")
            return

        # Store the result in the global EXTRACT_DIRS
        EXTRACT_DIRS[software.sha256]["result"] = entries

    for entry_prefix, extract_path in entries:
        # Merges our install prefix with the entry's install prefix (where applicable)
        prefix = "/".join(filter(None, [install_prefix, entry_prefix]))

        # Create a new context entry and add it to the queue
        new_entry = ContextEntry(
            archive=filename,
            installPrefix=prefix,
            extractPaths=[extract_path],
            skipProcessingArchive=True,
        )
        context_queue.put(new_entry)
        logger.info(
            f"New ContextEntry added for extracted files: {extract_path} (prefix: {entry_prefix})"
        )


def decompress_to(filename: str, output_folder: str, compression_format: str) -> bool:
    if compression_format == "ZIP":
        decompress_zip_file(filename, output_folder)
    elif compression_format == "TAR":
        extract_tar_file(filename, output_folder)
    elif compression_format in {"GZIP", "BZIP2", "XZ"}:
        try:
            tar_modes = {
                "GZIP": "r:gz",
                "BZIP2": "r:bz2",
                "XZ": "r:xz",
            }
            extract_tar_file(filename, output_folder, tar_modes[compression_format], True)
        except tarfile.ReadError as e:
            # Check if we expected it to be readable as a compressed tar file
            if (
                ".tar" in pathlib.Path(filename).suffixes
                or ".tgz" in pathlib.Path(filename).suffixes
            ):
                logger.error(f"Error decompressing tar file {filename}: {e}")
                logger.info(
                    f"Attempting to decompress {filename} using the appropriate library as a single file"
                )
            # Since it doesn't seem to be a compressed tar file, try just decompressing the file
            return decompress_file(filename, output_folder, compression_format)
    elif compression_format == "RAR":
        decompress_rar_file(filename, output_folder)
    else:
        raise ValueError(f"Unsupported compression format: {compression_format}")
    return True


def decompress_zip_file(filename: str, output_folder: str):
    try:
        with zipfile.ZipFile(filename, "r") as f:
            f.extractall(path=output_folder)
    except zipfile.BadZipFile as e:
        logger.error(f"Error extracting ZIP file {filename}: {e}")
    logger.info(f"Extracted ZIP contents to {output_folder}")


def decompress_file(
    filename: str, output_folder: str, compression_type: Literal["GZIP", "BZIP2", "XZ"]
) -> bool:
    filepath = pathlib.Path(filename)
    output_filename = filepath.name

    extensions = {
        "GZIP": ".gz",
        "BZIP2": ".bz2",
        "XZ": ".xz",
    }
    if filename.endswith(extensions[compression_type]):
        output_filename = filepath.stem

    modules = {
        "GZIP": gzip,
        "BZIP2": bz2,
        "XZ": lzma,
    }
    try:
        module = modules[compression_type]
        with (
            module.open(filename, "rb") as f_in,
            (Path(output_folder) / output_filename).open("wb") as f_out,
        ):
            shutil.copyfileobj(f_in, f_out)
    except gzip.BadGzipFile as e:
        # Likely only the first stream of a concatenated file was decompressed, so we will still keep the temp dir
        logger.warning(
            f"Trailing garbage bytes or concatenated streams ignored for {filename}: {e}"
        )
    except OSError as e:
        logger.warning(f"Unable to decompress {filename}: {e}")
        # This file will be completely unusable.
        return False
    return True


def extract_tar_file(
    filename: str,
    output_folder: str,
    open_mode: Literal["r", "r:*", "r:", "r:gz", "r:bz2", "r:xz"] = "r",
    throw_on_read_error: bool = True,
):
    try:
        with tarfile.open(filename, open_mode) as tar:
            tar.extractall(path=output_folder)
    except FileNotFoundError:
        logger.error(f"File not found: {filename}")
    except tarfile.TarError as e:
        if throw_on_read_error and isinstance(e, tarfile.ReadError):
            raise e
        logger.error(f"Error extracting tar file: {e}")
    logger.info(f"Extracted TAR contents to {output_folder}")


def decompress_rar_file(filename: str, output_folder: str):
    try:
        rf = rarfile.RarFile(filename)
        rf.extractall(path=output_folder)
    except rarfile.Error as e:
        logger.error(f"Error extracting rar file: {e}")
    logger.info(f"Extracted RAR contents to {output_folder}")


def setup_extracted_dirs():
    """Get the list of directories where files have been extracted."""
    should_cache_extractions = ConfigManager().get("decompression", "cache_extractions", True)
    if should_cache_extractions and EXTRACT_DIRS_PATH.exists():
        try:
            with Path(EXTRACT_DIRS_PATH).open() as f:
                GLOBAL_EXTRACT_DIRS = json.load(f)
            if not isinstance(GLOBAL_EXTRACT_DIRS, dict):
                logger.error(f"Invalid format in {EXTRACT_DIRS_PATH}. Expected a dictionary.")
                GLOBAL_EXTRACT_DIRS = {}
        except json.JSONDecodeError:
            logger.error(f"Failed to read extracted directories from {EXTRACT_DIRS_PATH}.")
            GLOBAL_EXTRACT_DIRS = {}
    else:
        GLOBAL_EXTRACT_DIRS = {}


def store_extracted_dirs():
    """Store the current extracted directories to a JSON file."""
    should_cache_extractions = ConfigManager().get("decompression", "cache_extractions", True)
    if should_cache_extractions:
        try:
            with Path(EXTRACT_DIRS_PATH).open("w") as f:
                json.dump(EXTRACT_DIRS, f)
        except OSError as e:
            logger.error(f"Failed to write extracted directories to {EXTRACT_DIRS_PATH}: {e}")


def create_extract_dir():
    return tempfile.mkdtemp(prefix=EXTRACT_DIRS_PREFIX, dir=EXTRACT_DIR)


def delete_extract_dirs():
    exited_gracefully = exit_hook.has_exited_gracefully()
    should_cache_extractions = ConfigManager().get("decompression", "cache_extractions", True)
    should_persist_extractions = should_cache_extractions and ConfigManager().get(
        "decompression", "persist_extractions", False
    )
    keys = list(EXTRACT_DIRS.keys())
    for key in keys:
        # Extraction was in progress or failed; we have no reason to keep it
        extraction_failed = not EXTRACT_DIRS[key]["result"]
        should_delete = extraction_failed or (not should_persist_extractions and exited_gracefully)
        if not should_cache_extractions or should_delete:
            temp_dir = EXTRACT_DIRS[key]["path"]
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
            del EXTRACT_DIRS[key]


def setup_rar_support():
    RAR_SUPPORT["enabled"] = False

    should_enable_rar = ConfigManager().get("rar", "enabled", True)
    if should_enable_rar:
        try:
            result = rarfile.tool_setup()
            if result.setup["open_cmd"][0] in ("UNRAR_TOOL", "UNAR_TOOL"):
                RAR_SUPPORT["enabled"] = True
                return
        except rarfile.RarCannotExec:
            pass
        logger.warning(
            "Install 'Unrar' or 'unar' tool for RAR archive decompression. RAR decompression disabled until installed."
        )


@surfactant.plugin.hookimpl
def init_hook(command_name: str | None = None):
    """Initialize the file decompression plugin."""
    setup_extracted_dirs()
    setup_rar_support()


@atexit.register
def cleanup_hook():
    """Clean up temporary directories and store extraction cache on exit."""
    delete_extract_dirs()
    store_extracted_dirs()
