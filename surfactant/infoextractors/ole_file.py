# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from queue import Queue
from typing import Any

import olefile
import pymsi
from loguru import logger
from pymsi.msi.component import Component
from pymsi.msi.directory import Directory
from pymsi.thirdparty.refinery.cab import CabFolder

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.context import ContextEntry
from surfactant.infoextractors import file_decompression
from surfactant.sbomtypes import SBOM, Software

# https://learn.microsoft.com/en-us/windows/win32/msi/property-reference#system-folder-properties
DEFAULT_PATHS = {
    "AdminToolsFolder": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools",
    "AppDataFolder": "C:\\Users\\USER\\AppData\\Roaming",
    "CommonAppDataFolder": "C:\\ProgramData",
    "CommonFiles64Folder": "C:\\Program Files\\Common Files",
    "CommonFilesFolder": "C:\\Program Files (x86)\\Common Files",
    "DesktopFolder": "C:\\Users\\USER\\Desktop",
    "FavoritesFolder": "C:\\Users\\USER\\Favorites",
    "FontsFolder": "C:\\Windows\\Fonts",
    "LocalAppDataFolder": "C:\\Users\\USER\\AppData\\Local",
    "MyPicturesFolder": "C:\\Users\\USER\\Pictures",
    "NetHoodFolder": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts",
    "PersonalFolder": "C:\\Users\\USER\\Documents",
    "PrintHoodFolder": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts",
    "ProgramFiles64Folder": "C:\\Program Files",
    "ProgramFilesFolder": "C:\\Program Files (x86)",
    "ProgramMenuFolder": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs",
    "RecentFolder": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
    "SendToFolder": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\SendTo",
    "StartMenuFolder": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu",
    "StartupFolder": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "System16Folder": "C:\\Windows\\System",
    "System64Folder": "C:\\Windows\\System32",
    "SystemFolder": "C:\\Windows\\System32",
    "TempFolder": "C:\\Users\\USER\\AppData\\Local\\Temp",
    "TemplateFolder": "C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\Templates",
    "WindowsFolder": "C:\\Windows",
    "WindowsVolume": "C:\\",
}


def replace_root_id(system_folder_id: str) -> str | None:
    path = ConfigManager().get(
        "ole", f"replacement_{system_folder_id}", DEFAULT_PATHS.get(system_folder_id)
    )
    if path:
        path = path.replace("\\", "/")
    return path


def supports_file(filetype: list[str]) -> bool:
    return "OLE" in filetype


# pylint: disable=too-many-positional-arguments
@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: list[str],
    software_field_hints: list[tuple[str, object, int]],
    context_queue: "Queue[ContextEntry]",
    current_context: ContextEntry | None,
) -> object:
    if not supports_file(filetype):
        return None
    ole_info = extract_ole_info(filename)
    if ole_info and "ole" in ole_info:
        if "subject" in ole_info["ole"]:
            software_field_hints.append(("name", ole_info["ole"]["subject"], 80))
        if "revision_number" in ole_info["ole"]:
            software_field_hints.append(("version", ole_info["ole"]["revision_number"], 80))
        if "author" in ole_info["ole"]:
            software_field_hints.append(("vendor", ole_info["ole"]["author"], 80))
        if "comments" in ole_info["ole"]:
            software_field_hints.append(("comments", ole_info["ole"]["comments"], 80))

        if ole_info["ole"].get("clsid_type") == "MSI":
            file_decompression.create_extraction(
                filename, software, context_queue, current_context, extract_msi
            )

    return ole_info


def extract_ole_info(filename: str) -> dict[str, Any]:
    file_details: dict[str, Any] = {}

    with olefile.OleFileIO(filename) as ole:
        md = ole.get_metadata()
        file_details["ole"] = {}

        # to check if an OLE is an MSI file, check the root storage object CLSID
        # {000c1084-0000-0000-c000-000000000046}	MSI
        # {000c1086-0000-0000-c000-000000000046}    Windows Installer Patch MSP
        # extensions are typically .msi and .msp for files with these two clsid's
        # less common would be a .msm (merge) with the same clsid as MSI
        # as well as .mst (transform) with a clsid of 000c1082
        if ole.root and hasattr(ole.root, "clsid"):
            file_details["ole"]["clsid"] = str(ole.root.clsid).lower()
            if file_details["ole"]["clsid"] == "000c1082-0000-0000-c000-000000000046":
                file_details["ole"]["clsid_type"] = "MST"
            if file_details["ole"]["clsid"] == "000c1084-0000-0000-c000-000000000046":
                file_details["ole"]["clsid_type"] = "MSI"  # or msm, depending on file extension
            if file_details["ole"]["clsid"] == "000c1086-0000-0000-c000-000000000046":
                file_details["ole"]["clsid_type"] = "MSP"

        for prop in md.SUMMARY_ATTRIBS:
            if value := getattr(md, prop, None):
                if isinstance(value, bytes):
                    file_details["ole"][prop] = value.decode("unicode_escape")
                else:
                    file_details["ole"][prop] = str(value)

    return file_details


def extract_msi(filename: str, output_folder: str) -> list[tuple[str, str]]:
    output_path = Path(output_folder)

    try:
        with pymsi.Package(Path(filename)) as package:
            msi = pymsi.Msi(package, True)

            preprocess_msi_decompression(msi)

            entries = extract_msi_root(msi.root, output_path)
            if entries:
                logger.debug(f"Extracted {entries}")
                logger.info(f"Extracted MSI contents to {output_path}")
            return entries
    except (FileNotFoundError, UnicodeDecodeError, ValueError, OSError, KeyError) as e:
        # if the msi files are missing .cab files, FileNotFoundError will catch it
        logger.warning(f"Issue with MSI extraction: {e}")
        return []


def preprocess_msi_decompression(msi: pymsi.Msi):
    folders: list[CabFolder] = []
    for media in msi.medias.values():
        if media.cabinet and media.cabinet.disks:
            for disk in media.cabinet.disks.values():
                for directory in disk:
                    for folder in directory.folders:
                        if folder not in folders:
                            folders.append(folder)

    total_folders = len(folders)
    logger.debug(f"Found {total_folders} folders in .cab files")

    # Use ThreadPoolExecutor to speed up decompression.
    # This is especially useful for LZX, which is implemented in pure Python.
    executor = ThreadPoolExecutor()
    completed_count = 0
    futures = {}
    try:
        for folder in folders:
            future = executor.submit(folder.decompress)
            futures[future] = folder

        for future in as_completed(futures):
            try:
                future.result()
                completed_count += 1
                folder = futures[future]
                logger.trace(f"Decompressed .cab folder: {folder}")
            except KeyboardInterrupt as e:
                raise e
            except (ValueError, RuntimeError, NotImplementedError, EOFError):
                logger.opt(exception=True).error(f"Error decompressing folder {futures[future]}")
    finally:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=False)

    logger.debug("Decompression of .cab folders completed")


def extract_msi_root(root: Directory, output: Path) -> list[tuple[str, str]]:
    if not output.exists():
        output.mkdir(parents=True, exist_ok=True)

    temp_installdir: Directory | None = None

    def move_to_temp_installdir(item: Component | Directory):
        nonlocal temp_installdir
        if not temp_installdir:
            temp_installdir = Directory(
                {
                    "Directory": "_TEMPINSTALLDIR",
                    "Directory_Parent": root.id,
                    "DefaultDir": "INSTALLDIR",
                }
            )
            temp_installdir.parent = root
        if isinstance(item, Component):
            temp_installdir.components[item.id] = component
        elif isinstance(item, Directory):
            temp_installdir.children[item.id] = item
        else:
            raise TypeError(f"Unsupported item type: {type(item)}")

    for component in root.components.values():
        move_to_temp_installdir(component)

    entries = []

    for child in root.children.values():
        folder_name = child.id
        if "." in folder_name:
            folder_name, guid = folder_name.split(".", 1)
            if child.id != folder_name:
                logger.warning(f"MSI Directory ID '{child.id}' has a GUID suffix ({guid}).")

        if not replace_root_id(folder_name):
            logger.warning(
                f"MSI Directory ID '{folder_name}' has no replacement path defined. The MSI file may still be valid, but the path will not be accurate."
            )
            move_to_temp_installdir(child)
            continue
        extract_msi_directory(child, output / folder_name)
        entries.append((replace_root_id(folder_name), str(output / folder_name)))

    if temp_installdir is not None:
        extract_msi_directory(temp_installdir, output / temp_installdir.name)
        entries.append((None, str(output / temp_installdir.name)))

    return entries


def extract_msi_directory(root: Directory, output: Path):
    if not output.exists():
        output.mkdir(parents=True, exist_ok=True)

    for component in root.components.values():
        for file in component.files.values():
            if file.media is None:
                continue
            cab_file = file.resolve()
            (output / file.name).write_bytes(cab_file.decompress())

    for child in root.children.values():
        extract_msi_directory(child, output / child.name)
