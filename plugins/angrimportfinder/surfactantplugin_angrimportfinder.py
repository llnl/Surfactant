# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
from pathlib import Path

import angr
from cle import CLECompatibilityError
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


@surfactant.plugin.hookimpl(specname="extract_file_info")
# extract_strings(sbom: SBOM, software: Software, filename: str, filetype: str):
# def angrimport_finder(filename: str, filetype: str, filehash: str):
def angrimport_finder(sbom: SBOM, software: Software, filename: str, filetype: list[str]):
    """
    :param sbom(SBOM): The SBOM that the software entry/file is being added to. Can be used to add observations or analysis data.
    :param software(Software): The software entry associated with the file to extract information from.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (List[str]): File type information based on magic bytes.
    """

    # Only parsing executable files
    if not ("ELF" in filetype or "PE" in filetype):
        return
    filehash = str(software.sha256)
    filename = Path(filename)
    flist = []

    # Performing check to see if file has been analyzed already
    existing_json = None
    output_name = None
    for f in Path.cwd().glob("*_additional_metadata.json"):
        flist.append((f.stem).split("_")[0])
        if filehash == (f.stem).split("_")[0]:
            existing_json = f
            output_name = f

    if existing_json:
        with open(existing_json) as json_file:
            existing_data = json.load(json_file)
        if (
            "imported function names" in existing_data
            and "exported function names" in existing_data
        ):
            logger.info(f"Already extracted {filename.name}")
        else:
            try:
                logger.info(
                    f"Found existing JSON file for {filename.name} but without 'imported function names' or 'exported function names' keys. Proceeding with extraction."
                )
                # Add your extraction code here.
                if filename.name not in existing_data["filename"]:
                    existing_data["filename"].append(filename.name)
                existing_data["imported function names"] = []
                existing_data["exported function names"] = []
                # Create an angr project
                try:
                    project = angr.Project(filename, auto_load_libs=False)

                    # Get the imported functions using symbol information
                    for symbol in project.loader.main_object.symbols:
                        if symbol.is_import:
                            existing_data["imported function names"].append(symbol.name)
                        elif symbol.is_export:
                            existing_data["exported function names"].append(symbol.name)
                except IndexError as e:
                    logger.warning(f"Error while parsing PE file: {filename}: {e}")
                    return

                # Write the string_dict to the output JSON file
                with open(output_name, "w") as json_file:
                    json.dump(existing_data, json_file, indent=4)
            except CLECompatibilityError as e:
                logger.info(f"Angr Error {filename} {e}")
    else:
        try:
            # Validate the file path
            if not filename.exists():
                raise FileNotFoundError(f"No such file: '{filename}'")

            # Extract filename without extension
            output_path = Path.cwd() / f"{filehash}_additional_metadata.json"
            metadata = {}
            metadata["sha256hash"] = filehash
            metadata["filename"] = [filename.name]
            metadata["imported function names"] = []
            metadata["exported function names"] = []
            # Create an angr project
            try:
                project = angr.Project(filename.as_posix(), auto_load_libs=False)
                # Get the functions using symbol information
                for symbol in project.loader.main_object.symbols:
                    if symbol.is_import:
                        metadata["imported function names"].append(symbol.name)
                    elif symbol.is_export:
                        metadata["exported function names"].append(symbol.name)
            except IndexError as e:
                logger.warning(f"Error while parsing PE file: {filename}: {e}")
                return
            # Write the string_dict to the output JSON file
            with open(output_path, "w") as json_file:
                json.dump(metadata, json_file, indent=4)

            logger.info(f"Data written to {output_path}")
        except CLECompatibilityError as e:
            logger.info(f"Angr Error {filename} {e}")
