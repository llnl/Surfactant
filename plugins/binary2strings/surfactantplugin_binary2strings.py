# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
from pathlib import Path

import binary2strings as b2s
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


@surfactant.plugin.hookimpl(specname="extract_file_info")
def extract_strings(sbom: SBOM, software: Software, filename: str, filetype: list[str]):
    """
    Extract ASCII strings from a binary file using binary2strings.
    :param sbom(SBOM): The SBOM that the software entry/file is being added to. Can be used to add observations or analysis data.
    :param software(Software): The software entry associated with the file to extract information from.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (List[str]): File type information based on magic bytes.
    """
    shaHash = str(software.sha256)
    min_len = 4
    # Only parsing executable files
    if not ("ELF" in filetype or "PE" in filetype):
        return

    filename = Path(filename)
    flist = []

    # Performing check to see if file has been analyzed already
    existing_json = None
    output_name = None
    for f in Path.cwd().glob("*_additional_metadata.json"):
        flist.append((f.stem).split("_")[0])
        if shaHash == (f.stem).split("_")[0]:
            existing_json = f
            output_name = f

    if existing_json:
        with Path(existing_json).open() as json_file:
            existing_data = json.load(json_file)
        if "strings" in existing_data:
            logger.info(f"Already extracted {filename.name}")
        else:
            logger.info(
                f"Found existing JSON file for {filename.name} but without 'strings' key. Proceeding with extraction."
            )
            # Add your extraction code here.
            if filename.name not in existing_data["filename"]:
                existing_data["filename"].append(filename.name)

            existing_data["strings"] = []
            # Extract and write strings using binary2strings
            with Path(filename).open("rb") as f_bin:
                data = f_bin.read()
                for string, _encoding, _span, _is_interesting in b2s.extract_all_strings(
                    data, only_interesting=True
                ):
                    if len(string) >= min_len:
                        existing_data["strings"].append(string)
            # Write the string_dict to the output JSON file
            with Path(output_name).open("w") as json_file:
                json.dump(existing_data, json_file, indent=4)

    else:
        # Validate the file path
        if not filename.exists():
            raise FileNotFoundError(f"No such file: '{filename}'")

        # Extract filename without extension
        output_path = Path.cwd() / f"{shaHash}_additional_metadata.json"
        string_dict = {}
        string_dict["sha256hash"] = shaHash
        string_dict["filename"] = [filename.name]
        string_dict["strings"] = []

        # Extract and write strings using binary2strings
        with Path(filename).open("rb") as f_bin:
            data = f_bin.read()
            for string, _encoding, _span, _is_interesting in b2s.extract_all_strings(
                data, only_interesting=True
            ):
                # you might adjust the condition below to filter strings based on your needs
                if len(string) >= min_len:
                    string_dict["strings"].append(string)

        # Write the string_dict to the output JSON file
        with Path(output_path).open("w") as json_file:
            json.dump(string_dict, json_file, indent=4)

        logger.info(f"Data written to {output_path}")
