# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import argparse
import copy
import json
import os
import re

from surfactant.sbomtypes import SBOM

# The following code adds the data present in additional_metadata.json files to an input
# sbom and outputs it at a new location.

#     - It uses the sha256hash field to perform linkages
#     - It does overwrite the output location

# Usage:
#     python3 scripts/merge_additional_metadata.py . sbom_without_metadata.json output_sbom_file.json


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "metadata_dir",
        help='The directory that contains the "additional metadata" files',
    )
    parser.add_argument("input_sbom", help="The SBOM for the additional metadata to be merged into")
    parser.add_argument("output_file", help="The output file")
    _args = parser.parse_args()
    return _args


if __name__ == "__main__":
    args = parse_args()
    with open(args.input_sbom, encoding="utf-8") as f:
        sbom = SBOM.from_json(f.read())
    lookup_table = {}
    for sw in sbom.software:
        if sw.sha256:
            lookup_table.setdefault(sw.sha256, []).append(sw)
    for path in os.scandir(args.metadata_dir):
        if path.is_file() and re.fullmatch(r"[a-z0-9]{64}_additional_metadata\.json", path.name):
            with open(path, encoding="utf-8") as f:
                additional_data = json.load(f)
            if not isinstance(additional_data, dict):
                raise TypeError(f"Additional metadata file must contain a JSON object: {path.name}")
            if "sha256hash" not in additional_data:
                raise ValueError(f"Additional metadata file must contain sha256hash: {path.name}")
            if not isinstance(additional_data["sha256hash"], str):
                raise TypeError(
                    f"Additional metadata file must contain a string sha256hash: {path.name}"
                )

            matches = lookup_table.get(additional_data["sha256hash"], [])
            if not matches:
                raise ValueError(
                    "No software entry found for additional metadata file "
                    f"{path.name} with sha256hash={additional_data['sha256hash']}"
                )
            for sw in matches:
                if additional_data not in sw.metadata:
                    sw.metadata.append(copy.deepcopy(additional_data))
    with open(args.output_file, "w", encoding="utf-8") as f:
        f.write(sbom.to_json(indent=4))
