# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import pathlib

from surfactant.filetypeid.id_magic import identify_file_type
from surfactant.infoextractors.a_out_file import extract_file_info
from surfactant.sbomtypes import SBOM, Software

# Files are relative to tests/data/a_out_files
_file_to_machine_type = {
    "big_m68020.aout": "M68020",
    "big_netbsd_i386.aout": "NetBSD/i386",
    "big_netbsd_sparc.aout": "NetBSD/SPARC",
    "little_386.aout": "386",
    "little_unknown.aout": "Unknown",
}


def test_a_out_machine_type():
    base_path = pathlib.Path(__file__).parent.absolute()
    data_dir = os.path.join(base_path, "..", "data", "a_out_files")
    for file_name, machine_type in _file_to_machine_type.items():
        file_path = os.path.join(data_dir, file_name)
        file_type = identify_file_type(file_path)
        file_info = extract_file_info(
            SBOM(),
            Software.create_software_from_file(file_path),
            file_path,
            file_type,
        )
        assert file_info["aoutMachineType"] == machine_type
