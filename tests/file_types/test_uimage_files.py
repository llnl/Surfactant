# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import pathlib

from surfactant.filetypeid.id_magic import identify_file_type
from surfactant.infoextractors.uimage_file import extract_file_info
from surfactant.sbomtypes import SBOM, Software

# Files are relative to tests/data/uimage_files
_uimage_files = {
    "hello_world.img": {
        "header_crc": "0x92c6061b",
        "timestamp": 1741809003,
        "data_size": 61,
        "load_addr": "0x1234",
        "entry_point": "0x5678",
        "data_crc": "0x21ae6b9e",
        "os": "LINUX",
        "os_description": "Linux",
        "arch": "ARM",
        "arch_description": "ARM",
        "image_type": "FIRMWARE",
        "image_type_description": "Firmware",
        "compression_type": "None",
        "name": "Test uImage",
    },
}


def test_uimage_files():
    base_path = pathlib.Path(__file__).parent.absolute()
    data_dir = os.path.join(base_path, "..", "data", "uimage_files")
    for file_name, expected_values in _uimage_files.items():
        file_path = os.path.join(data_dir, file_name)
        file_type = identify_file_type(file_path)
        assert file_type == ["UIMAGE"]
        sw_field_hints = []
        file_info = extract_file_info(
            SBOM(),
            Software.create_software_from_file(file_path),
            file_path,
            file_type,
            sw_field_hints,
        )
        assert sw_field_hints == [("name", "Test uImage", 40)]
        assert "uimage_header" in file_info
        uimage_header = file_info["uimage_header"]
        for key, expected_value in expected_values.items():
            assert key in uimage_header, f"Missing key: {key}"
            assert uimage_header[key] == expected_value, (
                f"Value mismatch for {key}: expected {expected_value}, got {uimage_header[key]}"
            )


def test_bad_uimage_file():
    base_path = pathlib.Path(__file__).parent.absolute()
    file_path = os.path.join(base_path, "..", "data", "uimage_files", "bad1.img")
    file_type = identify_file_type(file_path)
    assert file_type == ["UIMAGE"]
    sw_field_hints = []
    file_info = extract_file_info(
        SBOM(),
        Software.create_software_from_file(file_path),
        file_path,
        file_type,
        sw_field_hints,
    )
    assert file_info is None
