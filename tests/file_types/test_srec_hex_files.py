# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import os
import pathlib

from surfactant.infoextractors.srec_hex import (
    read_hex_info,
    read_srecord_info,
    write_write_info_to_file,
)

_base_path = pathlib.Path(__file__).parent.absolute()
_data_dir = os.path.join(_base_path, "..", "data", "binary")
_expected_output_loc = os.path.join(_base_path, "..", "data", "msitest_no1", "test.msi")


def test_srec_extract(tmp_path):
    with open(tmp_path / "srec_test.bin", "wb") as f:
        write_info = read_srecord_info(os.path.join(_data_dir, "test.srec"))
        assert write_info is not None
        assert write_write_info_to_file(f, write_info, trim_leading_zeros=False)
    with open(tmp_path / "srec_test.bin", "rb") as f:
        output_data = f.read()
    with open(_expected_output_loc, "rb") as f:
        expected_data = f.read()
    assert output_data == expected_data


def test_hex_extract(tmp_path):
    with open(tmp_path / "hex_test.bin", "wb") as f:
        write_info = read_hex_info(os.path.join(_data_dir, "test.hex"))
        assert write_info is not None
        assert write_write_info_to_file(f, write_info, trim_leading_zeros=False)
    with open(tmp_path / "hex_test.bin", "rb") as f:
        output_data = f.read()
    with open(_expected_output_loc, "rb") as f:
        expected_data = f.read()
    assert output_data == expected_data
