# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pathlib

from surfactant.infoextractors.srec_hex import (
    read_hex_info,
    read_srecord_info,
    write_write_info_to_file,
)

_data_dir = pathlib.Path(__file__).parent.parent / "data" / "binary"
_expected_output_loc = _data_dir / "test.msi"


def test_srec_extract(tmp_path):
    with (tmp_path / "srec_test.bin").open("wb") as f:
        write_info = read_srecord_info(str(_data_dir / "test.srec"))
        assert write_info is not None
        assert write_write_info_to_file(f, write_info, trim_leading_zeros=False)
    with (tmp_path / "srec_test.bin").open("rb") as f:
        output_data = f.read()
    with _expected_output_loc.open("rb") as f:
        expected_data = f.read()
    assert output_data == expected_data


def test_hex_extract(tmp_path):
    with (tmp_path / "hex_test.bin").open("wb") as f:
        write_info = read_hex_info(str(_data_dir / "test.hex"))
        assert write_info is not None
        assert write_write_info_to_file(f, write_info, trim_leading_zeros=False)
    with (tmp_path / "hex_test.bin").open("rb") as f:
        output_data = f.read()
    with _expected_output_loc.open("rb") as f:
        expected_data = f.read()
    assert output_data == expected_data
