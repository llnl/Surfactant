# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import os
import pathlib
import sys
import zlib

import pytest

from surfactant.filetypeid.id_extension import identify_file_type as identify_extension_file_type
from surfactant.filetypeid.id_hex import identify_file_type as identify_hex_file_type
from surfactant.filetypeid.id_magic import identify_file_type

# Files are relative to tests/data/
_file_to_file_type = {
    "a_out_files/big_m68020.aout": "A.OUT big",
    "a_out_files/big_netbsd_i386.aout": "A.OUT big",
    "a_out_files/big_netbsd_sparc.aout": "A.OUT big",
    "a_out_files/little_386.aout": "A.OUT little",
    "a_out_files/little_unknown.aout": "A.OUT little",
    "coff_files/intel_80386_coff": "COFF",
    "ELF_shared_obj_test_no1/bin/hello_world": "ELF",
    "ELF_shared_obj_test_no1/lib/libtestlib.so": "ELF",
    "java_class_no1/HelloWorld.class": "JAVACLASS",
    "mach_o_dylib_test_no1/bin/hello_world": "MACHO64",
    "mach_o_dylib_test_no1/lib/libtestlib.dylib": "MACHO64",
    "msitest_no1/test.msi": "OLE",
    "NET_app_config_test_no1/ConsoleApp2.exe": "PE",
    "NET_app_config_test_no1/bin/Debug/net6.0/hello.dll": "PE",
    "Windows_dll_test_no1/hello_world.exe": "PE",
    "Windows_dll_test_no1/testlib.dll": "PE",
    "cpio_files/hi_little.cpio": "CPIO_BIN little",
    "cpio_files/hi_big.cpio": "CPIO_BIN big",
    "cpio_files/cpio_char_new.cpio": "CPIO_ASCII_NEW",
    "cpio_files/cpio_char_old.cpio": "CPIO_ASCII_OLD",
    "cd_iso_files/cd_iso_8001.iso": "ISO_9660_CD",
    "cd_iso_files/cd_iso_8801.iso": "ISO_9660_CD",
    "cd_iso_files/cd_iso_9001.iso": "ISO_9660_CD",
    "zstandard/hi.txt.zst": "ZSTANDARD",
    "mac_os_dmg/mac_os.dmg": "MACOS_DMG",
}


def test_magic_id():
    base_path = pathlib.Path(__file__).parent.absolute()
    data_dir = os.path.join(base_path, "..", "data")
    for file_name, file_type in _file_to_file_type.items():
        assert identify_file_type(os.path.join(data_dir, file_name)) == [file_type]


def test_zlib_basic(tmp_path):
    for compress_level in range(10):
        write_to = tmp_path / f"basic_{compress_level}.zlib"
        write_to.write_bytes(zlib.compress(b"hello", level=compress_level))
        assert identify_file_type(write_to) == ["ZLIB"]


def test_extension_id_returns_list(tmp_path):
    write_to = tmp_path / "hello.py"
    write_to.write_text("print('hello')\n", encoding="utf-8")

    assert identify_extension_file_type(write_to) == ["PYTHON"]


def test_hex_id_returns_list(tmp_path):
    write_to = tmp_path / "sample.hex"
    write_to.write_text(":10010000214601360121470136007EFE09D2190140\n", encoding="utf-8")

    assert identify_hex_file_type(write_to) == ["INTEL_HEX"]


@pytest.mark.skipif(
    sys.version_info < (3, 11), reason="zlib.compress wbits only available from Python 3.11+"
)
def test_zlib_window(tmp_path):
    for compress_level in range(10):
        for window_size in range(9, 16):
            write_to = tmp_path / f"window_{compress_level}_{window_size}.zlib"
            write_to.write_bytes(zlib.compress(b"hello", level=compress_level, wbits=window_size))
            assert identify_file_type(write_to) == ["ZLIB"]
