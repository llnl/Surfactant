# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from surfactant.infoextractors.js_file import js_db_manager


def test_parse_raw_data_invalid_json_returns_empty():
    assert js_db_manager.parse_raw_data("{not valid json") == {}


def test_parse_raw_data_truncated_download_returns_empty():
    assert js_db_manager.parse_raw_data('{"jquery": {"extractors":') == {}


def test_parse_raw_data_non_object_returns_empty():
    assert js_db_manager.parse_raw_data("[1, 2, 3]") == {}


def test_parse_raw_data_valid_entry_is_kept():
    raw = '{"jquery": {"extractors": {"filecontent": ["jquery-\\\\d"]}}}'
    parsed = js_db_manager.parse_raw_data(raw)
    assert "jquery" in parsed
    assert parsed["jquery"]["filecontent"] == ["jquery-\\d"]
