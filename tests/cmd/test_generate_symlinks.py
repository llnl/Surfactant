# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
"""Regression tests for symlink handling in ``surfactant generate``.

These guard against a regression where ``resolve_link`` looped on the
``Path.is_symlink`` *method object* (always truthy) and then called
``readlink()`` on a non-symlink, raising ``OSError`` and aborting the whole
SBOM generation run for any input tree containing a symlink.
"""

import json
import os
from pathlib import Path

import pytest

from surfactant.cmd.generate import resolve_link, sbom

# Creating symlinks on Windows generally requires elevated privileges or
# developer mode, so skip these tests there rather than fail spuriously.
pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="Symlink creation typically unavailable/unprivileged on Windows"
)


def test_resolve_link_relative_file(tmp_path):
    """A relative symlink to a regular file resolves without raising."""
    extract_dir = tmp_path
    target = extract_dir / "real.txt"
    target.write_text("hello")
    link = extract_dir / "link.txt"
    link.symlink_to("real.txt")

    result = resolve_link(str(link), str(extract_dir), str(extract_dir))

    assert result is not None
    assert Path(result).name == "real.txt"
    assert Path(result).read_text() == "hello"


def test_resolve_link_dangling_returns_none(tmp_path):
    """A symlink whose target does not exist resolves to None (not a crash)."""
    extract_dir = tmp_path
    link = extract_dir / "dangling"
    link.symlink_to("does_not_exist")

    assert resolve_link(str(link), str(extract_dir), str(extract_dir)) is None


def test_resolve_link_multi_hop_chain(tmp_path):
    """A multi-hop relative symlink chain resolves."""
    extract_dir = tmp_path
    target = extract_dir / "real.txt"
    target.write_text("hi")
    hop1 = extract_dir / "hop1"
    hop1.symlink_to("real.txt")
    hop2 = extract_dir / "hop2"
    hop2.symlink_to("hop1")

    result = resolve_link(str(hop2), str(extract_dir), str(extract_dir))

    assert result is not None
    assert Path(result).name == "real.txt"


def test_resolve_link_loop_returns_none(tmp_path):
    """A self-referential symlink loop is detected and returns None."""
    extract_dir = tmp_path
    a = extract_dir / "a"
    b = extract_dir / "b"
    a.symlink_to("b")
    b.symlink_to("a")

    assert resolve_link(str(a), str(extract_dir), str(extract_dir)) is None


def test_generate_directory_with_symlink_does_not_crash(tmp_path):
    """End-to-end: a scanned directory containing a symlink produces an SBOM."""
    sample = tmp_path / "sample"
    sample.mkdir()
    binfile = sample / "app.bin"
    binfile.write_bytes(b"binary content for sbom\n")
    (sample / "app_link").symlink_to("app.bin")

    config_path = str(tmp_path / "config.json")
    output_path = str(tmp_path / "out.json")
    Path(config_path).write_text(
        json.dumps([{"extractPaths": [sample.as_posix()], "installPrefix": "/opt/app/"}])
    )

    # pylint: disable=no-value-for-parameter
    sbom([config_path, output_path], standalone_mode=False)
    # pylint: enable

    assert Path(output_path).exists(), "generate produced no SBOM output"
    generated = json.loads(Path(output_path).read_text())
    # The real file must be present in the SBOM.
    filenames = {fn for sw in generated["software"] for fn in (sw.get("fileName") or [])}
    assert "app.bin" in filenames
