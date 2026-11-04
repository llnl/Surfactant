# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import io

from surfactant.output import dot_writer
from surfactant.sbomtypes import SBOM, Software


def _make_sbom():
    sbom = SBOM()
    app = Software(fileName=["app.exe"])
    lib = Software(fileName=["helper.dll"])
    sbom.software = [app, lib]
    sbom.create_relationship(app.UUID, lib.UUID, "Uses")
    return sbom, app, lib


def test_dot_writer_short_name():
    assert dot_writer.short_name() == "dot"


def test_dot_writer_emits_digraph_nodes_and_edges():
    sbom, app, lib = _make_sbom()

    outfile = io.StringIO()
    dot_writer.write_sbom(sbom, outfile)
    output = outfile.getvalue()

    # Well-formed digraph
    assert output.startswith("digraph SBOM {")
    assert output.rstrip().endswith("}")

    # A labeled node for each software entry
    assert f'"{app.UUID}" [label="app.exe"];' in output
    assert f'"{lib.UUID}" [label="helper.dll"];' in output

    # The relationship rendered as a labeled directed edge
    assert f'"{app.UUID}" -> "{lib.UUID}" [label="Uses"];' in output


def test_dot_writer_falls_back_to_uuid_label():
    sbom = SBOM()
    unnamed = Software()
    sbom.software = [unnamed]

    outfile = io.StringIO()
    dot_writer.write_sbom(sbom, outfile)
    output = outfile.getvalue()

    assert f'"{unnamed.UUID}" [label="{unnamed.UUID}"];' in output


def test_dot_writer_handles_empty_sbom():
    outfile = io.StringIO()
    dot_writer.write_sbom(SBOM(), outfile)
    output = outfile.getvalue()

    assert output.startswith("digraph SBOM {")
    assert output.rstrip().endswith("}")
    assert "->" not in output
