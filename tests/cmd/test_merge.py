# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json
import random
import string
from pathlib import Path

import pytest

from surfactant.cmd.merge import merge
from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM
from tests.cmd import common


def get_sbom3():
    with Path(
        Path(__file__).parent / "../data/sample_sboms/helics_binaries_sbom.json",
    ).open() as f:
        return SBOM.from_json(f.read())


def get_sbom4():
    with Path(Path(__file__).parent / "../data/sample_sboms/helics_libs_sbom.json").open() as f:
        return SBOM.from_json(f.read())


# Test Functions
def test_simple_merge_method():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()

    # Merge in place
    merged_sbom = sbom1
    merged_sbom.merge(sbom2)

    common.test_simple_merge_method(common.get_sbom1(), common.get_sbom2(), merged_sbom)


@pytest.mark.skip(reason="No way of validating this test yet")
def test_merge_with_circular_dependency():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()
    circular_dependency_sbom = sbom1

    # inject a circular edge via the new graph API
    circular_dependency_sbom.create_relationship(
        "a5db7e12-fe3d-490e-90b8-98a8bfaace09",
        "dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
        "Contains",
    )

    outfile = Path(generate_filename("test_merge_with_circular_dependency"))
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [circular_dependency_sbom, sbom2]

    with outfile.open("w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, output_writer)
    # TODO add validation checks here

    Path(outfile).resolve().unlink()


@pytest.mark.skip(reason="No way of properly validating this test yet")
def test_cmdline_merge():
    sbom3 = get_sbom3()
    sbom4 = get_sbom4()
    # Test simple merge of two sboms
    outfile = Path(generate_filename("test_cmdline_merge"))
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom3, sbom4]
    with outfile.open("w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, output_writer)

    # TODO add validation checks here
    with outfile.open() as j:
        generated_sbom = json.loads(j.read())
    with (Path(__file__).parent / "../data/sample_sboms/helics_sbom.json").open() as j:
        ground_truth_sbom = json.loads(j.read())
    outfile.resolve().unlink()


def test_merge_does_not_emit_systems():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()
    outfile = Path(generate_filename("test_merge_does_not_emit_systems"))
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]

    with outfile.open("w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, output_writer)

    with outfile.open() as j:
        generated_sbom = json.loads(j.read())

    assert "systems" not in generated_sbom or not generated_sbom["systems"]

    Path(outfile).resolve().unlink()


def generate_filename(name, ext=".json"):
    res = "".join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return str(name + "_" + res + ext)
