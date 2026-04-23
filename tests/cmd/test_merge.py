# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json
import os
import pathlib
import random
import string

import pytest

from surfactant.cmd.merge import merge
from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM
from tests.cmd import common


def get_config():
    return {
        "system": {
            "UUID": "6a0ee431-842f-4963-8867-ef0ef6998003",
            "name": "",
            "vendor": None,
            "captureStart": 1689186121,
            "captureEnd": 1689186146,
        }
    }


def get_sbom3():
    with open(
        pathlib.Path(__file__).parent / "../data/sample_sboms/helics_binaries_sbom.json",
    ) as f:
        return SBOM.from_json(f.read())


def get_sbom4():
    with open(
        pathlib.Path(__file__).parent / "../data/sample_sboms/helics_libs_sbom.json"
    ) as f:
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

    outfile_name = generate_filename("test_merge_with_circular_dependency")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [circular_dependency_sbom, sbom2]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, get_config(), output_writer)
    # TODO add validation checks here
    os.remove(os.path.abspath(outfile_name))


@pytest.mark.skip(reason="No way of properly validating this test yet")
def test_cmdline_merge():
    sbom3 = get_sbom3()
    sbom4 = get_sbom4()
    # Test simple merge of two sboms
    outfile_name = generate_filename("test_cmdline_merge")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    config_file = get_config()
    input_sboms = [sbom3, sbom4]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer)

    # TODO add validation checks here
    with open(outfile_name) as j:
        generated_sbom = json.loads(j.read())
    with open(pathlib.Path(__file__).parent / "../data/sample_sboms/helics_sbom.json") as j:
        ground_truth_sbom = json.loads(j.read())
    os.remove(os.path.abspath(outfile_name))


def test_merge_with_add_system_true():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()
    outfile_name = generate_filename("test_merge_with_add_system_true")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    config_file["system"]["UUID"] = "6a0ee431-842f-4963-8867-ef0ef6998003"
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=True)

    with open(outfile_name) as j:
        generated_sbom = json.loads(j.read())
    assert generated_sbom["systems"]
    assert generated_sbom["systems"][0]["UUID"] == config_file["system"]["UUID"]

    os.remove(os.path.abspath(outfile_name))


def test_merge_with_add_system_false():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()
    outfile_name = generate_filename("test_merge_with_add_system_false")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    config_file["system"]["UUID"] = "6a0ee431-842f-4963-8867-ef0ef6998003"
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=False)

    with open(outfile_name) as j:
        generated_sbom = json.loads(j.read())
    assert not generated_sbom["systems"]

    os.remove(os.path.abspath(outfile_name))


def test_merge_with_custom_system_relationship():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()
    outfile_name = generate_filename("test_merge_with_custom_system_relationship")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    config_file["systemRelationship"] = "DependsOn"
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=True)

    with open(outfile_name) as j:
        generated_sbom = json.loads(j.read())
    for relationship in generated_sbom["relationships"]:
        if relationship["xUUID"] == config_file["system"]["UUID"]:
            assert relationship["relationship"] == "DependsOn"

    os.remove(os.path.abspath(outfile_name))


def test_merge_with_specified_system_uuid():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()
    outfile_name = generate_filename("test_merge_with_specified_system_uuid")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    system_uuid = "123e4567-e89b-12d3-a456-426614174000"
    with open(outfile_name, "w") as sbom_outfile:
        merge(
            input_sboms,
            sbom_outfile,
            config_file,
            output_writer,
            add_system=True,
            system_uuid=system_uuid,
        )

    with open(outfile_name) as j:
        generated_sbom = json.loads(j.read())
    assert any(system["UUID"] == system_uuid for system in generated_sbom["systems"])

    os.remove(os.path.abspath(outfile_name))


def test_prevent_orphaned_system_uuid():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()
    outfile_name = generate_filename("test_prevent_orphaned_system_uuid")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    # Get rid of the system UUID field from the config file
    # This will make it try to generate a random UUID, but won't add it since add_system is False
    del config_file["system"]["UUID"]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=False)

    with open(outfile_name) as j:
        generated_sbom = json.loads(j.read())
    assert not generated_sbom["systems"]

    os.remove(os.path.abspath(outfile_name))


def test_add_random_system_uuid():
    sbom1 = common.get_sbom1()
    sbom2 = common.get_sbom2()
    outfile_name = generate_filename("test_prevent_orphaned_system_uuid")
    pm = get_plugin_manager()
    output_writer = pm.get_plugin("surfactant.output.cytrics_writer")
    input_sboms = [sbom1, sbom2]
    config_file = get_config()
    # Get rid of the system UUID field from the config file
    # This will make it try to generate a random UUID, but won't add it since add_system is False
    original_config_system_UUID = config_file["system"]["UUID"]
    del config_file["system"]["UUID"]
    with open(outfile_name, "w") as sbom_outfile:
        merge(input_sboms, sbom_outfile, config_file, output_writer, add_system=True)

    with open(outfile_name) as j:
        generated_sbom = json.loads(j.read())
    assert generated_sbom["systems"]
    # Check that the UUID of the generated system is actually random
    assert generated_sbom["systems"][0]["UUID"] != original_config_system_UUID

    os.remove(os.path.abspath(outfile_name))


def generate_filename(name, ext=".json"):
    res = "".join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return str(name + "_" + res + ext)
