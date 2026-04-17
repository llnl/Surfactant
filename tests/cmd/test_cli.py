# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pathlib

import pytest

from surfactant.cmd.cli import cli_add, cli_find
from surfactant.cmd.cli_commands import Cli
from surfactant.sbomtypes import SBOM, Software


@pytest.fixture(name="test_sbom")
def fixture_test_sbom():
    with open(pathlib.Path(__file__).parent / "../data/sample_sboms/helics_sbom.json", "r") as f:
        sbom = SBOM.from_json(f.read())
        return sbom


def _compare_sboms(one: SBOM, two: SBOM) -> bool:
    # Sort hardware and software for deterministic ordering
    one.hardware = sorted(one.hardware, key=lambda x: x.UUID)
    two.hardware = sorted(two.hardware, key=lambda x: x.UUID)

    one.software = sorted(one.software, key=lambda x: x.UUID)
    two.software = sorted(two.software, key=lambda x: x.UUID)

    # Compare graphs directly:
    def edge_sig(g):
        return {(u, v, key.upper()) for u, v, key in g.edges(keys=True)}

    if edge_sig(one.graph) != edge_sig(two.graph):
        return False

    # finally compare everything else via to_dict except relationships:
    d1 = one.to_dict()
    d2 = two.to_dict()
    d1.pop("relationships", None)
    d2.pop("relationships", None)
    return d1 == d2


bad_software = Software(
    UUID="477da45b-bb38-450e-93f7-e525aaaa6862",
    name=None,
    size=16367492,
    fileName=["helics.tar.gz"],
    installPath=[],
    containerPath=[],
    captureTime="2023-07-12T17:42:01Z",
    version="",
    vendor=[],
    description="",
    sha1="0d21026ee953eeaa31cafef5118be56f46867267",
    sha256="f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9",
    md5="5fbf80df5004db2f0ce1f78b524024fe",
    relationshipAssertion="Unknown",
    comments=[],
    supplementaryFiles=[],
)
bad_software.bad_key = 1.24553

bad_sbom = SBOM(software=[bad_software])


def test_find_by_sha256(test_sbom):
    out_bom = cli_find().execute(
        test_sbom, sha256="f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9"
    )
    assert len(out_bom.software) == 1
    assert (
        out_bom.software[0].sha256
        == "f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9"
    )


def test_find_by_multiple_hashes(test_sbom):
    out_bom = cli_find().execute(
        test_sbom,
        sha256="f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9",
        md5="5fbf80df5004db2f0ce1f78b524024fe",
    )
    assert len(out_bom.software) == 1
    assert (
        out_bom.software[0].sha256
        == "f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9"
    )


def test_find_by_mismatched_hashes(test_sbom):
    out_bom = cli_find().execute(
        test_sbom,
        sha256="f41ca6f7c447225df3a7eef754d303d22cf877586735fb2d56d1eb15bf1daed9",
        md5="2ff380e740d2eb09e5d67f6f2cd17636",
    )
    assert len(out_bom.software) == 0


def test_find_by_containerPath(test_sbom):
    out_bom = cli_find().execute(test_sbom, containerpath="477da45b-bb38-450e-93f7-e525aaaa6862/")
    assert len(out_bom.software) == 7


def test_find_with_malformed_sbom():
    out_bom = cli_find().execute(bad_sbom, bad_key=1.24553)  # Unsupported Type
    assert len(out_bom.software) == 0
    out_bom = cli_find().execute(bad_sbom, bad_key="testing")  # Supported Type
    assert len(out_bom.software) == 0


def test_find_with_bad_filter():
    out_bom = cli_find().execute(bad_sbom, bad_filter="testing")  # Supported Type
    assert len(out_bom.software) == 0
    out_bom = cli_find().execute(bad_sbom, bad_filter=1.234)  # Unsupported Type
    assert len(out_bom.software) == 0


def test_add_by_file(test_sbom):
    previous_software_len = len(test_sbom.software)
    out_bom = cli_add().execute(
        test_sbom, file=pathlib.Path(__file__).parent / "../data/a_out_files/big_m68020.aout"
    )
    assert len(out_bom.software) == previous_software_len + 1
    assert (
        out_bom.software[8].sha256
        == "9e125f97e5f180717096c57fa2fdf06e71cea3e48bc33392318643306b113da4"
    )


def test_add_entry(test_sbom):
    entry = {
        "UUID": "6b50c545-3e07-4aec-bbb0-bae07704143a",
        "name": [{"nameValue": "Test Aout File", "nameType": "product name"}],
        "size": 4,
        "fileName": ["big_m68020.aout"],
        "installPath": [],
        "containerPath": [],
        "captureTime": "2024-05-14T12:48:38Z",
        "sha1": "fbf8688fbe1976b6f324b0028c4b97137ae9139d",
        "sha256": "9e125f97e5f180717096c57fa2fdf06e71cea3e48bc33392318643306b113da4",
        "md5": "e8d3808a4e311a4262563f3cb3a31c3e",
        "comments": [{"comment": "This is a test entry."}],
    }
    previous_software_len = len(test_sbom.software)
    out_bom = cli_add().execute(test_sbom, entry=entry)
    assert len(out_bom.software) == previous_software_len + 1
    assert (
        out_bom.software[8].sha256
        == "9e125f97e5f180717096c57fa2fdf06e71cea3e48bc33392318643306b113da4"
    )


def test_add_relationship(test_sbom):
    relationship = {
        "xUUID": "455341bb-2739-4918-9805-e1a93e27e2a4",
        "yUUID": "e286a415-6c6b-427d-9fe6-d7dbb0486f7d",
        "relationship": "Uses",
    }

    # count pre-existing edges
    previous_rel_len = test_sbom.graph.number_of_edges()

    # Add the new relationship via the CLI
    out_bom = cli_add().execute(test_sbom, relationship=relationship)

    # after add, graph should have one more edge
    assert out_bom.graph.number_of_edges() == previous_rel_len + 1


def test_add_installpath(test_sbom):
    containerPathPrefix = "477da45b-bb38-450e-93f7-e525aaaa6862/"
    installPathPrefix = "/bin/"
    out_bom = cli_add().execute(test_sbom, installpath=(containerPathPrefix, installPathPrefix))
    for sw in out_bom.software:
        if containerPathPrefix in sw.containerPath:
            assert installPathPrefix in sw.installPath


def test_cli_base_serialization(test_sbom):
    serialized = Cli.serialize(test_sbom)
    deserialized = Cli.deserialize(serialized)

    # compare by graph contents and other fields, ignore object identity
    assert _compare_sboms(test_sbom, deserialized)


def test_add_entry_capturetime(test_sbom):
    entry = {
        "UUID": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        "notHashable": True,
        "captureTime": "2024-01-01T00:00:00Z",
    }

    out_bom = cli_add().execute(test_sbom, entry=entry)
    assert out_bom.software[-1].captureTime == "2024-01-01T00:00:00Z"


def test_add_entry_invalid_capturetime(test_sbom):
    entry = {
        "UUID": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "notHashable": True,
        "captureTime": "invalid",
    }

    with pytest.raises(ValueError):
        cli_add().execute(test_sbom, entry=entry)
