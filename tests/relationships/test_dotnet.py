# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM, Relationship, Software

APPLICATION_UUID = "11111111-1111-4111-8111-111111111111"
SAMEDIRLIB_UUID = "22222222-2222-4222-8222-222222222222"
SUBDIRLIB_UUID = "33333333-3333-4333-8333-333333333333"
CULTURELIB_UUID = "44444444-4444-4444-8444-444444444444"

sbom = SBOM(
    software=[
        Software(
            UUID=APPLICATION_UUID,
            notHashable=True,
            fileName=["application"],
            installPath=["C:\\application"],
            metadata=[
                {
                    "dotnetAssemblyRef": [{"Name": "samedirlib"}],
                },
                {
                    "dotnetAssemblyRef": [{"Name": "subdirlib"}],
                },
                {
                    "dotnetAssemblyRef": [
                        {
                            "Name": "culturelib",
                            "Culture": "culture",
                        }
                    ],
                },
            ],
        ),
        Software(
            UUID=SAMEDIRLIB_UUID,
            notHashable=True,
            fileName=["samedirlib.dll"],
            installPath=["C:\\samedirlib.dll"],
        ),
        Software(
            UUID=SUBDIRLIB_UUID,
            notHashable=True,
            fileName=["subdirlib.dll"],
            installPath=["C:\\subdirlib\\subdirlib.dll"],
        ),
        Software(
            UUID=CULTURELIB_UUID,
            notHashable=True,
            fileName=["culturelib.dll"],
            installPath=["C:\\culture\\culturelib.dll"],
        ),
    ],
)


def test_same_directory():
    dotnet = get_plugin_manager().get_plugin("surfactant.relationships.dotnet_relationship")
    sw = sbom.software[0]
    md = sw.metadata[0]
    assert dotnet.establish_relationships(sbom, sw, md) == [
        Relationship(APPLICATION_UUID, SAMEDIRLIB_UUID, "Uses")
    ]


def test_subdir():
    dotnet = get_plugin_manager().get_plugin("surfactant.relationships.dotnet_relationship")
    sw = sbom.software[0]
    md = sw.metadata[1]
    assert dotnet.establish_relationships(sbom, sw, md) == [
        Relationship(APPLICATION_UUID, SUBDIRLIB_UUID, "Uses")
    ]


def test_culture():
    dotnet = get_plugin_manager().get_plugin("surfactant.relationships.dotnet_relationship")
    sw = sbom.software[0]
    md = sw.metadata[2]
    assert dotnet.establish_relationships(sbom, sw, md) == [
        Relationship(APPLICATION_UUID, CULTURELIB_UUID, "Uses")
    ]