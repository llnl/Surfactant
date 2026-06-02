# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM, Relationship, Software

APPLICATION_UUID = "11111111-1111-4111-8111-111111111111"
LIBRARY_UUID = "22222222-2222-4222-8222-222222222222"

sbom = SBOM(
    bomFormat="cytrics",
    specVersion="1.0.1",
    software=[
        Software(
            UUID=APPLICATION_UUID,
            notHashable=True,
            fileName=["application.exe"],
            installPath=["C:\\application.exe"],
            metadata=[
                {
                    "peImport": ["library.dll"],
                }
            ],
        ),
        Software(
            UUID=LIBRARY_UUID,
            notHashable=True,
            fileName=["library.dll"],
            installPath=["C:\\library.dll"],
            metadata=[{}],
        ),
    ],
)


def test_same_directory():
    plugin = get_plugin_manager().get_plugin("surfactant.relationships.pe_relationship")
    app = sbom.software[0]
    md = app.metadata[0]
    assert plugin.establish_relationships(sbom, app, md) == [
        Relationship(APPLICATION_UUID, LIBRARY_UUID, "Uses")
    ]
