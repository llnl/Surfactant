# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import json

from surfactant.sbomtypes import SBOM


def test_generate_result_no_install_prefix(output_path: str, extract_path: str):
    with open(output_path) as f:
        generated_sbom = json.load(f)

    assert len(generated_sbom["software"]) == 2

    expected_software_names = {"hello_world.exe", "testlib.dll"}
    actual_software_names = {software["fileName"][0] for software in generated_sbom["software"]}
    assert expected_software_names == actual_software_names

    expected_install_paths = {
        "hello_world.exe": extract_path + "/hello_world.exe",
        "testlib.dll": extract_path + "/testlib.dll",
    }
    for software in generated_sbom["software"]:
        assert software["installPath"][0] == expected_install_paths[software["fileName"][0]]

    uuids = {software["fileName"][0]: software["UUID"] for software in generated_sbom["software"]}
    assert len(generated_sbom["relationships"]) == 1
    assert generated_sbom["relationships"][0] == {
        "xUUID": uuids["hello_world.exe"],
        "yUUID": uuids["testlib.dll"],
        "relationship": "Uses",
    }


# Generate Sample SBOMs
sbom1_json = """{
  "bomFormat": "cytrics",
  "specVersion": "1.0.1",
  "software": [
    {
      "UUID": "dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
      "fileName": [
        "helics.tar.gz"
      ],
      "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
    },
    {
      "UUID": "08526f02-8f08-485d-bfd1-ea16ce964fd2",
      "fileName": [
        "helics_binary"
      ],
      "installPath": [
        "/bin/helics_binary"
      ],
      "containerPath": [
        "dd6f7f6b-7c31-4a4a-afef-14678b9942bf/bin/helics_binary"
      ],
      "sha256": "2222222222222222222222222222222222222222222222222222222222222222"
    },
    {
      "UUID": "a5db7e12-fe3d-490e-90b8-98a8bfaace09",
      "fileName": [
        "lib1.so"
      ],
      "installPath": [
        "/lib64/lib1.so"
      ],
      "containerPath": [
        "dd6f7f6b-7c31-4a4a-afef-14678b9942bf/lib64/lib1.so"
      ],
      "sha256": "3333333333333333333333333333333333333333333333333333333333333333"
    }
  ],
  "relationships": [
    {
      "xUUID": "08526f02-8f08-485d-bfd1-ea16ce964fd2",
      "yUUID": "a5db7e12-fe3d-490e-90b8-98a8bfaace09",
      "relationship": "Uses"
    },
    {
      "xUUID": "dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
      "yUUID": "08526f02-8f08-485d-bfd1-ea16ce964fd2",
      "relationship": "Contains"
    },
    {
      "xUUID": "dd6f7f6b-7c31-4a4a-afef-14678b9942bf",
      "yUUID": "a5db7e12-fe3d-490e-90b8-98a8bfaace09",
      "relationship": "Contains"
    }
  ]
}"""


def get_sbom1():
    return SBOM.from_json(sbom1_json)


sbom2_json = """{
        "bomFormat": "cytrics",
        "specVersion": "1.0.1",
        "software": [
            {
            "UUID": "625a07da-7eed-47b9-a0fa-47dcbf76574a",
            "name": null,
            "size": null,
            "fileName": [
                "helics_plugin.tar.gz"
            ],
            "sha256": "4444444444444444444444444444444444444444444444444444444444444444"
            },
            {
            "UUID": "820d3ddc-14d7-4ce5-833c-beede8725366",
            "fileName": [
                "helics_plugin"
            ],
            "installPath": [
                "/bin/helics_plugin"
            ],
            "containerPath": [
                "625a07da-7eed-47b9-a0fa-47dcbf76574a/bin/helics_plugin"
            ],
            "sha256": "5555555555555555555555555555555555555555555555555555555555555555"
            },
            {
            "UUID": "df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            "fileName": [
                "lib_plugin.so"
            ],
            "installPath": [
                "/lib64/lib_plugin.so"
            ],
            "containerPath": [
                "625a07da-7eed-47b9-a0fa-47dcbf76574a/lib64/lib_plugin.so"
            ],
            "sha256": "6666666666666666666666666666666666666666666666666666666666666666"
            }
        ],
        "relationships": [
            {
            "xUUID": "820d3ddc-14d7-4ce5-833c-beede8725366",
            "yUUID": "df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            "relationship": "Uses"
            },
            {
            "xUUID": "625a07da-7eed-47b9-a0fa-47dcbf76574a",
            "yUUID": "820d3ddc-14d7-4ce5-833c-beede8725366",
            "relationship": "Contains"
            },
            {
            "xUUID": "625a07da-7eed-47b9-a0fa-47dcbf76574a",
            "yUUID": "df81b6a7-f9df-42f1-85ee-86a8865fa5f1",
            "relationship": "Contains"
            }
        ]
        }"""


def get_sbom2():
    return SBOM.from_json(sbom2_json)


def test_simple_merge_method(sbom1, sbom2, merged_sbom):
    # Capture each SBOM's original software entries
    orig_sw1, orig_sw2 = list(sbom1.software), list(sbom2.software)

    # Expect the merged list to be the union of the two originals
    expected_sw = orig_sw1 + orig_sw2
    assert sorted(merged_sbom.software, key=lambda x: x.UUID) == sorted(
        expected_sw, key=lambda x: x.UUID
    )

    # Verify graph edges union: use edges(keys=True) to pull relationship key
    def extract_edges(sbom):
        return set(sbom.graph.edges(keys=True))

    expected_edges = extract_edges(sbom1) | extract_edges(sbom2)
    assert extract_edges(merged_sbom) == expected_edges
