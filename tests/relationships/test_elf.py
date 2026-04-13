# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

from surfactant.plugin.manager import get_plugin_manager
from surfactant.sbomtypes import SBOM, Relationship, Software

BROKER_UUID = "11111111-1111-4111-8111-111111111111"
HELICS_APPS_UUID = "22222222-2222-4222-8222-222222222222"
ZMQ_UUID = "33333333-3333-4333-8333-333333333333"
COMM_UUID = "44444444-4444-4444-8444-444444444444"
COMM_CPP_UUID = "55555555-5555-4555-8555-555555555555"

sbom = SBOM(
    software=[
        Software(
            UUID=BROKER_UUID,
            notHashable=True,
            fileName=["helics_broker"],
            installPath=["/usr/local/bin/helics_broker"],
            metadata=[
                {
                    "elfDependencies": ["libhelicscpp-apps.so"],
                    "elfRpath": [],
                    "elfRunpath": ["$ORIGIN:$ORIGIN/../lib:/usr/lib/x86_64-linux-gnu"],
                    "elfDynamicFlags": [{"DF_ORIGIN": False}],
                    "elfDynamicFlags1": [{"DF_1_ORIGIN": False, "DF_1_NODEFLIB": False}],
                }
            ],
        ),
        Software(
            UUID=HELICS_APPS_UUID,
            notHashable=True,
            fileName=["libhelicscpp-apps.so"],
            installPath=["/usr/local/lib/libhelicscpp-apps.so"],
            metadata=[
                {
                    "elfDependencies": ["libzmq.so"],
                    "elfRpath": [],
                    "elfRunpath": ["$ORIGIN:$ORIGIN/../lib:/usr/lib/x86_64-linux-gnu"],
                    "elfDynamicFlags": [],
                    "elfDynamicFlags1": [],
                }
            ],
        ),
        Software(
            UUID=ZMQ_UUID,
            notHashable=True,
            fileName=["libzmq.so"],
            installPath=["/lib/libzmq.so", "/customlib/abspath/libzmq.so"],
            metadata=[
                {
                    "elfDependencies": [],
                    "elfRpath": [],
                    "elfRunpath": [],
                    "elfDynamicFlags": [],
                    "elfDynamicFlags1": [],
                }
            ],
        ),
        Software(
            UUID=COMM_UUID,
            notHashable=True,
            fileName=["libcomm.so"],
            installPath=["/customlib/relpath/misc/libcomm.so"],
            metadata=[
                {
                    "elfDependencies": ["/customlib/abspath/libzmq.so"],
                    "elfRpath": [],
                    "elfRunpath": [],
                    "elfDynamicFlags": [],
                    "elfDynamicFlags1": [],
                }
            ],
        ),
        Software(
            UUID=COMM_CPP_UUID,
            notHashable=True,
            fileName=["libcomm-cpp.so"],
            installPath=["/customlib/relpath/libcomm-cpp.so"],
            metadata=[
                {
                    "elfDependencies": ["misc/libcomm.so"],
                    "elfRpath": [],
                    "elfRunpath": [],
                    "elfDynamicFlags": [],
                    "elfDynamicFlags1": [],
                }
            ],
        ),
    ],
)


def test_relative_paths():
    elfPlugin = get_plugin_manager().get_plugin("surfactant.relationships.elf_relationship")
    sw = sbom.software[4]
    md = sw.metadata[0]
    # located in /customlib/relpath/misc, dependency specified as being under misc/ relative path
    assert elfPlugin.establish_relationships(sbom, sw, md) == [
        Relationship(COMM_CPP_UUID, COMM_UUID, "Uses")
    ]


def test_absolute_paths():
    elfPlugin = get_plugin_manager().get_plugin("surfactant.relationships.elf_relationship")
    sw = sbom.software[3]
    md = sw.metadata[0]
    # located in /customlib/abspath
    assert elfPlugin.establish_relationships(sbom, sw, md) == [
        Relationship(COMM_UUID, ZMQ_UUID, "Uses")
    ]


def test_default_system_paths():
    elfPlugin = get_plugin_manager().get_plugin("surfactant.relationships.elf_relationship")
    sw = sbom.software[1]
    md = sw.metadata[0]
    # located in /lib
    assert elfPlugin.establish_relationships(sbom, sw, md) == [
        Relationship(HELICS_APPS_UUID, ZMQ_UUID, "Uses")
    ]


def test_dst_expansion():
    elfPlugin = get_plugin_manager().get_plugin("surfactant.relationships.elf_relationship")
    sw = sbom.software[0]
    md = sw.metadata[0]
    # uses origin expansion
    assert elfPlugin.establish_relationships(sbom, sw, md) == [
        Relationship(BROKER_UUID, HELICS_APPS_UUID, "Uses")
    ]
