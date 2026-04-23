# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import argparse
import json
import sys
import uuid as uuid_module
from collections import deque


def is_valid_uuid4(u) -> bool:
    """Check if a uuid is valid

    Args:
        u (string): uuid in string form.

    Returns:
        bool: true if u is a valid uuid and false if it is not.
    """
    try:
        u_test = uuid_module.UUID(u, version=4)
    except ValueError:
        return False
    return str(u_test) == u


def find_relationship_entry(
    sbom,
    xUUID: str | None = None,
    yUUID: str | None = None,
    relationship: str | None = None,
) -> dict | None:
    """Search for a specific relationship entry and check if a match exists.

    Args:
        sbom (dict): Dictionary containing sbom entries.
        xUUID (Optional[str]): Component x UUID. Defaults to None.
        yUUID (Optional[str]): Component y UUID. Defaults to None.
        relationship (Optional[str]): Describes the relationships between two components. Options are 'Uses', 'Contains'. Defaults to None.

    Returns:
        Optional[dict]: Dictionary entry that contains information where the xUUID, yUUID and relationship all match. If no match, returns None.
    """
    for rel in sbom["relationships"]:
        all_match = True
        if xUUID:
            if rel["xUUID"] != xUUID:
                all_match = False
        if yUUID:
            if rel["yUUID"] != yUUID:
                all_match = False
        if relationship:
            if rel["relationship"] != relationship:
                all_match = False
        if all_match:
            return rel
    return None


def find_star_relationship_entry(
    sbom,
    xUUID: str | None = None,
    yUUID: str | None = None,
    relationship: str | None = None,
) -> dict | None:
    """Search for a star relationship entry and check if a match exists.

    Args:
        sbom (dict): Dictionary containing sbom entries.
        xUUID (Optional[str]): Component x UUID. Defaults to None.
        yUUID (Optional[str]): Component y UUID. Defaults to None.
        relationship (Optional[str]): Describes the star relationship between two components. Defaults to None.

    Returns:
        Optional[dict]: Dictionary entry that contains information wehre the xUUID, yUUID, and relationship all match. If no match, returns None.
    """
    for rel in sbom["starRelationships"]:
        all_match = True
        if xUUID:
            if rel["xUUID"] != xUUID:
                all_match = False
        if yUUID:
            if rel["yUUID"] != yUUID:
                all_match = False
        if relationship:
            if rel["relationship"] != relationship:
                all_match = False
        if all_match:
            return rel
    return None


def find_systems_entry(
    sbom, uuid: str | None = None, name: str | None = None
) -> dict | None:
    """Search for a systems entry and check if a match exists.

    Args:
        sbom (dict): Dictionary containing sbom entries.
        uuid (Optional[str]): Contains component UUID. Defaults to None.
        name (Optional[str]): Name of the larger file the component came from. Defaults to None.

    Returns:
        Optional[dict]: Dictionary entry that contains the matching system entry. If no match, returns None.
    """
    for system in sbom["systems"]:
        all_match = True
        if uuid:
            if system["UUID"] != uuid:
                all_match = False
        if name:
            if system["name"] != name:
                all_match = False
        if all_match:
            return system
    return None


def find_software_entry(
    sbom,
    uuid: str | None = None,
    sha256: str | None = None,
    md5: str | None = None,
    sha1: str | None = None,
) -> dict | None:
    """Search for a specific software entry and check if a match exists.

    Args:
        sbom (dict): Dictionary containing sbom entries.
        uuid (Optional[str]): Contains component UUID. Defaults to None.
        sha256 (Optional[str]): SHA256 hash of component. Defaults to None.
        md5 (Optional[str]): MD5 hash of component. Defaults to None.
        sha1 (Optional[str]): SHA1 hash of component. Defaults to None.

    Returns:
        Optional[dict]: Dictionary entry that contains the matching software entry. If no match, returns None.
    """
    for sw in sbom["software"]:
        all_match = True
        if uuid:
            if sw["UUID"] != uuid:
                all_match = False
        if sha256:
            if sw["sha256"] != sha256:
                all_match = False
        if md5:
            if sw["md5"] != md5:
                all_match = False
        if sha1:
            if sw["sha1"] != sha1:
                all_match = False
        if all_match:
            return sw
    return None


def merge_number_same(e1: int, e2: int, k: str):
    """Merges two entries if the number is the same.

    Args:
        e1 (int): Number.
        e2 (int): Number.
        k (str): Name of the field to compare the two numbers.
    """
    # use e2 number if field isn't in e1
    if k not in e1:
        if k in e2:
            e1[k] = e2[k]
    else:
        if k in e2:
            if e1[k] != e2[k]:
                print(f"Field {k} that should match does not! e1={e1} e2={e2}")


def merge_number_lt(e1: int, e2: int, k: str):
    """Merge two entries and assign the lesser of the two numbers.

    Args:
        e1 (int): Number.
        e2 (int): Number.
        k (str): Name of the field to compare the two numbers.
    """
    # use e2 number if the field isn't in e1
    if k not in e1:
        if k in e2:
            e1[k] = e2[k]
    else:
        if k in e2:
            if e1[k] > e2[k]:
                e1[k] = e2[k]


def merge_number_gt(e1: int, e2: int, k: str):
    """Merge two entries and assign the greater of the two numbers.

    Args:
        e1 (int): Number.
        e2 (int): Number.
        k (str): Name of the field to compare the two numbers.
    """
    # use e2 number if the field isn't in e1
    if k not in e1:
        if k in e2:
            e1[k] = e2[k]
    else:
        if k in e2:
            if e1[k] < e2[k]:
                e1[k] = e2[k]


def merge_string(e1: str, e2: str, k: str):
    """Merge two entries. If empty, keep empty.

    Args:
        e1 (str): String with information.
        e2 (str): String with information.
        k (str): Name of the field to compare the two strings.
    """
    if k not in e1 or not e1[k]:
        # worst case, e2 has an empty string/null just like e1
        if k in e2:
            e1[k] = e2[k]


def merge_array(e1, e2, k):
    if k not in e1 or not e1[k]:
        # e2 is at worst empty list like e1, or contains some entries
        if k in e2:
            e1[k] = e2[k]
    else:
        # e1 is guaranteed to have a list with at least one entry
        # merge in items from e2 that aren't already in e1
        if k in e2 and e2[k]:
            for item in e2[k]:
                if item not in e1[k]:
                    e1[k].append(item)


# merges data from two systems entries, modifying the first to contain new info from the second
def merge_systems_entries(e1, e2):
    # name
    merge_string(e1, e2, "name")
    # captureStart
    merge_number_lt(e1, e2, "captureStart")
    # captureEnd
    merge_number_gt(e1, e2, "captureEnd")
    # officialName
    merge_string(e1, e2, "officialName")
    # vendor
    merge_array(e1, e2, "vendor")
    # description
    merge_string(e1, e2, "description")
    # provenance
    merge_array(e1, e2, "provenance")
    return e1["UUID"], e2["UUID"]


# merges data from two software entries, modifying the first entry to contain new info from the second (under the assumption that hashes are the same, so certain values must match)
def merge_software_entries(e1, e2):
    # sha256
    merge_string(e1, e2, "sha256")
    # sha1
    merge_string(e1, e2, "sha1")
    # md5
    merge_string(e1, e2, "md5")
    # name
    merge_string(e1, e2, "name")
    # fileName
    merge_array(e1, e2, "fileName")
    # installPath
    merge_array(e1, e2, "installPath")
    # containerPath
    merge_array(e1, e2, "containerPath")
    # size
    merge_number_same(e1, e2, "size")
    # captureTime
    merge_number_lt(e1, e2, "captureTime")  # favor the older time
    # version
    merge_string(e1, e2, "version")
    # vendor
    merge_array(e1, e2, "vendor")
    # description
    merge_string(e1, e2, "description")
    # relationshipAssertion
    merge_string(e1, e2, "relationshipAssertion")
    if "relationshipAssertion" in e1 and e1["relationshipAssertion"] == "Unknown":
        # e2 has a better relationshipAssertion than "Unknown"
        if (
            "relationshipAssertion" in e2
            and e2["relationshipAssertion"]
            and e2["relationshipAssertion"] != "Unknown"
        ):
            e1["relationshipAssertion"] = e2["relationshipAssertion"]
    # comments
    merge_string(e1, e2, "comments")
    # metadata
    merge_array(e1, e2, "metadata")
    # supplementaryFiles
    merge_array(e1, e2, "supplementaryFiles")
    # provenance
    merge_array(e1, e2, "provenance")
    # recordedInstitution
    merge_string(e1, e2, "recordedInstitution")
    # components
    merge_array(e1, e2, "components")
    return e1["UUID"], e2["UUID"]


def merge_sbom(sbom_m, sbom):
    # some older SBOMs might have duplicate hashes within them... create a new merged sbom to avoid issues...
    merged_sbom = {
        "systems": [],
        "software": [],
        "relationships": [],
        "analysisData": [],
        "observations": [],
        "starRelationships": [],
    }
    # merged/old to new UUID map
    uuid_updates = {}
    # merge systems entries
    if "systems" in sbom_m:
        for system in sbom_m["systems"]:
            # check for duplicate UUID/name, merge with existing entry
            if existing_system := find_systems_entry(
                merged_sbom, uuid=system["UUID"], name=system["name"]
            ):
                # merge system entries
                u1, u2 = merge_systems_entries(existing_system, system)
                print(f"MERGE_DUPLICATE_SYS: uuid1={u1}, uuid2={u2}")
                uuid_updates[u2] = u1
            else:
                merged_sbom["systems"].append(system)
    if "systems" in sbom:
        for system in sbom["systems"]:
            # check for duplicate UUID/name, merge with existing entry
            if existing_system := find_systems_entry(
                merged_sbom, uuid=system["UUID"], name=system["name"]
            ):
                # merge system entries
                u1, u2 = merge_systems_entries(existing_system, system)
                print(f"MERGE_DUPLICATE_SYS: uuid1={u1}, uuid2={u2}")
                uuid_updates[u2] = u1
            else:
                merged_sbom["systems"].append(system)
    # merge software entries
    if "software" in sbom_m:
        for sw in sbom_m["software"]:
            # check for a duplicate hash, and merge with the existing entry
            if existing_sw := find_software_entry(
                merged_sbom, sha256=sw["sha256"], md5=sw["md5"], sha1=sw["sha1"]
            ):
                u1, u2 = merge_software_entries(existing_sw, sw)
                print(f"MERGE_DUPLICATE: uuid1={u1}, uuid2={u2}")
                uuid_updates[u2] = u1
            else:
                merged_sbom["software"].append(sw)
    if "software" in sbom:
        for sw in sbom["software"]:
            if existing_sw := find_software_entry(
                merged_sbom, sha256=sw["sha256"], md5=sw["md5"], sha1=sw["sha1"]
            ):
                u1, u2 = merge_software_entries(existing_sw, sw)
                print(f"MERGE DUPLICATE: uuid1={u1}, uuid2={u2}")
                uuid_updates[u2] = u1
            else:
                merged_sbom["software"].append(sw)
    # merge relationships
    if "relationships" in sbom_m:
        for rel in sbom_m["relationships"]:
            # rewrite UUIDs before doing the search
            if rel["xUUID"] in uuid_updates:
                rel["xUUID"] = uuid_updates[rel["xUUID"]]
            if rel["yUUID"] in uuid_updates:
                rel["yUUID"] = uuid_updates[rel["xUUID"]]
            if existing_rel := find_relationship_entry(
                merged_sbom,
                xUUID=rel["xUUID"],
                yUUID=rel["yUUID"],
                relationship=rel["relationship"],
            ):
                print("DUPLICATE RELATIONSHIP: {existing_rel}")
            else:
                merged_sbom["relationships"].append(rel)
    if "relationships" in sbom:
        for rel in sbom["relationships"]:
            # rewrite UUIDs before doing the search
            if rel["xUUID"] in uuid_updates:
                rel["xUUID"] = uuid_updates[rel["xUUID"]]
            if rel["yUUID"] in uuid_updates:
                rel["yUUID"] = uuid_updates[rel["yUUID"]]
            if existing_rel := find_relationship_entry(
                merged_sbom,
                xUUID=rel["xUUID"],
                yUUID=rel["yUUID"],
                relationship=rel["relationship"],
            ):
                print(f"DUPLICATE RELATIONSHIP: {existing_rel}")
            else:
                merged_sbom["relationships"].append(rel)
    # rewrite container path UUIDs using rewrite map/list
    for sw in merged_sbom["software"]:
        if "containerPath" in sw and sw["containerPath"]:
            for idx, path in enumerate(sw["containerPath"]):
                u = path[:36]
                # if container path starts with an invalid uuid4, sbom might not be valid
                if is_valid_uuid4(u):
                    if u in uuid_updates:
                        updated_path = path.replace(u, uuid_updates[u], 1)
                        sw["containerPath"][idx] = updated_path
            # remove duplicates
            sw["containerPath"] = [*set(sw["containerPath"])]
    print(f"UUID UPDATES: {uuid_updates}")
    # merge analysisData
    if "analysisData" in sbom_m:
        for analysisData in sbom_m["analysisData"]:
            # checks for duplicates might be nice, but unlikely to encounter often as these are added manually
            merged_sbom["analysisData"].append(analysisData)
    if "analysisData" in sbom:
        for analysisData in sbom["analysisData"]:
            merged_sbom["analysisData"].append(analysisData)
    # merge observations
    if "observations" in sbom_m:
        for observation in sbom_m["observations"]:
            # checks for duplicates might be nice, but unlikely to encounter often as these are added manually
            merged_sbom["observations"].append(observation)
    if "observations" in sbom:
        for observation in sbom["observations"]:
            merged_sbom["observations"].append(observation)
    # merge starRelationships
    if "starRelationships" in sbom_m:
        for rel in sbom_m["starRelationships"]:
            # rewrite UUIDs before doing the search
            if rel["xUUID"] in uuid_updates:
                rel["xUUID"] = uuid_updates[rel["xUUID"]]
            if rel["yUUID"] in uuid_updates:
                rel["yUUID"] = uuid_updates[rel["xUUID"]]
            if existing_rel := find_star_relationship_entry(
                merged_sbom,
                xUUID=rel["xUUID"],
                yUUID=rel["yUUID"],
                relationship=rel["relationship"],
            ):
                print("DUPLICATE STAR RELATIONSHIP: {existing_rel}")
            else:
                merged_sbom["starRelationships"].append(rel)
    if "starRelationships" in sbom:
        for rel in sbom["starRelationships"]:
            # rewrite UUIDs before doing the search
            if rel["xUUID"] in uuid_updates:
                rel["xUUID"] = uuid_updates[rel["xUUID"]]
            if rel["yUUID"] in uuid_updates:
                rel["yUUID"] = uuid_updates[rel["yUUID"]]
            if existing_rel := find_star_relationship_entry(
                merged_sbom,
                xUUID=rel["xUUID"],
                yUUID=rel["yUUID"],
                relationship=rel["relationship"],
            ):
                print(f"DUPLICATE RELATIONSHIP: {existing_rel}")
            else:
                merged_sbom["starRelationships"].append(rel)
    return merged_sbom


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config_file",
        metavar="CONFIG_FILE",
        nargs="?",
        type=argparse.FileType("r"),
        help="Config file (JSON); make sure keys with paths do not have a trailing /",
    )
    parser.add_argument(
        "--sbom_outfile",
        metavar="SBOM_OUTPUT",
        nargs="?",
        type=argparse.FileType("w"),
        default=sys.stdout,
        help="Output SBOM file",
    )
    parser.add_argument("input_sbom", type=argparse.FileType("r"), nargs="+")
    args = parser.parse_args()

    msbom = {
        "systems": [],
        "software": [],
        "relationships": [],
        "analysisData": [],
        "observations": [],
        "starRelationships": [],
    }
    for f in args.input_sbom:
        in_sbom = json.load(f)
        msbom = merge_sbom(msbom, in_sbom)

    print(len(msbom["software"]))
    print(len(msbom["relationships"]))

    # construct a graph for adding a system relationship to all root software entries
    rel_graph = {}
    # add all UUIDs as nodes in the graph
    for system in msbom["systems"]:
        rel_graph[system["UUID"]] = []
    for sw in msbom["software"]:
        rel_graph[sw["UUID"]] = []
    # iterate through all relationships, adding edges to the adjacency list
    for rel in msbom["relationships"]:
        # check case where xUUID doesn't exist (and error if yUUID doesn't exist) in the graph
        if rel["xUUID"] not in rel_graph or rel["yUUID"] not in rel_graph:
            print("====ERROR xUUID or yUUID doesn't exist====")
            print(rel)
            continue
        # consider also including relationship type for the edge
        # treat as directed graph, with inverted edges (pointing to parents) so dfs will eventually lead to the root parent node for a (sub)graph
        rel_graph[rel["yUUID"]].append(rel["xUUID"])

    visited = set()
    roots = set()
    rootFound = set()
    recursionStack = deque()

    # maintain a recursion stack to check for cycles; if we are visiting a node that is in the stack, there is a cycle; arbitrarily pick one to add as a root
    def dfs(rel):
        recursionStack.append(rel)
        # if the node is already visited, no revisiting required
        if rel in visited:
            recursionStack.pop()
            return rel in rootFound
        # mark the node as visited
        visited.add(rel)
        # the node has no parents, it is a root
        if not rel_graph[rel]:
            roots.add(rel)
            rootFound.add(rel)
            recursionStack.pop()
            return True
        cycle = False
        # node is not a root, move on to parents
        for parent in rel_graph[rel]:
            # detect cycles
            if parent in recursionStack:
                print(f"CYCLE DETECTED: {parent} {rel}")
                cycle = True
            if dfs(parent):
                rootFound.add(rel)
        # if there was a cycle, and none of the parents led to a definite root node
        if cycle and rel not in rootFound:
            print(f"CYCLE AND NO ROOT FOUND, SETTING {rel} AS THE ROOT")
            roots.add(rel)
            rootFound.add(rel)
        recursionStack.pop()
        return rel in rootFound

    for rel in rel_graph:
        dfs(rel)
    print(f"ROOTS: {roots}")

    # construct the most accurate system object we can, using a mix of user provided info and times loaded from the SBOM
    system = {}
    if args.config_file:
        config = json.load(args.config_file)
        system = config["system"]
    # make sure the required fields are present and at least mostly valid
    if "UUID" not in system or not is_valid_uuid4(system["UUID"]):
        system["UUID"] = str(uuid_module.uuid4())
    if "name" not in system:
        system["name"] = ""
    captureStart = -1
    captureEnd = -1
    for sw in msbom["software"]:
        if captureStart == -1 or sw["captureTime"] < captureStart:
            captureStart = sw["captureTime"]
        if captureEnd == -1 or sw["captureTime"] > captureEnd:
            captureEnd = sw["captureTime"]
    if "captureStart" not in system or not system["captureStart"]:
        system["captureStart"] = captureStart
    if "captureEnd" not in system or not system["captureEnd"]:
        system["captureEnd"] = captureEnd
    msbom["systems"].append(system)
    print(f"SYSTEM: {system}")

    # add a system relationship to each root software/systems entry identified
    for r in roots:
        msbom["relationships"].append(
            {"xUUID": system["UUID"], "yUUID": r, "relationship": "Includes"}
        )

    json.dump(msbom, args.sbom_outfile, indent=4)


if __name__ == "__main__":
    main()
