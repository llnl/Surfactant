# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def _escape(text: str) -> str:
    """Escape a string for use inside a DOT double-quoted ID."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _node_label(software: Software) -> str:
    """Pick a human-readable label for a software node.

    Prefer a file name, then a recorded name, and fall back to the UUID so
    every node is always labeled with something.
    """
    if software.fileName:
        return software.fileName[0]
    if software.name:
        for entry in software.name:
            value = getattr(entry, "nameValue", None)
            if value:
                return value
    return software.UUID


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    """Write the SBOM's software and their relationships as a Graphviz DOT digraph.

    Each software entry becomes a node and each logical relationship becomes a
    directed edge labeled with the relationship type. Filesystem/symlink edges
    are omitted so the graph matches the logical relationships emitted in the
    SBOM's JSON output.
    """
    outfile.write("digraph SBOM {\n")
    outfile.write("    rankdir=LR;\n")
    outfile.write("    node [shape=box];\n")

    # Emit a labeled node for every software entry, and remember which UUIDs
    # are software so we only draw edges between known nodes.
    software_uuids = set()
    if sbom.software:
        for sw in sbom.software:
            software_uuids.add(sw.UUID)
            outfile.write(f'    "{_escape(sw.UUID)}" [label="{_escape(_node_label(sw))}"];\n')

    # Emit logical relationships only. Mirror the filtering used when writing
    # relationships to the SBOM JSON: drop symlink edges and any edge touching
    # a filesystem "path" node.
    for u, v, key, _attrs in sbom.graph.edges(keys=True, data=True):
        if str(key).lower() == "symlink":
            continue
        utype = sbom.graph.nodes.get(u, {}).get("type")
        vtype = sbom.graph.nodes.get(v, {}).get("type")
        if utype == "path" or vtype == "path":
            continue
        if u not in software_uuids or v not in software_uuids:
            continue
        outfile.write(f'    "{_escape(u)}" -> "{_escape(v)}" [label="{_escape(str(key))}"];\n')

    outfile.write("}\n")


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    return "dot"
