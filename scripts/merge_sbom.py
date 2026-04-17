# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import argparse
import sys
from contextlib import ExitStack

import networkx as nx
from loguru import logger

from surfactant.sbomtypes import SBOM


def _log_merge_summary(merged_sbom: SBOM) -> None:
    roots = [
        n
        for n, deg in merged_sbom.graph.in_degree()
        if deg == 0 and merged_sbom.graph.nodes.get(n, {}).get("type") != "path"
    ]
    logger.info(f"ROOT NODES: {roots}")

    cycles = list(nx.simple_cycles(merged_sbom.graph))
    if cycles:
        logger.warning(f"SBOM CYCLE(S) DETECTED: {cycles}")
    else:
        logger.info("No cycles detected in SBOM graph")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--sbom_outfile",
        metavar="SBOM_OUTPUT",
        nargs="?",
        type=str,
        default="-",
        help="Output SBOM file",
    )
    parser.add_argument("input_sbom", type=str, nargs="+")
    args = parser.parse_args()

    with ExitStack() as stack:
        sbom_outfile = (
            sys.stdout
            if args.sbom_outfile == "-"
            else stack.enter_context(open(args.sbom_outfile, "w", encoding="utf-8"))
        )
        input_sboms = [
            sys.stdin if path == "-" else stack.enter_context(open(path, "r", encoding="utf-8"))
            for path in args.input_sbom
        ]

        sboms = [SBOM.from_json(f.read()) for f in input_sboms]
        merged_sbom = sboms[0]

        for sbom_m in sboms[1:]:
            merged_sbom.merge(sbom_m)

        _log_merge_summary(merged_sbom)
        sbom_outfile.write(merged_sbom.to_json(indent=4))


if __name__ == "__main__":
    main()
