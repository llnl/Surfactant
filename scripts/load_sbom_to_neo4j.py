#!/usr/bin/env python3
"""Standalone loader for importing an existing CyTRICS SBOM into Neo4j.

Usage:

    export NEO4J_URI=neo4j://localhost:7687
    export NEO4J_USER=neo4j
    export NEO4J_PASSWORD=your-password
    python load_sbom_to_neo4j.py existing-sbom.json

This script assumes it is run inside a Surfactant checkout or environment where
`surfactant` is importable. It imports `export_sbom_to_neo4j` from the sibling
neo4j_writer.py file.
"""

from __future__ import annotations

import argparse
import json
import os

from neo4j import GraphDatabase
from surfactant.input_readers.cytrics_reader import read_sbom

from surfactant.output.neo4j_writer import export_sbom_to_neo4j


def main() -> None:
    parser = argparse.ArgumentParser(description="Import an existing Surfactant/CyTRICS SBOM into Neo4j")
    parser.add_argument("sbom_json", help="Path to an existing CyTRICS SBOM JSON file")
    parser.add_argument("--database", default=os.environ.get("NEO4J_DATABASE", "neo4j"))
    parser.add_argument("--batch-size", type=int, default=int(os.environ.get("NEO4J_BATCH_SIZE", "1000")))
    args = parser.parse_args()

    uri = os.environ.get("NEO4J_URI")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD")
    if not uri:
        raise SystemExit("NEO4J_URI is required, for example neo4j://localhost:7687")
    if password is None:
        raise SystemExit("NEO4J_PASSWORD is required")

    with open(args.sbom_json, "r", encoding="utf-8") as infile:
        sbom = read_sbom(infile)

    with GraphDatabase.driver(uri, auth=(user, password)) as driver:
        summary = export_sbom_to_neo4j(
            sbom,
            driver=driver,
            database=args.database,
            batch_size=args.batch_size,
        )

    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
