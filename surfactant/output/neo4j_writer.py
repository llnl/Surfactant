# Copyright 2026
# SPDX-License-Identifier: MIT
"""Neo4j output writer for Surfactant CyTRICS SBOMs.

Place this file at:

    surfactant/output/neo4j_writer.py

Then run Surfactant with:

    surfactant generate --skip_gather --skip_relationships \
      --output_format surfactant.output.neo4j_writer \
      empty-context.json neo4j-import-summary.json existing-sbom.json

Required environment variables:

    NEO4J_URI       e.g. neo4j://localhost:7687
    NEO4J_USER      e.g. neo4j
    NEO4J_PASSWORD  your password

Optional:

    NEO4J_DATABASE  default: neo4j
    NEO4J_BATCH_SIZE default: 1000
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, is_dataclass
from pathlib import PurePosixPath
from typing import Any

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM

from neo4j import GraphDatabase


_PRIMITIVE = (str, int, float, bool)
_SAFE_REL_TYPE_RE = re.compile(r"[^A-Za-z0-9_]")


@surfactant.plugin.hookimpl
def short_name() -> str | None:
    return "neo4j"


def _is_path_graph_node(attrs: Mapping[str, Any]) -> bool:
    return str((attrs or {}).get("type") or "").lower() == "path"


def _is_logical_graph_edge(graph: Any, u: Any, v: Any, key: Any) -> bool:
    if str(key).lower() == "symlink":
        return False

    if _is_path_graph_node(graph.nodes.get(u, {})):
        return False
    if _is_path_graph_node(graph.nodes.get(v, {})):
        return False

    return True


def _count_logical_graph_edges(graph: Any) -> int:
    if graph is None:
        return 0

    return sum(
        1
        for u, v, key in graph.edges(keys=True)
        if _is_logical_graph_edge(graph, u, v, key)
    )


@surfactant.plugin.hookimpl
def write_sbom(sbom: SBOM, outfile) -> None:
    """Write the SBOM's NetworkX graphs into Neo4j.

    This output plugin intentionally writes a small JSON import summary to the
    given outfile because the real output target is Neo4j.
    """
    logger.info("Neo4j writer selected")

    uri = os.environ.get("NEO4J_URI")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD")
    database = os.environ.get("NEO4J_DATABASE", "neo4j")
    try:
        batch_size = int(os.environ.get("NEO4J_BATCH_SIZE", "1000"))
    except ValueError as exc:
        raise RuntimeError("NEO4J_BATCH_SIZE must be an integer") from exc

    if batch_size <= 0:
        raise RuntimeError("NEO4J_BATCH_SIZE must be greater than zero")

    graph = getattr(sbom, "graph", None)
    fs_tree = getattr(sbom, "fs_tree", None)

    logger.info(
        "Neo4j writer received SBOM: "
        f"software={len(getattr(sbom, 'software', []) or [])}, "
        f"logical_relationships={_count_logical_graph_edges(graph)}, "
        f"graph_nodes={graph.number_of_nodes() if graph is not None else 'None'}, "
        f"graph_edges_total={graph.number_of_edges() if graph is not None else 'None'}, "
        f"fs_tree_nodes={fs_tree.number_of_nodes() if fs_tree is not None else 'None'}, "
        f"fs_tree_edges={fs_tree.number_of_edges() if fs_tree is not None else 'None'}"
    )

    if not uri:
        raise RuntimeError("NEO4J_URI is required, for example neo4j://localhost:7687")
    if password is None:
        raise RuntimeError("NEO4J_PASSWORD is required")

    logger.info(
        f"Connecting to Neo4j uri={uri} database={database} user={user} batch_size={batch_size}"
    )

    with GraphDatabase.driver(uri, auth=(user, password)) as driver:
        logger.debug("Verifying Neo4j connectivity")
        driver.verify_connectivity()
        logger.info("Neo4j connectivity verified")

        summary = export_sbom_to_neo4j(
            sbom,
            driver=driver,
            database=database,
            batch_size=batch_size,
        )

    logger.info(f"Neo4j import summary: {summary}")

    outfile.write(json.dumps(summary, indent=2, sort_keys=True))
    outfile.write("\n")
    outfile.flush()

    logger.info(f"Wrote Neo4j import summary to {getattr(outfile, 'name', '<stream>')}")


def export_sbom_to_neo4j(
    sbom: SBOM, *, driver, database: str = "neo4j", batch_size: int = 1000
) -> dict[str, int]:
    """Export sbom.graph and sbom.fs_tree to Neo4j.

    Model:
      (:SBOM:SBOMEntity)
      (:Software:SBOMEntity)
      (:Path:SBOMEntity)
      (:Hash:SBOMEntity)
      (:GraphEntity:SBOMEntity)

    Logical SBOM relationships from sbom.graph become relationships whose type is
    the sanitized NetworkX MultiDiGraph edge key, for example CONTAINS or USES.
    Filesystem/path edges mirrored into sbom.graph are skipped here because
    sbom.fs_tree is the authoritative source for filesystem topology.

    Filesystem edges from sbom.fs_tree become:
      FS_CONTAINS       for structural parent -> child edges
      SYMLINK           for symlink edges
      HAS_CONTENT_HASH  for path -> sha256:<digest> edges

    Every node and relationship gets a stable id property so the import is
    idempotent.
    """
    bom_uuid = getattr(sbom, "bomUUID", "unknown")
    nodes_by_label, rels_by_type = _build_import_rows(sbom)

    node_count = sum(len(rows) for rows in nodes_by_label.values())
    rel_count = sum(len(rows) for rows in rels_by_type.values())

    logger.info(
        "Prepared Neo4j import rows: "
        f"bomUUID={bom_uuid}, "
        f"nodes={node_count}, "
        f"relationships={rel_count}, "
        f"node_labels={sorted(nodes_by_label.keys())}, "
        f"relationship_types={sorted(rels_by_type.keys())}"
    )

    if node_count == 0:
        logger.warning("Neo4j import has zero nodes prepared; database will remain empty")
    if rel_count == 0:
        logger.warning("Neo4j import has zero relationships prepared")

    with driver.session(database=database) as session:
        logger.info("Creating Neo4j uniqueness constraint")
        session.execute_write(_create_constraints)

        for label, rows in nodes_by_label.items():
            logger.info(f"Importing {len(rows)} Neo4j nodes with label {label}")
            for batch_number, chunk in enumerate(_chunks(rows, batch_size), start=1):
                logger.debug(
                    f"Merging Neo4j node batch label={label} batch={batch_number} size={len(chunk)}"
                )
                session.execute_write(_merge_nodes, label, chunk)

        for rel_type, rows in rels_by_type.items():
            logger.info(f"Importing {len(rows)} Neo4j relationships with type {rel_type}")
            for batch_number, chunk in enumerate(_chunks(rows, batch_size), start=1):
                logger.debug(
                    f"Merging Neo4j relationship batch type={rel_type} "
                    f"batch={batch_number} size={len(chunk)}"
                )
                session.execute_write(_merge_relationships, rel_type, chunk)

        database_counts = session.execute_read(_verify_import_counts, bom_uuid)

    logger.info(f"Verified Neo4j database counts for bomUUID={bom_uuid}: {database_counts}")

    relationship_rows = [r for rows in rels_by_type.values() for r in rows]
    logical_graph_edge_count = sum(
        1 for r in relationship_rows if r["props"].get("source_graph") == "graph"
    )
    fs_tree_edge_count = sum(
        1
        for r in relationship_rows
        if r["props"].get("source_graph") == "fs_tree"
        and r["props"].get("edge_type") is not None
    )
    installed_at_count = sum(
        1 for r in relationship_rows if r["props"].get("relationship") == "INSTALLED_AT"
    )

    return {
        "nodes": node_count,
        "relationships": rel_count,
        "software": len(nodes_by_label.get("Software", [])),
        "paths": len(nodes_by_label.get("Path", [])),
        "hashes": len(nodes_by_label.get("Hash", [])),
        "logical_graph_edges": logical_graph_edge_count,
        "fs_tree_edges": fs_tree_edge_count,
        "installed_at_edges": installed_at_count,
        "database_nodes_for_bom": database_counts["nodes"],
        "database_relationships_for_bom": database_counts["relationships"],
    }


def _create_constraints(tx) -> None:
    result = tx.run(
        "CREATE CONSTRAINT sbom_entity_id IF NOT EXISTS FOR (n:SBOMEntity) REQUIRE n.id IS UNIQUE"
    )
    summary = result.consume()
    logger.debug(f"Constraint query counters: {summary.counters}")


def _verify_import_counts(tx, bom_uuid: str) -> dict[str, int]:
    rel_prefix = f"{bom_uuid}:rel:"
    record = tx.run(
        """
        MATCH (n:SBOMEntity {bomUUID: $bom_uuid})
        WITH count(n) AS nodes
        OPTIONAL MATCH ()-[r]->()
        WHERE r.id STARTS WITH $rel_prefix
        RETURN nodes, count(r) AS relationships
        """,
        bom_uuid=bom_uuid,
        rel_prefix=rel_prefix,
    ).single()

    return {
        "nodes": int(record["nodes"]) if record else 0,
        "relationships": int(record["relationships"]) if record else 0,
    }


def _merge_nodes(tx, label: str, rows: list[dict[str, Any]]) -> None:
    label = _safe_label(label)
    query = f"""
    UNWIND $rows AS row
    MERGE (n:SBOMEntity {{id: row.id}})
    SET n += row.props
    SET n:{label}
    """
    result = tx.run(query, rows=rows)
    summary = result.consume()
    logger.debug(f"Merged node rows label={label} rows={len(rows)} counters={summary.counters}")


def _merge_relationships(tx, rel_type: str, rows: list[dict[str, Any]]) -> None:
    rel_type = _safe_rel_type(rel_type)
    query = f"""
    UNWIND $rows AS row
    MATCH (a:SBOMEntity {{id: row.source_id}})
    MATCH (b:SBOMEntity {{id: row.target_id}})
    MERGE (a)-[r:{rel_type} {{id: row.id}}]->(b)
    SET r += row.props
    """
    result = tx.run(query, rows=rows)
    summary = result.consume()
    logger.debug(
        f"Merged relationship rows type={rel_type} rows={len(rows)} counters={summary.counters}"
    )


def _build_import_rows(
    sbom: SBOM,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    bom_uuid = getattr(sbom, "bomUUID", "unknown")
    software_by_uuid = {
        getattr(sw, "UUID", None): sw
        for sw in getattr(sbom, "software", [])
        if getattr(sw, "UUID", None)
    }

    node_records: dict[str, tuple[str, dict[str, Any]]] = {}
    relationships: list[tuple[str, str, str, dict[str, Any]]] = []

    # The SBOM root node.
    sbom_node_id = _node_id(bom_uuid, "sbom", bom_uuid)
    node_records[sbom_node_id] = (
        "SBOM",
        _clean_props(
            {
                "id": sbom_node_id,
                "bomUUID": bom_uuid,
                "raw_id": bom_uuid,
                "kind": "sbom",
                "bomFormat": getattr(sbom, "bomFormat", None),
                "bomDescription": getattr(sbom, "bomDescription", None),
                "specVersion": getattr(sbom, "specVersion", None),
            }
        ),
    )

    # Software objects carry the richest properties.
    for sw in getattr(sbom, "software", []) or []:
        sw_uuid = getattr(sw, "UUID", None)
        if not sw_uuid:
            continue
        nid = _node_id(bom_uuid, "software", sw_uuid)
        node_records[nid] = ("Software", _software_props(sw, bom_uuid, nid))
        relationships.append(
            (
                sbom_node_id,
                nid,
                "HAS_SOFTWARE",
                {
                    "id": _rel_id(bom_uuid, "sbom", bom_uuid, sw_uuid, "HAS_SOFTWARE"),
                    "bomUUID": bom_uuid,
                    "source_graph": "sbom",
                    "relationship": "HAS_SOFTWARE",
                },
            )
        )

    # Nodes from the logical relationship graph.
    graph = getattr(sbom, "graph", None)
    if graph is not None:
        for raw_node, attrs in graph.nodes(data=True):
            if _is_path_graph_node(attrs):
                continue
            nid, label, props = _node_from_raw(bom_uuid, raw_node, attrs, software_by_uuid)
            _upsert_node(node_records, nid, label, props)

        for u, v, key, attrs in graph.edges(keys=True, data=True):
            if not _is_logical_graph_edge(graph, u, v, key):
                continue

            source_id, _, _ = _node_from_raw(bom_uuid, u, graph.nodes.get(u, {}), software_by_uuid)
            target_id, _, _ = _node_from_raw(bom_uuid, v, graph.nodes.get(v, {}), software_by_uuid)
            rel_type = _safe_rel_type(key or "RELATED_TO")
            rel_props = _clean_props(
                {
                    "id": _rel_id(bom_uuid, "graph", u, v, key),
                    "bomUUID": bom_uuid,
                    "source_graph": "graph",
                    "nx_key": str(key),
                    "relationship": str(key),
                    **(attrs or {}),
                }
            )
            relationships.append((source_id, target_id, rel_type, rel_props))

    # Nodes and edges from the filesystem tree.
    fs_tree = getattr(sbom, "fs_tree", None)
    if fs_tree is not None:
        for raw_node, attrs in fs_tree.nodes(data=True):
            nid, label, props = _fs_node_from_raw(bom_uuid, raw_node, attrs, software_by_uuid)
            _upsert_node(node_records, nid, label, props)

            sw_uuid = (attrs or {}).get("software_uuid")
            if sw_uuid and sw_uuid in software_by_uuid:
                sw_id = _node_id(bom_uuid, "software", sw_uuid)
                relationships.append(
                    (
                        sw_id,
                        nid,
                        "INSTALLED_AT",
                        {
                            "id": _rel_id(
                                bom_uuid, "installed_at", sw_uuid, raw_node, "INSTALLED_AT"
                            ),
                            "bomUUID": bom_uuid,
                            "source_graph": "fs_tree",
                            "relationship": "INSTALLED_AT",
                        },
                    )
                )

        for u, v, attrs in fs_tree.edges(data=True):
            source_id, _, _ = _fs_node_from_raw(
                bom_uuid, u, fs_tree.nodes.get(u, {}), software_by_uuid
            )
            target_id, _, _ = _fs_node_from_raw(
                bom_uuid, v, fs_tree.nodes.get(v, {}), software_by_uuid
            )
            edge_type = (attrs or {}).get("type") or "contains"
            if edge_type == "symlink":
                rel_type = "SYMLINK"
            elif edge_type == "hash":
                rel_type = "HAS_CONTENT_HASH"
            else:
                rel_type = "FS_CONTAINS"
            rel_props = _clean_props(
                {
                    "id": _rel_id(
                        bom_uuid, "fs_tree", u, v, edge_type, (attrs or {}).get("subtype")
                    ),
                    "bomUUID": bom_uuid,
                    "source_graph": "fs_tree",
                    "edge_type": edge_type,
                    **(attrs or {}),
                }
            )
            relationships.append((source_id, target_id, rel_type, rel_props))

    logger.debug(
        "Built raw Neo4j import records before grouping: "
        f"node_records={len(node_records)}, relationships={len(relationships)}"
    )

    nodes_by_label: dict[str, list[dict[str, Any]]] = {}
    for nid, (label, props) in node_records.items():
        props = {**props, "id": nid}
        nodes_by_label.setdefault(label, []).append({"id": nid, "props": props})

    rels_by_type: dict[str, list[dict[str, Any]]] = {}
    seen_rel_ids = set()
    for source_id, target_id, rel_type, props in relationships:
        rel_type = _safe_rel_type(rel_type)
        rel_id = props.get("id") or _rel_id(bom_uuid, "rel", source_id, target_id, rel_type)
        if rel_id in seen_rel_ids:
            continue
        seen_rel_ids.add(rel_id)
        rel_props = {**props, "id": rel_id}
        rels_by_type.setdefault(rel_type, []).append(
            {
                "source_id": source_id,
                "target_id": target_id,
                "id": rel_id,
                "props": _clean_props(rel_props),
            }
        )

    return nodes_by_label, rels_by_type


def _upsert_node(
    node_records: dict[str, tuple[str, dict[str, Any]]],
    nid: str,
    label: str,
    props: dict[str, Any],
) -> None:
    if nid not in node_records:
        node_records[nid] = (label, props)
        return

    old_label, old_props = node_records[nid]
    priority = {"SBOM": 5, "Software": 4, "Hash": 3, "Path": 2, "GraphEntity": 1}
    best_label = label if priority.get(label, 0) > priority.get(old_label, 0) else old_label
    node_records[nid] = (best_label, {**old_props, **props})


def _node_from_raw(
    bom_uuid: str,
    raw_node: Any,
    attrs: Mapping[str, Any],
    software_by_uuid: Mapping[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    raw = str(raw_node)
    if raw in software_by_uuid:
        nid = _node_id(bom_uuid, "software", raw)
        return nid, "Software", _software_props(software_by_uuid[raw], bom_uuid, nid)

    node_type = str((attrs or {}).get("type") or "").lower()
    if node_type == "path":
        return _path_node(bom_uuid, raw, attrs)
    if raw.startswith("sha256:") or node_type == "hash":
        return _hash_node(bom_uuid, raw, attrs)

    nid = _node_id(bom_uuid, "graph", raw)
    return (
        nid,
        "GraphEntity",
        _clean_props(
            {
                "id": nid,
                "bomUUID": bom_uuid,
                "raw_id": raw,
                "kind": node_type or "graph",
                **(attrs or {}),
            }
        ),
    )


def _fs_node_from_raw(
    bom_uuid: str,
    raw_node: Any,
    attrs: Mapping[str, Any],
    software_by_uuid: Mapping[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    raw = str(raw_node)
    node_type = str((attrs or {}).get("type") or "").lower()
    if raw in software_by_uuid:
        nid = _node_id(bom_uuid, "software", raw)
        return nid, "Software", _software_props(software_by_uuid[raw], bom_uuid, nid)
    if raw.startswith("sha256:") or node_type == "hash":
        return _hash_node(bom_uuid, raw, attrs)
    return _path_node(bom_uuid, raw, attrs)


def _path_node(
    bom_uuid: str, path: str, attrs: Mapping[str, Any]
) -> tuple[str, str, dict[str, Any]]:
    nid = _node_id(bom_uuid, "path", path)
    return (
        nid,
        "Path",
        _clean_props(
            {
                "id": nid,
                "bomUUID": bom_uuid,
                "raw_id": path,
                "kind": "path",
                "path": path,
                "name": PurePosixPath(path).name or path,
                **(attrs or {}),
            }
        ),
    )


def _hash_node(
    bom_uuid: str, raw_hash: str, attrs: Mapping[str, Any]
) -> tuple[str, str, dict[str, Any]]:
    algorithm = None
    digest = raw_hash
    if ":" in raw_hash:
        algorithm, digest = raw_hash.split(":", 1)
    nid = _node_id(bom_uuid, "hash", raw_hash)
    return (
        nid,
        "Hash",
        _clean_props(
            {
                "id": nid,
                "bomUUID": bom_uuid,
                "raw_id": raw_hash,
                "kind": "hash",
                "algorithm": algorithm,
                "digest": digest,
                **(attrs or {}),
            }
        ),
    )


def _software_props(sw: Any, bom_uuid: str, nid: str) -> dict[str, Any]:
    sw_uuid = getattr(sw, "UUID", None)
    data = _plain(sw)
    props: dict[str, Any] = {
        "id": nid,
        "bomUUID": bom_uuid,
        "raw_id": sw_uuid,
        "kind": "software",
        "uuid": sw_uuid,
        "sha256": getattr(sw, "sha256", None),
        "sha1": getattr(sw, "sha1", None),
        "md5": getattr(sw, "md5", None),
        "fileName": getattr(sw, "fileName", None),
        "installPath": getattr(sw, "installPath", None),
        "containerPath": getattr(sw, "containerPath", None),
        "vendor": getattr(sw, "vendor", None),
        "version": getattr(sw, "version", None),
        "description": getattr(sw, "description", None),
        "name_display": _name_display(getattr(sw, "name", None)),
        "data_json": json.dumps(data, sort_keys=True, default=str),
    }
    return _clean_props(props)


def _name_display(name_value: Any) -> str | None:
    if not name_value:
        return None
    if isinstance(name_value, str):
        return name_value
    names: list[str] = []
    for item in name_value if isinstance(name_value, list) else [name_value]:
        plain = _plain(item)
        if isinstance(plain, dict):
            for key in ("name", "value"):
                value = plain.get(key)
                if isinstance(value, str):
                    names.append(value)
                    break
        elif isinstance(plain, str):
            names.append(plain)
    return ", ".join(dict.fromkeys(names)) if names else None


def _clean_props(props: Mapping[str, Any]) -> dict[str, Any]:
    """Convert values to Neo4j-safe node/relationship properties.

    Neo4j properties should be primitives or homogeneous-ish lists of primitives.
    Nested dicts/lists are serialized as JSON strings under the original key.
    """
    clean: dict[str, Any] = {}
    for key, value in props.items():
        if value is None:
            continue
        value = _plain(value)
        if (
            isinstance(value, _PRIMITIVE)
            or isinstance(value, list)
            and all(isinstance(v, _PRIMITIVE) for v in value)
        ):
            clean[key] = value
        else:
            clean[f"{key}_json"] = json.dumps(value, sort_keys=True, default=str)
    return clean


def _plain(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, set):
        return sorted(_plain(v) for v in value)
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    return value


def _node_id(bom_uuid: str, kind: str, raw_id: Any) -> str:
    return f"{bom_uuid}:{kind}:{raw_id}"


def _rel_id(bom_uuid: str, graph_name: str, *parts: Any) -> str:
    joined = "|".join(str(part) for part in (bom_uuid, graph_name, *parts))
    return f"{bom_uuid}:rel:{hashlib.sha1(joined.encode('utf-8')).hexdigest()}"


def _safe_label(label: Any) -> str:
    label = str(label or "GraphEntity")
    label = _SAFE_REL_TYPE_RE.sub("_", label)
    if not label or label[0].isdigit():
        label = f"N_{label}"
    return label


def _safe_rel_type(value: Any) -> str:
    rel_type = str(value or "RELATED_TO").upper()
    rel_type = _SAFE_REL_TYPE_RE.sub("_", rel_type)
    rel_type = rel_type.strip("_") or "RELATED_TO"
    if rel_type[0].isdigit():
        rel_type = f"R_{rel_type}"
    return rel_type


def _chunks(rows: Iterable[dict[str, Any]], size: int) -> Iterable[list[dict[str, Any]]]:
    chunk: list[dict[str, Any]] = []
    for row in rows:
        chunk.append(row)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk
