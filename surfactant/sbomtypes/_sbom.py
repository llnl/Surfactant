# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# pylint: disable=too-many-lines
from __future__ import annotations

import json
import pathlib
import uuid as uuid_module
from collections import deque
from dataclasses import asdict, dataclass, field, fields
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx
from dataclasses_json import config, dataclass_json
from loguru import logger

from surfactant.utils.paths import basename_posix, normalize_path

from ._analysisdata import AnalysisData
from ._file import File
from ._hardware import Hardware
from ._observation import Observation
from ._provenance import SoftwareProvenance
from ._relationship import Relationship, StarRelationship
from ._software import Software, SoftwareComponent
from ._system import System

INTERNAL_FIELDS = {"software_lookup_by_sha256"}


def recover_serializers(cls):
    """
    After dataclass_json has bound its own to_dict/to_json,
    restore any _to_dict/_to_json overrides.
    """
    if hasattr(cls, "to_dict_override"):
        cls.to_dict = cls.to_dict_override
    if hasattr(cls, "to_json_override"):
        cls.to_json = cls.to_json_override
    return cls


@recover_serializers
@dataclass_json
@dataclass
class SBOM:
    # pylint: disable=too-many-public-methods
    # pylint: disable=R0902
    systems: List[System] = field(default_factory=list)
    hardware: List[Hardware] = field(default_factory=list)
    software: List[Software] = field(default_factory=list)
    # relationships: Set[Relationship] = field(default_factory=set)  # (removed relationships field. Graph is now the single source of truth)
    _loaded_relationships: List[Relationship] = (
        field(  # this metadata will capture the old array on load (but won’t re-emit it)
            default_factory=list,
            metadata=config(field_name="relationships", exclude=lambda _: True),
        )
    )
    analysisData: List[AnalysisData] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    starRelationships: Set[StarRelationship] = field(default_factory=set)
    software_lookup_by_sha256: Dict = field(default_factory=dict)
    fs_tree: nx.DiGraph = field(
        init=False,
        repr=False,
        metadata=config(exclude=lambda _: True),
    )
    graph: nx.MultiDiGraph = field(
        init=False,
        repr=False,
        # metadata=config(exclude=lambda _: True),  # internal graph; excluded from JSON
        metadata=config(exclude=lambda _: True),
    )  # Add a NetworkX directed graph for quick traversal/query

    _pending_dir_links: List[Tuple[str, str]] = field(
        default_factory=list,
        init=False,
        repr=False,
        metadata=config(exclude=lambda _: True),
    )

    # Deferred file-level symlinks (link_path, target_path, subtype)
    # Queues symlink edges discovered before target nodes exist in fs_tree.
    # Flushed later by expand_pending_file_symlinks() to ensure no links are lost.
    _pending_file_links: List[Tuple[str, str, Optional[str]]] = field(
        default_factory=list,
        init=False,
        repr=False,
        metadata=config(exclude=lambda _: True),
    )

    def __post_init__(self):
        # If called like SBOM(raw_dict), raw_dict will be in .systems
        if isinstance(self.systems, dict) and not self.hardware and not self.software:
            raw = self.systems

            # zero out every container
            self.systems = []
            self.hardware = []
            self.software = []
            self.analysisData = []
            self.observations = []
            self._loaded_relationships = []
            self.starRelationships = set()

            # prepare valid field-name sets
            SYSTEM_FIELDS = {f.name for f in fields(System)}
            HARDWARE_FIELDS = {f.name for f in fields(Hardware)}
            SOFTWARE_FIELDS = {f.name for f in fields(Software)}
            REL_FIELDS = {f.name for f in fields(Relationship)}
            AD_FIELDS = {f.name for f in fields(AnalysisData)}
            OBS_FIELDS = {f.name for f in fields(Observation)}
            STAR_FIELDS = {f.name for f in fields(StarRelationship)}

            # rehydrate systems
            for sys_data in raw.get("systems", []):
                clean = {k: v for k, v in sys_data.items() if k in SYSTEM_FIELDS}
                self.systems.append(System(**clean))

            # rehydrate hardware
            for hw_data in raw.get("hardware", []):
                clean = {k: v for k, v in hw_data.items() if k in HARDWARE_FIELDS}
                self.hardware.append(Hardware(**clean))

            # rehydrate software
            for sw_data in raw.get("software", []):
                clean = {k: v for k, v in sw_data.items() if k in SOFTWARE_FIELDS}
                self.software.append(Software(**clean))

            # rehydrate relationships into the loader list
            for rel_data in raw.get("relationships", []):
                clean = {k: v for k, v in rel_data.items() if k in REL_FIELDS}
                self._loaded_relationships.append(Relationship(**clean))

            # rehydrate analysisData
            for ad_data in raw.get("analysisData", []):
                clean = {k: v for k, v in ad_data.items() if k in AD_FIELDS}
                self.analysisData.append(AnalysisData(**clean))

            # rehydrate observations
            for obs_data in raw.get("observations", []):
                clean = {k: v for k, v in obs_data.items() if k in OBS_FIELDS}
                self.observations.append(Observation(**clean))

            # rehydrate starRelationships
            for sr_data in raw.get("starRelationships", []):
                clean = {k: v for k, v in sr_data.items() if k in STAR_FIELDS}
                self.starRelationships.add(StarRelationship(**clean))

        # Strip out internal-only fields so dataclass logic and JSON serializers ignore them
        # pylint: disable=access-member-before-definition
        self.__dataclass_fields__ = {
            k: v for k, v in self.__dataclass_fields__.items() if k not in INTERNAL_FIELDS
        }

        # Build the Relationship graph from systems/software and loaded relationships
        self.build_rel_graph()

        # Initialize fs_tree
        self.fs_tree = nx.DiGraph()

        # Populate from installPaths (if present)
        for sw in self.software:
            self._add_software_to_fs_tree(sw)

    def _add_software_to_fs_tree(self, sw: "Software") -> None:
        """
        Adds the install paths of a Software object to the SBOM's filesystem tree (fs_tree).

        This method normalizes each install path to POSIX format, constructs parent-child
        directory edges, and attaches the software UUID as a node attribute at the final path.

        Args:
            sw (Software): The software object whose install paths are to be added.

        Side Effects:
            Modifies self.fs_tree (a NetworkX DiGraph) by:
                - Creating parent-child edges for each path segment.
                - Ensuring the full install path node exists.
                - Tagging the final node with the software's UUID.

        Example:
            For installPath = ["C:\\app\\bin"], this will create:
                - Nodes: "C:", "C:/app", "C:/app/bin"
                - Edges: "C:" → "C:/app", "C:/app" → "C:/app/bin"
                - Node "C:/app/bin" will have attribute {"software_uuid": sw.UUID}
        """
        if not sw.installPath:
            return  # Nothing to add if no install paths

        for path in sw.installPath:
            # Normalize Windows or Unix paths to a consistent POSIX string
            norm_path = normalize_path(path)
            parts = pathlib.PurePosixPath(norm_path).parts

            # Build parent-child relationships for all intermediate directories
            for i in range(1, len(parts)):
                parent = normalize_path(*parts[:i])
                child = normalize_path(*parts[: i + 1])
                self.fs_tree.add_edge(parent, child)

            # Ensure the final node exists before assigning attributes
            if not self.fs_tree.has_node(norm_path):
                self.fs_tree.add_node(norm_path)

            # Associate this path node with the software UUID
            self.fs_tree.nodes[norm_path]["software_uuid"] = sw.UUID

            # wire the file → hash edge so hash-equivalence works
            if sw.sha256:
                try:
                    self.record_hash_node(norm_path, sw.sha256)
                except Exception as e:  # pylint: disable=broad-exception-caught
                    logger.warning(f"[fs_tree] Failed to attach hash edge for {norm_path}: {e}")

    def get_software_by_path(
        self,
        path: str,
        *,
        case_insensitive: bool = False,
    ) -> Optional[Software]:
        """
        Retrieve a Software entry by normalized install path, using the fs_tree (with optional
        case-insensitive fallback and symlink traversal).

        This function normalizes the provided path into POSIX format and first attempts an exact,
        case-sensitive lookup in the filesystem graph (`fs_tree`). If the lookup succeeds and the
        node contains a ``software_uuid``, the corresponding Software entry is returned.

        If the exact match fails and ``case_insensitive`` is enabled, a Windows-style
        case-insensitive resolution is attempted: the function identifies the parent directory
        of the requested path and scans its child nodes for a basename match using
        case-folding. This preserves strict behavior for Unix/ELF callers while allowing PE
        relationship resolvers to emulate Windows filesystem case-insensitivity.

        If neither the exact lookup nor the optional case-insensitive fallback finds a match,
        the function performs a breadth-first traversal along outgoing symlink edges
        (``type="symlink"``) beginning at the normalized path. The traversal continues until a
        node containing a ``software_uuid`` is encountered or a depth limit is reached.

        Args:
            path (str):
                Raw input path (Windows or POSIX). Path separators are normalized but casing is
                preserved.
            case_insensitive (bool):
                Enable Windows-style case-insensitive fallback matching when the exact lookup
                fails. Defaults to ``False`` so that ELF/Unix resolution remains strictly
                case-sensitive.

        Returns:
            Optional[Software]:
                The resolved Software entry if any resolution method succeeds, otherwise ``None``.

        Behavior Summary:
            - Normalizes path separators to POSIX style (case preserved).
            - Performs an exact, case-sensitive fs_tree lookup.
            - Optionally performs case-insensitive basename matching within the parent directory
            (Windows-specific behavior; opt-in only).
            - Traverses outgoing symlink edges breadth-first, with cycle prevention.
            - Applies a conservative depth cap to avoid pathological traversal.
            - Returns the first reachable node containing ``software_uuid``.
        """
        # Normalize the input path to POSIX format to match internal fs_tree representation
        norm_path = normalize_path(path)

        # Attempt direct node lookup (case-sensitive, fast path)
        node = self.fs_tree.nodes.get(norm_path)
        if node and "software_uuid" in node:
            return self._find_software_entry(uuid=node["software_uuid"])

        # Optional Windows-style, case-insensitive fallback
        # Only for callers that explicitly opt-in, to avoid changing ELF/Unix semantics.
        if case_insensitive:
            target = pathlib.PurePosixPath(norm_path)
            parent = target.parent.as_posix()
            basename_ci = target.name.casefold()

            if self.fs_tree.has_node(parent):
                for _src, child, _data in self.fs_tree.out_edges(parent, data=True):
                    child_name_ci = pathlib.PurePosixPath(child).name.casefold()
                    if child_name_ci == basename_ci:
                        candidate = self.fs_tree.nodes.get(child)
                        if candidate and "software_uuid" in candidate:
                            logger.debug(
                                "[fs_tree] case-insensitive match: %s → %s",
                                norm_path,
                                child,
                            )
                            return self._find_software_entry(uuid=candidate["software_uuid"])

        # Attempt to resolve via symlink traversal (BFS) with a depth cap
        visited = set()
        queue = deque([(norm_path, 0)])  # (node, depth)
        MAX_SYMLINK_STEPS = 1000  # conservative cap; adjust if needed

        while queue:
            current, depth = queue.popleft()

            if current in visited:
                continue
            visited.add(current)

            # Depth cap guard
            if depth > MAX_SYMLINK_STEPS:
                logger.warning(
                    "[fs_tree] Aborting symlink traversal for %s after %d steps",
                    path,
                    MAX_SYMLINK_STEPS,
                )
                break

            # If the node doesn't exist in the graph, there are no edges to follow
            if not self.fs_tree.has_node(current):
                continue

            # Check each symlink edge from current node
            for _, target, attrs in self.fs_tree.out_edges(current, data=True):
                if attrs.get("type") == "symlink":
                    target_node = self.fs_tree.nodes.get(target, {})
                    if "software_uuid" in target_node:
                        logger.debug(f"[fs_tree] Resolved {path} via symlink: {current} → {target}")
                        return self._find_software_entry(uuid=target_node["software_uuid"])
                    if target not in visited:
                        queue.append((target, depth + 1))

        # No match found after traversal
        return None

    def get_symlink_sources_for_path(self, path: str) -> List[str]:
        """
        Retrieve all symlink paths (direct and transitive) that point to the given target path.

        This function performs a *reverse traversal* of the filesystem graph (`fs_tree`),
        starting from the specified `path` and walking **incoming** symlink edges
        (`link → target`) to collect every symlink node that ultimately resolves to
        that target.

        The method is effectively the inverse of :meth:`get_software_by_path`, which
        walks *outgoing* symlink edges to resolve a symlink to its destination.

        Behavior:
            - Follows only edges with attribute ``type="symlink"``.
            - Traverses breadth-first to handle multi-hop symlink chains
              (e.g., A → B → C → /usr/bin/ls).
            - Avoids cycles and repeated nodes using a visited set.
            - Returns all normalized symlink paths that resolve to the given target path.
            - Logs debug information for each edge visited and for each discovered source.

        Args:
            path (str): The target filesystem path (can be POSIX or Windows-style).

        Returns:
            List[str]: A sorted list of all symlink paths (direct or transitive)
                       that point to the provided target path.
                       Empty if none are found.

        Example:
            Given:
                /usr/bin/dirE/link_to_F → /usr/bin/dirF
                /usr/bin/dirF/runthat → /usr/bin/echo

            Then:
                get_symlink_sources_for_path("/usr/bin/echo")
                → ["/usr/bin/dirF/runthat", "/usr/bin/dirE/link_to_F/runthat"]
        """
        norm_target = normalize_path(path)
        if not self.fs_tree.has_node(norm_target):
            logger.debug(f"[fs_tree] Target path not found in graph: {norm_target}")
            return []

        results: Set[str] = set()
        visited: Set[str] = set()
        queue: deque[str] = deque([norm_target])

        logger.debug(f"[fs_tree] Starting reverse symlink traversal from: {norm_target}")

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            # Iterate over all incoming symlink edges: src → current
            for src, _dst, attrs in self.fs_tree.in_edges(current, data=True):
                if attrs.get("type") != "symlink":
                    continue

                if src not in results:
                    results.add(src)
                    logger.debug(f"[fs_tree] Found symlink source: {src} → {current}")

                # Continue traversal upward through the graph (transitive links)
                if src not in visited:
                    queue.append(src)

        logger.debug(
            f"[fs_tree] Reverse symlink traversal complete for {norm_target}: "
            f"{len(results)} sources found."
        )

        return sorted(results)

    def build_rel_graph(self) -> None:
        """Rebuild the directed graph from systems, software, and any loaded relationships."""
        self.graph = nx.MultiDiGraph()
        for sys in self.systems:
            self.graph.add_node(sys.UUID, type="System")
        for sw in self.software:
            self.graph.add_node(sw.UUID, type="Software")
        # rehydrate edges from loaded JSON (if any)
        for rel in self._loaded_relationships:
            self.graph.add_edge(rel.xUUID, rel.yUUID, key=rel.relationship)

    def add_relationship(self, rel: Relationship) -> None:
        # The Relationship object get wired into the graph key=…
        if not self.graph.has_node(rel.xUUID):
            self.graph.add_node(rel.xUUID, type="Unknown")
        if not self.graph.has_node(rel.yUUID):
            self.graph.add_node(rel.yUUID, type="Unknown")

        # the edge key is the relationship type
        self.graph.add_edge(rel.xUUID, rel.yUUID, key=rel.relationship)

    def create_relationship(self, xUUID: str, yUUID: str, relationship: str) -> Relationship:
        # ensure nodes exist
        if not self.graph.has_node(xUUID):
            self.graph.add_node(xUUID, type="Unknown")
        if not self.graph.has_node(yUUID):
            self.graph.add_node(yUUID, type="Unknown")

        # record the edge, keyed by the relationship
        self.graph.add_edge(xUUID, yUUID, key=relationship)

        # return a Relationship object for backwards-compat
        return Relationship(xUUID, yUUID, relationship)

    def find_relationship_object(self, r: Relationship) -> bool:
        """
        Return True if an exact edge (r.xUUID → r.yUUID) exists
        in the graph with key=r.relationship.
        """
        return self.graph.has_edge(r.xUUID, r.yUUID, key=r.relationship)

    def find_relationship(self, xUUID: str, yUUID: str, relationship: str) -> bool:
        """
        Same as find_relationship_object, but takes raw args.
        """
        return self.graph.has_edge(xUUID, yUUID, key=relationship)

    def has_relationship(
        self,
        xUUID: Optional[str] = None,
        yUUID: Optional[str] = None,
        relationship: Optional[str] = None,
    ) -> bool:
        """
        Return True if there exists at least one edge u→v in the graph
        matching the optional filters (u, v, and/or relationship key).
        """
        # Fast-path if all three are specified
        if xUUID and yUUID and relationship:
            return self.graph.has_edge(xUUID, yUUID, key=relationship)

        # Otherwise scan all edges with keys
        for u, v, key in self.graph.edges(keys=True):
            if xUUID and u != xUUID:
                continue
            if yUUID and v != yUUID:
                continue
            if relationship and key.upper() != relationship.upper():
                continue
            return True
        return False

    def find_software(self, sha256: Optional[str]) -> Optional[Software]:
        if sha256 in self.software_lookup_by_sha256:
            return self.software_lookup_by_sha256[sha256]
        return None

    def add_software(self, sw: Software) -> None:
        if sw.sha256 is not None:
            self.software_lookup_by_sha256[sw.sha256] = sw
        self.software.append(sw)

        # Add a node for the new software
        if not self.graph.has_node(sw.UUID):
            self.graph.add_node(sw.UUID, type="Software")

        self._add_software_to_fs_tree(sw)

    def _add_symlink_edge(
        self, src: str, dst: str, *, subtype: Optional[str] = None, log_prefix: str = "[fs_tree]"
    ) -> None:
        """
        Internal helper to safely add a symlink edge to both fs_tree and graph.

        Ensures:
        - Both nodes exist in fs_tree and graph with type="Path".
        - The fs_tree edge is labeled type="symlink" with optional subtype.
        - The logical graph mirrors the same edge with key="symlink".
        - Duplicate edges are ignored gracefully.

        Args:
            src (str): Path of the symlink source.
            dst (str): Target path of the symlink.
            subtype (Optional[str]): File or directory indicator.
            log_prefix (str): Optional prefix for debug logs.
        """
        # Add edge to fs_tree if not present
        if not self.fs_tree.has_edge(src, dst):
            self.fs_tree.add_edge(src, dst, type="symlink", subtype=subtype)
            logger.debug(f"{log_prefix} Added symlink edge: {src} → {dst} [subtype={subtype}]")

        # Ensure both nodes exist and are typed as Path in the logical graph
        for node in (src, dst):
            if not self.graph.has_node(node):
                self.graph.add_node(node, type="Path")
            elif "type" not in self.graph.nodes[node]:
                self.graph.nodes[node]["type"] = "Path"

        # Add mirrored edge in graph if not already present
        if not self.graph.has_edge(src, dst, key="symlink"):
            self.graph.add_edge(src, dst, key="symlink")
            logger.debug(f"[graph] Added symlink edge: {src} → {dst}")

    def _record_symlink(
        self, link_path: str, target_path: str, *, subtype: Optional[str] = None
    ) -> None:
        """
        Record a filesystem symlink in both the SBOM's relationship graph and its fs_tree.

        This method adds the given symlink as a relationship between two filesystem
        path nodes (`link_path` → `target_path`). It ensures the link exists in both
        the logical relationship graph (`graph`) and the physical filesystem graph (`fs_tree`),
        maintaining internal consistency between them.

        Steps:
            1. Normalize both input paths to POSIX format.
            2. If the target node does not yet exist in the fs_tree (common when the
               target software entry is added later), queue the link for deferred
               creation in `expand_pending_file_symlinks()`.
            3. Otherwise, create the primary symlink edge immediately using `_add_symlink_edge()`.
            4. If the symlink is a directory:
               - Register it for deferred mirroring in `_pending_dir_links`
                 (expanded later by `expand_pending_dir_symlinks()`).
               - Immediately synthesize one-hop chained symlinks for any direct,
                 non-symlink children of the target directory.

        Args:
            link_path (str): Path of the symlink itself (e.g., "/opt/app/lib/foo.so").
            target_path (str): Absolute path of the resolved symlink target (e.g., "/usr/lib/foo.so").
            subtype (Optional[str]): Optional category for the symlink ("file" or "directory").

        Behavior:
            - Ensures link and target nodes exist as Path-type nodes in both graphs.
            - Defers file symlinks whose targets are not yet known to ensure completeness.
            - Adds missing edges consistently in both structures.
            - Defers deeper directory mirroring to avoid recursive loops.
        """

        # ----------------------------------------------------------------------
        # Step 1: Normalize paths to consistent POSIX-style representation
        # ----------------------------------------------------------------------
        link_node = normalize_path(link_path)
        target_node = normalize_path(target_path)

        # ----------------------------------------------------------------------
        # Step 2: If target node is missing, defer file symlink creation
        # ----------------------------------------------------------------------
        logger.debug(f"[fs_tree] subtype={subtype}")
        if subtype != "directory" and not self.fs_tree.has_node(target_node):
            self._pending_file_links.append((link_node, target_node, subtype))
            logger.debug(f"[fs_tree] Queued deferred file symlink: {link_node} → {target_node}")
            return

        # ----------------------------------------------------------------------
        # Step 3: Create the primary symlink edge between link and target
        # ----------------------------------------------------------------------
        self._add_symlink_edge(link_node, target_node, subtype=subtype)

        # ----------------------------------------------------------------------
        # Step 4: Handle directory symlinks — queue and synthesize one-hop children
        # ----------------------------------------------------------------------
        if subtype == "directory":
            # Register for deferred expansion after all directories are processed
            self._pending_dir_links.append((link_node, target_node))
            logger.debug(
                f"[fs_tree] Queued directory symlink for deferred expansion: "
                f"{link_node} → {target_node}"
            )

            # Identify direct (non-symlink) children under the target directory
            child_edges = [
                (src, dst)
                for src, dst, data in self.fs_tree.edges(target_node, data=True)
                if data.get("type") != "symlink"  # include only structural edges
            ]

            if not child_edges:
                logger.debug(
                    f"[fs_tree] No immediate children found under {target_node}; skipping chained edges."
                )
                return

            # Create one-hop chained symlink edges for each direct child
            for _, child in child_edges:
                child_basename = PurePosixPath(child).name
                synthetic_link = normalize_path(str(PurePosixPath(link_node) / child_basename))

                # Add synthetic child edge via the shared helper
                self._add_symlink_edge(synthetic_link, child, subtype="file")
                logger.debug(
                    f"[fs_tree] (immediate) Synthetic chained symlink created: "
                    f"{synthetic_link} → {child}"
                )

    def record_symlink(
        self, link_path: str, target_path: str, *, subtype: Optional[str] = None
    ) -> None:
        """Public, stable API to record a filesystem symlink in the SBOM graphs.

        Validates inputs and delegates to the internal ``_record_symlink`` which
        handles normalization, node/edge creation, and deduplication.

        Args:
            link_path: Path of the symlink itself (install path).
            target_path: Resolved absolute path of the symlink target.
            subtype: Optional qualifier (e.g., "file" or "directory").
        """
        logger.debug(f"{link_path} -> {target_path} ({subtype})")
        if not isinstance(link_path, str) or not isinstance(target_path, str):
            raise TypeError("link_path and target_path must be strings")
        if not link_path or not target_path:
            raise ValueError("link_path and target_path must be non-empty")

        # Delegate to internal implementation (already normalizes & dedupes)
        self._record_symlink(link_path, target_path, subtype=subtype)

    def record_hash_node(self, file_path: str, sha256: str) -> None:
        """
        Record a hash equivalence edge between a filesystem path and its content hash.

        This method links the given file node to a virtual hash node (e.g., "sha256:<digest>"),
        allowing the fs_tree to represent content-equivalence relationships across files.
        Such hash-based edges enable detection of identical files that were copied,
        flattened, or dereferenced during extraction—restoring logical symlink equivalence
        and supporting later deduplication.

        Args:
            file_path (str): Absolute or relative path of the file within the extraction root.
            sha256 (str): SHA-256 digest string representing the file's content.

        Behavior:
            - Normalizes `file_path` to POSIX-style notation for consistent node keys.
            - Ensures the hash node exists in the fs_tree with type="Hash".
            - Adds a directed "hash" edge from the file node → hash node.

        Example:
            /usr/bin/su  →  sha256:f163759953aafc083e9ee25c20cda300ae01e37612eb24e54086cacffe1aca5a
        """
        file_node = normalize_path(file_path)
        hash_node = f"sha256:{sha256}"

        logger.debug(f"[fs_tree] Recording hash node for file: {file_node} (hash={hash_node})")

        # Ensure both nodes exist, guarding against accidental type overrides
        if self.fs_tree.has_node(hash_node):
            existing_type = self.fs_tree.nodes[hash_node].get("type")
            if existing_type != "Hash":
                logger.warning(
                    f"[fs_tree] Node {hash_node} already exists with type={existing_type}, "
                    "overwriting to type=Hash"
                )
            else:
                logger.debug(f"[fs_tree] Reusing existing hash node: {hash_node}")
        else:
            self.fs_tree.add_node(hash_node, type="Hash")
            logger.debug(f"[fs_tree] Added new hash node: {hash_node}")

        self.fs_tree.nodes[hash_node]["type"] = "Hash"  # enforce correct type
        self.fs_tree.add_edge(file_node, hash_node, type="hash")
        logger.debug(f"[fs_tree] Added hash edge: {file_node} → {hash_node} (type=hash)")

    def get_hash_equivalents(self, path_node: str) -> set[str]:
        """
        Return all filesystem paths in fs_tree that share the same hash node
        as the given target. Used as a fallback when symlink metadata is missing
        but identical file content (hash) indicates equivalence.

        Args:
            path_node (str): Normalized path node in fs_tree.

        Returns:
            set[str]: Other filesystem path nodes that point to the same hash node.
        """
        equivalents = set()
        if not self.fs_tree.has_node(path_node):
            logger.debug(f"[fs_tree] get_hash_equivalents: target node not found: {path_node}")
            return equivalents

        # Find hash edges (path → sha256:...)
        for _, hash_node, data in self.fs_tree.out_edges(path_node, data=True):
            if data.get("type") == "hash":
                logger.debug(f"[fs_tree] Found hash edge: {path_node} → {hash_node}")
                # For each path that shares this hash node, collect siblings
                for src, _ in self.fs_tree.in_edges(hash_node):
                    if src != path_node:
                        equivalents.add(src)
                        logger.debug(f"[fs_tree] Added hash-equivalent sibling: {src}")

        if equivalents:
            logger.debug(
                f"[fs_tree] get_hash_equivalents: {path_node} has {len(equivalents)} "
                f"equivalent path(s): {sorted(equivalents)}"
            )
        else:
            logger.debug(
                f"[fs_tree] get_hash_equivalents: no hash-equivalent siblings for {path_node}"
            )

        return equivalents

    def add_software_entries(
        self, entries: Optional[List[Software]], parent_entry: Optional[Software] = None
    ):
        """
        Add software entries to the SBOM graph, merging duplicates, preserving existing edges,
        attaching "Contains" relationships to an optional parent, and recording ANY
        file- or directory-level symlinks under each installPath.

        Args:
            entries (Optional[List[Software]]): list of Software instances to add.
            parent_entry (Optional[Software]): if provided, attach a "Contains" edge from this parent to each entry.
        """
        if not entries:
            return

        # if a software entry already exists with a matching file hash, augment the info in the existing entry
        for sw in entries:
            #  Merge duplicates by sha256 (or insert if new)
            existing = self.find_software(sw.sha256)
            if existing and Software.check_for_hash_collision(existing, sw):
                logger.warning(f"Hash collision between {existing.name} and {sw.name}")

            if existing:
                # Merge into existing node
                # Duplicate → merge data & edges, drop the old UUID
                kept_uuid, old_uuid = existing.merge(sw)
                logger.debug(f"Merged {sw.UUID} into {kept_uuid}, removing {old_uuid}")

                # Redirect *incoming* edges to the kept node
                for src, _, key, attrs in list(self.graph.in_edges(old_uuid, keys=True, data=True)):
                    self.graph.add_edge(src, kept_uuid, key=key, **attrs)

                # Redirect *outgoing* edges from the old node
                for _, dst, key, attrs in list(
                    self.graph.out_edges(old_uuid, keys=True, data=True)
                ):
                    self.graph.add_edge(kept_uuid, dst, key=key, **attrs)

                # Remove the old UUID entirely
                if self.graph.has_node(old_uuid):
                    self.graph.remove_node(old_uuid)
                node_uuid = kept_uuid

            else:
                # New software → add node
                self.add_software(sw)
                node_uuid = sw.UUID
                logger.debug(f"Added new software node {node_uuid}")

                # ------------------------------------------------------------------
                # If another software entry already has the same sha256, link them by hash equivalence
                # ------------------------------------------------------------------
                if sw.sha256:
                    for other in self.software:
                        if other is not sw and other.sha256 == sw.sha256:
                            # Both files share the same content hash — link them to the same hash node
                            for path in sw.installPath or []:
                                try:
                                    self.record_hash_node(path, sw.sha256)
                                except Exception as e:  # pylint: disable=broad-exception-caught
                                    logger.warning(
                                        f"[fs_tree] Failed to record hash link for {path}: {e}"
                                    )
                            for path in other.installPath or []:
                                try:
                                    self.record_hash_node(path, sw.sha256)
                                except Exception as e:  # pylint: disable=broad-exception-caught
                                    logger.warning(
                                        f"[fs_tree] Failed to record hash link for {path}: {e}"
                                    )
                            logger.debug(
                                f"[fs_tree] Linked identical content by hash: "
                                f"{sw.installPath} ↔ {other.installPath}"
                            )
                            break

            # Attach a Contains edge from parent, if any
            if parent_entry:
                parent_uuid = parent_entry.UUID
                if not self.graph.has_edge(parent_uuid, node_uuid, key="Contains"):
                    self.graph.add_edge(parent_uuid, node_uuid, key="Contains")
                    logger.debug(f"Attached Contains edge: {parent_uuid} → {node_uuid}")

            # Symlink capture under each installPath ---
            for raw in sw.installPath or []:
                p = pathlib.Path(raw)

                # If the installPath itself is a symlink (file or dir)
                if p.is_symlink():
                    real = p.resolve()
                    subtype = "file" if not p.is_dir() else "directory"
                    logger.debug(f"Found installPath symlink: {p} → {real} (subtype={subtype})")
                    # Call the helper to record this symlink in fs_tree
                    self._record_symlink(str(p), str(real), subtype=subtype)

                # If it's a directory, scan immediate children for symlinks
                if p.is_dir():
                    for child in p.iterdir():
                        if child.is_symlink():
                            real = child.resolve()
                            subtype = "file" if not child.is_dir() else "directory"
                            logger.debug(
                                f"Found child symlink: {child} → {real} (subtype={subtype})"
                            )
                            self._record_symlink(str(child), str(real), subtype=subtype)

    def expand_pending_dir_symlinks(self) -> None:
        """
        Expand all deferred directory symlinks recorded in `_pending_dir_links`.

        Each deferred pair `(link_node, target_node)` represents a directory-level
        symlink such as `/usr/bin/dirE/link_to_F → /usr/bin/dirF`.

        This function performs a one-hop mirror expansion to create synthetic
        symlink edges linking each immediate child of the target directory back
        under the symlink source. For example:

            /usr/bin/dirE/link_to_F/runthat → /usr/bin/dirF/runthat

        The goal is to replicate the main branch’s behavior for cross-directory
        mirroring (e.g., dirE ↔ dirF) without over-expanding into recursive
        `link_to_F/link_to_E/...` chains.

        Behavior:
            - Processes only valid directory symlink targets already present in `fs_tree`.
            - Collects *depth-1* descendants (immediate children) of the target directory.
            - Skips already-existing synthetic edges to avoid duplication.
            - Ensures that mirrored nodes are properly typed as `Path` in both graphs.
            - Mirrors all edges into both `fs_tree` and `graph` for consistency.
        """

        pending_count = len(self._pending_dir_links)
        logger.debug(f"[fs_tree] Expanding {pending_count} pending directory symlinks")

        # ----------------------------------------------------------------------
        # Process each deferred directory symlink pair
        # ----------------------------------------------------------------------
        for link_node, target_node in list(self._pending_dir_links):
            if not self.fs_tree.has_node(target_node):
                logger.debug(
                    f"[fs_tree] Skipping {link_node} → {target_node} (target missing in fs_tree)"
                )
                continue

            # Normalize and prepare for prefix-based matching
            target_prefix = target_node.rstrip("/") + "/"

            # ------------------------------------------------------------------
            # Collect immediate child nodes (depth-1 only, avoid recursive nesting)
            # ------------------------------------------------------------------
            immediate_children: List[str] = []
            for child in list(self.fs_tree.nodes):
                if child.startswith(target_prefix) and child != target_node:
                    tail = child[len(target_prefix) :]
                    if "/" not in tail and tail:  # ensure depth-1 only
                        immediate_children.append(child)

            logger.debug(
                f"[fs_tree] Deferred mirror for {link_node} → {target_node}: "
                f"{len(immediate_children)} immediate children found"
            )

            # ------------------------------------------------------------------
            # Create synthetic edges for each immediate child
            # ------------------------------------------------------------------
            for child in immediate_children:
                # Derive the synthetic symlink path using normalize_path + basename_posix
                child_basename = basename_posix(child)
                synthetic_link = normalize_path(link_node, child_basename)

                # Skip if this symlink edge already exists
                if self.fs_tree.has_edge(synthetic_link, child):
                    logger.debug(f"[fs_tree] Skipping existing edge: {synthetic_link} → {child}")
                    continue

                # Add synthetic symlink edge to both fs_tree and graph
                self._add_symlink_edge(synthetic_link, child, subtype="file")
                logger.debug(
                    f"[fs_tree] (deferred) Synthetic chained symlink created: "
                    f"{synthetic_link} → {child}"
                )

        logger.debug(
            f"[fs_tree] Deferred symlink expansion complete — processed {pending_count} entries."
        )

        logger.debug(
            f"[fs_tree] Deferred symlink expansion complete — processed {pending_count} entries."
        )

    def expand_pending_file_symlinks(self) -> None:
        """
        Expand all deferred file symlinks recorded in `_pending_file_links`.

        Ensures that file-level symlinks pointing to targets that were not yet
        added to the fs_tree at record time are created once the full graph exists.
        """
        pending_count = len(self._pending_file_links)
        logger.debug(f"[fs_tree] Expanding {pending_count} pending file symlinks")

        for link_node, target_node, subtype in list(self._pending_file_links):
            if self.fs_tree.has_edge(link_node, target_node):
                continue
            if not self.fs_tree.has_node(target_node):
                logger.debug(
                    f"[fs_tree] Skipping deferred file link {link_node} → {target_node} (missing target)"
                )
                continue
            self._add_symlink_edge(link_node, target_node, subtype=subtype)
            logger.debug(f"[fs_tree] Deferred file symlink created: {link_node} → {target_node}")

        self._pending_file_links.clear()

    def inject_symlink_metadata(self) -> None:
        """
        Populate legacy-style symlink metadata into each Software entry using fs_tree
        relationships, hash-equivalence, and gathered filename aliases.

        This method restores compatibility with legacy SBOM outputs by reintroducing
        metadata fields that explicitly describe file aliasing relationships.

        It collects three classes of alias information:

            1. **Filesystem Symlinks:** incoming symlink edges in `fs_tree`
               (e.g., "usr/sbin/runuser" → "usr/bin/su")

            2. **Hash-Equivalent Siblings:** other files that share identical content
               (sha256) but appear at different install paths.

            3. **Gathered Filename Aliases:** additional names from `sw.fileName`
               that were injected during the gather phase but are not canonical
               basenames of the install paths (e.g., bash-completion stubs like
               "runuser" for "su").

        The resulting metadata entries are merged or appended under each
        `Software.metadata` list in a legacy-compatible format:

            - ``fileNameSymlinks`` — list of alternate basenames
            - ``installPathSymlinks`` — list of alternate full install paths

        This operation:
            • Traverses all Software entries
            • Derives alias sets from symlink edges, identical hashes, and fileName extras
            • Merges metadata without duplication
            • Does *not* alter fs_tree or graph topology

        Example output:
            {
                "fileName": ["su"],
                "metadata": [
                    {"fileNameSymlinks": ["runuser"]},
                    {"installPathSymlinks": ["usr/sbin/runuser"]}
                ]
            }
        """

        logger.debug("[fs_tree] Injecting legacy-style symlink metadata into Software entries")

        # ----------------------------------------------------------------------
        # Iterate over all software entries and derive metadata from fs_tree
        # ----------------------------------------------------------------------
        for sw in self.software:
            if not sw.installPath:
                continue

            file_symlinks = set()
            path_symlinks = set()

            # ------------------------------------------------------------------
            # For each installPath, gather direct and indirect symlink aliases
            # ------------------------------------------------------------------
            for path in sw.installPath:
                logger.debug(f"[fs_tree] Processing installPath for symlink injection: {path}")

                # --------------------------------------------------------------
                # 1. Reverse lookup: find symlink nodes that point to this path
                # --------------------------------------------------------------
                sources = self.get_symlink_sources_for_path(path)
                if sources:
                    logger.debug(f"[fs_tree] Found symlink sources for {path}: {sources}")
                    for src in sources:
                        path_symlinks.add(src)
                        file_symlinks.add(PurePosixPath(src).name)

                # --------------------------------------------------------------
                # 2. Include hash-equivalent siblings (same content)
                # --------------------------------------------------------------
                hash_equivs = self.get_hash_equivalents(path)
                if hash_equivs:
                    logger.debug(
                        f"[fs_tree] Found hash-equivalent siblings for {path}: {hash_equivs}"
                    )
                    for equiv in hash_equivs:
                        if equiv not in path_symlinks:
                            path_symlinks.add(equiv)
                            file_symlinks.add(PurePosixPath(equiv).name)

            # ------------------------------------------------------------------
            # 3. Add gathered filename aliases not tied to install basenames
            # ------------------------------------------------------------------
            primary_basenames = {PurePosixPath(p).name for p in (sw.installPath or [])}
            file_name_extras = set(sw.fileName or []) - primary_basenames
            if file_name_extras:
                file_symlinks |= file_name_extras
                logger.debug(
                    f"[fs_tree] Added gathered filename aliases for {sw.UUID}: {sorted(file_name_extras)}"
                )

            # ------------------------------------------------------------------
            # Skip entries with no discovered symlink or hash equivalence
            # ------------------------------------------------------------------
            if not (file_symlinks or path_symlinks):
                continue

            # ------------------------------------------------------------------
            # 4. Merge alias metadata into Software.metadata
            # ------------------------------------------------------------------
            if sw.metadata is None:
                sw.metadata = []

            def _merge_md(key: str, values: set[str], *, _sw: Software = sw) -> None:
                """Merge or append a metadata entry for the given key, avoiding duplication."""
                if not values:
                    return
                merged = sorted(values)
                for md in _sw.metadata:
                    if isinstance(md, dict) and key in md:
                        existing = set(md[key])
                        md[key] = sorted(existing | set(merged))
                        logger.debug(f"[fs_tree] Merged {key} for {_sw.UUID}: {md[key]}")
                        break
                else:
                    _sw.metadata.append({key: merged})
                    logger.debug(f"[fs_tree] Appended {key} for {_sw.UUID}: {merged}")

            _merge_md("fileNameSymlinks", file_symlinks)
            _merge_md("installPathSymlinks", path_symlinks)

            # Optional: legacy-style alias duplication into fileName[]
            for alias in file_symlinks:
                if alias not in sw.fileName:
                    sw.fileName.append(alias)
                    logger.debug(f"[fs_tree] Added alias '{alias}' to fileName for {sw.UUID}")

        logger.debug("[fs_tree] Completed symlink metadata injection pass")

    # pylint: disable=too-many-arguments
    def create_software(
        self,
        *,  # all arguments are keyword-only
        name: Optional[str] = None,
        size: Optional[int] = None,
        sha1: Optional[str] = None,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
        fileName: Optional[List[str]] = None,
        installPath: Optional[List[str]] = None,
        containerPath: Optional[List[str]] = None,
        captureTime: Optional[int] = None,
        version: Optional[str] = None,
        vendor: Optional[List[str]] = None,
        description: Optional[str] = None,
        relationshipAssertion: Optional[str] = None,
        comments: Optional[str] = None,
        metadata: Optional[List[object]] = None,
        supplementaryFiles: Optional[List[File]] = None,
        provenance: Optional[List[SoftwareProvenance]] = None,
        recordedInstitution: Optional[str] = None,
        components: Optional[List[SoftwareComponent]] = None,
    ) -> Software:
        sw = Software(
            name=name,
            size=size,
            sha1=sha1,
            sha256=sha256,
            md5=md5,
            fileName=fileName,
            installPath=installPath,
            containerPath=containerPath,
            captureTime=captureTime,
            version=version,
            vendor=vendor,
            description=description,
            relationshipAssertion=relationshipAssertion,
            comments=comments,
            metadata=metadata,
            supplementaryFiles=supplementaryFiles,
            provenance=provenance,
            recordedInstitution=recordedInstitution,
            components=components,
        )
        self.software_lookup_by_sha256[sw.sha256] = sw
        self.software.append(sw)
        return sw

    def merge(self, sbom_m: SBOM):
        # merged/old to new UUID map
        uuid_updates: Dict[str, str] = {}

        # 1) Merge systems
        if sbom_m.systems:
            for system in sbom_m.systems:
                # check for duplicate UUID/name, merge with existing entry
                if existing_system := self._find_systems_entry(uuid=system.UUID, name=system.name):
                    # merge system entries
                    u1, u2 = existing_system.merge(system)
                    logger.info(f"MERGE_DUPLICATE_SYS: uuid1={u1}, uuid2={u2}")
                    uuid_updates[u2] = u1

                    # Redirect any existing edges from u2 -> u1 in self.graph
                    if hasattr(self, "graph") and self.graph.has_node(u2):
                        # for each predecessor of u2, add edge (pred -> u1)
                        # Redirect incoming edges to the merged node u1
                        for pred, _, key, attrs in self.graph.in_edges(u2, keys=True, data=True):
                            self.graph.add_edge(pred, u1, key=key, **attrs)

                        # For each successor of u2, add edge (u1 -> succ)
                        # Redirect outgoing edges from u2 → u1
                        for _, succ, key, attrs in self.graph.out_edges(u2, keys=True, data=True):
                            self.graph.add_edge(u1, succ, key=key, **attrs)

                        # Then drop the old node
                        self.graph.remove_node(u2)

                else:
                    self.systems.append(system)

                    # Add the new system node into the graph
                    if hasattr(self, "graph"):
                        self.graph.add_node(system.UUID, type="System")

        # 2) Merge software
        if sbom_m.software:
            for sw in sbom_m.software:
                # NOTE: Do we want to pass in teh UUID here? What if we have two different UUIDs for the same file? Should hashes be required?
                if existing_sw := self._find_software_entry(
                    uuid=sw.UUID, sha256=sw.sha256, md5=sw.md5, sha1=sw.sha1
                ):
                    u1, u2 = existing_sw.merge(sw)
                    logger.info(f"MERGE DUPLICATE: uuid1={u1}, uuid2={u2}")
                    uuid_updates[u2] = u1

                    # Redirect any existing edges from u2 -> u1 in self.graph
                    if hasattr(self, "graph") and self.graph.has_node(u2):
                        # Redirect incoming edges to the merged node u1
                        for pred, _, key, attrs in self.graph.in_edges(u2, keys=True, data=True):
                            self.graph.add_edge(pred, u1, key=key, **attrs)
                        # Redirect outgoing edges from u2 → u1
                        for _, succ, key, attrs in self.graph.out_edges(u2, keys=True, data=True):
                            self.graph.add_edge(u1, succ, key=key, **attrs)

                        # Then drop the old node
                        self.graph.remove_node(u2)

                else:
                    self.software.append(sw)

                    # Add the new software node in the graph
                    if hasattr(self, "graph"):
                        self.graph.add_node(sw.UUID, type="Software")

        # 3) Merge relationships from the incoming SBOM’s MultiDiGraph
        for src, dst, rel_type in sbom_m.graph.edges(keys=True):
            # Skip path/symlink edges during merge as well
            if str(rel_type).lower() == "symlink":
                continue
            if sbom_m.graph.nodes.get(src, {}).get("type") == "Path":
                continue
            if sbom_m.graph.nodes.get(dst, {}).get("type") == "Path":
                continue

            # apply any UUID remaps from merged systems/software
            xUUID = uuid_updates.get(src, src)
            yUUID = uuid_updates.get(dst, dst)

            # skip exact duplicates
            if self.graph.has_edge(xUUID, yUUID, key=rel_type):
                logger.info(f"DUPLICATE RELATIONSHIP: {xUUID} → {yUUID} [{rel_type}]")
            else:
                # add a new edge, keyed by the relationship
                self.graph.add_edge(xUUID, yUUID, key=rel_type)

        # 4) Rewrite any containerPath UUIDs
        for sw in self.software:
            if sw.containerPath:
                for idx, path in enumerate(sw.containerPath):
                    u = path[:36]
                    # if container path starts with an invalid uuid4, sbom might not be valid
                    if self.is_valid_uuid4(u):
                        if u in uuid_updates:
                            updated_path = path.replace(u, uuid_updates[u], 1)
                            sw.containerPath[idx] = updated_path
                # remove duplicates
                sw.containerPath = [*set(sw.containerPath)]

        logger.info(f"UUID UPDATES: {uuid_updates}")

        # 5) Merge analysisData, observations, starRelationships
        for ad in sbom_m.analysisData:
            self.analysisData.append(ad)
        for obs in sbom_m.observations:
            self.observations.append(obs)
        for star_rel in sbom_m.starRelationships:
            # rewrite UUIDs before doing the search
            if star_rel.xUUID in uuid_updates:
                star_rel.xUUID = uuid_updates[star_rel.xUUID]
            if star_rel.yUUID in uuid_updates:
                star_rel.yUUID = uuid_updates[star_rel.yUUID]
            if existing_star_rel := self._find_star_relationship_entry(
                xUUID=star_rel.xUUID,
                yUUID=star_rel.yUUID,
                relationship=star_rel.relationship,
            ):
                logger.info(f"DUPLICATE STAR RELATIONSHIP: {existing_star_rel}")
            else:
                self.starRelationships.add(star_rel)

    def _find_systems_entry(
        self, uuid: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[System]:
        """Merge helper function to find and return
        the matching system entry in the provided sbom.

        Args:
            uuid (Optional[str]): The uuid of the desired system entry.
            name (Optional[str]): The name of the desired system entry.

        Returns:
            Optional[System]: The system found that matches the given criteria, otherwise None.
        """
        for system in self.systems:
            if uuid:
                if system.UUID != uuid:
                    continue
            if name:
                if system.name != name:
                    continue
            return system
        return None

    def _find_software_entry(
        self,
        uuid: Optional[str] = None,
        sha256: Optional[str] = None,
        md5: Optional[str] = None,
        sha1: Optional[str] = None,
    ) -> Optional[Software]:
        """Merge helper function to find and return
        the matching software entry in the provided sbom.

        Args:
            uuid (Optional[str]): The uuid of the desired software entry to match against if no hashes were provided.
            sha256 (Optional[str]): The sha256 of the desired software entry.
            md5 (Optional[str]): The md5 of the desired software entry.
            sha1 (Optional[str]): The sha1 of the desired software entry.

        Returns:
            Optional[Software]: The software entry found that matches the given criteria, otherwise None.
        """
        for sw in self.software:
            match = False
            # If we have hashes to check
            if sha256 or md5 or sha1:
                # Check if we have both sides of the comparison, then compare. At least one hash must match
                if sw.sha256 and sha256:
                    if sw.sha256 == sha256:
                        match = True
                if sw.md5 and md5:
                    if sw.md5 == md5:
                        match = True
                if sw.sha1 and sha1:
                    if sw.sha1 == sha1:
                        match = True
            # If no hashes to check, match by UUID
            else:
                if sw.UUID == uuid:
                    match = True
            if match:
                return sw
        return None

    def _find_relationship_entry(
        self,
        xUUID: Optional[str] = None,
        yUUID: Optional[str] = None,
        relationship: Optional[str] = None,
    ) -> Optional[Relationship]:
        """Merge helper function to find and return
        the matching relationship entry in the provided sbom.

        Locate and return the first matching Relationship object
        found in the MultiDiGraph.

        Args:
            xUUID (Optional[str]): The xUUID of the desired relationship entry.
            yUUID (Optional[str]): The yUUID of the desired relationship entry.
            relationship (Optional[str]): The relationship type of the desired relationship entry.

        Returns:
            Optional[Relationship]: The relationship entry found that matches the given criteria, otherwise None.
        """
        for u, v, key in self.graph.edges(keys=True):
            if xUUID and u != xUUID:
                continue
            if yUUID and v != yUUID:
                continue
            if relationship and key.upper() != relationship.upper():
                continue
            # reconstruct the Relationship object for merge‐logic
            return Relationship(xUUID=u, yUUID=v, relationship=key)
        return None

    def _find_star_relationship_entry(
        self,
        xUUID: Optional[str] = None,
        yUUID: Optional[str] = None,
        relationship: Optional[str] = None,
    ) -> Optional[StarRelationship]:
        """Merge helper function to find and return
        the matching star relationship entry in the provided sbom.

        Args:
            xUUID (Optional[str]): The xUUID of the desired relationship entry.
            yUUID (Optional[str]): The yUUID of the desired relationship entry.
            relationship (Optional[str]): The relationship type of the desired relationship entry.

        Returns:
            Optional[StarRelationship]: The star relationship found that matches the given criteria, otherwise None.
        """
        for rel in self.starRelationships:
            if xUUID:
                if rel.xUUID != xUUID:
                    continue
            if yUUID:
                if rel.yUUID != yUUID:
                    continue
            if relationship:
                if rel.relationship != relationship:
                    continue
            return rel
        return None

    def is_valid_uuid4(self, u: str) -> bool:
        """Merge helper function to check if a uuid is valid.

        Args:
            u (str):  The UUID to check.

        Returns:
            bool: True if the UUID is valid, otherwise False.
        """
        try:
            u_test = uuid_module.UUID(u, version=4)
        except ValueError:
            return False
        return str(u_test) == u

    def get_children(self, xUUID: str, rel_type: Optional[str] = None) -> List[str]:
        """
        Return all v such that there is an edge xUUID → v,
        optionally filtered by relationship key.
        """
        children = []
        for _, v, key in self.graph.out_edges(xUUID, keys=True):
            if rel_type is None or key.upper() == rel_type.upper():
                children.append(v)
        return children

    def get_parents(self, yUUID: str, rel_type: Optional[str] = None) -> List[str]:
        """
        Return all u such that there is an edge u → yUUID,
        optionally filtered by relationship key.
        """
        parents = []
        for u, _, key in self.graph.in_edges(yUUID, keys=True):
            if rel_type is None or key.upper() == rel_type.upper():
                parents.append(u)
        return parents

    def to_dict_override(self) -> dict:
        """
        Convert the SBOM object into a serializable dictionary for JSON output,
        excluding internal graph structures and filtering out non-logical
        (filesystem-related) relationships.

        This method performs the following steps:
        1. Creates a dictionary from the SBOM dataclass fields using `asdict()`.
        2. Removes internal-only attributes that should not be serialized
           (`graph`, `fs_tree`, `_loaded_relationships`, `_pending_dir_links`,
           `_pending_file_links`).
        3. Converts any `set` values in the remaining fields to `list` so the
        output is JSON-compatible.
        4. Builds a filtered `relationships` list from the SBOM's main `graph`:
        - Skips any edges where the key (relationship type) is `"symlink"`.
        - Skips edges where either endpoint node has `type="Path"`, indicating
            the node represents a filesystem path rather than a logical software
            entity.
        - Keeps only logical relationships between software UUIDs or other
            non-path entities.

        Returns:
            dict: A JSON-serializable representation of the SBOM, with only
                logical relationships included in the `relationships` list.
        """
        # Start with the dataclass dump and strip internals
        data = asdict(self)
        data.pop("graph", None)
        data.pop("fs_tree", None)
        data.pop("_loaded_relationships", None)
        data.pop("_pending_dir_links", None)
        data.pop("_pending_file_links", None)

        # Convert sets → lists for JSON
        for k, v in list(data.items()):
            if isinstance(v, set):
                data[k] = list(v)

        # Only emit logical relationships (exclude filesystem/path symlinks)
        rels = []
        for u, v, key in self.graph.edges(keys=True):
            # Skip symlink edges
            if str(key).lower() == "symlink":
                continue
            # Skip any edge where either endpoint is a filesystem Path node
            utype = self.graph.nodes.get(u, {}).get("type")
            vtype = self.graph.nodes.get(v, {}).get("type")
            if utype == "Path" or vtype == "Path":
                continue
            rels.append({"xUUID": u, "yUUID": v, "relationship": key})

        data["relationships"] = rels

        return data

    def to_json_override(self, *args, **kwargs) -> str:
        """
        Serialize via our to_dict_override, passing through any json.dumps kwargs.
        """
        return json.dumps(self.to_dict_override(), *args, **kwargs)
