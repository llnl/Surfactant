from copy import deepcopy

import pytest

from surfactant.sbomtypes import SBOM, Relationship, Software


def _add_relationship(sbom, source, target, kind="Uses"):
    sbom.add_relationship(Relationship(xUUID=source.UUID, yUUID=target.UUID, relationship=kind))


@pytest.mark.parametrize("include_hash", [True, False])
@pytest.mark.parametrize("include_new_relationship", [True, False])
def test_same_uuid_merge_preserves_existing_relationships(include_hash, include_new_relationship):
    parent = Software(sha256="a" * 64)
    component = Software(
        sha256="b" * 64 if include_hash else None,
        notHashable=not include_hash,
        version="1.0",
    )
    dependency = Software(sha256="c" * 64)
    sbom = SBOM(software=[parent, component, dependency])
    _add_relationship(sbom, parent, component, "Contains")
    _add_relationship(sbom, component, dependency)
    original_nodes = deepcopy(dict(sbom.graph.nodes(data=True)))
    original_edges = deepcopy(list(sbom.graph.edges(keys=True, data=True)))

    update = Software(
        UUID=component.UUID,
        sha256=component.sha256,
        notHashable=component.notHashable,
        version="2.0",
    )
    incoming = SBOM(software=[update])
    new_dependency = Software(sha256="d" * 64)
    if include_new_relationship:
        incoming.add_software(new_dependency)
        _add_relationship(incoming, update, new_dependency)

    sbom.merge(incoming)

    assert component.version == "2.0"
    for node, attributes in original_nodes.items():
        assert sbom.graph.has_node(node)
        assert dict(sbom.graph.nodes[node]) == attributes
    for source, target, kind, attributes in original_edges:
        assert sbom.graph.has_edge(source, target, key=kind)
        assert sbom.graph[source][target][kind] == attributes
    if include_new_relationship:
        assert sbom.graph.has_edge(component.UUID, new_dependency.UUID, key="Uses")


def test_repeated_snapshot_merge_preserves_software_node_types():
    component = Software(sha256="a" * 64)
    dependency = Software(sha256="b" * 64)
    sbom = SBOM(software=[component, dependency])
    _add_relationship(sbom, component, dependency)
    incoming = deepcopy(sbom)

    for _ in range(2):
        sbom.merge(incoming)
        assert len(sbom.software) == 2
        assert sbom.graph.nodes[component.UUID]["type"] == "Software"
        assert sbom.graph.nodes[dependency.UUID]["type"] == "Software"
        assert sbom.graph.has_edge(component.UUID, dependency.UUID, key="Uses")


def test_distinct_uuid_merge_still_remaps_incoming_relationships():
    component = Software(sha256="a" * 64)
    duplicate = Software(sha256=component.sha256)
    dependency = Software(sha256="b" * 64)
    sbom = SBOM(software=[component])
    incoming = SBOM(software=[duplicate, dependency])
    _add_relationship(incoming, duplicate, dependency)

    sbom.merge(incoming)

    assert len(sbom.software) == 2
    assert sbom.graph.has_edge(component.UUID, dependency.UUID, key="Uses")
    assert not sbom.graph.has_node(duplicate.UUID)
