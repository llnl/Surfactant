# pylint: disable=redefined-outer-name
import pytest

from surfactant.sbomtypes import SBOM, Software

UUID_LS = "11111111-1111-4111-8111-111111111111"
UUID_LIBC = "22222222-2222-4222-8222-222222222222"
UUID_RUN = "33333333-3333-4333-8333-333333333333"
UUID_WIN = "44444444-4444-4444-8444-444444444444"
UUID_LIBZMQ = "55555555-5555-4555-8555-555555555555"
UUID_REL_DST = "66666666-6666-4666-8666-666666666666"


@pytest.fixture
def software_entries():
    return [
        Software(UUID=UUID_LS, installPath=["/usr/bin/ls"], sha256="a" * 64),
        Software(UUID=UUID_LIBC, installPath=["/usr/lib/libc.so"], sha256="b" * 64),
        Software(UUID=UUID_RUN, installPath=["/opt/tools/bin/run"], sha256="c" * 64),
    ]


def test_fs_tree_population(software_entries):
    """
    Verify that SBOM._add_software_to_fs_tree() builds the filesystem tree correctly.

    Expectations:
      - Each installPath is normalized and inserted into fs_tree.
      - All intermediate directory nodes are created (e.g., /usr, /usr/bin).
      - Edges reflect parent->child directory hierarchy.
      - Leaf nodes (final installPath) are tagged with the correct software_uuid.
    """
    sbom = SBOM()
    for sw in software_entries:
        sbom.add_software(sw)  # triggers _add_software_to_fs_tree()
    fs = sbom.fs_tree

    # Check that expected nodes exist
    assert fs.has_node("/usr")
    assert fs.has_node("/usr/bin")
    assert fs.has_node("/usr/bin/ls")
    assert fs.has_node("/usr/lib/libc.so")
    assert fs.has_node("/opt/tools/bin/run")

    # Check that edges reflect directory hierarchy
    assert fs.has_edge("/usr", "/usr/bin")
    assert fs.has_edge("/usr/bin", "/usr/bin/ls")
    assert fs.has_edge("/usr/lib", "/usr/lib/libc.so")
    assert fs.has_edge("/opt", "/opt/tools")
    assert fs.has_edge("/opt/tools/bin", "/opt/tools/bin/run")

    # Check software UUID tagging
    assert fs.nodes["/usr/bin/ls"]["software_uuid"] == UUID_LS
    assert fs.nodes["/usr/lib/libc.so"]["software_uuid"] == UUID_LIBC
    assert fs.nodes["/opt/tools/bin/run"]["software_uuid"] == UUID_RUN


def test_get_software_by_path(software_entries):
    """
    Verify SBOM.get_software_by_path() returns the correct Software object.

    Expectations:
      - For a valid installPath, it returns the matching Software (by UUID).
      - For a missing path, it returns None.
      - Normalization ensures consistent lookups (tested separately).
    """
    sbom = SBOM()
    for sw in software_entries:
        sbom.add_software(sw)

    sw1 = sbom.get_software_by_path("/usr/bin/ls")
    sw2 = sbom.get_software_by_path("/opt/tools/bin/run")
    sw_invalid = sbom.get_software_by_path("/nonexistent")

    assert sw1.UUID == UUID_LS
    assert sw2.UUID == UUID_RUN
    assert sw_invalid is None


def test_fs_tree_windows_normalization():
    r"""
    Ensure Windows-style paths are normalized into POSIX form in fs_tree.

    Behavior:
      - SBOM.add_software() converts r"C:\Tools\bin\run.exe" to "C:/Tools/bin/run.exe".
      - get_software_by_path() should resolve with either Windows-style backslashes
        or normalized POSIX-style slashes.
    """
    sbom = SBOM()
    win_sw = Software(
        UUID=UUID_WIN,
        installPath=[r"C:\Tools\bin\run.exe"],
        sha256="d" * 64,
    )
    sbom.add_software(win_sw)

    # Node should exist using POSIX-normalized form
    assert sbom.fs_tree.has_node("C:/Tools/bin/run.exe")
    # Lookup should work with either style
    assert sbom.get_software_by_path(r"C:\Tools\bin\run.exe").UUID == UUID_WIN
    assert sbom.get_software_by_path("C:/Tools/bin/run.exe").UUID == UUID_WIN


def test_get_software_by_path_symlink_traversal():
    """
    Verify get_software_by_path() can resolve symlinks in fs_tree.

    Cases:
      - Single-hop alias: /lib/libc.so.6 -> /usr/lib/libc.so.6
      - Multi-hop alias:  /lib/libc.so -> /lib/libc.so.6 -> /usr/lib/libc.so.6

    Expected:
      - Both /lib/libc.so.6 and /lib/libc.so resolve to the target Software at
        /usr/lib/libc.so.6.
    """
    sbom = SBOM()
    target = Software(
        UUID=UUID_LIBC,
        installPath=["/usr/lib/libc.so.6"],
        sha256="e" * 64,
    )
    sbom.add_software(target)

    # Single-hop alias
    sbom.record_symlink("/lib/libc.so.6", "/usr/lib/libc.so.6", subtype="file")
    assert sbom.get_software_by_path("/lib/libc.so.6").UUID == UUID_LIBC

    # Multi-hop alias
    sbom.record_symlink("/lib/libc.so", "/lib/libc.so.6", subtype="file")
    assert sbom.get_software_by_path("/lib/libc.so").UUID == UUID_LIBC


def test_get_software_by_path_symlink_cycle_guard():
    """
    Ensure symlink cycles do not cause infinite loops.

    Case:
      - /a -> /b
      - /b -> /a
      - Neither node has a software_uuid tag.

    Expected:
      - get_software_by_path("/a") returns None gracefully without recursion errors.
    """
    sbom = SBOM()

    # Pre-create both nodes so file symlinks are recorded immediately rather than
    # deferred into _pending_file_links.
    sbom.fs_tree.add_node("/a")
    sbom.fs_tree.add_node("/b")

    sbom.record_symlink("/a", "/b", subtype="file")
    sbom.record_symlink("/b", "/a", subtype="file")

    assert sbom.fs_tree.has_edge("/a", "/b")
    assert sbom.fs_tree.has_edge("/b", "/a")
    assert sbom.get_software_by_path("/a") is None


def test_to_dict_override_filters_path_edges():
    """
    Confirm that to_dict_override() excludes filesystem-only edges.

    Steps:
      - Add a Software with installPath=/usr/bin/ls.
      - Record a symlink /bin/ls -> /usr/bin/ls (creates Path nodes and symlink edge).
      - Call to_dict_override().

    Expected:
      - 'graph' and 'fs_tree' internals are absent from the output dict.
      - No relationship entries involve '/bin/ls' or '/usr/bin/ls' path nodes.
    """
    sbom = SBOM()
    sw = Software(UUID=UUID_LS, installPath=["/usr/bin/ls"], sha256="f" * 64)
    sbom.add_software(sw)

    sbom.record_symlink("/bin/ls", "/usr/bin/ls", subtype="file")
    data = sbom.to_dict_override()

    assert "graph" not in data and "fs_tree" not in data
    assert data["relationships"] == []


def test_create_relationship_invalid_uuid_does_not_mutate_graph():
    """
    Ensure invalid relationship UUIDs are rejected before the graph is mutated.
    """
    sbom = SBOM()
    initial_node_count = sbom.graph.number_of_nodes()
    initial_edge_count = sbom.graph.number_of_edges()

    with pytest.raises(ValueError):
        sbom.create_relationship("not-a-uuid", UUID_REL_DST, "Contains")

    assert sbom.graph.number_of_nodes() == initial_node_count
    assert sbom.graph.number_of_edges() == initial_edge_count
    assert not sbom.graph.has_node("not-a-uuid")
    assert not sbom.graph.has_node(UUID_REL_DST)


def test_expand_pending_dir_symlinks_creates_chained_edges(tmp_path):
    """
    Verify that expand_pending_dir_symlinks() synthesizes one-hop chained edges
    for deferred directory symlinks.

    Scenario:
        dirE/link_to_F -> dirF
        dirF/runthat    -> /bin/echo

    Expected:
        After expansion, fs_tree contains:
        /dirE/link_to_F/runthat -> /dirF/runthat
    """
    sbom = SBOM()

    # Create base structure
    sbom.fs_tree.add_edge("/usr/bin", "/usr/bin/dirE")
    sbom.fs_tree.add_edge("/usr/bin", "/usr/bin/dirF")
    sbom.fs_tree.add_edge("/usr/bin/dirF", "/usr/bin/dirF/runthat")

    # Record directory symlink (deferred expansion)
    sbom.record_symlink("/usr/bin/dirE/link_to_F", "/usr/bin/dirF", subtype="directory")

    # Expand queued directory symlinks
    sbom.expand_pending_dir_symlinks()

    # Verify synthetic chained edge was created
    assert sbom.fs_tree.has_edge("/usr/bin/dirE/link_to_F/runthat", "/usr/bin/dirF/runthat")


def test_fs_tree_reconstruction_from_metadata():
    """
    Verify that fs_tree symlink edges are reconstructed from metadata after deserialization.

    Scenario:
        1. Create SBOM with software and symlinks
        2. Inject symlink metadata (simulating serialization prep)
        3. Serialize to JSON and deserialize
        4. Verify get_software_by_path() works with symlinks post-deserialization

    This tests the fix for the issue where SBOMs loaded from JSON lost all
    symlink edges because fs_tree is excluded from serialization.
    """
    # Create SBOM with a library and its symlink aliases
    sbom = SBOM()
    lib = Software(
        UUID=UUID_LIBZMQ,
        fileName=["libzmq.so.5.2.6"],
        installPath=["/usr/lib64/libzmq.so.5.2.6"],
        sha256="abc123def456",
    )
    sbom.add_software(lib)

    # Manually add installPathSymlinks metadata (normally done by inject_symlink_metadata)
    lib.metadata = [
        {"fileNameSymlinks": ["libzmq.so", "libzmq.so.5"]},
        {"installPathSymlinks": ["/usr/lib64/libzmq.so", "/usr/lib64/libzmq.so.5"]},
    ]

    # Verify direct lookup works before serialization
    assert sbom.get_software_by_path("/usr/lib64/libzmq.so.5.2.6").UUID == UUID_LIBZMQ

    # Serialize to JSON and deserialize (simulating save/load cycle)
    json_str = sbom.to_json()
    sbom_restored = SBOM.from_json(json_str)

    # Critical test: symlink paths should resolve after deserialization
    # These should work because _rebuild_fs_tree_from_metadata() reconstructs the edges
    assert sbom_restored.get_software_by_path("/usr/lib64/libzmq.so.5.2.6").UUID == UUID_LIBZMQ
    assert sbom_restored.get_software_by_path("/usr/lib64/libzmq.so").UUID == UUID_LIBZMQ
    assert sbom_restored.get_software_by_path("/usr/lib64/libzmq.so.5").UUID == UUID_LIBZMQ

    # Verify fs_tree has the symlink edges
    assert sbom_restored.fs_tree.has_node("/usr/lib64/libzmq.so")
    assert sbom_restored.fs_tree.has_node("/usr/lib64/libzmq.so.5")
    assert sbom_restored.fs_tree.has_edge("/usr/lib64/libzmq.so", "/usr/lib64/libzmq.so.5.2.6")
    assert sbom_restored.fs_tree.has_edge("/usr/lib64/libzmq.so.5", "/usr/lib64/libzmq.so.5.2.6")
