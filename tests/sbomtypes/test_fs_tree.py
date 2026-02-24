# pylint: disable=redefined-outer-name
import pytest

from surfactant.sbomtypes import SBOM, Software


@pytest.fixture
def software_entries():
    return [
        Software(UUID="uuid-1", installPath=["/usr/bin/ls"]),
        Software(UUID="uuid-2", installPath=["/usr/lib/libc.so"]),
        Software(UUID="uuid-3", installPath=["/opt/tools/bin/run"]),
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
    assert fs.nodes["/usr/bin/ls"]["software_uuid"] == "uuid-1"
    assert fs.nodes["/usr/lib/libc.so"]["software_uuid"] == "uuid-2"
    assert fs.nodes["/opt/tools/bin/run"]["software_uuid"] == "uuid-3"


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

    assert sw1.UUID == "uuid-1"
    assert sw2.UUID == "uuid-3"
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
    win_sw = Software(UUID="uuid-win", installPath=[r"C:\Tools\bin\run.exe"])
    sbom.add_software(win_sw)

    # Node should exist using POSIX-normalized form
    assert sbom.fs_tree.has_node("C:/Tools/bin/run.exe")
    # Lookup should work with either style
    assert sbom.get_software_by_path(r"C:\Tools\bin\run.exe").UUID == "uuid-win"
    assert sbom.get_software_by_path("C:/Tools/bin/run.exe").UUID == "uuid-win"


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
    target = Software(UUID="uuid-libc", installPath=["/usr/lib/libc.so.6"])
    sbom.add_software(target)

    # Single-hop alias
    sbom.record_symlink("/lib/libc.so.6", "/usr/lib/libc.so.6", subtype="file")
    assert sbom.get_software_by_path("/lib/libc.so.6").UUID == "uuid-libc"

    # Multi-hop alias
    sbom.record_symlink("/lib/libc.so", "/lib/libc.so.6", subtype="file")
    assert sbom.get_software_by_path("/lib/libc.so").UUID == "uuid-libc"


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
    sbom.record_symlink("/a", "/b", subtype="file")
    sbom.record_symlink("/b", "/a", subtype="file")
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
    sw = Software(UUID="uuid-1", installPath=["/usr/bin/ls"])
    sbom.add_software(sw)

    sbom.record_symlink("/bin/ls", "/usr/bin/ls", subtype="file")
    data = sbom.to_dict_override()

    assert "graph" not in data and "fs_tree" not in data
    for rel in data.get("relationships", []):
        assert rel["xUUID"] != "/bin/ls" and rel["yUUID"] != "/usr/bin/ls"


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
        UUID="uuid-libzmq",
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
    assert sbom.get_software_by_path("/usr/lib64/libzmq.so.5.2.6").UUID == "uuid-libzmq"

    # Serialize to JSON and deserialize (simulating save/load cycle)
    json_str = sbom.to_json()
    sbom_restored = SBOM.from_json(json_str)

    # Critical test: symlink paths should resolve after deserialization
    # These should work because _rebuild_fs_tree_from_metadata() reconstructs the edges
    assert sbom_restored.get_software_by_path("/usr/lib64/libzmq.so.5.2.6").UUID == "uuid-libzmq"
    assert sbom_restored.get_software_by_path("/usr/lib64/libzmq.so").UUID == "uuid-libzmq"
    assert sbom_restored.get_software_by_path("/usr/lib64/libzmq.so.5").UUID == "uuid-libzmq"

    # Verify fs_tree has the symlink edges
    assert sbom_restored.fs_tree.has_node("/usr/lib64/libzmq.so")
    assert sbom_restored.fs_tree.has_node("/usr/lib64/libzmq.so.5")
    assert sbom_restored.fs_tree.has_edge("/usr/lib64/libzmq.so", "/usr/lib64/libzmq.so.5.2.6")
    assert sbom_restored.fs_tree.has_edge("/usr/lib64/libzmq.so.5", "/usr/lib64/libzmq.so.5.2.6")
