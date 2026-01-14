from pathlib import PurePosixPath

from surfactant.utils.paths import normalize_path


def test_single_string_path():
    """Normalize a single Windows-style path string to POSIX format."""
    assert normalize_path("C:\\Program Files\\App") == "C:/Program Files/App"


def test_multiple_parts():
    """Join multiple path parts into a normalized POSIX-style path."""
    assert normalize_path("C:", "Program Files", "App") == "C:/Program Files/App"


def test_with_purepath():
    """Combine a PurePosixPath with a string part and normalize the result."""
    assert normalize_path(PurePosixPath("C:/Program Files"), "App") == "C:/Program Files/App"


def test_trailing_slash_is_preserved():
    """Strip trailing slashes from non-root POSIX paths."""
    assert normalize_path("C:/App/") == "C:/App"  # PosixPath strips trailing slashes


def test_empty_parts():
    """Normalize an empty string to the current directory ('.')."""
    assert normalize_path("") == "."


def test_pureposixpath_with_literal_backslash():
    """If given a PurePosixPath, a literal backslash should be preserved."""
    path = PurePosixPath("foo\\bar")  # backslash is part of the filename
    result = normalize_path(path)
    assert result == "foo\\bar"  # ensure it's not replaced with a forward slash


def test_pureposixpath_mixed_with_string():
    """When mixing a PurePosixPath and a string, only the string parts are cleaned."""
    path = PurePosixPath("foo\\bar")
    result = normalize_path(path, "baz\\qux")
    # The PurePosixPath part should keep its backslash, the string part should be normalized
    assert result == "foo\\bar/baz/qux"


def test_no_arguments_returns_dot():
    """normalize_path() with no arguments should return '.'"""
    assert normalize_path() == "."


def test_absolute_path_overrides_previous_parts():
    """Absolute path parts should override earlier parts, matching pathlib semantics."""
    assert normalize_path("/root", "/etc/passwd") == "/etc/passwd"


def test_redundant_slashes_are_collapsed():
    """Multiple slashes between parts should collapse into a single slash."""
    assert normalize_path("foo//bar", "baz") == "foo/bar/baz"


def test_dot_and_dotdot_not_resolved():
    """Relative navigation components should be preserved (no resolution)."""
    assert normalize_path("foo/../bar") == "foo/../bar"


def test_trailing_slash_in_middle_part_is_ignored():
    """Trailing slashes in intermediate parts should not affect joining."""
    assert normalize_path("foo/", "bar/") == "foo/bar"
