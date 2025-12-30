import pathlib
from typing import Union


def normalize_path(*path_parts: Union[str, pathlib.PurePosixPath]) -> str:
    """
    Normalize one or more path parts into a single POSIX-style path string.

    This function ensures that Windows-style path separators ('\\') in string
    inputs are replaced with forward slashes ('/'), producing a consistent,
    POSIX-style representation. However, if any argument is already a
    ``pathlib.PurePath`` (such as a PurePosixPath), it is passed through
    unchanged — ensuring that literal backslashes within file or directory
    names are preserved.

    Args:
        *path_parts: One or more path components. Each may be a string
            (which will be normalized) or a PurePath object (which will be
            preserved as-is).

    Returns:
        str: A normalized POSIX-style path string (e.g., 'C:/Program Files/App').

    Examples:
        >>> normalize_path("C:\\Program Files\\App")
        'C:/Program Files/App'
        >>> normalize_path(PurePosixPath("foo\\bar"))
        'foo\\bar'
    """
    cleaned_parts = [
        # If this part is already a PurePath (e.g. PurePosixPath),
        # don't modify it — we assume it already uses the correct separators.
        # Otherwise, replace Windows backslashes in string inputs.
        p if isinstance(p, pathlib.PurePath) else str(p).replace("\\", "/")
        for p in path_parts
    ]

    # Join all parts into a single PurePosixPath, ensuring POSIX separators.
    # The resulting string will always use '/' as path delimiters.
    return pathlib.PurePosixPath(*cleaned_parts).as_posix()


def basename_posix(path: Union[str, pathlib.PurePath]) -> str:
    """
    Return the POSIX-style basename of a path. Never raises for string inputs.
    - Uses normalize_path for consistent slash handling.
    - Strips trailing slash for non-root paths so 'dir/' -> 'dir'.
    """
    s = normalize_path(path)  # ensures a POSIX string
    if s and s != "/":
        s = s.rstrip("/")  # keep '/' as-is; makes 'dir/' -> 'dir'
    # For strings, PurePosixPath(...).name returns:
    #   '' for '' / '.' / '/' ; 'dir' for 'dir' or 'dir/'
    return pathlib.PurePosixPath(s).name
