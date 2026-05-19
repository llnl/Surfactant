# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import pathlib


def posix_normpath(path: str) -> pathlib.PurePosixPath:
    """Normalize a path to a POSIX path, with '..' path components removing the previous directory.
    This is similar to os.path.normpath, but it also removes leading '..' path components for relative
    paths. Note that symlinks are not followed, so in some cases the result may not be a valid path on
    the local filesystem. For example, posix_normpath("/a/b/../c") == "/a/c", but if "/a/b" is a symlink
    to "/x/y", then "/a/c" is not a valid path on the local filesystem. Future work could add an option
    to track symlinks encountered in order to resolve them."""
    posix_path = pathlib.PurePosixPath(path)

    # Remove '..' path component and preceding path component
    # PurePosixPath.parts is a tuple, so we can't modify it in-place
    parts = list(posix_path.parts)
    i = 0
    while i < len(parts):
        if parts[i] == "..":
            del parts[i]
            if i > 1 or (i > 0 and parts[0] not in ("//", "/")):
                del parts[i - 1]
                i -= 1
        else:
            i += 1
    return pathlib.PurePosixPath(*parts)
