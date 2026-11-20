# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
import os
import pathlib

import click


# pylint: disable=too-few-public-methods
class SpecimenContextParamType(click.Path):
    """
    A custom Click parameter type for handling specimen context paths.
    This class extends `click.Path` to provide additional functionality for
    handling different types of context paths, including files, directories,
    and JSON context configuration files.
    Attributes:
        name (str): The name of the parameter type, set to "context".
    Methods:
        convert(value, param, ctx):
            Converts the input value based on its prefix and returns the appropriate
            context data. Supports the following prefixes:
            - "file:" for file paths
            - "dir:" for directory paths
            - "context:" for JSON context configuration files
            If no prefix is provided, it attempts to determine if the value is a file
            and loads it as JSON if possible. Otherwise, it treats the value as a
            directory path.
    """

    name = "specimen_context"

    @staticmethod
    def _get_param_type(filename: str):
        """Determines the type and properties of a parameter based on its filename prefix.
        Args:
            filename (str): The filename string to analyze, optionally with a type prefix
        Returns:
            tuple: A 3-tuple containing:
                - str: The parameter type ('FILE', 'DIR', 'CONTEXT', or '' for default)
                - Path: The filepath as a Path object
                - Path or None: The install prefix path (for files), directory path (for dirs),
                  or None (for context or default)
        """

        if filename.startswith("file:"):
            filepath = pathlib.Path(filename[5:])
            return "FILE", filepath, filepath.parent
        if filename.startswith("dir:"):
            filepath = pathlib.Path(filename[4:])
            return "DIR", filepath, filepath
        if filename.startswith("context:"):
            filepath = pathlib.Path(filename[7:])
            return "CONTEXT", filepath, None
        return "", pathlib.Path(filename), None

    def convert(self, value, param, ctx):
        # value received may already be the right type
        if isinstance(value, list):
            return value

        param_type, filepath, installprefix = self._get_param_type(value)

        # validate filepath exists and is readable
        if not filepath.exists():
            self.fail(f"{value!r} does not exist", param, ctx)
        if not os.access(filepath, os.R_OK):
            self.fail(f"{value!r} is not readable", param, ctx)

        # no explicit type given, use heuristics to determine correct type
        if not param_type:
            # if it's a file (that ends in .json) then treat it as a CONTEXT file
            # if it's not a file then probably a directory (or something odd...)
            if filepath.is_file():
                if filepath.suffix.lower() == ".json":
                    param_type = "CONTEXT"
                else:
                    param_type = "FILE"
                    installprefix = filepath.parent
            else:
                param_type = "DIR"
                installprefix = filepath

        if param_type in ("FILE", "DIR"):
            # avoid a relative directory of "./" as the install prefix
            if not installprefix.is_absolute() and len(installprefix.parts) == 0:
                installprefix = ""
            else:
                installprefix = installprefix.as_posix()
            # emulate a context configuration file with the given path
            context = [{"extractPaths": [filepath.as_posix()], "installPrefix": installprefix}]
        elif param_type == "CONTEXT":
            with click.open_file(filepath) as f:
                try:
                    context = json.load(f)
                except json.decoder.JSONDecodeError as err:
                    self.fail(
                        f"{filepath.as_posix()!r} context file contains invalid JSON", param, ctx
                    )

                for entry in context:
                    if "extractPaths" not in entry:
                        self.fail(f"missing extractPaths in context file entry: {entry}")
                    extract_path = entry["extractPaths"]
                    for pth in extract_path:
                        extract_path_convert = pathlib.Path(pth)
                        if not extract_path_convert.exists():
                            self.fail(f"invalid extract path in context file: {pth}", param, ctx)
                    if "archive" in entry:
                        archive_path = pathlib.Path(entry["archive"])
                        if not archive_path.exists():
                            self.fail(f"invalid archive path in context file: {entry['archive']}")
        else:
            self.fail(f"{value!r} is not a valid specimen context type", param, ctx)

        return context
