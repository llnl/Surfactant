# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import pathlib
from collections.abc import Iterable
from typing import Any, List, Union

from surfactant.sbomtypes import SBOM, Software


# return all matching dotnet assemblies or DLLs that could be loaded on Windows
# TODO: an intermediate file format should keep files in different places but matching hashes separate until
# relationships are established; this would make so we can use .NET metadata about versions, strong names, etc
# and not accidentally mix and match cultures/app config info that could differ for different copies of the same
# file (due to app config files pointing to different assemblies despite DLL having same hash)
# culture information to find the right assembly from app config file is likely to vary (though almost always neutral/none)
def find_installed_software(
    sbom: SBOM, probedirs: List[Any], filename: Union[str, List[str]]
) -> List[Software]:
    possible_matches = []
    # iterate through all sbom entries
    for e in sbom.software:
        # Skip if no install path (e.g. installer/temporary file)
        if e.installPath is None:
            continue
        for pdir in probedirs:
            if isinstance(filename, str):
                filename = [filename]
            for fname in filename:
                # installPath contains full path+filename, so check for all combinations of probedirs+filename
                pfile = pathlib.PureWindowsPath(pdir, fname)
                if isinstance(e.installPath, Iterable):
                    for ifile in e.installPath:
                        # PureWindowsPath is case-insensitive for file/directory names
                        if pfile == pathlib.PureWindowsPath(ifile):
                            # matching probe directory and filename, add software to list
                            possible_matches.append(e)
    return possible_matches


# construct a list of directories to probe for establishing dotnet relationships
def get_dotnet_probedirs(software: Software, refCulture, refName, dnProbingPaths):
    probedirs = []
    # probe for the referenced assemblies
    if isinstance(software.installPath, Iterable):
        for install_filepath in software.installPath:
            install_basepath = pathlib.PureWindowsPath(install_filepath).parent.as_posix()
            if refCulture is None or refCulture == "":
                # [application base] / [assembly name].dll
                # [application base] / [assembly name] / [assembly name].dll
                probedirs.append(pathlib.PureWindowsPath(install_basepath).as_posix())
                probedirs.append(pathlib.PureWindowsPath(install_basepath, refName).as_posix())
                if dnProbingPaths is not None:
                    # add probing private paths
                    for path in dnProbingPaths:
                        # [application base] / [binpath] / [assembly name].dll
                        # [application base] / [binpath] / [assembly name] / [assembly name].dll
                        probedirs.append(pathlib.PureWindowsPath(install_basepath, path).as_posix())
                        probedirs.append(
                            pathlib.PureWindowsPath(install_basepath, path, refName).as_posix()
                        )
            else:
                # [application base] / [culture] / [assembly name].dll
                # [application base] / [culture] / [assembly name] / [assembly name].dll
                probedirs.append(pathlib.PureWindowsPath(install_basepath, refCulture).as_posix())
                probedirs.append(
                    pathlib.PureWindowsPath(install_basepath, refName, refCulture).as_posix()
                )
                if dnProbingPaths is not None:
                    # add probing private paths
                    for path in dnProbingPaths:
                        # [application base] / [binpath] / [culture] / [assembly name].dll
                        # [application base] / [binpath] / [culture] / [assembly name] / [assembly name].dll
                        probedirs.append(
                            pathlib.PureWindowsPath(install_basepath, path, refCulture).as_posix()
                        )
                        probedirs.append(
                            pathlib.PureWindowsPath(
                                install_basepath, path, refName, refCulture
                            ).as_posix()
                        )
    return probedirs
