# Copyright 2026 Lawrence Livermore Natioanl Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass
from inspect import getframeinfo, stack
from typing import Any, Dict, List, Optional

from loguru import logger


@dataclass
# pylint: disable-next=too-many-instance-attributes
class ContextEntry:
    """
    Represents an entry in the processing queue for directories/files.

    Attributes:
        extractPaths (List[str]): The absolute or relative paths to the files or folders to gather information on.
            Note that Unix style '/' directory separators should be used in paths, even on Windows.
        archive (Optional[str]): The full path, including file name, of the archive file that the files or folders
            in `extractPaths` were extracted from. Used to collect metadata about the overall sample and establish
            "Contains" relationships.
        installPrefix (Optional[str]): The path where the files in `extractPaths` would be if installed
            correctly on an actual system. If not provided, `extractPaths` will be used as the install prefixes.
        omitUnrecognizedTypes (Optional[bool]): If True, files with unrecognized types will be omitted from the generated SBOM.
        includeFileExts (Optional[List[str]]): A list of file extensions to include, even if not recognized by Surfactant.
            `omitUnrecognizedTypes` must be set to True for this to take effect.
        excludeFileExts (Optional[List[str]]): A list of file extensions to exclude, even if recognized by Surfactant.
            If both `omitUnrecognizedTypes` and `includeFileExts` are set, the specified extensions in `includeFileExts`
            will still be included.
        skipProcessingArchive (Optional[bool]): If True, skip processing the given archive file with info extractors.
            Software entry for the archive file will only contain basic information such as hashes. Default is False.
        containerPrefix (Optional[str]): The prefix to use for the generated SBOM's containerPath.  Used to indicate that the
            `extractPaths` specified should map to a specific subfolder within the corresponding archive file.
        pluginConf (Optional[Dict[str, Any]]): Configuration information for specific plugins.
            See plugin docstrings or documentation for configuration details.
    """

    extractPaths: List[str]
    archive: Optional[str] = None
    installPrefix: Optional[str] = None
    omitUnrecognizedTypes: Optional[bool] = None
    includeFileExts: Optional[List[str]] = None
    excludeFileExts: Optional[List[str]] = None
    skipProcessingArchive: Optional[bool] = False
    containerPrefix: Optional[str] = None
    pluginConf: Optional[Dict[str, Any]] = None

    def get_pconf(self, name: str, conf_key: str, default: Optional[Any]) -> Optional[Any]:
        """
        Get the value of a plugin's configuration

        Args:
            name (str): The plugin to look for.  (Ex. surfactant.plugin.capa) Use __name__ if looking for a plugin's own configuration.
            conf_key (str): Configuration option to look for in the pluginConf dictionary.
            default (Optional[Any]): Default value to use if conf_key has no associated value
        """
        if not self.pluginConf:
            caller = getframeinfo(stack()[1][0])
            logger.trace(f"get_pconf() called from {caller.filename}:{caller.lineno}")
            logger.debug(
                f"No plugin configuration present, using default value: {default} for {name}: {conf_key}"
            )
            return default
        module = self.pluginConf[name]
        if not module:
            caller = getframeinfo(stack()[1][0])
            logger.trace(f"get_pconf() called from {caller.filename}:{caller.lineno}")
            logger.debug(
                f"No plugin configuration for {name}, using default value: {default} for {conf_key}"
            )
            return default
        field = module[conf_key]
        if not field:
            caller = getframeinfo(stack()[1][0])
            logger.trace(f"get_pconf() called from {caller.filename}:{caller.lineno}")
            logger.debug(
                f"No plugin configuration for {name}: {conf_key}, using default value: {default}"
            )
            return default
        return field
