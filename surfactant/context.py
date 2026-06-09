# Copyright 2026 Lawrence Livermore Natioanl Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from dataclasses import dataclass

# from inspect import getframeinfo, stack
from typing import Any

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

    extractPaths: list[str]
    archive: str | None = None
    installPrefix: str | None = None
    omitUnrecognizedTypes: bool | None = None
    includeFileExts: list[str] | None = None
    excludeFileExts: list[str] | None = None
    skipProcessingArchive: bool | None = False
    containerPrefix: str | None = None
    pluginConf: dict[str, Any] | None = None

    def get_pconf(self, name: str, conf_key: str, default: Any | None) -> Any | None:
        """
        Get the value of a plugin's configuration

        Args:
            name (str): The plugin to look for.  (Ex. surfactant.plugin.capa) Use __name__ if looking for a plugin's own configuration.
            conf_key (str): Configuration option to look for in the pluginConf dictionary.
            default (Optional[Any]): Default value to use if conf_key has no associated value
        """
        if not self.pluginConf:
            logger.debug(
                f"No plugin configuration present, using default value: {default} for {name}: {conf_key}"
            )
            return default
        if name not in self.pluginConf:
            logger.debug(
                f"No plugin configuration for {name}, using default value: {default} for {conf_key}"
            )
            return default
        module = self.pluginConf[name]
        if conf_key not in module:
            logger.debug(
                f"No plugin configuration for {name}: {conf_key}, using default value: {default}"
            )
            return default
        field = module[conf_key]
        return field
