# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

"""
Config Options:
    enable_docker_scout(bool): Enable Docker Scout, default is True.
"""

import gzip
import json
import subprocess
import tempfile

from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, Software


class DockerScoutManager:
    def __init__(self) -> None:
        # Initialize ConfigManager
        config_manager = ConfigManager()

        # Retrieve the configuration option
        enable_docker_scout = config_manager.get("docker", "enable_docker_scout", True)

        # Set disable_docker_scout based on the configuration
        self.disable_docker_scout = not enable_docker_scout
        self.docker_scout_installed = False

    def check_docker_scout_installed(self) -> None:
        """Check if Docker Scout is installed and update the state accordingly."""
        if self.disable_docker_scout:
            return  # Do nothing if Docker Scout is disabled by config

        try:
            result = subprocess.run(["docker", "scout"], capture_output=True, check=False)
            self.docker_scout_installed = result.returncode == 0
        except FileNotFoundError:
            self.docker_scout_installed = False

        self.disable_docker_scout = not self.docker_scout_installed
        if not self.docker_scout_installed:
            logger.warning(
                "Install Docker Scout to scan containers for additional information. "
                "You can also disable this check by running 'surfactant config docker.enable_docker_scout false'."
            )

    def run_docker_scout(self, filename: str) -> object:
        """Run Docker Scout on the given file and return the results."""
        if self.disable_docker_scout:
            return {}  # Do nothing if Docker Scout is disabled by config

        try:
            result = subprocess.run(
                ["docker", "scout", "sbom", "--format", "spdx", f"fs://{filename}"],
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                logger.warning(f"Running Docker Scout on {filename} failed")
                return {}
            spdx_out = json.loads(result.stdout)
            return {"dockerSPDX": spdx_out}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Docker Scout output for {filename}: {e}")
            return {}


# Initialize DockerScoutManager to check installation status
dsManager = DockerScoutManager()


def supports_file(filetype: list[str]) -> bool:
    """Check if the file type is supported."""
    if "DOCKER_TAR" in filetype or "DOCKER_GZIP" in filetype:
        return True
    return False


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    """Extract file information using Docker Scout if supported."""
    if dsManager.disable_docker_scout or not supports_file(filetype):
        return None
    return extract_docker_info(filetype, filename)


def extract_docker_info(filetype: list[str], filename: str) -> object:
    """Extract Docker information based on file type."""
    if "DOCKER_GZIP" in filetype:
        with open(filename, "rb") as gzip_in:
            gzip_data = gzip_in.read()
        with tempfile.NamedTemporaryFile() as gzip_out:
            gzip_out.write(gzip.decompress(gzip_data))
            gzip_out.flush()  # Ensure data is written before reading
            return dsManager.run_docker_scout(gzip_out.name)
    return dsManager.run_docker_scout(filename)


@surfactant.plugin.hookimpl
def init_hook(command_name: str | None = None) -> None:
    if command_name != "update-db" and not dsManager.disable_docker_scout:
        dsManager.check_docker_scout_installed()


@surfactant.plugin.hookimpl
def settings_name() -> str | None:
    return "docker"
