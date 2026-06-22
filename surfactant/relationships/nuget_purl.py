# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import requests
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, NameEntry, Relationship, Software


class __NuGetManager:
    def __init__(self):
        self.disabled = True
        self.package_base_address = []

    def init_urls(self):
        # Get the base PackageBaseAddress URL
        r = requests.get("https://api.nuget.org/v3/index.json")
        if r.status_code != 200:
            logger.warning(f"NuGet API returned {r.status_code}; disabling")
            self.disabled = True
            return

        self.disabled = False
        self.package_base_address = [
            x["@id"] for x in r.json()["resources"] if x["@type"] == "PackageBaseAddress/3.0.0"
        ]
        # remove trailing "/" if present
        for i, pba in enumerate(self.package_base_address):
            if pba[-1] == "/":
                self.package_base_address[i] = pba[:-1]

    def get_package_url(self, package_name: str, package_version: str) -> str | None:
        if self.disabled:
            return None

        for url in self.package_base_address:
            r = requests.get(f"{url}/{package_name.lower()}/index.json")
            if r.status_code != 200:
                continue

            if versions := r.json()["versions"]:
                if package_version in versions:
                    # Found a matching package version, so include it
                    return f"pkg:nuget/{package_name}@{package_version}"
                # Unknown package version; exclude the version
                return f"pkg:nuget/{package_name}"

        return None


__nuget = __NuGetManager()


@surfactant.plugin.hookimpl
def init_hook(command_name: str | None = None):
    __nuget.init_urls()


@surfactant.plugin.hookimpl
def establish_relationships(sbom: SBOM, software: Software, metadata) -> list[Relationship] | None:
    """Checks NuGet for a package name and adds it as a name if it exists"""

    if __nuget.disabled:
        return

    if "dotnetAssembly" not in metadata:
        logger.debug(
            f"[nuget_purl] Skipping: No dotnetAssembly info for NuGet PURL in {software.UUID}"
        )
        return

    for dna in metadata["dotnetAssembly"]:
        if purl := __nuget.get_package_url(dna["Name"], dna["Version"]):
            if software.name is None:
                software.name = []
            software.name.append(NameEntry(purl, "PURL"))
