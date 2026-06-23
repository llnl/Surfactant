# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import requests
from loguru import logger
import zipfile
import io
import pathlib

import surfactant.plugin
from surfactant.sbomtypes import SBOM, NameEntry, Relationship, Software


class __NuGetManager:
    def __init__(self):
        self.disabled = True
        self.package_base_addresses = []

    def init_urls(self):
        # Get the base PackageBaseAddress URL
        r = requests.get("https://api.nuget.org/v3/index.json")
        if r.status_code != 200:
            logger.warning(f"NuGet API returned {r.status_code}; disabling")
            self.disabled = True
            return

        self.disabled = False
        self.package_base_addresses = [
            x["@id"] for x in r.json()["resources"] if x["@type"] == "PackageBaseAddress/3.0.0"
        ]
        # remove trailing "/" if present
        for i, pba in enumerate(self.package_base_addresses):
            if pba[-1] == "/":
                self.package_base_addresses[i] = pba[:-1]

    def download_nuget(self, package_name: str, package_version: str) -> zipfile.ZipFile | None:
        for url in self.package_base_addresses:
            pn_low = package_name.lower()
            ver_low = package_version.lower()
            r = requests.get(f"{url}/{pn_low}/{ver_low}/{pn_low}.{ver_low}.nupkg", stream=True)
            if r.status_code != 200:
                continue
            try:
                # For some reason, have to wrap r.raw (a file-like object)
                # into an io.BytesIO object to get it to read correctly.
                # No idea why.
                return zipfile.ZipFile(io.BytesIO(r.raw.read()))
            except zipfile.BadZipFile as e:
                logger.warning(f"Could not unpack {pn_low}.{ver_low}.nupkg - {e}")
        return None

    def file_is_in_package(self, file_name: str, package_name: str, package_version: str) -> bool:
        if nuget := self.download_nuget(package_name, package_version):
            for f in nuget.infolist():
                if pathlib.Path(f.filename).name == file_name:
                    return True
        return False

    def get_package_url(self, file_name: str, package_name: str, package_version: str) -> str | None:
        if self.disabled:
            return None

        for url in self.package_base_addresses:
            r = requests.get(f"{url}/{package_name.lower()}/index.json")
            if r.status_code != 200:
                continue

            if versions := r.json()["versions"]:
                if package_version in versions:
                    # Found a matching package version, check that specific version
                    if self.file_is_in_package(file_name, package_name, package_version):
                        return f"pkg:nuget/{package_name}@{package_version}"
                else:
                    # Unknown package version; check the latest package version
                    latest_version = versions[-1]
                    if self.file_is_in_package(file_name, package_name, latest_version):
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
        if software.fileName:
            for name in software.fileName:
                if purl := __nuget.get_package_url(name, dna["Name"], dna["Version"]):
                    if software.name is None:
                        software.name = []
                    software.name.append(NameEntry(purl, "PURL"))
