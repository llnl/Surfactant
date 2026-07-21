# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

"""
Config Options:
    enable_lookups(bool):
        Enable NuGet network requests, default is False.
"""

# Don't have this as a configuration until the TUI supports int/float
# request_timeout(int):
#     Time to wait for a NuGet network response in seconds, default is 30.

import io
import pathlib
import zipfile

import requests
from loguru import logger

import surfactant.plugin
from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes import SBOM, NameEntry, Relationship, Software


class _NuGetManager:
    def __init__(self):
        self.disabled = True
        self.package_base_addresses = []

        # self.request_timeout = float(ConfigManager().get("nuget", "request_timeout", 30.0))
        self.request_timeout = 30

        # package_name.lower() -> version list, or None if the package wasn't
        # found. None is cached to avoid re-querying misses.
        self._index_cache: dict[str, list[str] | None] = {}

        # (package_name.lower(), version.lower()) -> set of nupkg member basenames.
        # An empty set means download failed/not found; cached so the same
        # nupkg is never re-downloaded during an enrichment pass.
        self._members_cache: dict[tuple[str, str], set[str]] = {}

    def init_urls(self):
        # Get the base PackageBaseAddress URL
        try:
            r = requests.get("https://api.nuget.org/v3/index.json", timeout=self.request_timeout)
            r.raise_for_status()
            resources = r.json()["resources"]
        except (requests.RequestException, ValueError, KeyError) as e:
            logger.warning(f"NuGet API unavailable ({e}); disabling NuGet lookups")
            self.disabled = True
            return

        self.disabled = False
        self.package_base_addresses = [
            x["@id"] for x in resources if x["@type"] == "PackageBaseAddress/3.0.0"
        ]
        # remove trailing "/" if present
        for i, pba in enumerate(self.package_base_addresses):
            if pba[-1] == "/":
                self.package_base_addresses[i] = pba[:-1]

    def download_nuget(self, package_name: str, package_version: str) -> zipfile.ZipFile | None:
        pn_low = package_name.lower()
        ver_low = package_version.lower()
        for url in self.package_base_addresses:
            try:
                r = requests.get(
                    f"{url}/{pn_low}/{ver_low}/{pn_low}.{ver_low}.nupkg",
                    stream=True,
                    timeout=self.request_timeout,
                )
            except requests.RequestException as e:
                logger.warning(f"NuGet download failed for {pn_low}.{ver_low}.nupkg - {e}")
                continue
            if r.status_code != 200:
                continue
            try:
                return zipfile.ZipFile(io.BytesIO(r.raw.read()))
            except zipfile.BadZipFile as e:
                logger.warning(f"Could not unpack {pn_low}.{ver_low}.nupkg - {e}")
        return None

    def file_is_in_package(self, file_name: str, package_name: str, package_version: str) -> bool:
        key = (package_name.lower(), package_version.lower())
        if key not in self._members_cache:
            members: set[str] = set()
            if nuget := self.download_nuget(package_name, package_version):
                members = {pathlib.Path(f.filename).name.lower() for f in nuget.infolist()}
            # Cache even an empty set so a failed/missing download isn't retried.
            self._members_cache[key] = members
        return file_name.lower() in self._members_cache[key]

    def _get_versions(self, package_name: str) -> list[str] | None:
        """Returns a package's version list, caching the result.

        Queries each PackageBaseAddress until one serves the package's
        index.json. The result - including a negative None - is cached per
        package name, so repeated files from the same package cost one request.
        """
        key = package_name.lower()
        if key in self._index_cache:
            return self._index_cache[key]

        versions: list[str] | None = None
        for url in self.package_base_addresses:
            try:
                r = requests.get(f"{url}/{key}/index.json", timeout=self.request_timeout)
                if r.status_code != 200:
                    continue

                versions = r.json().get("versions") or None
            except (requests.RequestException, ValueError) as e:
                logger.warning(f"NuGet index lookup failed for {key} - {e}")
                continue

            if versions:
                break

        self._index_cache[key] = versions
        return versions

    def get_package_url(
        self, file_name: str, package_name: str, package_version: str | list[str]
    ) -> str | None:
        if self.disabled:
            return None

        if package_name is None:
            return None

        versions = self._get_versions(package_name)
        if not versions:
            return None

        if isinstance(package_version, str):
            candidate_versions = [package_version]
        else:
            candidate_versions = package_version

        if found_version := next((v for v in candidate_versions if v in versions), None):
            # Found a matching package version, check that specific version
            if self.file_is_in_package(file_name, package_name, found_version):
                return f"pkg:nuget/{package_name}@{found_version}"
        else:
            # Unknown package version; check the latest stable package version if available
            stable = [v for v in versions if "-" not in v] or versions
            latest_version = stable[-1]
            if self.file_is_in_package(file_name, package_name, latest_version):
                return f"pkg:nuget/{package_name}"

        return None


_nuget = _NuGetManager()


@surfactant.plugin.hookimpl
def init_hook(command_name: str | None = None):
    if command_name != "generate":
        return

    if not ConfigManager().get("nuget", "enable_lookups", False):
        logger.info("[nuget_purl] NuGet lookups disabled via config (nuget.enable_lookups=false)")
        _nuget.disabled = True
        return

    _nuget.init_urls()


@surfactant.plugin.hookimpl
def establish_relationships(sbom: SBOM, software: Software, metadata) -> list[Relationship] | None:
    """Checks NuGet for a package name and adds it as a name if it exists"""

    if _nuget.disabled:
        return

    if not isinstance(metadata, dict) or "dotnetAssembly" not in metadata:
        logger.debug(
            f"[nuget_purl] Skipping: No dotnetAssembly info for NuGet PURL in {software.UUID}"
        )
        return

    # From real samples, found that "FileInfo" "ProductVersion" is often better than "dotnetAssembly"
    # "Version" values (could search for that as a fallback if desired); ideal might be to have an
    # option to turn "ProductName" file info field into a NuGet package name
    fi = metadata.get("FileInfo", {})
    product_version = fi.get("ProductVersion", "").split('+', 1)[0]
    for dna in metadata.get("dotnetAssembly"):
        if software.fileName:
            for name in software.fileName:
                if purl := _nuget.get_package_url(name, dna.get("Name"), product_version):
                    if software.name is None:
                        software.name = []
                    software.name.append(NameEntry(purl, "package URL (purl)"))


@surfactant.plugin.hookimpl
def settings_name() -> str | None:
    return "nuget"
