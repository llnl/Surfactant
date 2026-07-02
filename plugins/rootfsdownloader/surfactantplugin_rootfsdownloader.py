# Copyright 2026 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

# Currently using Ubuntu downloads at: https://partner-images.canonical.com/oci/
# Another possible source (for other distros): https://images.linuxcontainers.org/

from loguru import logger
import dataclasses
import datetime
import requests
from bs4 import BeautifulSoup, Tag
from typing import Generator
import gzip
import tarfile
import io

import surfactant.plugin
import surfactant.configmanager
from surfactant.sbomtypes import SBOM, Software, Relationship

@dataclasses.dataclass
class DownloadedInfo:
    distro: str
    version: str
    date: datetime.date

    def __hash__(self) -> int:
        return hash((self.distro, self.version, self.date))


class RootfsManager:
    __config = surfactant.configmanager.ConfigManager()
    __webpage_archive: dict[str, str] = {}
    __downloaded_info: set[DownloadedInfo] = set()
    # The version info extracted from a webpage
    # Not a dict so the order on the webpage can be retained, which puts
    # the newest version at the end
    __version_archive: list[tuple[str, list[tuple[str, datetime.date]]]] = []
    # Mapping from ELF arch names  to download arch names
    __ELF_ARCH_TO_DOWNLOAD_ARCH: dict[str, str] = {
        "EM_X86_64": "amd64",
        "EM_AARCH64": "arm64",
        "EM_ARM": "armhf",
        "EM_PPC64": "ppc64el",
        "EM_RISCV": "riscv64",
        "EM_S390": "s390x",
    }
    __UBUNTU_BASE_DOWNLOAD_URL: str = "https://partner-images.canonical.com/oci/"

    def __init__(self):
        # Create the data directory if needed
        self.data_dir = self.__config.get_data_dir_path() / "rootfs_downloads"
        if not self.data_dir.exists():
            self.data_dir.mkdir(parents=True)
        else:
            for child in self.data_dir.iterdir():
                if child.is_dir():
                    if info := self.try_decode_filename(child.name):
                        self.__downloaded_info.add(info)
                    else:
                        logger.warning(f"Could not parse filename of downloaded rootfs: {child}")

    def try_decode_filename(self, name: str) -> DownloadedInfo | None:
        split = name.split("@")
        if len(split) != 3:
            return None
        datesplit = split[2].split("-")
        if len(datesplit) != 3:
            return None
        return DownloadedInfo(
            split[0],
            split[1],
            datetime.date(*(int(x) for x in datesplit))
        )

    def get_web_subpage(self, subpage: str) -> str | None:
        if subpage in self.__webpage_archive:
            return self.__webpage_archive[subpage]

        r = requests.get(f"{self.__UBUNTU_BASE_DOWNLOAD_URL}{subpage}")
        if r.status_code != 200:
            return None

        self.__webpage_archive[subpage] = r.text
        return r.text

    # Each table has the same format, so this can be used to iterate
    # over meaningful entries in the table
    def webpage_table_info(self, subpage: str) -> Generator[list[Tag], None, None]:
        if root_page := self.get_web_subpage(subpage):
            html = BeautifulSoup(root_page, features="html.parser")
            raw_info: list[list[Tag]] = []
            # Extract each row of the table into a list
            if body := html.find("body"):
                if table := body.find("table"):
                    for tr in (tr for tr in table if isinstance(tr, Tag)):
                        raw_info.append([td for td in tr if isinstance(td, Tag)])
            # Information starts at the fourth row
            yield from raw_info[3:]

    # Iterates over the directories on a webpage
    def dirs_on_webpage(self, subpage: str) -> Generator[tuple[str, datetime.date], None, None]:
        for row in self.webpage_table_info(subpage):
            # Directories have 5 elements and the first column is an image with a [DIR] alt img
            if len(row) == 5:
                if img := row[0].find("img"):
                    if "alt" in img.attrs and img.attrs["alt"] == "[DIR]":
                        if a := row[1].find("a"):
                            raw_date = row[2].text.split(' ')[0]
                            yield (a.text, datetime.date(*(int(x) for x in raw_date.split('-'))))

    # Iterates over the .tar.gz files on a webpage
    # This is needed since, for some reason, the number of "ubuntu" strings is inconsistent
    # Just returns the name of the files
    def tar_gz_on_webpage(self, subpage: str) -> Generator[str, None, None]:
        # This is very similar to the dirs_on_webpage; they could maybe be combined?
        for row in self.webpage_table_info(subpage):
            if len(row) == 5:
                if img := row[0].find("img"):
                    if "src" in img.attrs and img.attrs["src"] == "/icons/compressed.gif":
                        if a := row[1].find("a"):
                            yield a.text

    # Potential future work:
    #   - More considerations than just architecture
    #   - More distros than just Ubuntu
    #   - Download older versions, etc.
    def download_if_needed(self, architecture: str):
        # Download the version information if needed
        if len(self.__version_archive) == 0:
            # This takes a long time so print some status messages on what's happening
            logger.info("Downloading Ubuntu version info")
            for (ver_name, _) in self.dirs_on_webpage(""):
                logger.info(f"Parsing Ubuntu version {ver_name}...")
                self.__version_archive.append((
                    ver_name,
                    [x for x in self.dirs_on_webpage(ver_name) if x[0] != "current/"]
                ))

        # The latest version is always at the end so use that
        version_name, version_downloads = self.__version_archive[-1]
        # Also use the latest version download
        download_dir, modified_date = min(version_downloads, key=lambda x: x[1])
        # Download it if needed
        arch = self.__ELF_ARCH_TO_DOWNLOAD_ARCH[architecture]
        dir_name = f"ubuntu-{version_name[:-1]}@{arch}@{modified_date.strftime("%Y-%m-%d")}"
        if dir_ver := self.try_decode_filename(dir_name):
            if dir_ver not in self.__downloaded_info:
                for f in self.tar_gz_on_webpage(f"{version_name}{download_dir}"):
                    if f"{arch}-root" in f:
                        r = requests.get(
                            f"{self.__UBUNTU_BASE_DOWNLOAD_URL}{version_name}{download_dir}{f}",
                            stream=True
                        )

                        if r.status_code != 200:
                            continue

                        logger.info(f"Downloading {f}")

                        (self.data_dir / dir_name).mkdir(exist_ok=True)
                        with gzip.GzipFile(fileobj=io.BytesIO(r.raw.read())) as gfile:
                            with tarfile.TarFile(fileobj=gfile) as tfile:
                                tfile.extractall(self.data_dir / dir_name)
                                self.__downloaded_info.add(dir_ver)


rootfs_manager = RootfsManager()

@surfactant.plugin.hookimpl
def establish_relationships(
    sbom: SBOM, software: Software, metadata: object
) -> list[Relationship] | None:
    if type(metadata) is dict and "elfArchitecture" in metadata:
        rootfs_manager.download_if_needed(metadata["elfArchitecture"])
