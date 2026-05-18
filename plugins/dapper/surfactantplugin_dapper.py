import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software

try:
    from dapper_python.databases.linuxDB import LinuxDB
    from dapper_python.dataset_loader import DatasetCatalog
    from dapper_python.normalize import NormalizedFileName, normalize_file_name

    DAPPER_AVAILABLE = True
except ImportError:
    DAPPER_AVAILABLE = False
    logging.warning("dapper-python not installed. Dapper plugin will be disabled.")


@dataclass
class DapperPackageInfo:
    """Information about a package found by Dapper."""

    package_name: str
    package_dataset: str
    original_name: str
    file_path: str
    normalized_name: str | None = None
    version: str | None = None
    soabi: str | None = None

    @classmethod
    def from_result(cls, result, dataset_name, filename):
        """Create DapperPackageInfo from database query result."""

        normalized_result = normalize_file_name(filename)

        if isinstance(normalized_result, NormalizedFileName):
            version = normalized_result.version
            soabi = normalized_result.soabi
            normalized_name = normalized_result.name
        else:
            version = None
            soabi = None
            normalized_name = filename

        return cls(
            package_name=result.package_name,
            package_dataset=dataset_name,
            original_name=filename,
            normalized_name=normalized_name,
            file_path=str(result.file_path),
            version=version,
            soabi=soabi,
        )


class DapperPlugin:  # pylint: disable=too-few-public-methods
    """Plugin to integrate Dapper package detection with Surfactant."""

    def __init__(self):
        """Initialize the Dapper plugin with dataset catalog."""
        self.catalog = None
        self.linux_datasets = []
        self.nuget_dataset = None
        if DAPPER_AVAILABLE:
            self._init_catalog()

    def _init_catalog(self):
        """Initialize the dataset catalog and check available datasets."""
        try:
            # Try to load the dataset catalog
            self.catalog = DatasetCatalog(app_name="dapper")

            # Check for available datasets
            available = self.catalog.get_available_datasets()

            # Look for Linux and NuGet datasets
            for dataset in available:
                if any(distro in dataset for distro in ["debian", "ubuntu"]):
                    self.linux_datasets.append(dataset)

            if not self.linux_datasets:
                pass  # No Linux datasets found for Dapper plugin

        except Exception:  # pylint: disable=broad-exception-caught
            self.catalog = None

    def lookup_package(self, file_path: str, file_types: list[str]) -> dict[str, Any] | None:
        """Provides package lookup for files in SBOMs."""
        if not self.catalog or not DAPPER_AVAILABLE:
            return None

        # Extract just the filename from the path
        filename = Path(file_path).name

        # Determine file type from Surfactant's filetype list
        file_type = None
        for ft in file_types:
            if "ELF" in ft:
                file_type = "ELF"
                break
            if "PE" in ft or "PE32" in ft or "DLL" in ft:
                file_type = "PE"
                break

        # Also check by extension if not detected
        if not file_type:
            ext = Path(filename).suffix.lower()
            if ext in [".so", ".o"] or (not ext and "." not in filename):
                file_type = "ELF"
            elif ext in [".dll", ".exe", ".sys"]:
                file_type = "PE"

        if not file_type:
            return None

        all_results = []  # Initialize here!

        # Query all Linux datasets for ELF files
        if file_type == "ELF" and self.linux_datasets:  # Check list, not None variable
            for dataset_name in self.linux_datasets:
                try:
                    db_path = self.catalog.get_dataset_path(dataset_name)

                    # Path resolution
                    if db_path and not db_path.is_absolute():
                        app_dir = Path(self.catalog.get_app_data_dir(self.catalog.app_name))
                        db_path = app_dir / db_path

                    if not db_path or not db_path.exists():
                        continue

                    linux_db = LinuxDB(db_path)
                    results = linux_db.query_filename(filename, normalize=False)

                    if results:
                        # Add results from this dataset
                        packages = [
                            asdict(DapperPackageInfo.from_result(r, dataset_name, filename))
                            for r in results
                        ]
                        all_results.extend(packages)

                except Exception:  # pylint: disable=broad-exception-caught
                    pass  # Error querying dataset

        if all_results:
            return {"dapper_packages": all_results}

        return None


# Global plugin instance
_PLUGIN_INSTANCE = None


def _get_plugin():
    global _PLUGIN_INSTANCE  # pylint: disable=global-statement
    if _PLUGIN_INSTANCE is None:
        _PLUGIN_INSTANCE = DapperPlugin()
    return _PLUGIN_INSTANCE


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: list[str],
) -> dict[str, Any] | None:
    if not DAPPER_AVAILABLE:
        return None

    plugin = _get_plugin()

    # Look up package information based on the file
    package_info = plugin.lookup_package(filename, filetype)

    if package_info:
        return package_info

    return None
