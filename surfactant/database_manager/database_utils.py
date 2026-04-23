# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from loguru import logger

from surfactant.configmanager import ConfigManager
from surfactant.database_manager.utils import (
    calculate_hash,
    download_content,
    get_source_for,
    load_db_version_metadata,
    save_db_version_metadata,
)


@dataclass
class DatabaseConfig:
    """
    Represents the configuration for a database used by a plugin.

    Attributes:
        database_dir (str): The database directory name for the class of databases (e.g., "js_library", "native_library").
        database_key (str): The key identifying the database (e.g., "retirejs").
        database_file (str): The file name of the database (e.g., "js_library_patterns_retirejs.json").
        source (str): The source URL of the database, or "file" if it's a local file.
        plugin_name (Optional[str]): The canonical name or short name of the plugin handling the database.
    """

    database_dir: str
    database_key: str
    database_file: str
    source: str
    plugin_name: str | None = None

    def __post_init__(self) -> None:
        # Validate that source is either a URL or "file"
        if self.source != "file":
            parsed_url = urlparse(self.source)
            # Check that the scheme is valid (http or https)
            if parsed_url.scheme not in {"http", "https"}:
                raise ValueError(
                    f"Invalid URL scheme: {parsed_url.scheme}. Expected 'http' or 'https'."
                )
            # Check that netloc is present
            if not parsed_url.netloc:
                raise ValueError(
                    f"Invalid URL for source: {self.source}",
                )

        # Ensure database_file ends with .json
        if not self.database_file.endswith(".json"):
            raise ValueError(
                f"database_file '{self.database_file}' must end with '.json'.",
            )


class BaseDatabaseManager(ABC):
    """Abstract base class for managing databases."""

    def __init__(self, config: DatabaseConfig) -> None:
        self.config = config

        # Attempt to retrieve an override URL using the database_dir (e.g., "js_library_patterns")
        # and the database_key (e.g., "retirejs").
        override_url = get_source_for(self.config.database_dir, self.config.database_key)
        if override_url:
            self.config.source = override_url
            logger.debug(
                "Using external URL override for {}: {}", self.config.database_key, override_url
            )
        else:
            logger.debug("Using hard-coded URL for {}", self.config.database_key)

        self.new_hash: str | None = None
        self.download_timestamp: str | None = None
        self._database: dict[str, Any] | None = None

        # Ensure the parent directory exists
        path = self.database_version_file_path
        path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def data_dir(self) -> Path:
        """Returns the base directory for storing database (.json) and version tracking (TOML) files."""
        return ConfigManager().get_data_dir_path() / "databases"

    @property
    def database_version_file_path(self) -> Path:
        """Path to the database version file (e.g., TOML file)."""
        return self.data_dir / f"{self.config.database_dir}" / "version_info.toml"

    @property
    def database_file_path(self) -> Path:
        """Path to the JSON database file."""
        return self.data_dir / f"{self.config.database_dir}" / f"{self.config.database_file}"

    @property
    def database_info(self) -> dict[str, Any]:
        """Returns metadata about the database patterns."""
        return {
            "database_key": self.config.database_key,
            "database_file": self.config.database_file,
            "source": self.config.source,
            "hash_value": self.new_hash,
            "timestamp": self.download_timestamp,
        }

    def initialize_database(self, command_name: str | None = None) -> None:
        """
        Initialization hook to load the pattern database.

        Args:
            command_name (Optional[str], optional): The name of the command invoking the initialization.
                If set to "update-db", the database will not be loaded.

        Returns:
            None
        """
        if command_name != "update-db":
            logger.debug("Initializing {}...", self.config.plugin_name)
            self.load_db()
            logger.debug("Initializing {} complete.", self.config.plugin_name)

    def load_db(self) -> None:
        """Loads the database from a JSON file."""
        try:
            with self.database_file_path.open("r") as db_file:
                self._database = json.load(db_file)
        except FileNotFoundError:
            logger.warning(
                "{} database could not be loaded. Run `surfactant plugin update-db {}` to fetch the database.",
                self.config.database_key,
                self.config.plugin_name,
            )
            self._database = None

    def get_database(self) -> dict[str, Any] | None:
        """Returns the loaded database."""
        if self._database is None:
            self.load_db()
        return self._database

    def save_database(self, data: dict[str, Any]) -> None:
        """Saves the database to a JSON file."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        with self.database_file_path.open("w") as db_file:
            json.dump(data, db_file, indent=4)
        logger.info("{} database saved successfully.", self.config.database_key)

    @abstractmethod
    def parse_raw_data(self, raw_data: str) -> dict[str, Any]:
        """Parses raw database data into a structured format."""
        # No implementation needed for abstract methods.

    def download_and_update_database(self, force: bool = False) -> str:
        raw_data = download_content(self.config.source)
        if not raw_data:
            return "No update occurred. Failed to download database."

        new_hash = calculate_hash(raw_data)
        current_data = load_db_version_metadata(
            self.database_version_file_path, self.config.database_key
        )

        if not force and current_data and new_hash == current_data.get("hash"):
            return "No update occurred. Database is up-to-date."

        parsed_data = self.parse_raw_data(raw_data)
        if parsed_data is None:
            return "No update occurred. Failed to parse raw data."

        self.save_database(parsed_data)
        self.new_hash = new_hash
        self.download_timestamp = datetime.now(timezone.utc).isoformat()
        save_db_version_metadata(self.database_version_file_path, self.database_info)
        return "Update complete."
