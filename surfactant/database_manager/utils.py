# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import hashlib
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import requests
import tomlkit
from loguru import logger
from requests.exceptions import RequestException
from tomlkit import parse

from surfactant.configmanager import ConfigManager

RTD_URL = "https://surfactant.readthedocs.io/en/latest/database_sources.toml"


@lru_cache(maxsize=1)
def _get_rtd_raw() -> str | None:
    raw = download_content(RTD_URL)
    logger.debug("Fetched RTD singleton for URL: {}", RTD_URL)
    return raw


def download_content(url: str, timeout: int = 10, retries: int = 3) -> str | None:
    """
    Downloads content from a given URL with retry logic and timeout.

    Args:
        url (str): The URL of the content to download.
        timeout (int): The timeout in seconds for each request attempt.
        retries (int): Number of retry attempts for the download.

    Returns:
        Optional[str]: The content as a string if the request is successful,
                       or None if an error occurs.
    """
    attempt = 0
    while attempt < retries:
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                logger.debug("Request successful! URL:{}", url)
                return response.text
            if response.status_code == 404:
                logger.debug("Resource not found. URL: {}", url)
                return None
            logger.debug("Unexpected status code {} for URL: {}", response.status_code, url)
        except RequestException as e:
            logger.debug("Attempt {} - Error fetching URL {}: {}", str(attempt + 1), url, e)

        attempt += 1
        sleep_time = 2**attempt  # exponential backoff
        logger.debug("Retrying in {} seconds...", sleep_time)
        time.sleep(sleep_time)

    return None


def calculate_hash(data: str) -> str:
    """
    Calculate the SHA-256 hash of the given data.

    Args:
        data (str): The input string to hash.

    Returns:
        str: The SHA-256 hash of the input string.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _read_toml_file(file_path: str | Path) -> dict[str, Any] | None:
    """
    Read and parse a TOML file.

    Args:
        file_path (Union[str, Path]): The path to the TOML file.

    Returns:
        Optional[Dict[str, Any]]: The parsed TOML data, or None if the file does not exist.
    """
    path = Path(file_path) if not isinstance(file_path, Path) else file_path
    try:
        with path.open("r") as f:
            return tomlkit.load(f)
    except FileNotFoundError:
        return None
    except tomlkit.exceptions.TOMLKitError as e:
        raise ValueError(f"Error parsing TOML file at {file_path}: {e}") from e


def _write_toml_file(file_path: str | Path, data: dict[str, Any]) -> None:
    """
    Write data to a TOML file.

    Args:
        file_path (Union[str, Path]): The path to the TOML file.
        data (Dict[str, Any]): The data to write to the file.
    """
    path = Path(file_path) if not isinstance(file_path, Path) else file_path
    with path.open("w") as f:
        tomlkit.dump(data, f)


def load_db_version_metadata(
    version_file_path: str | Path, database_key: str
) -> dict[str, str] | None:
    """
    Load the database version metadata for a specific database from the specified TOML file.

    Args:
        version_file_path (Union[str, Path]): The path to the TOML file that tracks database versions.
        database_key (str): The key identifying the database.

    Returns:
        Optional[Dict[str, str]]: A dictionary with metadata for the database, or None if not found.

        Example structure:
        {
            "retirejs": {
                "file": "js_library_patterns_retirejs.json",
                "source": "https://example.com/source.json",
                "hash": "abc123...",
                "timestamp": "2025-02-10T19:18:34.784116Z"
            },
            "abc": {
                "file": "some_other_library_patterns_abc.json",
                "source": "https://example.com/other_source.json",
                "hash": "def456...",
                "timestamp": "2025-02-10T20:00:00.000000Z"
            }
        }
    """
    db_metadata = _read_toml_file(version_file_path)
    if db_metadata is None:
        return None

    return db_metadata.get(database_key, {})


def save_db_version_metadata(version_info: str | Path, database_info: dict[str, str]) -> None:
    """
    Save the metadata for a specific database to the specified TOML file.

    Args:
        version_info (Union[str, Path]): The path to the TOML file.
        database_info (Dict[str, str]): A dictionary containing keys:
            - "database_key": The key identifying the database  (e.g., "retirejs")..
            - "database_file": The file name of the database (e.g., "js_library_patterns_retirejs.json").
            - "source": The source URL of the database.
            - "hash_value": The hash value of the database file.
            - "timestamp": The timestamp when the database was downloaded.

    Raises:
        ValueError: If required keys are missing from database_info.
    """
    required_keys = {"database_key", "database_file", "source", "hash_value", "timestamp"}
    if not required_keys.issubset(database_info):
        raise ValueError(f"database_info must contain the keys: {required_keys}")

    db_metadata = _read_toml_file(version_info) or {}
    new_data = {
        database_info["database_key"]: {
            "file": database_info["database_file"],
            "source": database_info["source"],
            "hash": database_info["hash_value"],
            "timestamp": database_info["timestamp"],
        }
    }
    db_metadata.update(new_data)
    _write_toml_file(version_info, db_metadata)


def fetch_db_config() -> dict:
    """
    Load the database_sources.toml from local docs/
    """
    # Get local docs copy in the source tree:
    local = Path(__file__).parents[2] / "docs" / "database_sources.toml"
    return _read_toml_file(local)


def get_source_for(database_category: str, key: str) -> str:
    """
    Retrieve the URL for a given database category and key.

    Resolution order:
      1. Runtime override in user config.
      2. Local docs/database_sources.toml when running Surfactant from an editable install from a git clone of the Surfactant repo.
      3. ReadTheDocs hosted database_sources.toml file.
      4. Fallback to hard-coded URL in child class code.
    """

    # First, check the runtime config for an override
    config_manager = ConfigManager()
    config = config_manager.config
    runtime_url = config_manager.get("sources", f"{database_category}.{key}")
    if runtime_url not in ("", [], {}, "[]", "{}", None, "None"):
        logger.debug("Using command line overide url: {}", runtime_url)
        return runtime_url  # Return the command line override URL if present

    # Second, check docs/database_sources.toml for the URL
    config = fetch_db_config()
    try:
        if config:
            logger.debug(
                "Using command docs/database_sources.toml: {}",
                config["sources"][database_category][key],
            )
            return config["sources"][database_category][key]
        logger.debug("Failed to get local docs/database_sources.toml")
    except KeyError:
        logger.debug("No external override found for [{}].{}", database_category, key)

    # Third, check ReadTheDocs
    raw_data = _get_rtd_raw()
    if raw_data:
        config = parse(raw_data)  # Parse the raw TOML text into a tomlkit.document.Document
        try:
            runtime_url = config["sources"][database_category][key]
            logger.debug("Using RTD url: {}", runtime_url)
            return runtime_url  # Return url from RTD
        except tomlkit.exceptions.NonExistentKey:
            logger.debug("No RTD override found for [{}].{}", database_category, key)

    return None  # 4th, fall back to the hardcoded URLs in the code
