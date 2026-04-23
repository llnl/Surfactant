# Copyright 2024 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import gzip
import subprocess
import tempfile

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def check_if_grype_installed() -> bool:
    try:
        result = subprocess.run(["grype", "--help"], capture_output=True, check=False).returncode
        if result == 0:
            logger.debug("Grype is installed and ready to use.")
        else:
            logger.warning("Grype is not installed or not functioning correctly.")
        return result == 0
    except FileNotFoundError:
        logger.error("Grype is not installed. Please install it to use this plugin.")
        return False


disable_plugin = not check_if_grype_installed()


def run_grype(filename: str) -> object:
    logger.debug(f"Starting grype scan for file: {filename}")
    result = subprocess.run(["grype", filename], capture_output=True, check=False)
    if result.returncode != 0:
        logger.warning(f"Running grype on {filename} failed with return code {result.returncode}")
        logger.debug(f"Grype stderr: {result.stderr.decode().strip()}")
        return None
    logger.debug(f"Grype scan completed successfully for file: {filename}")
    output = result.stdout.decode()
    logger.debug(
        f"Grype raw output: {output[:200]}..."
    )  # Log the first 200 characters of the output
    to_ret = []
    # skip the header on the first line
    for line in output.split("\n")[1:]:
        columns = [s.strip() for s in line.split("  ") if s.strip()]
        # Skip empty lines
        if len(columns) == 0:
            continue
        # Assume that the "Fixed In" field is missing if there's only 5 entries
        name = columns[0]
        installed = columns[1]
        if len(columns) == 5:
            fixed_in = ""
            type_ = columns[2]
            vuln = columns[3]
            severity = columns[4]
        else:
            fixed_in = columns[2]
            type_ = columns[3]
            vuln = columns[4]
            severity = columns[5]
        to_ret.append(
            {
                "name": name,
                "installed": installed,
                "fixed_in": fixed_in,
                "type": type_,
                "vulnerability": vuln,
                "severity": severity,
            }
        )
    return {"grype_output": to_ret}


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM, software: Software, filename: str, filetype: list[str], children: list
) -> list[Software] | None:
    if disable_plugin:
        return None

    if not ("DOCKER_TAR" in filetype or "DOCKER_GZIP" in filetype):
        return None

    try:
        if "DOCKER_GZIP" in filetype:
            logger.debug(f"Decompressing gzip file: {filename}")
            with open(filename, "rb") as gzip_in:
                gzip_data = gzip_in.read()
            with tempfile.NamedTemporaryFile() as gzip_out:
                gzip_out.write(gzip.decompress(gzip_data))
                logger.debug(f"Decompressed file written to temporary file: {gzip_out.name}")
                return run_grype(gzip_out.name)

        # For DOCKER_TAR or other supported types
        return run_grype(filename)

    except FileNotFoundError:
        logger.error(f"File not found: {filename}")
    except PermissionError:
        logger.error(f"Permission denied when accessing file: {filename}")
    except gzip.BadGzipFile:
        logger.error(f"Invalid gzip file: {filename}")
    except OSError as e:
        logger.error(f"OS error while processing file {filename}: {e}")

    return None


@surfactant.plugin.hookimpl
def update_db(force: bool = False):
    logger.info("Starting grype database update...")
    # Example update logic
    try:
        cmd = ["grype", "db", "update"]
        if force:
            # Add any force-specific options if grype supports them
            # For now, the standard update command will re-download if needed
            pass
        subprocess.check_call(cmd)
        logger.info("Grype database updated successfully.")
        return "Database updated successfully."
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to update Grype database: {e}")
        return f"Failed to update database: {e}"


@surfactant.plugin.hookimpl
def short_name():
    return "grype"
