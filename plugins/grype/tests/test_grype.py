import gzip
import importlib.util
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path
from shutil import which

import docker
import pytest

from surfactant.configmanager import ConfigManager

logging.basicConfig(level=logging.INFO)

# Globals
PLUGIN_NAME = "surfactantplugin_grype"
DOCKER_IMAGE = "hello-world"
GRYPE_OUTPUT_KEY = "grype_output"


def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
    return result.stdout.strip()


@pytest.fixture(scope="session")
def setup_environment_fixture():
    """Fixture to install Grype dependency."""
    check_dependency_availability()

    # Verify and install required tools
    install_grype()


def check_dependency_availability():
    # Check for Docker SDK
    if importlib.util.find_spec("docker") is None:
        pytest.skip("Docker SDK for Python is not installed.")

    # Check for Surfactant
    if importlib.util.find_spec("surfactant") is None:
        pytest.skip("Surfactant is not installed.")


def install_grype() -> None:
    """
    Install Grype if not already present on PATH.
    Always pulls the latest release.
    """
    # If grype already on PATH and --version succeeds, skip install
    if which("grype"):
        try:
            out = subprocess.run(
                ["grype", "--version"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            logging.info("Grype already installed: %s", out)
            return
        except subprocess.CalledProcessError:
            logging.warning("Found grype binary, but version check failed; reinstalling.")

    logging.info("Installing Grype via get.anchore.io…")
    # Use the official Anchore installer to fetch and install the latest Grype
    cmd = "curl -sSfL https://get.anchore.io/grype | sudo sh -s -- -b /usr/local/bin"
    subprocess.run(cmd, shell=True, check=True)

    # Verify installation
    try:
        out = subprocess.run(
            ["grype", "--version"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        logging.info("Grype installed successfully: %s", out)
    except subprocess.CalledProcessError as e:
        logging.error("Installation seemed to succeed but version check failed: %s", e)
        raise


def enable_plugin(plugin_name):
    """Enable a plugin using the Surfactant API directly."""
    # Get config manager
    config_manager = ConfigManager()

    # Retrieve the current list of disabled plugins
    section = "core"
    section_key = "disable_plugins"
    disabled_plugins = config_manager.get(section, section_key, [])

    # If the plugin is in the disabled list, remove it
    if plugin_name in disabled_plugins:
        disabled_plugins.remove(plugin_name)
        config_manager.set(section, section_key, disabled_plugins)

    # Verify the plugin is now enabled (not in the disabled list)
    disabled_plugins = config_manager.get(section, section_key, [])
    assert plugin_name not in disabled_plugins, f"{plugin_name} still found in disabled plugins"

    logging.info("Plugin '%s' is now enabled", plugin_name)


def disable_plugin(plugin_name):
    """Disable a plugin using the Surfactant API directly."""
    # Get config manager
    config_manager = ConfigManager()

    # Retrieve the current list of disabled plugins
    section = "core"
    section_key = "disable_plugins"
    disabled_plugins = config_manager.get(section, section_key, [])

    # If the plugin is not in the disabled list, add it
    if plugin_name not in disabled_plugins:
        disabled_plugins.append(plugin_name)
        config_manager.set(section, section_key, disabled_plugins)

    # Verify the plugin is now disabled (in the disabled list)
    disabled_plugins = config_manager.get(section, section_key, [])
    assert plugin_name in disabled_plugins, f"{plugin_name} not found in disabled plugins"

    logging.info("Plugin '%s' is now disabled", plugin_name)


def run_surfactant_generate(config_file, output_sbom_path):
    """Run surfactant generate using Python subprocess in a platform-independent way."""
    # Use the Python executable from the current environment
    python_exe = sys.executable

    # Build the command using list form to avoid shell injection issues
    cmd = [python_exe, "-m", "surfactant", "generate", config_file, str(output_sbom_path)]

    # Run the command
    logging.info("Running command: %s", " ".join(cmd))
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)

    logging.info("Successfully generated SBOM: '%s'", output_sbom_path)
    return result.stdout


@pytest.fixture(scope="session", name="config_and_tarball_fixture")
def create_config_and_tarball_fixture(tmp_path_factory):
    """
    Fixture to create the configuration file and Docker tarball for testing.
    The tarball contains the 'hello-world' Docker container filesystem.
    """
    # Create a session-scoped temporary directory
    temp_dir = tmp_path_factory.mktemp("session_temp")

    # Initialize Docker client
    logging.info("Initializing Docker client...")
    docker_client = docker.from_env()

    # Pull Docker image
    logging.info("Pulling Docker image: '%s':latest", DOCKER_IMAGE)
    docker_client.images.pull(DOCKER_IMAGE, tag="latest")
    logging.info("Successfully pulled Docker image: '%s':latest", DOCKER_IMAGE)

    # Save Docker image to tar file
    temp_tar_file = Path(temp_dir / "myimage_latest.tar")
    logging.info("Saving Docker image to file: '%s'", temp_tar_file)
    with temp_tar_file.open("wb") as f:
        bytes_written = 0
        for chunk in docker_client.images.get(f"{DOCKER_IMAGE}:latest").save(named=True):
            f.write(chunk)
            bytes_written += len(chunk)
    logging.info(
        "Successfully saved Docker image to file: '%s' ('%s' bytes)", temp_tar_file, bytes_written
    )

    # Change ownership of the file to the current user
    Path.chmod(temp_tar_file, 0o644)
    # Export the container's filesystem to a tarball
    tarball_file = Path(temp_dir / "myimage_latest.tar.gz")

    # Compress the docker image and save to file
    with temp_tar_file.open("rb") as f_in:
        logging.info("Compressing Docker image tar file with gzip...")
        with gzip.open(tarball_file, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

    # Remove the temporary tar file
    try:
        temp_tar_file.unlink()
        logging.info("Temporary tar file removed")
    except OSError as e:
        logging.warning("Failed to remove temporary tar file: '%s'", e)

    # Remove Docker image
    logging.info("Removing Docker image: '%s':latest", DOCKER_IMAGE)
    docker_client.images.remove(f"{DOCKER_IMAGE}:latest")
    logging.info("Successfully removed Docker image: '%s':latest", DOCKER_IMAGE)

    # Create the configuration file
    config_data = [{"extractPaths": [str(tarball_file)], "installPrefix": "/usr/"}]
    config_file = temp_dir / "config_dockertball.json"
    with Path(config_file).open("w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4)
    logging.info("Configuration file created: '%s'", config_file)

    return str(config_file), str(tarball_file)


def test_debug_create_config_and_tarball(config_and_tarball_fixture):
    # pytest test_grype.py -k test_debug_create_config_and_tarball -v
    # Call the fixture and unpack its return values
    config_file, tarball_file = config_and_tarball_fixture

    # Log the outputs for debugging
    logging.info("Config file path: '%s'", config_file)
    logging.info("Tarball file path: '%s'", tarball_file)

    # Assert that the files were created successfully
    assert config_file is not None, "Config file was not created"
    assert tarball_file is not None, "Tarball file was not created"


@pytest.mark.usefixtures("setup_environment_fixture", "config_and_tarball_fixture")
def test_surfactant_generate(config_and_tarball_fixture, tmp_path_factory):
    """Test the Surfactant generate command with the Grype plugin."""
    # Unpack the fixture values
    config_file, tarball_file = config_and_tarball_fixture

    # Create a temporary directory for the test
    temp_dir = tmp_path_factory.mktemp("test_temp")

    # **********************
    # **** Enabled Test ***
    # **********************

    # Enable and verify the Grype plugin is enabled
    enable_plugin(PLUGIN_NAME)

    # Run the Surfactant generate command (with Grype enabled)
    output_enabled_sbom = Path(temp_dir / "docker_tball_grype-enabled_sbom.json")
    logging.info(config_file)
    with Path(config_file).open(encoding="utf-8") as f:
        config_out = json.load(f)
    logging.info(json.dumps(config_out, indent=4))
    logging.info("Running surfactant generate via API for: '%s'", output_enabled_sbom)
    run_surfactant_generate(config_file, output_enabled_sbom)

    # Verify the SBOM file is created
    assert output_enabled_sbom.exists(), f"SBOM file not created: {output_enabled_sbom}"

    # Read and parse the SBOM
    with Path(output_enabled_sbom).open(encoding="utf-8") as f:
        sbom_enabled = json.load(f)

    # Assert that the Grype output is present
    logging.info("ENABLED")
    logging.info(json.dumps(sbom_enabled, indent=4))
    assert any(GRYPE_OUTPUT_KEY in entry for entry in sbom_enabled["software"][0]["metadata"]), (
        "Grype output should be present when the plugin is enabled"
    )

    # Assert that the Grype output is empty (in this specific test case)
    assert all(
        entry.get(GRYPE_OUTPUT_KEY) == []
        for entry in sbom_enabled["software"][0]["metadata"]
        if GRYPE_OUTPUT_KEY in entry
    ), "Grype output should be empty for a minimal tarball with no vulnerabilities"

    # **********************
    # **** Disabled Test ***
    # **********************

    # Disable and verify the Grype plugin is disabled
    disable_plugin(PLUGIN_NAME)

    # Disable the Grype plugin and verify the plugin is disabled
    output_disabled_sbom = Path(temp_dir / "docker_tball_grype-disabled_sbom.json")
    logging.info("Running surfactant generate via API for: '%s'", output_disabled_sbom)
    run_surfactant_generate(config_file, output_disabled_sbom)

    # Verify the SBOM file is created
    assert output_disabled_sbom.exists(), f"SBOM file not created: {output_disabled_sbom}"

    # Read and parse the SBOM
    with output_disabled_sbom.open(encoding="utf-8") as f:
        sbom_disabled = json.load(f)

    # Assert that the Grype output is not present
    logging.info("DISABLED")
    logging.info(json.dumps(sbom_disabled, indent=4))
    assert not any(
        GRYPE_OUTPUT_KEY in entry for entry in sbom_disabled["software"][0]["metadata"]
    ), "Grype output should not be present when the plugin is disabled"

    # ************************
    # *** Test consistency ***
    # ************************

    # Compare the two SBOMs for consistency (except for Grype output)
    assert sbom_disabled["software"][0]["fileName"] == sbom_enabled["software"][0]["fileName"], (
        "File names should match between disabled and enabled cases"
    )
    assert sbom_disabled["software"][0]["sha256"] == sbom_enabled["software"][0]["sha256"], (
        "SHA256 hashes should match between disabled and enabled cases"
    )
