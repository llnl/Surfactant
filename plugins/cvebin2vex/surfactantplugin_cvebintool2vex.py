import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def run_cve_bin_tool(input_file_path, shaHash, output_dir):
    cvebin_file_name = f"{shaHash}_{input_file_path.stem}.json"
    output_file_path = output_dir / cvebin_file_name

    cdxvex_file_name = f"{shaHash}_{input_file_path.stem}.cdxvex"
    vex_output_path = output_dir / cdxvex_file_name

    try:
        command = [
            "cve-bin-tool",
            "--offline",
            "--input-file",
            str(input_file_path),
            "--output",
            str(output_file_path),
            "--format",
            "json",
            "--vex",
            str(vex_output_path),
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        # Check the exit status
        if result.returncode in (0, 1):
            return output_file_path  # Return path to the generated JSON file
    except subprocess.CalledProcessError as e:
        logger.error(
            f"Error running CVE-bin-tool: {e}\nOutput: {e.output}\nError: {e.stderr}",
            file=sys.stderr,
        )
    return None


def convert_cve_to_openvex(json_output_path, shaHash, output_dir):
    openvex_file_name = f"{json_output_path.stem}.vex"
    openvex_output = output_dir / openvex_file_name

    # Open and read the .json file
    try:
        with Path(json_output_path).open() as file:
            cve_data = json.load(file)
    except json.JSONDecodeError as e:
        logger.error(f"Error reading JSON file: {e}")
        return
    except OSError as e:
        logger.error(f"IO error when reading {json_output_path}: {e}")

    openvex_template = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": "Surfactant plugin cvebintool2vex",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "version": 1,
        "tooling": "Surfactant (https://github.com/LLNL/Surfactant)",
        "statements": [],
    }

    for entry in cve_data:
        # Convert CVE data to OpenVEX format
        statement = {
            "vulnerability": {"name": entry["cve_number"]},
            "products": [
                {"@id": f"cpe:2.3:a:{entry['vendor']}:{entry['product']}:{entry['version']}:::::"}
            ],
            "status": "under_investigation",
            "source": entry["source"],
            "cvss_version": entry["cvss_version"],
            "cvss_vector": entry["cvss_vector"],
            "severity": entry["severity"],
        }
        openvex_template["statements"].append(statement)

    # Save the OpenVEX output to a new file
    try:
        with Path(openvex_output).open("w") as outfile:
            json.dump(openvex_template, outfile, indent=4)
    except OSError as e:
        logger.error(f"IO error when writing {openvex_output}: {e}")


def process_input(input_path, shaHash, output_dir=None):
    input_path = Path(input_path)
    if output_dir is None:
        output_dir = Path.cwd()

    if input_path.is_dir():
        for input_file in input_path.glob("*.*"):
            if input_file.suffix.lower() not in [".bin", ".exe", ".jar"]:
                continue
            process_file(input_file, shaHash, output_dir)
    elif input_path.is_file():
        process_file(input_path, shaHash, output_dir)
    else:
        logger.info(f"Error: {input_path} is neither a file nor a directory.")


def process_file(input_file, shaHash, output_directory):
    try:
        json_output_path = run_cve_bin_tool(input_file, shaHash, output_directory)
        if json_output_path:
            convert_cve_to_openvex(json_output_path, shaHash, output_directory)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running CVE-bin-tool: {e}")
    except json.JSONDecodeError as e:
        logger.error(f"JSON decoding error in {input_file}: {e}")
    except OSError as e:
        logger.error(f"I/O error processing {input_file}: {e}")

    # Check if the expected JSON file was created and proceed if it exists
    cvebin_file_name = f"{shaHash}_{input_file.stem}.json"
    jsonfile = output_directory / cvebin_file_name
    if not jsonfile.exists():
        logger.warning(f"Expected JSON file does not exist: {jsonfile}")


def delete_extra_files(*file_paths):
    for file_path in file_paths:
        try:
            if file_path.exists():
                file_path.unlink()
        except PermissionError as e:
            logger.error(f"Permission error deleting {file_path}: {e}")

        except OSError as e:
            logger.error(f"OS error deleting {file_path}: {e}")


@surfactant.plugin.hookimpl(specname="extract_file_info")
def cvebintool2vex(sbom: SBOM, software: Software, filename: str, filetype: list[str]):
    """
    :param sbom(SBOM): The SBOM that the software entry/file is being added to. Can be used to add observations or analysis data.
    :param software(Software): The software entry associated with the file to extract information from.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (List[str]): File type information based on magic bytes.
    """
    # Only parsing executable files
    if not ("ELF" in filetype or "PE" in filetype):
        return

    shaHash = str(software.sha256)
    filename = Path(filename)
    output_dir = Path.cwd()

    existing_json_path = output_dir / f"{shaHash}_additional_metadata.json"
    if existing_json_path.exists():
        with Path(existing_json_path).open() as file:
            data = json.load(file)
    else:
        data = {
            "sha256hash": shaHash,
            "filename": [filename.name],
            "openvex": [],
            "cyclonedx-vex": [],
            "cve-bin-tool": [],
        }

    # Assuming JSON, CDXVEX, and VEX files are processed here
    process_input(filename, shaHash, output_dir)
    # and you have the output files: .json, .cdxvex, .vex

    # Integrate .cdxvex and .vex file contents
    cdxvex_file_path = output_dir / f"{shaHash}_{filename.stem}.cdxvex"
    vex_file_path = output_dir / f"{shaHash}_{filename.stem}.vex"
    json_file_path = output_dir / f"{shaHash}_{filename.stem}.json"

    if cdxvex_file_path.exists() and vex_file_path.exists() and json_file_path.exists():
        # For .cdxvex and .vex files, if they contain JSON, parse them as such; otherwise, read as text
        try:
            with Path(cdxvex_file_path).open() as file:
                cdxvex_data = json.load(file)  # Assuming .cdxvex file is in JSON format
            data["cyclonedx-vex"].append(cdxvex_data)
        except json.JSONDecodeError:
            with Path(cdxvex_file_path).open() as file:
                cdxvex_data = file.read()  # Fallback if not JSON
            data["cyclonedx-vex"].append(cdxvex_data)

        try:
            with Path(vex_file_path).open() as file:
                vex_data = json.load(file)  # Assuming .vex file is in JSON format
            data["openvex"].append(vex_data)
        except json.JSONDecodeError:
            with Path(vex_file_path).open() as file:
                vex_data = file.read()  # Fallback if not JSON
            data["openvex"].append(vex_data)

        with Path(json_file_path).open() as file:
            json_data = json.load(file)
        data["cve-bin-tool"].append(json_data)

    # Attempt to save the updated data
    try:
        with Path(existing_json_path).open("w") as file:
            json.dump(data, file, indent=4)
            logger.info(f"Updated data saved to {existing_json_path}")
    except OSError as e:
        logger.error(f"IO error when writing {existing_json_path}: {e}")

    # Clean up extra files
    delete_extra_files(cdxvex_file_path, vex_file_path, json_file_path)


@surfactant.plugin.hookimpl
def update_db(force: bool = False):
    # Example update logic
    try:
        cmd = ["cve-bin-tool", "--update", "now", "."]
        if force:
            # Add any force-specific options if cve-bin-tool supports them
            # For now, the standard update command will re-download if needed
            pass
        subprocess.check_call(cmd)
        return "Database updated successfully."
    except subprocess.CalledProcessError as e:
        return f"Failed to update database: {e}"
