# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
from pathlib import Path

import angr
from cle import CLECompatibilityError
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


@surfactant.plugin.hookimpl(specname="extract_file_info")
# extract_strings(sbom: SBOM, software: Software, filename: str, filetype: str):
# def angrimport_finder(filename: str, filetype: str, filehash: str):
def reachability(sbom: SBOM, software: Software, filename: str, filetype: str):
    """
    :param sbom(SBOM): The SBOM that the software entry/file is being added to. Can be used to add observations or analysis data.
    :param software(Software): The software entry associated with the file to extract information from.
    :param filename (str): The full path to the file to extract information from.
    :param filetype (str): File type information based on magic bytes.
    """

    # Only parsing executable files
    if filetype not in ["ELF", "PE"]:
        pass
    filename = Path(filename)

    database = {}

    try:
        if not filename.exists():
            raise FileNotFoundError(f"No such file: '{filename}'")
        # Add your extraction code here.
        # Create an angr project
        project = angr.Project(filename, load_options={"auto_load_libs": True})

        # library dependencies {import: library}
        lookup = {}
        for obj in project.loader.main_object.imports.keys():
            library = project.loader.find_symbol(obj)
            if library is None:
                continue
            lookup[obj] = library.owner.provides

        # recreates our angr project without the libraries loaded to save on time
        project = angr.Project(filename, load_options={"auto_load_libs": False})

        # holds every export address error is here
        exports = [
            func.rebased_addr for func in project.loader.main_object.symbols if func.is_export
        ]  # _exports is only available for PE files

        cfg = project.analyses.CFGFast(
            start_at_entry=False, force_smart_scan=False, function_starts=exports
        )

        # go through every exported function
        for exp_addr in exports:
            exp_name = cfg.functions.get(exp_addr)
            if exp_name is None:
                continue
            database[exp_name.name] = {}
            exp_name = exp_name.name

            # goes through every function that is reachable from exported function
            for imported_address in cfg.functions.callgraph.successors(exp_addr):
                imported_function = cfg.functions.get(imported_address)

                # checks if the function is imported
                if imported_function.name in project.loader.main_object.imports.keys():
                    library = lookup[imported_function.name]

                    if library not in database[exp_name].keys():
                        database[exp_name][library] = []

                    # adds our reachable imported function as a dependency
                    if imported_function.name not in database[exp_name][library]:
                        database[exp_name][library].append(imported_function.name)

        return {"export_fn_reachability": database}

    except CLECompatibilityError as e:
        logger.info(f"Angr Error {filename} {e}")
        return None
