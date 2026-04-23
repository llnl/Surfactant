# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

# https://en.wikipedia.org/wiki/Comparison_of_executable_file_formats
# https://github.com/erocarrera/pefile/blob/master/pefile.py#L2914
# pefile only handles MZ magic bytes, but ZM might be valid as well
# there could also be some other supported Windows EXE formats such as NE, LE, LX, TX, and COM (generally no header, except CP/M 3 format COM has RET instruction)

import pathlib
import re
from typing import Any

import defusedxml.ElementTree
import dnfile
from loguru import logger

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software


def supports_file(filetype: list[str]) -> bool:
    return "PE" in filetype


@surfactant.plugin.hookimpl
def extract_file_info(
    sbom: SBOM,
    software: Software,
    filename: str,
    filetype: list[str],
    software_field_hints: list[tuple[str, object, int]],
) -> object:
    if not supports_file(filetype):
        return None
    pe_info = extract_pe_info(filename)
    if pe_info:
        if "FileInfo" in pe_info:
            fi = pe_info["FileInfo"]
            if "ProductName" in fi:
                software_field_hints.append(("name", fi["ProductName"], 80))
            if "FileVersion" in fi:
                software_field_hints.append(("version", fi["FileVersion"], 80))
            if "CompanyName" in fi:
                software_field_hints.append(("vendor", fi["CompanyName"], 80))
            if "FileDescription" in fi:
                software_field_hints.append(("description", fi["FileDescription"], 80))
            if "Comments" in fi:
                software_field_hints.append(("comments", fi["Comments"], 80))
    return pe_info


# https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
# Values for CPU types that can appear in a PE file
pe_machine_types = {
    0x0: "UNKNOWN",
    0x184: "ALPHA",  # Alpha_AXP
    0x284: "ALPHA64",  # Also AXP64
    0x1D3: "AM33",
    0x8664: "AMD64",
    0x1C0: "ARM",
    0xAA64: "ARM64",
    0x1C4: "ARMNT",
    0xC0EE: "CEE",
    0xCEF: "CEF",
    0xEBC: "EBC",
    0x14C: "I386",
    0x200: "IA64",
    0x6232: "LOONGARCH32",
    0x6264: "LOONGARCH64",
    0x9041: "M32R",
    0x266: "MIPS16",
    0x366: "MIPSFPU",
    0x466: "MIPSFPU16",
    0x1F0: "POWERPC",
    0x1F1: "POWERPCFP",
    0x160: "R3000",  # Big-Endian
    0x162: "R3000",  # Little-Endian
    0x166: "R4000",
    0x168: "R10000",
    0x5032: "RISCV32",
    0x5064: "RISCV64",
    0x5128: "RISCV128",
    0x1A2: "SH3",
    0x1A3: "SH3DSP",
    0x1A4: "SH3E",
    0x1A6: "SH4",
    0x1A8: "SH5",
    0x1C2: "THUMB",
    0x520: "TRICORE",
    0x169: "WCEMIPSV2",
}

# https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#windows-subsystem
# Values for Windows subsystem optional header field that determines which is required to run the image
pe_subsystem_types = {
    0: "UNKNOWN",
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    8: "NATIVE_WINDOWS",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
    16: "WINDOWS_BOOT_APPLICATION",
    17: "XBOX_CODE_CATALOG",
}


def extract_pe_info(filename: str) -> object:
    try:
        pe = dnfile.dnPE(filename, fast_load=False)
    except (OSError, dnfile.PEFormatError):
        return {}

    file_details: dict[str, Any] = {"OS": "Windows"}
    if pe.FILE_HEADER is not None:
        if pe.FILE_HEADER.Machine in pe_machine_types:
            file_details["peMachine"] = pe_machine_types[pe.FILE_HEADER.Machine]
        else:
            file_details["peMachine"] = pe.FILE_HEADER.Machine
            logger.warning("Unknown machine type encountered in PE file header")
    if pe.OPTIONAL_HEADER is not None:
        file_details["peOperatingSystemVersion"] = (
            f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}"
        )
        file_details["peSubsystemVersion"] = (
            f"{pe.OPTIONAL_HEADER.MajorSubsystemVersion}.{pe.OPTIONAL_HEADER.MinorSubsystemVersion}"
        )
        if pe.OPTIONAL_HEADER.Subsystem in pe_subsystem_types:
            file_details["peSubsystem"] = pe_subsystem_types[pe.OPTIONAL_HEADER.Subsystem]
        else:
            file_details["peSubsystem"] = pe.OPTIONAL_HEADER.Subsystem
            logger.warning("Unknown Windows Subsystem type encountered in PE file header")
        file_details["peLinkerVersion"] = (
            f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
        )

    if import_dir := getattr(pe, "DIRECTORY_ENTRY_IMPORT", None):
        # Imported Symbols
        file_details["peImport"] = []
        for entry in import_dir:
            file_details["peImport"].append(entry.dll.decode())

    if bound_import_dir := getattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT", None):
        # Bound Imported Symbols
        file_details["peBoundImport"] = []
        for entry in bound_import_dir:
            file_details["peBoundImport"].append(entry.name.decode())

    if delay_import_dir := getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", None):
        # Delay Imported Symbols
        file_details["peDelayImport"] = []
        for entry in delay_import_dir:
            file_details["peDelayImport"].append(entry.dll.decode())

    def get_com_desc(data_dir: list):  # mcutshaw's solution
        for x in data_dir:
            if "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR" == x.name:
                return x
        return None

    file_details["peIsExe"] = pe.is_exe()
    file_details["peIsDll"] = pe.is_dll()
    if opt_hdr := getattr(pe, "OPTIONAL_HEADER", None):
        if opt_hdr_data_dir := getattr(opt_hdr, "DATA_DIRECTORY", None):
            com_desc_dir = get_com_desc(opt_hdr_data_dir)
            if com_desc_dir is not None:
                file_details["peIsClr"] = (com_desc_dir.VirtualAddress > 0) and (
                    com_desc_dir.Size > 0
                )
            else:
                file_details["peIsClr"] = False

    if pe_fi := getattr(pe, "FileInfo", None):
        if len(pe_fi) > 0:
            file_details["FileInfo"] = {}
            for fi_entry in pe_fi[0]:
                if fi_entry.name == "StringFileInfo" and hasattr(fi_entry, "StringTable"):
                    for st in fi_entry.StringTable:
                        for st_entry in st.entries.items():
                            file_details["FileInfo"][st_entry[0].decode()] = st_entry[1].decode()

    # If this is a .NET assembly, extract information about it from the headers
    if dnet := getattr(pe, "net", None):
        if dnet_flags := getattr(dnet, "Flags", None):
            file_details["dotnetFlags"] = {
                "ILONLY": dnet_flags.CLR_ILONLY,
                "32BITREQUIRED": dnet_flags.CLR_32BITREQUIRED,
                "IL_LIBRARY": dnet_flags.CLR_IL_LIBRARY,
                "STRONGNAMESIGNED": dnet_flags.CLR_STRONGNAMESIGNED,
                "NATIVE_ENTRYPOINT": dnet_flags.CLR_NATIVE_ENTRYPOINT,
                "TRACKDEBUGDATA": dnet_flags.CLR_TRACKDEBUGDATA,
                "32BITPREFERRED": dnet_flags.CLR_PREFER_32BIT,
            }
        if dnet_mdtables := getattr(dnet, "mdtables", None):
            if assembly_info := getattr(dnet_mdtables, "Assembly", None):
                assemblies = []
                for a_info in assembly_info:
                    assemblies.append(get_assembly_info(a_info))
                file_details["dotnetAssembly"] = assemblies
            if assemblyref_info := getattr(dnet_mdtables, "AssemblyRef", None):
                assembly_refs = []
                for ar_info in assemblyref_info:
                    assembly_refs.append(get_assemblyref_info(ar_info))
                file_details["dotnetAssemblyRef"] = assembly_refs
            if implmap_info := getattr(dnet_mdtables, "ImplMap", None):
                imp_modules: list[dict[str, Any]] = []
                for im_info in implmap_info:
                    insert_implmap_info(im_info, imp_modules)
                file_details["dotnetImplMap"] = imp_modules

    # TODO for a custom intermediate SBOM format, the information read from the manifest and app config files
    # should be tied to a specific "<install path>/<file name>", in case the same file appears in separate
    # directories/file systems with different manifest/config file settings for paths to search
    file_details["dllRedirectionLocal"] = check_windows_dll_redirection_local(filename)

    manifest_info = get_windows_manifest_info(filename)
    if manifest_info:
        file_details["manifestFile"] = manifest_info

    app_config_info = get_windows_application_config_info(filename)
    if app_config_info:
        file_details["appConfigFile"] = app_config_info

    return file_details


def check_attribute_exists(obj):
    # Checks to see if obj has .value attribute.
    if hasattr(obj, "value") and obj.value is not None:
        if isinstance(obj.value, bytes):
            return obj.value.hex()
        return obj.value
    if hasattr(obj, "raw_data") and obj.raw_data is not None:
        return obj.raw_data.hex()
    if isinstance(obj, bytes):
        return obj.hex()
    # In this case, obj is most likely a string
    return obj


def add_core_assembly_info(asm_dict: dict[str, Any], asm_info):
    # REFERENCE: https://github.com/malwarefrank/dnfile/blob/096de1b3/src/dnfile/stream.py#L36-L39
    # HeapItemString value will be decoded string, or None if there was a UnicodeDecodeError

    asm_dict["Name"] = check_attribute_exists(asm_info.Name)
    asm_dict["Culture"] = check_attribute_exists(asm_info.Culture)

    asm_dict["Version"] = (
        f"{asm_info.MajorVersion}.{asm_info.MinorVersion}.{asm_info.BuildNumber}.{asm_info.RevisionNumber}"
    )

    # REFERENCE: https://github.com/malwarefrank/dnfile/blob/096de1b3/src/dnfile/stream.py#L62-L66
    # HeapItemBinary value is the bytes following the compressed int (indicating the length)
    if asm_info.PublicKey is not None:
        # PublicKey format is bytes
        asm_dict["PublicKey"] = check_attribute_exists(asm_info.PublicKey)


def add_assembly_flags_info(asm_dict, asm_info):
    # Info on flags
    # Processor Architecture fields/values: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.processorarchitecture?view=net-6.0
    # PA enum values in dnfile: https://github.com/malwarefrank/dnfile/blob/7441fe326e0cc254ed2944a18773d8b4fe99c4c6/src/dnfile/enums.py#L663-L671
    # .NET runtime corhdr.h PA enum: https://github.com/dotnet/runtime/blob/9d6396deb02161f5ee47af72ccac52c2e1bae458/src/coreclr/inc/corhdr.h#L747-L754
    # Assembly flags: https://learn.microsoft.com/en-us/dotnet/api/system.reflection.assemblyflags?view=net-6.0
    if a_flags := getattr(asm_info, "Flags", None):
        asm_dict["Flags"] = {
            "DisableJitCompileOptimizer": a_flags.afDisableJITcompileOptimizer,  # JIT compiler optimization disabled for assembly
            "EnableJitCompileTracking": a_flags.afEnableJITcompileTracking,  # JIT compiler tracking enabled for assembly
            "PublicKey": a_flags.afPublicKey,  # assembly ref has the full (unhashed) public key
            "Retargetable": a_flags.afRetargetable,  # impl of referenced assembly used at runtime may not match version seen at compile time
            "PA_Specified": a_flags.afPA_Specified,  # propagate processor architecture flags to AssemblyRef record
            "PA_None": a_flags.afPA_None,
            "PA_MSIL": a_flags.afPA_MSIL,
            "PA_x86": a_flags.afPA_x86,
            "PA_IA64": a_flags.afPA_IA64,
            "PA_AMD64": a_flags.afPA_AMD64,
            "PA_ARM": a_flags.afPA_Unknown1,  # based on enumeration values in docs, clr runtime corhdr.h, and dnfile
            "PA_ARM64": a_flags.afPA_Unknown2,
            "PA_NoPlatform": a_flags.afPA_Unknown3,  # applies to any platform but cannot run on any (e.g. reference assembly), "specified" should not be set
        }


def get_assembly_info(asm_info) -> dict[str, Any]:
    asm: dict[str, Any] = {}
    add_core_assembly_info(asm, asm_info)
    # REFERENCE: https://github.com/malwarefrank/dnfile/blob/fcccdaf/src/dnfile/enums.py#L851-L863
    # HashAlgID is a dnfile enum, based on possible .NET hash algs
    asm["HashAlgId"] = asm_info.HashAlgId.name
    add_assembly_flags_info(asm, asm_info)
    return asm


def get_assemblyref_info(asmref_info) -> dict[str, Any]:
    asmref: dict[str, Any] = {}
    add_core_assembly_info(asmref, asmref_info)
    # REFERENCE: https://github.com/malwarefrank/dnfile/blob/096de1b3/src/dnfile/stream.py#L62-L66
    # HeapItemBinary value is the bytes following the compressed int (indicating the length)
    # raw_data attribute has the compressed int indicating length included

    # HashValue format is bytes
    asmref["HashValue"] = check_attribute_exists(asmref_info.HashValue)
    add_assembly_flags_info(asmref, asmref_info)
    return asmref


def insert_implmap_info(im_info, imp_modules: list[dict[str, Any]]):
    # REFERENCE: https://github.com/malwarefrank/dnfile/blob/096de1b3/src/dnfile/stream.py#L36-L39
    # HeapItemString value will be decoded string, or None if there was a UnicodeDecodeError
    dllName = check_attribute_exists(im_info.ImportScope.row.Name)
    methodName = check_attribute_exists(im_info.ImportName)

    if dllName:
        for imp_module in imp_modules:
            if imp_module["Name"] == dllName:
                imp_module["Functions"].append(methodName)
                return
        imp_modules.append({"Name": dllName, "Functions": [methodName]})


def get_xmlns_and_tag(uri):
    check_xmlns = re.match(r"\{.*\}", uri.tag)
    xmlns = check_xmlns.group(0) if check_xmlns else ""
    tag = uri.tag
    if tag.startswith(xmlns):
        tag = tag.replace(xmlns, "", 1)
    return xmlns, tag


# check for manifest file on Windows (note: could also be a resource contained within an exe/dll)
# return any info that could be useful for establishing "Uses" relationships later
def get_windows_manifest_info(filename: str) -> dict[str, Any] | None:
    binary_filepath = pathlib.Path(filename)
    manifest_filepath = binary_filepath.with_suffix(binary_filepath.suffix + ".manifest")
    if manifest_filepath.exists():
        logger.info("Found application manifest file for " + filename)
        et = defusedxml.ElementTree.parse(manifest_filepath)
        manifest_info = {}

        # root element is <assembly> which could contain:
        # <assemblyIdentity>
        # <file>
        # <dependency>, which contains the usual <dependentAssembly> element found in Windows app config files
        for asm_e in et.getroot():
            asm_xmlns, asm_tag = get_xmlns_and_tag(asm_e)
            if asm_tag == "assemblyIdentity":
                if "assemblyIdentity" in manifest_info:
                    logger.warning(
                        "duplicate assemblyIdentity element found in the manifest file: "
                        + str(manifest_filepath)
                    )
                manifest_info["assemblyIdentity"] = asm_e.attrib
            if asm_tag == "file":
                if "file" not in manifest_info:
                    manifest_info["file"] = []
                manifest_info["file"].append(asm_e.attrib)
            if asm_tag == "dependency":
                if "dependency" in manifest_info:
                    logger.warning(
                        "duplicate dependency element found in the manifest file: "
                        + str(manifest_filepath)
                    )
                dependency_info: dict[str, Any] = {}
                for dependency in asm_e:
                    dependency_xmlns, dependency_tag = get_xmlns_and_tag(dependency)
                    if dependency_tag == "dependentAssembly":
                        if "dependentAssembly" not in dependency_info:
                            dependency_info["dependentAssembly"] = []
                        dependency_info["dependentAssembly"].append(
                            get_dependentAssembly_info(dependency)
                        )
                manifest_info["dependency"] = dependency_info
        return manifest_info
    return None


# returns info on a dependentAssembly
def get_dependentAssembly_info(da_et, config_filepath=""):
    daet_xmlns, daet_tag = get_xmlns_and_tag(da_et)
    if daet_tag != "dependentAssembly":
        logger.warning("element tree given was not for a dependentAssembly element tag")
    da_info = {}
    for da_e in da_et:
        da_xmlns, da_tag = get_xmlns_and_tag(da_e)
        if da_tag == "assemblyIdentity":
            if "assemblyIdentity" in da_info:
                logger.warning(
                    "duplicate assemblyIdentity element found in the app config file: "
                    + str(config_filepath)
                )
            da_info["assemblyIdentity"] = da_e.attrib
        if da_tag == "codeBase":
            if "codeBase" in da_info:
                logger.warning(
                    "duplicate codeBase element found in the app config file: "
                    + str(config_filepath)
                )
            da_info["codeBase"] = da_e.attrib
        if da_tag == "bindingRedirect":
            if "bindingRedirect" in da_info:
                logger.warning(
                    "duplicate bindingRedirect element found in the app config file: "
                    + str(config_filepath)
                )
            da_info["bindingRedirect"] = da_e.attrib
    return da_info


# returns a map for the given assembly binding element tree based on content within the element tree for an "assemblyBinding" tag
# the "assemblyBinding" tag can appear within either a <runtime> or <windows> element, or under the root <configuration> element
# <runtime>: could contain appliesTo attribute, probing, dependentAssembly, and qualifyAssembly elements
# <windows>: could contain probing, assemblyIdentity, and dependentAssembly elements
def get_assemblyBinding_info(ab_et, config_filepath=""):
    xmlns, tag = get_xmlns_and_tag(ab_et)
    if tag != "assemblyBinding":
        logger.warning("element tree given was not for an assemblyBinding tag")

    ab_info = {}

    # Specifies runtime version .NET assembly redirection applies to
    # uses .NET Framework version number; if not given, assemblyBinding
    # element applies to all versions of .NET Framework
    # ab_e.attrib["appliesTo"]
    if "appliesTo" in ab_et.attrib:
        ab_info["appliesTo"] = ab_et.attrib["appliesTo"]
    for ab_e in ab_et:
        ab_xmlns, ab_tag = get_xmlns_and_tag(ab_e)
        # <probing>
        # specifies subdirs of application's base dir to search for assemblies
        # privatePath: "bin;bin2\subbin;bin3"
        if ab_tag == "probing":
            if "probing" in ab_info:
                logger.warning(
                    "duplicate probing element found in the app config file: "
                    + str(config_filepath)
                )
            ab_info["probing"] = ab_e.attrib

        # <dependentAssembly> for .NET
        # binding policy and assembly location for dependent assemblies
        #   <assemblyIdentity>
        #   used to determine if this dependentAssembly config element should apply
        #   - name: name of the assembly
        #   - culture: (optional) specify language and country/region of assembly
        #   - publicKeyToken: (optional) specify assembly strong name
        #   - processorArchitecture: (optional) "x86", "amd64", "msil", or "ia64"
        #   <codeBase>
        #   specifies assembly to use; if not present, usual probing for assemblies
        #   - version: version of assembly the codebase applies to
        #   - href: URL where runtime can find specified version of assembly
        #   <bindingRedirect>
        #   redirect one assembly to another version
        #   - oldVersion: assembly version originally requested
        #   - newVersion: the assembly version to use instead
        if ab_tag == "dependentAssembly":
            if "dependentAssembly" not in ab_info:
                ab_info["dependentAssembly"] = []
            ab_info["dependentAssembly"].append(get_dependentAssembly_info(ab_e, config_filepath))

        # <qualifyAssembly>
        # replaces partial name in Assembly.Load with full name
        # - partialName: "math"
        # - fullName: "math,version=...,publicKeyToken=...,culture=neutral"
        if ab_tag == "qualifyAssembly":
            if "qualifyAssembly" in ab_info:
                logger.warning(
                    "duplicate qualifyAssembly element found in the app config file: "
                    + str(config_filepath)
                )
            ab_info["qualifyAssembly"] = ab_e.attrib
    return ab_info


# DLL redirection summary: redirection file with name_of_exe.local (contents are ignored) makes a check for mydll.dll happen in the application directory first,
# regardless of what the full path specified for LoadLibrary or LoadLibraryEx is (if no dll found in local directory, uses the typical search order)
def check_windows_dll_redirection_local(filename: str):
    binary_filepath = pathlib.Path(filename)
    config_filepath = binary_filepath.with_suffix(binary_filepath.suffix + ".local")
    return config_filepath.exists()


# check for an application configuration file and return (potentially) useful information
# https://learn.microsoft.com/en-us/dotnet/framework/deployment/how-the-runtime-locates-assemblies#application-configuration-file
# https://learn.microsoft.com/en-us/windows/win32/sbscs/application-configuration-files
def get_windows_application_config_info(filename: str):
    binary_filepath = pathlib.Path(filename)
    config_filepath = binary_filepath.with_suffix(binary_filepath.suffix + ".config")
    if config_filepath.exists():
        logger.info("Found application configuration file for " + filename)
        et = defusedxml.ElementTree.parse(config_filepath)
        app_config_info = {}

        # requiredRuntime is used for v1.0 of .NET Framework, supportedRuntime is for v1.1+
        supportedRuntime = et.find("./startup/supportedRuntime")
        requiredRuntime = et.find("./startup/requiredRuntime")
        if (supportedRuntime is not None) or (requiredRuntime is not None):
            startup_info = {}
            if (supportedRuntime is not None) and supportedRuntime.attrib:
                startup_info["supportedRuntime"] = supportedRuntime.attrib
            if (requiredRuntime is not None) and requiredRuntime.attrib:
                startup_info["requiredRuntime"] = requiredRuntime.attrib
            app_config_info["startup"] = startup_info

        # <linkedConfiguration href="URL of linked XML file" />
        # - seems to appear within an assemblyBinding element right under the root configuration element
        # - only format for href is `file://` either local or UNC
        # - includes assembly config file contents here, similar to #include
        linkedConfiguration = et.find("./assemblyBinding/linkedConfiguration")
        if (linkedConfiguration is not None) and linkedConfiguration.attrib:
            app_config_info["assemblyBinding"] = {"linkedConfiguration": linkedConfiguration.attrib}

        # The following appear within a <windows> element:
        # <probing privatePath="bin;..\bin2\subbin;bin3"/>
        # - valid starting on Windows Server 2008 R2 and Windows 7
        # - privatePath: (optional) specifies relative paths of subdirs of the app base dir that might contain assemblies
        # <assemblyBinding>
        # - first element must be an assemblyIdentity describing the assembly; followed by dependentAssembly elements (also below)
        #   <probing privatePath="bin;..\bin2\subbin;bin3"/>
        #   - valid starting on Windows Server 2008 R2 and Windows 7
        #   - privatePath: (optional) specifies relative paths of subdirs of the app base dir that might contain assemblies
        # <dependency> (based on the app config file schema, this
        # - contains one or more dependentAssembly elements (optional)
        #  <dependentAssembly>
        #  - contains assemblyIdentity that unique identifies an app
        #  - app config file redirects binding of application to side-by-side assemblies
        #    <assemblyIdentity processorArchitecture="X86" name="Microsoft.Windows.mysampleApp" type="win32" version="1.0.0.0"/>
        #    - describes side-by-side assembly the application depends on
        #    - type: must be "win32" lowercase
        #    - name: identifies app being affected by app config file or assembly being redirected
        #    - language: (optional) identifies the language by DHTML code or "*" if language neutral/worldwide use
        #    - processorArchitecture: the processor running the application
        #    - version: version of app or assembly
        #    - publicKeyToken: 16-char hex string w/ last 8 bytes of SHA-1 hash of public key the assembly is signed by
        #    <bindingRedirect oldVersion="1.0.0.0" newVersion="1.0.10.0"/>
        #    - oldVersion: assembly version being overridden or redirected
        #    - newVersion: replacement assembly version
        windows_et = et.find("./windows")
        if windows_et is not None:
            windows_info = {}
            for win_child in windows_et:
                xmlns, tag = get_xmlns_and_tag(win_child)
                if tag == "probing":
                    if "probing" in windows_info:
                        logger.warning(
                            "duplicate windows/probing element was found in the app config file: "
                            + str(config_filepath)
                        )
                    if "privatePath" in win_child.attrib:
                        windows_info["probing"] = {"privatePath": win_child.attrib["privatePath"]}
                    else:
                        logger.warning(
                            "windows/probing element missing privatePath attribute in app config file: "
                            + str(config_filepath)
                        )
                if tag == "assemblyBinding":
                    windows_info["assemblyBinding"] = get_assemblyBinding_info(win_child)
                if tag == "dependency":
                    dependency_info: dict[str, Any] = {}
                    for dependency in win_child:
                        dependency_xmlns, dependency_tag = get_xmlns_and_tag(dependency)
                        if dependency_tag == "dependentAssembly":
                            if "dependentAssembly" not in dependency_info:
                                dependency_info["dependentAssembly"] = []
                            dependency_info["dependentAssembly"].append(
                                get_dependentAssembly_info(dependency, config_filepath)
                            )
                    windows_info["dependency"] = dependency_info
            app_config_info["windows"] = windows_info

        # runtime element used for .NET related configuration info that can affect how the runtime locates assemblies to load
        runtime_et = et.find("./runtime")
        if runtime_et is not None:
            runtime_info = {}
            for rt_child in runtime_et:
                # Docs say "urn:schemas-microsoft-com:asm.v1" is the namespace for assemblyBinding
                xmlns, tag = get_xmlns_and_tag(rt_child)
                if tag == "developmentMode":
                    # attribute is either 'true' or 'false' (string)
                    # Causes runtime to search directory given in DEVPATH env var for assemblies first (skips signature checks)
                    if "developmentMode" in runtime_info:
                        logger.warning(
                            "duplicate developmentMode element was found in the app config file: "
                            + str(config_filepath)
                        )
                    if "developerInstallation" in rt_child.attrib:
                        runtime_info["developmentMode"] = {
                            "developerInstallation": rt_child.attrib["developerInstallation"]
                        }
                    else:
                        logger.warning(
                            "developmentMode element missing developerInstallation attribute in app config file: "
                            + str(config_filepath)
                        )
                if tag == "assemblyBinding":
                    runtime_info["assemblyBinding"] = get_assemblyBinding_info(
                        rt_child, config_filepath
                    )
            app_config_info["runtime"] = runtime_info

        # Info returned includes:
        # - runtime information related to .NET
        # - config options (codeBase, probing) that affect how .NET assemblies are located
        # - config options (probing) that affect how native Windows DLLs are found
        # - assembly identity info (processor targeted, etc)
        # - dependent assembly info (used to determine correct version of an assembly to use)
        return app_config_info
    return None
