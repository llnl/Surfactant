from sys import modules
from typing import Any

try:
    import javatools.jarinfo
except ModuleNotFoundError:
    pass

import surfactant.plugin
from surfactant.sbomtypes import SBOM, Software

# TODO: Add documentation about how to install javatools
# swig and libssl-dev needs to be installed on Ubuntu
# https://gitlab.com/m2crypto/m2crypto/-/blob/master/INSTALL.rst


def supports_file(filetype: list[str]) -> bool:
    supported_types = ("JAVACLASS", "JAR", "WAR", "EAR")
    for ft in filetype:
        if ft in supported_types:
            return True
    return False


@surfactant.plugin.hookimpl
def extract_file_info(sbom: SBOM, software: Software, filename: str, filetype: list[str]) -> object:
    if not supports_file(filetype):
        return None
    if "javatools" not in modules:
        # If the optional "java" dependency group isn't installed, skip gathering this info
        # javatools is LGPL licensed so making it optional is probably safer legally
        # and javatools also depends on Cheetah3 (ct3), which uses a compiled Python extension
        # that makes it less than portable (project isn't releasing pre-compiled wheels for
        # many platforms... and we don't use any of the functionality that depends on ct3)
        # In the future, may want to write our own simpler module to handle java class files
        # that could also support newer JDK opcodes, since javatools doesn't seem to get updated
        # regularly either
        return None
    return extract_java_info(filename, filetype)


# Map from internal major number to Java SE version
# https://docs.oracle.com/javase/specs/jvms/se20/html/jvms-4.html#jvms-4.1-200-B.2
_JAVA_VERSION_MAPPING = {
    45: "1.1",
    46: "1.2",
    47: "1.3",
    48: "1.4",
    49: "5.0",
    50: "6",
    51: "7",
    52: "8",
    53: "9",
    54: "10",
    55: "11",
    56: "12",
    57: "13",
    58: "14",
    59: "15",
    60: "16",
    61: "17",
    62: "18",
    63: "19",
    64: "20",
}


def handle_java_class(info: dict[str, Any], class_info: "javatools.JavaClassInfo"):
    # This shouldn't happen but just in-case it does don't overwrite information
    if class_info.get_this() in info["javaClasses"]:
        return
    info["javaClasses"][class_info.get_this()] = {}
    add_to = info["javaClasses"][class_info.get_this()]
    (major_version, _) = class_info.get_version()
    if major_version in _JAVA_VERSION_MAPPING:
        add_to["javaMinSEVersion"] = _JAVA_VERSION_MAPPING[major_version]
    add_to["javaExports"] = [*class_info.get_provides()]
    # I've seen this fail for some reason; catch errors on it and just ignore
    # them if it fails
    try:
        add_to["javaImports"] = [*class_info.get_requires()]
    except IndexError:
        # Should this be set to "Unknown" or similar?
        add_to["javaImports"] = []


def extract_java_info(filename: str, filetype: list[str]) -> object:
    info: dict[str, Any] = {"javaClasses": {}}
    if "JAR" in filetype or "EAR" in filetype or "WAR" in filetype:
        with javatools.jarinfo.JarInfo(filename) as jarinfo:
            for class_ in jarinfo.get_classes():
                handle_java_class(info, jarinfo.get_classinfo(class_))
    elif "JAVACLASS" in filetype:
        with open(filename, "rb") as f:
            class_info = javatools.JavaClassInfo()
            class_info.unpack(javatools.unpack(f))
        handle_java_class(info, class_info)
    return info
