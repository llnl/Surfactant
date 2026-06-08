# Copyright 2025 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT

import re
from dataclasses import dataclass

from surfactant.plugin.manager import get_plugin_manager


@dataclass
class PluginSetting:
    name: str
    type_: str | None
    description: str
    default: str | None


def extract_plugin_settings() -> dict[str, list[PluginSetting]]:
    """Extract settings information from plugin docstrings"""
    settings = {}
    pm = get_plugin_manager()
    for plugin in pm.get_plugins():
        if (
            plugin.__doc__
            and plugin.__doc__.find("Config Options:") != -1
            and plugin.settings_name()
        ):
            settings[plugin.settings_name()] = extract_settings_from_docstring(plugin.__doc__)
    return settings


__option_re = re.compile(r"([^(:]+)\s*([(][^)]+[)])?:(.*)")


def extract_settings_from_docstring(docstring: str) -> list[PluginSetting]:
    def count_leading_indentation(s: str) -> int:
        indent_amount = 0
        while indent_amount < len(s) and s[indent_amount].isspace():
            indent_amount += 1
        return indent_amount

    lines = docstring.splitlines()
    line_no = 0
    # Skip to the config options line
    while not lines[line_no].strip().startswith("Config Options:"):
        line_no += 1

    # Count the indentation of the next line (which should be the first option)
    line_no += 1
    indentation_amount = count_leading_indentation(lines[line_no])

    # Split by option (based on leading whitespace)
    settings_lines = []
    while line_no < len(lines) and count_leading_indentation(lines[line_no]) == indentation_amount:
        cur_line = lines[line_no].strip()
        while (
            line_no + 1 < len(lines)
            and count_leading_indentation(lines[line_no + 1]) > indentation_amount
        ):
            line_no += 1
            cur_line += " " + lines[line_no].strip()
        line_no += 1
        settings_lines.append(cur_line)

    settings = []
    for settings_line in settings_lines:
        m = __option_re.match(settings_line)
        if m:
            name, type_, desc = m.groups()
            # Remove the parentheses if a type was matched
            if type_:
                type_ = type_.strip()[1:][:-1].strip()
            default_value = None
            # Search for the start of the default string
            loc = desc.rfind("[default=")
            if loc != -1:
                end_loc = desc.rfind("]")
                default_value = desc[loc + 9 : end_loc].strip()
                desc = desc[:loc].strip()
            settings.append(PluginSetting(name.strip(), type_, desc.strip(), default_value))

    return settings
