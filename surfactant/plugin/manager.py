# Copyright 2023 Lawrence Livermore National Security, LLC
# See the top-level LICENSE file for details.
#
# SPDX-License-Identifier: MIT
import sys
from typing import Any, List, Optional

import pluggy
from loguru import logger

from surfactant.configmanager import ConfigManager
from surfactant.plugin import hookspecs


def _register_plugins(pm: pluggy.PluginManager) -> None:
    # pylint: disable=import-outside-toplevel
    # don't want all these imports as part of the file-level scope
    from surfactant.filetypeid import id_extension, id_hex, id_magic
    from surfactant.infoextractors import (
        a_out_file,
        coff_file,
        docker_image,
        elf_file,
        file_decompression,
        java_file,
        js_file,
        mach_o_file,
        native_lib_file,
        ole_file,
        pe_file,
        rpm_file,
        srec_hex,
        uimage_file,
    )
    from surfactant.input_readers import cytrics_reader
    from surfactant.output import (
        csv_writer,
        cyclonedx_writer,
        cytrics_writer,
        spdx_writer,
    )
    from surfactant.relationships import (
        dotnet_relationship,
        elf_relationship,
        java_relationship,
        pe_relationship,
    )

    internal_plugins = (
        id_magic,
        id_hex,
        id_extension,
        a_out_file,
        coff_file,
        docker_image,
        elf_file,
        java_file,
        mach_o_file,
        js_file,
        pe_file,
        ole_file,
        srec_hex,
        uimage_file,
        rpm_file,
        dotnet_relationship,
        elf_relationship,
        java_relationship,
        pe_relationship,
        csv_writer,
        cytrics_writer,
        cyclonedx_writer,
        spdx_writer,
        cytrics_reader,
        native_lib_file,
        file_decompression,
    )
    for plugin in internal_plugins:
        pm.register(plugin)


def set_blocked_plugins(pm: pluggy.PluginManager) -> None:
    """Gets the current list of blocked plugins from the config manager, then blocks and unregisters them with the plugin manager."""
    config_manager = ConfigManager()

    # Retrieve the current list of blocked plugins
    current_blocked_plugins = config_manager.get("core", "disable_plugins", [])
    for plugin_name in current_blocked_plugins:
        # Check if the plugin is already blocked
        if pm.is_blocked(plugin_name):
            logger.info(f"Plugin '{plugin_name}' is already disabled.")
            continue

        # Unregister the plugin
        plugin = pm.unregister(name=plugin_name)
        if plugin is None:
            logger.info(f"Disabled plugin '{plugin_name}' not found.")
            continue

        # Block the plugin to prevent future registration
        pm.set_blocked(plugin_name)


def is_plugin_blocked(pm: pluggy.PluginManager, plugin_name: str) -> bool:
    """
    Check if a plugin is blocked in the plugin manager.

    Args:
        pm (pluggy.PluginManager): The plugin manager instance.
        plugin_name (str): The name of the plugin to check.

    Returns:
        bool: True if the plugin is blocked, False otherwise.
    """
    if pm.is_blocked(plugin_name):
        return True
    return False


def get_plugin_manager() -> pluggy.PluginManager:
    pm = pluggy.PluginManager("surfactant")
    pm.add_hookspecs(hookspecs)
    pm.load_setuptools_entrypoints("surfactant")
    _register_plugins(pm)
    set_blocked_plugins(pm)
    pm.check_pending()
    return pm


def is_hook_implemented(pm: pluggy.PluginManager, plugin: object, hook_name: str) -> bool:
    """
    Checks if a specific hook is implemented by a given plugin.

    Args:
        pm (pluggy.PluginManager): The plugin manager instance.
        plugin (object): The plugin object to check.
        hook_name (str): The name of the hook to check for implementation.

    Returns:
        bool: True if the hook is implemented by the plugin, False otherwise.
    """
    hook_callers = pm.get_hookcallers(plugin)
    if hook_callers:
        for hook_caller in hook_callers:
            if hook_caller.name == hook_name:
                return True
    return False


def print_plugins(pm: pluggy.PluginManager) -> None:
    print("PLUGINS")
    for plugin in pm.get_plugins():
        plugin_name = pm.get_name(plugin) if pm.get_name(plugin) else ""
        print(f"\t> name: {plugin_name}")
        print(f"\t  canonical name: {pm.get_canonical_name(plugin)}")

        short_name = None

        # Check if the plugin has implemented the short_name hook
        hook_impl = is_hook_implemented(pm, plugin, "short_name")

        if hook_impl:
            short_name = plugin.short_name()  # Get the short name

        print(f"\t  short name: {short_name}\n")


def find_io_plugin(pm: pluggy.PluginManager, io_format: str, function_name: str) -> Optional[Any]:
    """
    Finds and returns a plugin that matches the specified input/output format and has the desired function.

    Args:
        pm (pluggy.PluginManager): The plugin manager instance.
        io_format (str): The name that the plugin is registered as.
        function_name (str): The name of the function.

    Returns:
        Optional[Any]: The found plugin instance that matches the specified `io_format` and
                        implements the `function_name`, or `None` if no such plugin is found.
                        If no plugin is found, an error is logged, and the program exits.

    Raises:
        SystemExit: If no plugin matching the criteria is found, the function logs an error message
                     and exits the program.
    """

    found_plugin = pm.get_plugin(io_format)

    if found_plugin is None:
        for plugin in pm.get_plugins():
            try:
                if plugin.short_name().lower() == io_format.lower() and hasattr(
                    plugin, function_name
                ):
                    found_plugin = plugin
                    break
            except AttributeError:
                pass

    if found_plugin is None:
        logger.error(f'No "{function_name}" plugin for format "{io_format}" found')
        sys.exit(1)

    return found_plugin


def find_plugin_by_name(pm: pluggy.PluginManager, name: str) -> Optional[Any]:
    """
    Finds a plugin by matching the given name against the plugin's registered name,
    canonical name, and its short name (if applicable).

    Args:
        pm (pluggy.PluginManager): The plugin manager instance.
        name (str): The name to match against the plugin's registered, canonical, and short names.

    Returns:
        Optional[Any]: The matched plugin instance or None if no match is found.
    """
    # Convert the name to lowercase for case-insensitive comparison
    name_lower = name.lower()

    for plugin in pm.get_plugins():
        # Get the registered and canonical names
        registered_name = pm.get_name(plugin).lower()
        canonical_name = pm.get_canonical_name(plugin).lower()

        # Check if the plugin has implemented the short_name hook
        short_name = None
        hook_impl = is_hook_implemented(pm, plugin, "short_name")

        if hook_impl:
            short_name = plugin.short_name()  # Get the short name

        # Convert short_name to lowercase if it exists
        short_name_lower = short_name.lower() if short_name else None

        # Check if any of the names match the given name
        if name_lower in (registered_name, canonical_name, short_name_lower):
            return plugin

    return None


def call_init_hooks(
    pm: pluggy.PluginManager, hook_filter: List[str] = None, command_name: str = None
) -> None:
    """
    Call the initialization hook for plugins that implement it.

    Args:
        pm (pluggy.PluginManager): The plugin manager instance.
        hook_filter (List[str]): A list of hook names to filter which plugins get initialized.
        command_name (str): The name of the command invoking the initialization.
    """
    for plugin in pm.get_plugins():
        if is_hook_implemented(pm, plugin, "init_hook"):
            # Check if the plugin implements any of the hooks in the filter
            if hook_filter:
                if not any(is_hook_implemented(pm, plugin, hook) for hook in hook_filter):
                    continue
            plugin.init_hook(command_name=command_name)
