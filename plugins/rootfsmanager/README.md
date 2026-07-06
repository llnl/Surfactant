# rootfs Manager for Surfactant

A plugin that manages `rootfs` files for Surfactant based on ELF metadata.

## Quickstart

In the same virtual environment that Surfactant was installed in, install this plugin with `pip install .`.
If pipx was used to install Surfactant, install this plugin with
`pipx inject surfactant git+https://github.com/LLNL/Surfactant#subdirectory=plugins/rootfsmanager`.

For developers making changes to this plugin, install it with `pip install -e .`.

## Uninstalling

This plugin can be uninstalled with `pip uninstall surfactantplugin-rootfsmanager`.
If pipx was used, it can be uninstalled with
`pipx uninject surfactant surfactantplugin-rootfsmanager`
