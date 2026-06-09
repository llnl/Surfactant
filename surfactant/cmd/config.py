from typing import Any

import click

from surfactant.configmanager import ConfigManager


@click.command("config")
@click.argument("key", required=True)
@click.argument("values", nargs=-1)
def config(key: str, values: list[str] | None):
    """Get or set a configuration value.

    If only KEY is provided, the current value is displayed.
    If both KEY and one or more VALUES are provided, the configuration value is set.
    KEY should be in the format 'section.option'.
    """
    config_manager = ConfigManager()

    if not values:
        # Get the configuration value
        try:
            section, option = key.split(".", 1)
        except ValueError as err:
            raise SystemExit("Invalid KEY given. Is it in the format 'section.option'?") from err
        result = config_manager.get(section, option)
        if result is None:
            click.echo(f"Configuration '{key}' not found.")
        else:
            click.echo(f"{key} = {result}")
    else:
        # Set the configuration value
        # Convert 'true' and 'false' strings to boolean
        converted_values: list[Any] = []
        for value in values:
            if value.lower() == "true":
                converted_values.append(True)
            elif value.lower() == "false":
                converted_values.append(False)
            else:
                converted_values.append(value)

        # If there's only one value, store it as a single value, otherwise store as a list
        final_value = converted_values[0] if len(converted_values) == 1 else converted_values

        try:
            section, option = key.split(".", 1)
        except ValueError as err:
            raise SystemExit("Invalid KEY given. Is it in the format 'section.option'?") from err
        config_manager.set(section, option, final_value)
        click.echo(f"Configuration '{key}' set to '{final_value}'.")
