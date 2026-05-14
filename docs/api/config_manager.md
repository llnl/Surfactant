# ConfigManager

The `ConfigManager` class is used to handle settings stored in a configuration file. It supports reading and writing configuration values while preserving formatting and comments, and it caches the configuration to avoid reloading it multiple times during the application's runtime. The underlying config file location is dependent on the operating system, though typically follows the XDG directory specification and respects the `XDG_CONFIG_HOME` environment variable on Unix-like platforms. On Windows, the configuration file is stored in the AppData Roaming folder (`%APPDATA%`).

## Usage

## Configuration File Location

The location of the configuration file varies depending on the platform:

- **Windows**: `%AppData%\surfactant\config.toml`
- **macOS**: `${XDG_CONFIG_HOME}/surfactant/config.toml`
- **Linux**: `${XDG_CONFIG_HOME}/surfactant/config.toml`

For systems that use `XDG_CONFIG_HOME`, if the environment variable is not set then the default location is `~/.config`.

## Example Configuration File

Here is an example of what the configuration file might look like:

```toml
[core]
author_name = "LLNL"
author_type = "organization"
```

### Initialization

To initialize the `ConfigManager`, simply import and create an instance:

```python
from surfactant.configmanager import ConfigManager

config_manager = ConfigManager()
```

This automatically handles loading a copy of the config file the first time an instance of the ConfigManager is created, effectively making it a snapshot in time of the configuration settings.

### Getting a Value

To retrieve a stored value, use the `get` method:

```python
value = config_manager.get('section', 'option', fallback='default_value')
```

- `section`: The section within the configuration file. For plugins this should be the plugin name.
- `option`: The option within the section.
- `fallback`: The fallback value if the option is not found.

Alternatively, dictionary-like access for reading is also supported:

```python
value = config_manager['section']['option']
```

However, this makes no guarantees that keys will exist and extra error handling **will be required**. If the `section` is not found then `None` is returned -- trying to access nested keys from this will fail. Furthermore, if the `section` does exist, you will need checks to see if a nested key exists before trying to access its value. A more realistic example would be:

```python
section_config = config_manager['section'] # May return `None`
value = section_config['option'] if section_config and 'option' in section_config else None
```

### Setting a Value

To set a value, use the `set` method:

```python
config_manager.set('section', 'option', 'new_value')
```

- `section`: The section within the configuration file. For plugins this should be the plugin name.
- `option`: The option within the section.
- `value`: The value to set.

NOTE: Most use cases should not need this.

### Saving the Configuration File

The configuration file is automatically saved when you set a value. The file can be manual saved using:

```python
config_manager._save_config()
```

NOTE: Most use cases should not need this.

### Loading the Configuration File

The configuration file can be reloaded using:

```python
config_manager._load_config()
```

NOTE: Most use cases should not need this.
