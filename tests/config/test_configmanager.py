import os
import platform
from pathlib import Path

import pytest

from surfactant.configmanager import ConfigManager


@pytest.fixture(name="config_manager")
def fixture_config_manager(tmp_path):
    # Use the tmp_path fixture for the temporary directory
    config_manager = ConfigManager(app_name="testapp", config_dir=tmp_path)
    yield config_manager
    # Cleanup after test
    ConfigManager.delete_instance("testapp")


def test_singleton(config_manager):
    config_manager2 = ConfigManager(app_name="testapp")
    assert config_manager is config_manager2


def test_set_and_get(config_manager):
    config_manager.set("Settings", "theme", "dark")
    theme = config_manager.get("Settings", "theme")
    assert theme == "dark"


def test_set_and_getitem(config_manager):
    config_manager.set("Settings", "theme", "dark")
    theme = config_manager["Settings"]["theme"]
    assert theme == "dark"


def test_createinstance_and_getitem(config_manager):
    config_manager.set("Settings", "theme", "dark")
    # ConfigManager instance accessed will be the same as the one created in the test fixture
    # so that the set value above will be present for testing
    settings_config = ConfigManager(app_name="testapp")["Settings"]
    assert settings_config
    assert "theme" in settings_config  # pylint: disable=unsupported-membership-test
    assert settings_config["theme"] == "dark"  # pylint: disable=unsubscriptable-object


def test_get_with_fallback(config_manager):
    fallback_value = "light"
    theme = config_manager.get("Settings", "theme", fallback=fallback_value)
    assert theme == fallback_value


def test_config_file_creation(config_manager):
    config_manager.set("Settings", "theme", "dark")
    assert config_manager.config_file_path.exists()


@pytest.mark.skipif(platform.system() != "Windows", reason="Test specific to Windows platform")
def test_windows_config_path():
    config_manager = ConfigManager(app_name="testapp")
    config_path = config_manager._get_config_file_path()  # pylint: disable=protected-access
    expected_config_dir = Path(os.getenv("APPDATA", str(Path("~\\AppData\\Roaming").expanduser())))
    assert expected_config_dir in config_path.parents
    assert config_path.parts[-2:] == ("testapp", "config.toml")
    # delete instance so other tests don't accidentally use it
    config_manager.delete_instance("testapp")


@pytest.mark.skipif(platform.system() == "Windows", reason="Test specific to Unix-like platforms")
def test_unix_config_path():
    config_manager = ConfigManager(app_name="testapp")
    config_path = config_manager._get_config_file_path()  # pylint: disable=protected-access
    expected_config_dir = Path(os.getenv("XDG_CONFIG_HOME", str(Path("~/.config").expanduser())))
    assert expected_config_dir in config_path.parents
    assert config_path.parts[-2:] == ("testapp", "config.toml")
    # delete instance so other tests don't accidentally use it
    config_manager.delete_instance("testapp")


@pytest.mark.skipif(platform.system() != "Windows", reason="Test specific to Windows platform")
def test_windows_data_dir_path():
    config_manager = ConfigManager(app_name="testapp")
    data_dir = config_manager.get_data_dir_path()  # pylint: disable=protected-access
    expected_data_dir = Path(os.getenv("LOCALAPPDATA", str(Path("~\\AppData\\Local").expanduser())))
    assert expected_data_dir in data_dir.parents
    assert data_dir.name == "testapp"
    # delete instance so other tests don't accidentally use it
    config_manager.delete_instance("testapp")


@pytest.mark.skipif(platform.system() == "Windows", reason="Test specific to Unix-like platforms")
def test_unix_data_dir_path():
    config_manager = ConfigManager(app_name="testapp")
    data_dir = config_manager.get_data_dir_path()  # pylint: disable=protected-access
    expected_data_dir = Path(os.getenv("XDG_DATA_HOME", str(Path("~/.local/share").expanduser())))
    assert expected_data_dir in data_dir.parents
    assert data_dir.name == "testapp"
    # delete instance so other tests don't accidentally use it
    config_manager.delete_instance("testapp")


def test_preserve_comments(config_manager):
    # Create a config file with some value and add in a comment line
    config_manager.set("Settings", "theme", "dark")
    with open(config_manager.config_file_path, "a") as configfile:
        configfile.write("\n# This is a comment\n")
    # Force reload of cached config in the ConfigManager
    config_manager._load_config()  # pylint: disable=protected-access
    assert config_manager.get("Settings", "theme") == "dark"

    # Set a new value to make ConfigManager to save an updated config file
    config_manager.set("Settings", "language", "en")
    with open(config_manager.config_file_path) as configfile:
        content = configfile.read()
    assert "# This is a comment" in content


def test_multiple_instances(tmp_path):
    # Make sure two separate config managers can more or less co-exist peacefully
    config_manager1 = ConfigManager(app_name="testapp1", config_dir=tmp_path)
    config_manager2 = ConfigManager(app_name="testapp2", config_dir=tmp_path)
    config_manager1.set("Settings", "theme", "dark")
    config_manager2.set("Settings", "theme", "light")
    assert config_manager1.get("Settings", "theme") == "dark"
    assert config_manager2.get("Settings", "theme") == "light"
    assert config_manager1.config_file_path.exists()
    assert config_manager2.config_file_path.exists()
    assert config_manager1.config_file_path != config_manager2.config_file_path
    ConfigManager.delete_instance("testapp1")
    ConfigManager.delete_instance("testapp2")


if __name__ == "__main__":
    pytest.main()
