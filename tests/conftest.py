"""Test configuration to keep the suite hermetic with respect to user config.

Several command modules read global settings through ConfigManager at import
time (for example the click ``--output_format`` default in
``surfactant/cmd/generate.py``). ConfigManager is a process-wide singleton
that, with the default ``config_dir=None``, reads the developer's real user
config such as ``~/.config/surfactant/config.toml``. An invalid value there
(for example ``core.output_format = ""``) then makes otherwise-correct tests
fail, which is exactly the problem reported in issue #470.

To make the suite independent of any global settings, point the config and
data lookups at empty temporary directories. This is done at module import
(before test modules import the command modules whose defaults are evaluated
eagerly) and again per test for anything created at runtime.
"""

import os
import tempfile

import pytest

from surfactant.configmanager import ConfigManager

# Redirect config/data lookups to empty temp dirs before any test module
# imports command modules that read config defaults at import time.
_ISOLATED_CONFIG_DIR = tempfile.mkdtemp(prefix="surfactant-test-config-")
_ISOLATED_DATA_DIR = tempfile.mkdtemp(prefix="surfactant-test-data-")
os.environ["XDG_CONFIG_HOME"] = _ISOLATED_CONFIG_DIR
os.environ["XDG_DATA_HOME"] = _ISOLATED_DATA_DIR
os.environ["APPDATA"] = _ISOLATED_CONFIG_DIR
os.environ["LOCALAPPDATA"] = _ISOLATED_DATA_DIR
ConfigManager._instances.clear()  # pylint: disable=protected-access


@pytest.fixture(autouse=True)
def isolate_surfactant_config(tmp_path, monkeypatch):
    """Give every test a clean, isolated ConfigManager backed by empty dirs."""
    config_home = tmp_path / "config"
    data_home = tmp_path / "data"
    config_home.mkdir()
    data_home.mkdir()

    # Unix-like lookups (see ConfigManager._get_config_file_path / get_data_dir_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.setenv("XDG_DATA_HOME", str(data_home))
    # Windows lookups
    monkeypatch.setenv("APPDATA", str(config_home))
    monkeypatch.setenv("LOCALAPPDATA", str(data_home))

    ConfigManager._instances.clear()  # pylint: disable=protected-access
    yield
    ConfigManager._instances.clear()  # pylint: disable=protected-access
