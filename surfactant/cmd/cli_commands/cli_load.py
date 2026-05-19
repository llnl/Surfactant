from pathlib import Path

from surfactant.cmd.cli_commands.cli_base import Cli
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager


class Load(Cli):
    """
    A class that implements the surfactant cli load functionality

    Attributes:
        input_format (str): The format for input sboms
    """

    def __init__(self, *args, input_format, **kwargs):
        """Executes the load class constructor

        Args:
            input_format (str): The format of the sbom being loaded
        """
        self.input_format = input_format
        super().__init__(*args, **kwargs)

    def execute(self, input_file):
        """Executes the main functionality of the load class

        Args:
            input_file: The sbom load into the cli
        """
        pm = get_plugin_manager()
        input_reader = find_io_plugin(pm, self.input_format, "read_sbom")
        self.sbom = input_reader.read_sbom(input_file)

        serialized_sbom = Cli.serialize(self.sbom)
        with Path(self.data_dir, self.sbom_filename).open("wb") as f:
            f.write(serialized_sbom)
