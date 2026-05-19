from pathlib import Path

from surfactant.cmd.cli_commands.cli_base import Cli
from surfactant.plugin.manager import find_io_plugin, get_plugin_manager


class Save(Cli):
    """
    A class that implements the surfactant cli save functionality

    Attributes:
        output_format (str): The format of the sbom to be outputted
    """

    def __init__(self, *args, output_format, **kwargs):
        """Executes the load class constructor

        Args:
            output_format (str): The format of the sbom to be outputted
        """
        self.output_format = output_format
        super().__init__(*args, **kwargs)

    def execute(self, output_file):
        """Executes the main functionality of the load class

        Args:
            output_file:  The file to save the sbom to
        """
        pm = get_plugin_manager()
        output_writer = find_io_plugin(pm, self.output_format, "write_sbom")

        with Path(self.data_dir, self.sbom_filename).open("rb") as f:
            data = f.read()
        self.sbom = Cli.deserialize(data)
        output_writer.write_sbom(self.sbom, output_file)
