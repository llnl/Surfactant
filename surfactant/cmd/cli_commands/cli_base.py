import pickle

from loguru import logger

from surfactant.configmanager import ConfigManager
from surfactant.sbomtypes._sbom import SBOM


class Cli:
    """
    A base class that implements the surfactant cli basic functionality

    Attributes:
        sbom: An internal record of sbom entries the class adds to as it finds more matches.
        subset: An internal record of the subset of sbom entries from the last cli find call.
        sbom_filename: A string value of the filename where the loaded sbom is stored.
        subset_filename: A string value of the filename where the current subset result from the "cli find" command is stored.
        match_functions: A dictionary of functions that provide matching functionality for given SBOM fields (i.e. uuid, sha256, installpath, etc)
        camel_case_conversions: A dictionary of string conversions from all lowercase to camelcase. Used to convert python click options to match the SBOM attribute's case

    """

    sbom: SBOM = None
    subset: SBOM = None
    sbom_filename: str
    subset_filename: str
    match_functions: dict
    camel_case_conversions: dict

    def __init__(self):
        self.sbom_filename = "sbom_cli"
        self.subset_filename = "subset_cli"
        # Create data directory
        self.data_dir = ConfigManager().get_data_dir_path()
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def serialize(sbom: SBOM):
        """Serializes a given sbom.

        Args:
            bom (SBOM): An instance of an SBOM to serialize

        Returns:
            bytes: A binary representation of the serialized SBOM.
        """
        if isinstance(sbom, SBOM):
            return pickle.dumps(sbom)
        logger.error(f"Could not serialize sbom - {type(sbom)} is not of type SBOM")
        return None

    @staticmethod
    def deserialize(data) -> SBOM:
        """Deserializes the given data and saves them in the SBOM class instance

        Args:
            data (bytes): The data to deserialize into an SBOM type

        Returns:
            SBOM: An SBOM instance.
        """
        try:
            return pickle.loads(data)
        except pickle.UnpicklingError as e:
            logger.error(f"Could not deserialize sbom from given data - {e}")
            return None
