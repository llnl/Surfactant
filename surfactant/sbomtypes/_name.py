from dataclasses import dataclass


@dataclass
class NameEntry:
    nameValue: str
    nameType: str

    def __post_init__(self) -> None:
        if not isinstance(self.nameValue, str):
            raise TypeError("nameValue must be a string")
        if not isinstance(self.nameType, str):
            raise TypeError("nameType must be a string")