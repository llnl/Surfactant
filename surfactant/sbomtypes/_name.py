from dataclasses import dataclass
from typing import Optional


@dataclass
class NameEntry:
    nameValue: Optional[str] = None
    nameType: Optional[str] = None

    def __post_init__(self) -> None:
        if self.nameValue is not None and not isinstance(self.nameValue, str):
            raise TypeError("nameValue must be a string or None")
        if self.nameType is not None and not isinstance(self.nameType, str):
            raise TypeError("nameType must be a string or None")