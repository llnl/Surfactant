from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class NameEntry:
    nameValue: Optional[str] = None
    nameType: Optional[str] = None

    def __post_init__(self) -> None:
        if self.nameValue is not None and not isinstance(self.nameValue, str):
            raise TypeError("nameValue must be a string or None")
        if self.nameType is not None and not isinstance(self.nameType, str):
            raise TypeError("nameType must be a string or None")

    @classmethod
    def from_hint(cls, value: Any) -> "NameEntry":
        if isinstance(value, cls):
            return value

        if isinstance(value, str):
            return cls(nameValue=value)

        if isinstance(value, Mapping):
            if "nameValue" in value:
                return cls(
                    nameValue=value.get("nameValue"),
                    nameType=value.get("nameType"),
                )

            if "name" in value:
                return cls(
                    nameValue=value["name"],
                    nameType=value.get("nameType"),
                )

            raise TypeError(
                "name hint mappings must contain 'nameValue' or legacy 'name'"
            )

        raise TypeError("name hints must be NameEntry, mapping, or string")