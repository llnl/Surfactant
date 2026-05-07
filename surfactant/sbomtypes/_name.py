from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


def _string_or_empty(value: Any, field_name: str) -> str:
    if value is None:
        return ""

    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")

    return value


@dataclass
class NameEntry:
    nameValue: str = ""
    nameType: str = ""

    def validate(self) -> None:
        if not isinstance(self.nameValue, str):
            raise TypeError("nameValue must be a string")
        if not isinstance(self.nameType, str):
            raise TypeError("nameType must be a string")

    @classmethod
    def from_hint(cls, value: Any) -> "NameEntry":
        if isinstance(value, cls):
            return value

        if isinstance(value, str):
            return cls(nameValue=value)

        if isinstance(value, Mapping):
            if "nameValue" in value:
                return cls(
                    nameValue=_string_or_empty(value.get("nameValue"), "nameValue"),
                    nameType=_string_or_empty(value.get("nameType"), "nameType"),
                )

            if "name" in value:
                return cls(
                    nameValue=_string_or_empty(value.get("name"), "name"),
                    nameType=_string_or_empty(value.get("nameType"), "nameType"),
                )

            raise TypeError("name hint mappings must contain 'nameValue' or legacy 'name'")

        raise TypeError("name hints must be NameEntry, mapping, or string")
