"""Schema-focused tests for CyTRICS captureTime fields.

These tests validate that Surfactant's captureTime handling remains aligned
with the checked-in CyTRICS schema at docs/cytrics_schema/schema.json.

Focus areas:
- Generated timestamps are RFC 3339 date-time strings in UTC
- Hardware captureTime accepts RFC 3339 strings and null
- Software captureTime accepts RFC 3339 strings and null
- File captureTime accepts RFC 3339 strings and rejects null
- Legacy epoch integers are rejected by schema validation
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker, ValidationError

from surfactant.utils.capture_time import utc_now_rfc3339


SCHEMA_PATH = Path("docs/cytrics_schema/schema.json")


def load_schema() -> dict:
    """Load the checked-in CyTRICS JSON schema from the repository."""
    with SCHEMA_PATH.open("r", encoding="utf-8") as schema_file:
        return json.load(schema_file)


@pytest.fixture(scope="module")
def schema() -> dict:
    """Provide the full CyTRICS schema for validation tests."""
    return load_schema()


@pytest.fixture(scope="module")
def format_checker() -> FormatChecker:
    """Provide a JSON Schema format checker for RFC 3339 date-time validation."""
    return FormatChecker()


def test_utc_now_rfc3339_returns_utc_rfc3339_string() -> None:
    """Verify utc_now_rfc3339 generates a UTC RFC 3339 date-time string."""
    capture_time = utc_now_rfc3339()

    assert isinstance(capture_time, str)
    assert capture_time.endswith("Z")
    assert "T" in capture_time
    assert "." not in capture_time


def test_hardware_capture_time_accepts_rfc3339_string(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify hardware.captureTime accepts a valid RFC 3339 date-time string."""
    hardware_item_schema = schema["definitions"]["hardware"]["items"]
    validator = Draft7Validator(hardware_item_schema, format_checker=format_checker)

    instance = {
        "UUID": "123e4567-e89b-12d3-a456-426614174000",
        "captureTime": "2024-12-10T19:39:10Z",
    }

    validator.validate(instance)


def test_hardware_capture_time_accepts_null(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify hardware.captureTime accepts null as allowed by the schema."""
    hardware_item_schema = schema["definitions"]["hardware"]["items"]
    validator = Draft7Validator(hardware_item_schema, format_checker=format_checker)

    instance = {
        "UUID": "123e4567-e89b-12d3-a456-426614174000",
        "captureTime": None,
    }

    validator.validate(instance)


def test_hardware_capture_time_rejects_epoch_integer(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify hardware.captureTime rejects legacy epoch integer timestamps."""
    hardware_item_schema = schema["definitions"]["hardware"]["items"]
    validator = Draft7Validator(hardware_item_schema, format_checker=format_checker)

    instance = {
        "UUID": "123e4567-e89b-12d3-a456-426614174000",
        "captureTime": 1733859550,
    }

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_software_capture_time_accepts_rfc3339_string(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify software.captureTime accepts a valid RFC 3339 date-time string."""
    software_item_schema = schema["definitions"]["software"]["items"]
    validator = Draft7Validator(software_item_schema, format_checker=format_checker)

    instance = {
        "UUID": "123e4567-e89b-12d3-a456-426614174000",
        "captureTime": "2024-12-10T19:39:10+00:00",
        "notHashable": True,
    }

    validator.validate(instance)


def test_software_capture_time_accepts_null(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify software.captureTime accepts null as allowed by the schema."""
    software_item_schema = schema["definitions"]["software"]["items"]
    validator = Draft7Validator(software_item_schema, format_checker=format_checker)

    instance = {
        "UUID": "123e4567-e89b-12d3-a456-426614174000",
        "captureTime": None,
        "notHashable": True,
    }

    validator.validate(instance)


def test_software_capture_time_rejects_missing_timezone(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify software.captureTime rejects date-time strings without a timezone."""
    software_item_schema = schema["definitions"]["software"]["items"]
    validator = Draft7Validator(software_item_schema, format_checker=format_checker)

    instance = {
        "UUID": "123e4567-e89b-12d3-a456-426614174000",
        "captureTime": "2024-12-10T19:39:10",
        "notHashable": True,
    }

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_software_capture_time_rejects_epoch_integer(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify software.captureTime rejects legacy epoch integer timestamps."""
    software_item_schema = schema["definitions"]["software"]["items"]
    validator = Draft7Validator(software_item_schema, format_checker=format_checker)

    instance = {
        "UUID": "123e4567-e89b-12d3-a456-426614174000",
        "captureTime": 1733859550,
        "notHashable": True,
    }

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_file_capture_time_accepts_rfc3339_string(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify sharedDefinitions.file.captureTime accepts a valid RFC 3339 string."""
    file_schema = schema["sharedDefinitions"]["file"]
    validator = Draft7Validator(file_schema, format_checker=format_checker)

    instance = {
        "filePath": "123e4567-e89b-12d3-a456-426614174000/test.bin",
        "description": "Test file",
        "category": "Image",
        "capturedBy": "pytest",
        "captureTime": "2024-12-10T20:39:10+01:00",
        "source": "unit-test",
    }

    validator.validate(instance)


def test_file_capture_time_rejects_null(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify sharedDefinitions.file.captureTime rejects null because it must be a string."""
    file_schema = schema["sharedDefinitions"]["file"]
    validator = Draft7Validator(file_schema, format_checker=format_checker)

    instance = {
        "filePath": "123e4567-e89b-12d3-a456-426614174000/test.bin",
        "description": "Test file",
        "category": "Image",
        "capturedBy": "pytest",
        "captureTime": None,
        "source": "unit-test",
    }

    with pytest.raises(ValidationError):
        validator.validate(instance)


def test_file_capture_time_rejects_missing_timezone(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify sharedDefinitions.file.captureTime rejects date-time strings without a timezone."""
    file_schema = schema["sharedDefinitions"]["file"]
    validator = Draft7Validator(file_schema, format_checker=format_checker)

    instance = {
        "filePath": "123e4567-e89b-12d3-a456-426614174000/test.bin",
        "description": "Test file",
        "category": "Image",
        "capturedBy": "pytest",
        "captureTime": "2024-12-10T19:39:10",
        "source": "unit-test",
    }

    with pytest.raises(ValidationError):
        validator.validate(instance)