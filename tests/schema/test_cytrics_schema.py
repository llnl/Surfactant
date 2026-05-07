"""Schema-focused tests for CyTRICS captureTime fields.

These tests validate that Surfactant's captureTime handling remains aligned
with the checked-in CyTRICS schema at docs/cytrics_schema/schema.json.

Focus areas:
- Generated timestamps are RFC 3339 date-time strings in UTC
- Hardware captureTime accepts RFC 3339 strings and null
- Software captureTime accepts RFC 3339 strings and null
- File captureTime accepts RFC 3339 strings and rejects null
- Supplementary filePath is treated as required ahead of the next schema update
- Invalid comment timestamps are caught by schema tests, not runtime constructors
- Legacy epoch integers are rejected by schema validation
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker, ValidationError

from surfactant.sbomtypes import CommentEntry, File, Hardware, SBOM, Software
from surfactant.utils.capture_time import utc_now_rfc3339

SCHEMA_PATH = Path("docs/cytrics_schema/schema.json")
SAMPLE_SBOM_PATHS = (
    Path("tests/data/sample_sboms/helics_binaries_sbom.json"),
    Path("tests/data/sample_sboms/helics_libs_sbom.json"),
    Path("tests/data/sample_sboms/helics_sbom.json"),
)


def load_schema() -> dict:
    """Load the checked-in CyTRICS JSON schema from the repository."""
    with SCHEMA_PATH.open("r", encoding="utf-8") as schema_file:
        return json.load(schema_file)


@pytest.fixture(scope="module", name="schema")
def schema_fixture() -> dict:
    """Provide the full CyTRICS schema for validation tests."""
    return load_schema()


@pytest.fixture(scope="module", name="format_checker")
def format_checker_fixture() -> FormatChecker:
    """Provide a JSON Schema format checker for RFC 3339 date-time validation."""
    return FormatChecker()


@pytest.fixture(scope="module", name="cytrics_validator")
def cytrics_validator_fixture(schema: dict, format_checker: FormatChecker) -> Draft7Validator:
    """Provide a validator for full CyTRICS SBOM documents."""
    return Draft7Validator(schema, format_checker=format_checker)


def assert_schema_valid(validator: Draft7Validator, instance: dict) -> None:
    """Assert an instance is schema-valid and report the first few failures."""
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda err: (list(err.absolute_path), err.message),
    )
    assert not errors, "\n".join(
        f"{list(error.absolute_path) or ['<root>']}: {error.message}" for error in errors[:5]
    )


def assert_schema_invalid_at(
    validator: Draft7Validator,
    instance: dict,
    expected_path: list[object],
) -> None:
    """Assert an instance is schema-invalid at the expected schema path."""
    errors = sorted(
        validator.iter_errors(instance),
        key=lambda err: (list(err.absolute_path), err.message),
    )
    assert errors
    assert any(list(error.absolute_path) == expected_path for error in errors), "\n".join(
        f"{list(error.absolute_path) or ['<root>']}: {error.message}" for error in errors[:5]
    )


def schema_with_required_supplementary_file_path(schema: dict) -> dict:
    """Return a schema copy with shared supplementary filePath marked required."""
    schema_copy = deepcopy(schema)
    file_schema = schema_copy["sharedDefinitions"]["file"]
    required_fields = list(file_schema.get("required", []))
    if "filePath" not in required_fields:
        required_fields.append("filePath")
    file_schema["required"] = required_fields
    return schema_copy


def test_format_checker_enforces_date_time() -> None:
    """Verify the test environment enforces JSON Schema date-time formats."""
    validator = Draft7Validator(
        {"type": "string", "format": "date-time"},
        format_checker=FormatChecker(),
    )

    with pytest.raises(ValidationError):
        validator.validate("not-rfc3339")


def test_utc_now_rfc3339_returns_utc_rfc3339_string() -> None:
    """Verify utc_now_rfc3339 generates a UTC RFC 3339 date-time string."""
    capture_time = utc_now_rfc3339()

    assert isinstance(capture_time, str)
    assert capture_time.endswith("Z")
    assert "T" in capture_time
    assert "." not in capture_time


@pytest.mark.parametrize("sample_path", SAMPLE_SBOM_PATHS)
def test_sample_sbom_fixture_is_schema_valid(
    sample_path: Path, cytrics_validator: Draft7Validator
) -> None:
    """Verify checked-in CyTRICS SBOM fixtures conform to the schema."""
    with sample_path.open("r", encoding="utf-8") as sample_file:
        assert_schema_valid(cytrics_validator, json.load(sample_file))


def test_serialized_sbom_is_schema_valid(cytrics_validator: Draft7Validator) -> None:
    """Verify Surfactant's normal serialized CyTRICS output conforms to the schema."""
    sbom = SBOM(
        software=[
            Software(
                UUID="11111111-1111-4111-8111-111111111111",
                fileName=["valid.bin"],
                sha256="a" * 64,
            )
        ]
    )

    assert_schema_valid(cytrics_validator, sbom.to_dict())


def test_runtime_sbom_serialization_does_not_validate_schema(
    cytrics_validator: Draft7Validator,
) -> None:
    """Verify schema-invalid SBOMs are not rejected during runtime serialization."""
    sbom = SBOM.from_dict(
        {
            "bomFormat": "cytrics",
            "specVersion": "1.0.1",
            "software": [
                {
                    "UUID": "22222222-2222-4222-8222-222222222222",
                    "captureTime": "not-rfc3339",
                    "notHashable": True,
                }
            ],
        }
    )

    serialized = sbom.to_dict()

    assert serialized["software"][0]["captureTime"] == "not-rfc3339"
    assert_schema_invalid_at(
        cytrics_validator,
        serialized,
        ["software", 0, "captureTime"],
    )


def test_runtime_comment_entry_does_not_validate_schema(
    cytrics_validator: Draft7Validator,
) -> None:
    """Verify invalid comment timestamps are rejected by schema tests, not construction."""
    sbom = SBOM(
        software=[
            Software(
                UUID="33333333-3333-4333-8333-333333333333",
                fileName=["valid.bin"],
                sha256="a" * 64,
                comments=[
                    CommentEntry(
                        comment="Invalid timestamp should be carried until schema validation.",
                        timestamp="not-rfc3339",
                    )
                ],
            )
        ]
    )

    serialized = sbom.to_dict()

    assert serialized["software"][0]["comments"][0]["timestamp"] == "not-rfc3339"
    assert_schema_invalid_at(
        cytrics_validator,
        serialized,
        ["software", 0, "comments", 0, "timestamp"],
    )


def test_explicit_software_validation_requires_supplementary_file_path() -> None:
    """Verify explicit validation treats supplementary filePath as required."""
    sw = Software(
        UUID="44444444-4444-4444-8444-444444444444",
        sha256="a" * 64,
        supplementaryFiles=[File(description="Missing filePath")],
    )

    with pytest.raises(ValueError, match="filePath is required"):
        sw.validate()


def test_explicit_hardware_validation_requires_supplementary_file_path() -> None:
    """Verify explicit hardware validation treats supplementary filePath as required."""
    hw = Hardware(
        UUID="77777777-7777-4777-8777-777777777777",
        supplementaryFiles=[File(description="Missing filePath")],
    )

    with pytest.raises(ValueError, match="filePath is required"):
        hw.validate()


def test_supplementary_file_with_file_path_is_valid_under_required_policy(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify supplementary files with filePath pass the upcoming schema rule."""
    validator = Draft7Validator(
        schema_with_required_supplementary_file_path(schema),
        format_checker=format_checker,
    )
    sbom = SBOM(
        software=[
            Software(
                UUID="55555555-5555-4555-8555-555555555555",
                sha256="b" * 64,
                supplementaryFiles=[
                    File(
                        filePath="55555555-5555-4555-8555-555555555555/manual.pdf",
                        description="Manual",
                    )
                ],
            )
        ]
    )

    assert_schema_valid(validator, sbom.to_dict())


def test_supplementary_file_without_file_path_is_invalid_under_required_policy(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify supplementary files without filePath fail the upcoming schema rule."""
    validator = Draft7Validator(
        schema_with_required_supplementary_file_path(schema),
        format_checker=format_checker,
    )
    sbom = SBOM(
        software=[
            Software(
                UUID="66666666-6666-4666-8666-666666666666",
                sha256="c" * 64,
                supplementaryFiles=[File(description="Missing filePath")],
            )
        ]
    )

    serialized = sbom.to_dict()

    assert "filePath" not in serialized["software"][0]["supplementaryFiles"][0]
    assert_schema_invalid_at(
        validator,
        serialized,
        ["software", 0, "supplementaryFiles", 0],
    )


def test_hardware_supplementary_file_without_file_path_is_invalid_under_required_policy(
    schema: dict, format_checker: FormatChecker
) -> None:
    """Verify hardware supplementary files without filePath fail the upcoming schema rule."""
    validator = Draft7Validator(
        schema_with_required_supplementary_file_path(schema),
        format_checker=format_checker,
    )
    sbom = SBOM(
        hardware=[
            Hardware(
                UUID="88888888-8888-4888-8888-888888888888",
                supplementaryFiles=[File(description="Missing filePath")],
            )
        ]
    )

    serialized = sbom.to_dict()

    assert "filePath" not in serialized["hardware"][0]["supplementaryFiles"][0]
    assert_schema_invalid_at(
        validator,
        serialized,
        ["hardware", 0, "supplementaryFiles", 0],
    )


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


def test_hardware_capture_time_accepts_null(schema: dict, format_checker: FormatChecker) -> None:
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


def test_software_capture_time_accepts_null(schema: dict, format_checker: FormatChecker) -> None:
    """Verify software.captureTime accepts null as allowed by the schema."""
    software_item_schema = schema["definitions"]["software"]["items"]
    validator = Draft7Validator(software_item_schema, format_checker=format_checker)

    instance = {
        "UUID": "123e4567-e89b-12d3-a456-426614174000",
        "captureTime": None,
        "notHashable": True,
    }

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


def test_file_capture_time_rejects_null(schema: dict, format_checker: FormatChecker) -> None:
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
