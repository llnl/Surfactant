"""Schema-focused tests for SBOMs using the CyTRICS format.

These tests ensure that generated SBOMs and data validation functions remain aligned
with the checked-in CyTRICS schema at docs/cytrics_schema/schema.json.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, FormatChecker, ValidationError

from surfactant.sbomtypes import SBOM, CommentEntry, File, Hardware, NameEntry, Software
from surfactant.utils.capture_time import utc_now_rfc3339, validate_capture_time

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
    checker = FormatChecker()

    @checker.checks("date-time", raises=(TypeError, ValueError))
    def _is_rfc3339_date_time(value: object) -> bool:
        if not isinstance(value, str):
            return True

        validate_capture_time(value, nullable=False, field_name="date-time")
        return True

    return checker


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


def test_format_checker_enforces_date_time(format_checker: FormatChecker) -> None:
    """Verify the test environment enforces JSON Schema date-time formats."""
    validator = Draft7Validator(
        {"type": "string", "format": "date-time"},
        format_checker=format_checker,
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


def test_explicit_name_entry_validation_rejects_null_values() -> None:
    """Verify explicit NameEntry validation rejects null field values."""
    with pytest.raises(TypeError, match="nameValue must be a string"):
        NameEntry(nameValue=None).validate()  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="nameType must be a string"):
        NameEntry(nameType=None).validate()  # type: ignore[arg-type]


def test_explicit_hardware_name_entry_validation_rejects_null_values() -> None:
    """Verify explicit Hardware validation rejects null NameEntry field values."""
    hw = Hardware(
        UUID="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        name=[NameEntry(nameValue=None)],  # type: ignore[arg-type]
    )

    with pytest.raises(TypeError, match="nameValue must be a string"):
        hw.validate()


def test_name_entry_empty_strings_are_schema_valid(cytrics_validator: Draft7Validator) -> None:
    """Verify empty nameValue/nameType strings satisfy the schema."""
    sbom = SBOM(
        software=[
            Software(
                UUID="99999999-9999-4999-8999-999999999999",
                sha256="d" * 64,
                name=[NameEntry()],
            )
        ]
    )

    serialized = sbom.to_dict()

    assert serialized["software"][0]["name"][0] == {
        "nameValue": "",
        "nameType": "",
    }
    assert_schema_valid(cytrics_validator, serialized)


def test_runtime_name_entry_serialization_does_not_hide_null_values(
    cytrics_validator: Draft7Validator,
) -> None:
    """Verify runtime serialization preserves invalid null NameEntry values."""
    sbom = SBOM(
        software=[
            Software(
                UUID="cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                sha256="f" * 64,
                name=[NameEntry(nameValue=None)],  # type: ignore[arg-type]
            )
        ]
    )

    serialized = sbom.to_dict()

    assert serialized["software"][0]["name"][0]["nameValue"] is None
    assert_schema_invalid_at(
        cytrics_validator,
        serialized,
        ["software", 0, "name", 0, "nameValue"],
    )


@pytest.mark.parametrize("field_name", ("nameValue", "nameType"))
def test_software_name_entry_rejects_null_values(
    cytrics_validator: Draft7Validator,
    field_name: str,
) -> None:
    """Verify schema validation rejects null nameValue/nameType values."""
    sbom = SBOM(
        software=[
            Software(
                UUID="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                sha256="e" * 64,
                name=[NameEntry(nameValue="valid", nameType="product name")],
            )
        ]
    )
    serialized = sbom.to_dict()
    serialized["software"][0]["name"][0][field_name] = None

    assert_schema_invalid_at(
        cytrics_validator,
        serialized,
        ["software", 0, "name", 0, field_name],
    )


def test_explicit_software_validation_allows_json_metadata_values() -> None:
    """Verify explicit Software validation allows non-dict JSON metadata values."""
    sw = Software(
        UUID="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        sha256="a" * 64,
        metadata=[
            "metadata string",
            123,
            1.5,
            True,
            None,
            ["nested", "array"],
            {"nested": "object"},
        ],
    )

    sw.validate()


def test_explicit_hardware_validation_allows_json_metadata_values() -> None:
    """Verify explicit Hardware validation allows non-dict JSON metadata values."""
    hw = Hardware(
        UUID="ffffffff-ffff-4fff-8fff-ffffffffffff",
        metadata=[
            "metadata string",
            123,
            1.5,
            True,
            None,
            ["nested", "array"],
            {"nested": "object"},
        ],
    )

    hw.validate()


def test_explicit_file_validation_rejects_null_file_path() -> None:
    """Verify explicit File validation rejects null filePath values."""
    with pytest.raises(TypeError, match="filePath must be a string"):
        File(filePath=None).validate()  # type: ignore[arg-type]


def test_runtime_file_path_serialization_does_not_hide_null_values(
    cytrics_validator: Draft7Validator,
) -> None:
    """Verify runtime serialization preserves invalid null filePath values."""
    sbom = SBOM(
        software=[
            Software(
                UUID="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                sha256="f" * 64,
                supplementaryFiles=[
                    File(filePath=None),  # type: ignore[arg-type]
                ],
            )
        ]
    )

    serialized = sbom.to_dict()

    assert serialized["software"][0]["supplementaryFiles"][0]["filePath"] is None
    assert_schema_invalid_at(
        cytrics_validator,
        serialized,
        ["software", 0, "supplementaryFiles", 0, "filePath"],
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
                supplementaryFiles=[
                    File(
                        filePath="66666666-6666-4666-8666-666666666666/manual.pdf",
                        description="Missing filePath",
                    )
                ],
            )
        ]
    )

    serialized = sbom.to_dict()
    del serialized["software"][0]["supplementaryFiles"][0]["filePath"]

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
                supplementaryFiles=[
                    File(
                        filePath="88888888-8888-4888-8888-888888888888/manual.pdf",
                        description="Missing filePath",
                    )
                ],
            )
        ]
    )

    serialized = sbom.to_dict()
    del serialized["hardware"][0]["supplementaryFiles"][0]["filePath"]

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
