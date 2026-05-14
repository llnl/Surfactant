import pytest

from surfactant.utils.capture_time import validate_capture_time


def test_validate_capture_time_accepts_zulu() -> None:
    """Verify validate_capture_time accepts UTC timestamps with Z suffix."""
    assert validate_capture_time("2024-12-10T19:39:10Z") == "2024-12-10T19:39:10Z"


def test_validate_capture_time_accepts_offset() -> None:
    """Verify validate_capture_time accepts timestamps with numeric timezone offsets."""
    assert validate_capture_time("2024-12-10T20:39:10+01:00") == "2024-12-10T20:39:10+01:00"


def test_validate_capture_time_accepts_null() -> None:
    """Verify validate_capture_time accepts null when nullable is enabled."""
    assert validate_capture_time(None) is None


def test_validate_capture_time_rejects_missing_timezone() -> None:
    """Verify validate_capture_time rejects timestamps without timezone information."""
    with pytest.raises(ValueError):
        validate_capture_time("2024-12-10T19:39:10")


def test_validate_capture_time_rejects_epoch_integer() -> None:
    """Verify validate_capture_time rejects legacy epoch integer values."""
    with pytest.raises(TypeError):
        validate_capture_time(1733859550)  # type: ignore[arg-type]
