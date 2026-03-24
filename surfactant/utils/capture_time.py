import re
from datetime import datetime, timezone
from typing import Optional

# RFC 3339 date-time with required timezone.
#
# Matches:
#   - 2024-12-10T19:39:10Z
#   - 2024-12-10T19:39:10+00:00
#   - 2024-12-10T20:39:10+01:00
#   - Optional fractional seconds are supported
#
# Enforces:
#   - Full date + time (YYYY-MM-DDTHH:MM:SS)
#   - Required timezone (Z or ±HH:MM)
#   - No support for missing timezone or truncated formats
#
# Note:
#   Calendar correctness (e.g., valid dates) is validated separately
#   using datetime parsing.
_RFC3339_CAPTURE_TIME_RE = re.compile(
    r"^"
    r"\d{4}-\d{2}-\d{2}"          # date
    r"[Tt]"
    r"\d{2}:\d{2}:\d{2}"          # time
    r"(?:\.\d+)?"                 # optional fractional seconds
    r"(?:[Zz]|[+-]\d{2}:\d{2})"   # required timezone
    r"$"
)

def validate_capture_time(
    value: Optional[str],
    *,
    nullable: bool = True,
    field_name: str = "captureTime",
) -> Optional[str]:
    """
    Validate a captureTime value against CyTRICS v1.0.1 expectations.

    This enforces a stricter interpretation of the schema's
    `"format": "date-time"` requirement by requiring full RFC 3339
    compliance *including timezone information*.

    Accepted formats include:
    - UTC with "Z" suffix: "2024-12-10T19:39:10Z"
    - Explicit offset:     "2024-12-10T20:39:10+01:00"
    - Optional fractional seconds are allowed

    Behavior:
    - Returns the original value if valid
    - Returns None if value is None and nullable=True
    - Raises ValueError if value is None and nullable=False
    - Raises TypeError if value is not a string or None
    - Raises ValueError if the string is not a valid RFC 3339 date-time
      with timezone information

    Validation is performed in two stages:
    1. Regex check for RFC 3339 structure and required timezone
    2. datetime parsing to ensure the timestamp is a valid calendar value

    Args:
        value: The captureTime value to validate.
        nullable: Whether None is allowed.
        field_name: Field name used in error messages.

    Returns:
        Optional[str]: The validated captureTime value.

    Raises:
        TypeError: If value is not a string (or None when allowed).
        ValueError: If value is invalid or missing required timezone.
    """
    if value is None:
        if nullable:
            return None
        raise ValueError(f"{field_name} cannot be null")

    if not isinstance(value, str):
        allowed = "string or null" if nullable else "string"
        raise TypeError(
            f"{field_name} must be a {allowed}; got {type(value).__name__}"
        )

    if not _RFC3339_CAPTURE_TIME_RE.fullmatch(value):
        raise ValueError(
            f"{field_name} must be an RFC 3339 date-time with timezone, "
            f"for example '2024-12-10T19:39:10Z' or "
            f"'2024-12-10T20:39:10+01:00'; got {value!r}"
        )

    # datetime.fromisoformat does not accept trailing 'Z', so normalize it.
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value

    try:
        datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} is not a valid calendar date/time: {value!r}"
        ) from exc

    return value


def utc_now_rfc3339() -> str:
    """
    Generate a captureTime value compliant with the CyTRICS v1.0.1 schema.

    Returns a UTC timestamp formatted as an RFC 3339 `date-time` string,
    using the canonical "Z" suffix for UTC (e.g., "2024-12-10T19:39:10Z").

    Notes:
    - Matches schema requirement: type = ["string", "null"], format = "date-time"
    - Always includes timezone information (UTC)
    - Microseconds are removed for consistency with schema examples
    - Output is safe for all captureTime fields (hardware, software, file)

    Returns:
        str: RFC 3339-compliant UTC timestamp
    """
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
