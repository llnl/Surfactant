from datetime import datetime, timezone

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
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )