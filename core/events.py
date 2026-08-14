"""Normalized filesystem event representation for Sentinel."""

from datetime import datetime, timezone
from typing import Any


def normalize_event(
    event_type: str,
    path: str,
    old_path: str | None = None,
    new_path: str | None = None,
) -> dict[str, Any]:
    """Create the database-ready representation of one filesystem event."""
    return {
        "event_id": None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "path": path,
        "old_path": old_path,
        "new_path": new_path,
    }
