"""Explicit user-owned protected target management."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .baseline import create_baseline, scan_target
from .database import (
    DatabaseError,
    active_protected_target,
    connect,
    insert_baseline_files,
    insert_protected_target,
    insert_protection_baseline,
    list_protected_targets,
)


class ProtectionError(Exception):
    """Raised when protection cannot be safely created."""


def normalize_target_path(target: str | Path) -> Path:
    try:
        candidate = Path(target).expanduser()
        if candidate.is_symlink():
            raise ProtectionError(f"Refusing to protect symlink or junction: {candidate}")
        return candidate.resolve(strict=True)
    except OSError as error:
        raise ProtectionError(f"Target not found: {target}") from error


def inspect_target(target: str | Path) -> dict[str, Any]:
    path = normalize_target_path(target)
    try:
        state = scan_target(path)
    except (OSError, ValueError) as error:
        raise ProtectionError(str(error)) from error
    return {
        "path": str(path),
        "path_key": str(path).casefold(),
        "target_type": "DIRECTORY" if path.is_dir() else "FILE",
        "file_count": len(state["files"]),
        "total_size": sum(int(file_data["size"]) for file_data in state["files"]),
    }


def create_protection(
    target: str | Path, confirmed: bool, database_path: str | Path | None = None
) -> dict[str, Any] | None:
    """Create one ACTIVE protection and its associated trusted baseline atomically."""
    summary = inspect_target(target)
    if not confirmed:
        return None

    try:
        baseline = create_baseline(summary["path"])
        created_at = datetime.now(timezone.utc).isoformat()
        target_data = {**summary, "status": "ACTIVE", "created_at": created_at}
        connection = connect(database_path)
        try:
            with connection:
                if active_protected_target(connection, target_data["path_key"]):
                    raise ProtectionError(f"Target is already actively protected: {target_data['path']}")
                target_id = insert_protected_target(connection, target_data)
                baseline_id = insert_protection_baseline(connection, target_id, baseline["created_at"])
                insert_baseline_files(connection, baseline_id, baseline["files"])
        finally:
            connection.close()
    except (DatabaseError, OSError, ValueError) as error:
        raise ProtectionError(str(error)) from error

    return {**target_data, "target_id": target_id, "baseline_id": baseline_id, "baseline_files": len(baseline["files"])}


def protections(database_path: str | Path | None = None) -> list[dict[str, Any]]:
    try:
        connection = connect(database_path)
        try:
            return [dict(row) for row in list_protected_targets(connection)]
        finally:
            connection.close()
    except DatabaseError as error:
        raise ProtectionError(str(error)) from error
