"""Local text-file ingestion for Sentinel."""

from datetime import datetime, timezone
from pathlib import Path

from .hasher import calculate_hash


class IngestionError(Exception):
    """Raised when a supplied text file cannot be ingested."""


def ingest_text_file(file_path: str | Path) -> dict[str, object]:
    path = Path(file_path).expanduser()
    if not path.is_file():
        raise IngestionError(f"File not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
        stat = path.stat()
    except (OSError, UnicodeDecodeError) as error:
        raise IngestionError(f"Unable to read text file {path}: {error}") from error

    return {
        "path": str(path.resolve()),
        "sha256": calculate_hash(path),
        "size": stat.st_size,
        "modified_time": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "baseline_created": datetime.now(timezone.utc).isoformat(),
        "content": content,
    }
