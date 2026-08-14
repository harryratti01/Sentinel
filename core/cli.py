"""Command-line entry point for the Sentinel vertical slice."""

import argparse
import sqlite3
from pathlib import Path

from .database import (
    DatabaseError,
    connect,
    insert_file,
    insert_filesystem_event,
    insert_processing_result,
)
from .acceptance import run_acceptance_demo
from .ingestion import IngestionError, ingest_text_file
from .processor import analyze_text
from .watcher import WatcherError, watch_directory


def run(file_path: str | Path, database_path: str | Path | None = None) -> tuple[int, dict[str, object] | None]:
    """Ingest, analyse, and persist one text file."""
    try:
        file_data = ingest_text_file(file_path)
        connection = connect(database_path)
        try:
            with connection:
                file_id = insert_file(connection, file_data)
                result = analyze_text(str(file_data["content"]))
                insert_processing_result(connection, file_id, result)
        finally:
            connection.close()
        return file_id, result
    except (IngestionError, DatabaseError, sqlite3.Error) as error:
        print(f"Sentinel error: {error}")
        return 1, None


def persist_and_print_event(event: dict[str, object]) -> None:
    """Persist a watcher event and immediately display its normalized form."""
    connection = connect()
    try:
        with connection:
            event_id = insert_filesystem_event(connection, event)
    finally:
        connection.close()

    event["event_id"] = event_id
    print(
        f"Event {event['event_id']}: {event['timestamp']} {event['event_type']} "
        f"path={event['path']} old_path={event['old_path']} new_path={event['new_path']}"
    )


def monitor(directory: str | Path) -> int:
    """Run directory monitoring until the user interrupts it."""
    try:
        watch_directory(directory, persist_and_print_event)
        return 0
    except (WatcherError, DatabaseError, sqlite3.Error) as error:
        print(f"Sentinel error: {error}")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Process a text file or monitor a directory with Sentinel.")
    parser.add_argument("file", nargs="?", help="Path to the text file to process")
    parser.add_argument("--watch", metavar="DIRECTORY", help="Continuously monitor a directory")
    parser.add_argument(
        "--acceptance-demo",
        action="store_true",
        help="Run the deterministic baseline/reconciliation acceptance scenario",
    )
    args = parser.parse_args()

    if args.acceptance_demo:
        run_acceptance_demo()
        return 0
    if args.watch:
        return monitor(args.watch)
    if not args.file:
        parser.error("provide a file to process or use --watch DIRECTORY")

    file_id, result = run(args.file)
    if result is None:
        return 1

    print(f"File processed: {Path(args.file).resolve()}")
    print(f"File ID: {file_id}")
    print(f"Processing status: {result['status']}")
    print(
        "Basic analysis: "
        f"{result['character_count']} characters, "
        f"{result['word_count']} words, "
        f"{result['line_count']} lines"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
