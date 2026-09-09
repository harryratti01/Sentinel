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
from .acceptance import run_acceptance_demo, run_protection_demo, run_monitor_demo
from .monitoring import MonitoringCoordinator
from .ingestion import IngestionError, ingest_text_file
from .processor import analyze_text
from .protection import (
    ProtectionError,
    create_protection,
    disable_protection,
    enable_protection,
    inspect_target,
    protections,
)
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


def monitor_protected_targets() -> int:
    """Continuously monitor all ACTIVE protected targets."""
    try:
        MonitoringCoordinator().run_forever()
        return 0
    except (WatcherError, DatabaseError, sqlite3.Error) as error:
        print(f"Sentinel error: {error}")
        return 1


def protect(target: str | Path) -> int:
    """Display a target summary and require explicit confirmation before protection."""
    try:
        summary = inspect_target(target)
        print(f"Target: {summary['path']}")
        print(f"Type: {summary['target_type']}")
        print(f"Files to protect: {summary['file_count']}")
        print(f"Total size: {summary['total_size']} bytes")
        answer = input("Create trusted baseline and begin protection? [y/N]: ")
        protection = create_protection(target, answer.strip().casefold() in {"y", "yes"})
        if protection is None:
            print("Protection not created.")
            return 0
        print(f"Protection ID: {protection['target_id']}")
        print(f"Baseline ID: {protection['baseline_id']}")
        print(f"Protection status: {protection['status']}")
        return 0
    except ProtectionError as error:
        print(f"Sentinel error: {error}")
        return 1


def show_protections() -> int:
    try:
        targets = protections()
    except ProtectionError as error:
        print(f"Sentinel error: {error}")
        return 1
    if not targets:
        print("No protected targets.")
        return 0
    for target in targets:
        print(
            f"{target['target_id']}: {target['path']} "
            f"{target['target_type']} {target['status']} {target['created_at']}"
        )
    return 0


def disable(protection_id: int) -> int:
    try:
        target = disable_protection(protection_id)
    except ProtectionError as error:
        print(f"Sentinel error: {error}")
        return 1
    print(f"Protection ID {target['target_id']} disabled.")
    return 0


def enable(protection_id: int) -> int:
    try:
        target = enable_protection(protection_id)
    except ProtectionError as error:
        print(f"Sentinel error: {error}")
        return 1
    print(f"Protection ID {target['target_id']} enabled.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Process a text file or monitor a directory with Sentinel.")
    parser.add_argument("file", nargs="?", help="Path to the text file to process")
    parser.add_argument("target", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--watch", metavar="DIRECTORY", help="Continuously monitor a directory")
    parser.add_argument(
        "--acceptance-demo",
        action="store_true",
        help="Run the deterministic baseline/reconciliation acceptance scenario",
    )
    parser.add_argument(
        "--protection-demo",
        action="store_true",
        help="Run the deterministic protection-management acceptance scenario",
    )
    parser.add_argument("--monitor-demo", action="store_true", help="Run the monitoring acceptance demo")
    args = parser.parse_args()

    if args.acceptance_demo:
        run_acceptance_demo()
        return 0
    if args.protection_demo:
        run_protection_demo()
        return 0
    if args.monitor_demo:
        run_monitor_demo()
        return 0
    if args.watch:
        return monitor(args.watch)
    if args.file == "protect":
        if not args.target:
            parser.error("protect requires a target path")
        return protect(args.target)
    if args.file == "protections":
        return show_protections()
    if args.file in {"disable", "enable"}:
        if not args.target:
            parser.error(f"{args.file} requires a protection ID")
        try:
            protection_id = int(args.target)
        except ValueError:
            parser.error("protection ID must be an integer")
        if protection_id <= 0:
            parser.error("protection ID must be a positive integer")
        return disable(protection_id) if args.file == "disable" else enable(protection_id)
    if args.file == "monitor":
        return monitor_protected_targets()
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
