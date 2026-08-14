"""End-to-end test for the minimal Sentinel workflow."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.cli import run
from core.database import DatabaseError, connect, insert_filesystem_event
from core.events import normalize_event
from core.watcher import _SentinelEventHandler


class SentinelWorkflowTest(unittest.TestCase):
    def test_ingests_analyzes_and_persists_a_text_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            source_file = directory / "sample.txt"
            database_file = directory / "sentinel.db"
            source_file.write_text("hello Sentinel\nsecond line", encoding="utf-8")

            file_id, result = run(source_file, database_file)

            self.assertGreater(file_id, 0)
            self.assertEqual(result["status"], "processed")
            self.assertEqual(result["character_count"], 26)
            self.assertEqual(result["word_count"], 4)
            self.assertEqual(result["line_count"], 2)

            connection = sqlite3.connect(database_file)
            try:
                saved_file = connection.execute(
                    "SELECT path, content FROM files WHERE id = ?", (file_id,)
                ).fetchone()
                saved_result = connection.execute(
                    "SELECT status, character_count, word_count, line_count "
                    "FROM processing_results WHERE file_id = ?",
                    (file_id,),
                ).fetchone()
            finally:
                connection.close()

            self.assertEqual(saved_file[1], "hello Sentinel\nsecond line")
            self.assertEqual(saved_result, ("processed", 26, 4, 2))

    def test_connection_enforces_foreign_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_file = Path(temporary_directory) / "sentinel.db"
            connection = connect(database_file)
            try:
                self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        """
                        INSERT INTO processing_results
                            (file_id, status, character_count, word_count, line_count, processed_at)
                        VALUES (999, 'processed', 1, 1, 1, 'now')
                        """
                    )
            finally:
                connection.close()

    def test_processing_failure_rolls_back_file_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            source_file = directory / "sample.txt"
            database_file = directory / "sentinel.db"
            source_file.write_text("text to roll back", encoding="utf-8")

            with patch(
                "core.cli.insert_processing_result",
                side_effect=DatabaseError("simulated result persistence failure"),
            ):
                file_id, result = run(source_file, database_file)

            self.assertEqual(file_id, 1)
            self.assertIsNone(result)
            connection = sqlite3.connect(database_file)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM files").fetchone()[0], 0)
                self.assertEqual(
                    connection.execute("SELECT COUNT(*) FROM processing_results").fetchone()[0], 0
                )
            finally:
                connection.close()

    def test_normalizes_and_persists_a_moved_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_file = Path(temporary_directory) / "sentinel.db"
            event = normalize_event(
                "MOVED",
                r"C:\monitored\renamed.txt",
                old_path=r"C:\monitored\original.txt",
                new_path=r"C:\monitored\renamed.txt",
            )

            connection = connect(database_file)
            try:
                with connection:
                    event_id = insert_filesystem_event(connection, event)
            finally:
                connection.close()

            self.assertIsNone(event["event_id"])
            self.assertIsInstance(event["timestamp"], str)
            self.assertEqual(event["event_type"], "MOVED")
            connection = sqlite3.connect(database_file)
            try:
                saved_event = connection.execute(
                    "SELECT event_id, event_type, path, old_path, new_path "
                    "FROM filesystem_events WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
            finally:
                connection.close()

            self.assertEqual(
                saved_event,
                (
                    event_id,
                    "MOVED",
                    r"C:\monitored\renamed.txt",
                    r"C:\monitored\original.txt",
                    r"C:\monitored\renamed.txt",
                ),
            )

    def test_watcher_normalizes_all_supported_event_types(self) -> None:
        events: list[dict[str, object]] = []
        handler = _SentinelEventHandler(events.append)

        handler.on_created(SimpleNamespace(src_path=r"C:\monitored\created.txt"))
        handler.on_modified(SimpleNamespace(src_path=r"C:\monitored\modified.txt"))
        handler.on_deleted(SimpleNamespace(src_path=r"C:\monitored\deleted.txt"))
        handler.on_moved(
            SimpleNamespace(
                src_path=r"C:\monitored\original.txt",
                dest_path=r"C:\monitored\renamed.txt",
            )
        )

        self.assertEqual([event["event_type"] for event in events], ["CREATED", "MODIFIED", "DELETED", "MOVED"])
        self.assertEqual(events[3]["path"], r"C:\monitored\renamed.txt")
        self.assertEqual(events[3]["old_path"], r"C:\monitored\original.txt")
        self.assertEqual(events[3]["new_path"], r"C:\monitored\renamed.txt")


if __name__ == "__main__":
    unittest.main()
