"""End-to-end test for the minimal Sentinel workflow."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.cli import run
from core.database import DatabaseError, connect


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


if __name__ == "__main__":
    unittest.main()
