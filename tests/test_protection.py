"""Real-filesystem tests for explicit protected-target management."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.database import DatabaseError
from core.protection import ProtectionError, create_protection, inspect_target, protections


class ProtectionIntegrationTest(unittest.TestCase):
    def _directory_with_files(self, directory: Path) -> Path:
        target = directory / "important"
        target.mkdir()
        (target / "one.txt").write_text("one", encoding="utf-8")
        nested = target / "nested"
        nested.mkdir()
        (nested / "two.txt").write_text("two", encoding="utf-8")
        return target

    def test_confirmed_directory_protection_persists_associated_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            target = self._directory_with_files(directory)
            database = directory / "sentinel.db"

            protection = create_protection(target, confirmed=True, database_path=database)

            self.assertIsNotNone(protection)
            self.assertEqual(protection["target_type"], "DIRECTORY")
            self.assertEqual(protection["status"], "ACTIVE")
            self.assertEqual(protection["baseline_files"], 2)
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM protected_targets").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM protection_baselines").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM baseline_files").fetchone()[0], 2)
            finally:
                connection.close()

    def test_declined_confirmation_has_no_database_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            target = self._directory_with_files(directory)
            database = directory / "sentinel.db"

            self.assertIsNone(create_protection(target, confirmed=False, database_path=database))
            self.assertFalse(database.exists())

    def test_missing_empty_duplicate_and_normalized_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            database = directory / "sentinel.db"
            with self.assertRaises(ProtectionError):
                create_protection(directory / "missing", True, database)

            empty = directory / "empty"
            empty.mkdir()
            first = create_protection(empty, True, database)
            self.assertEqual(first["baseline_files"], 0)
            self.assertEqual(inspect_target(empty)["path"], inspect_target(directory / "." / "empty")["path"])
            with self.assertRaises(ProtectionError):
                create_protection(directory / "." / "empty", True, database)
            self.assertEqual(len(protections(database)), 1)

    def test_database_failure_rolls_back_target_and_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            target = self._directory_with_files(directory)
            database = directory / "sentinel.db"
            with patch(
                "core.protection.insert_baseline_files",
                side_effect=DatabaseError("simulated baseline write failure"),
            ), self.assertRaises(ProtectionError):
                create_protection(target, True, database)

            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM protected_targets").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM protection_baselines").fetchone()[0], 0)
            finally:
                connection.close()
