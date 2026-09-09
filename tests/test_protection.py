"""Real-filesystem tests for explicit protected-target management."""

import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from core.cli import main as cli_main
from core.database import (
    DatabaseError,
    connect,
    insert_evidence_observation,
    insert_security_finding,
    list_evidence_observations,
    list_security_findings,
)
from core.monitoring import MonitoringCoordinator
from core.protection import (
    ProtectionError,
    create_protection,
    disable_protection,
    enable_protection,
    inspect_target,
    protections,
)


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

    def test_disable_enable_preserves_baseline_findings_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            target = self._directory_with_files(directory)
            database = directory / "sentinel.db"
            protection = create_protection(target, True, database)
            assert protection
            connection = connect(database)
            try:
                with connection:
                    insert_evidence_observation(connection, {
                        "target_id": protection["target_id"], "observed_at": "now", "event_type": "MODIFIED",
                        "path": str(target / "one.txt"), "old_path": None, "new_path": None,
                        "file_identity": None, "sha256": None, "size": None, "modified_time_ns": None,
                    })
                    insert_security_finding(connection, {
                        "target_id": protection["target_id"], "detected_at": "now", "finding_type": "MODIFIED",
                        "current_path": str(target / "one.txt"), "previous_path": str(target / "one.txt"),
                        "confidence": "HIGH", "evidence": "[]", "signature": "test-finding",
                    })
                baseline_before = [tuple(row) for row in connection.execute(
                    "SELECT path, relative_path, sha256, file_identity, modified_time_ns, size "
                    "FROM baseline_files ORDER BY baseline_file_id"
                )]
            finally:
                connection.close()

            self.assertEqual(disable_protection(protection["target_id"], database)["status"], "DISABLED")
            self.assertEqual(disable_protection(protection["target_id"], database)["status"], "DISABLED")
            disabled_monitor = MonitoringCoordinator(database)
            try:
                self.assertEqual(disabled_monitor.start(), 0)
            finally:
                disabled_monitor.stop()
            self.assertEqual(enable_protection(protection["target_id"], database)["status"], "ACTIVE")
            self.assertEqual(enable_protection(protection["target_id"], database)["status"], "ACTIVE")
            enabled_monitor = MonitoringCoordinator(database)
            try:
                self.assertEqual(enabled_monitor.start(), 1)
                self.assertEqual(enabled_monitor.monitored_target_ids, {protection["target_id"]})
            finally:
                enabled_monitor.stop()

            connection = connect(database)
            try:
                self.assertEqual([tuple(row) for row in connection.execute(
                    "SELECT path, relative_path, sha256, file_identity, modified_time_ns, size "
                    "FROM baseline_files ORDER BY baseline_file_id"
                )], baseline_before)
                self.assertEqual(len(list_evidence_observations(connection, protection["target_id"])), 1)
                self.assertEqual(len(list_security_findings(connection, protection["target_id"])), 1)
            finally:
                connection.close()

    def test_invalid_protection_id_is_clear_and_status_failure_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            target = self._directory_with_files(directory)
            database = directory / "sentinel.db"
            protection = create_protection(target, True, database)
            assert protection

            with self.assertRaisesRegex(ProtectionError, "Protection ID not found: 999"):
                disable_protection(999, database)
            with patch(
                "core.protection.update_protected_target_status",
                side_effect=DatabaseError("simulated status update failure"),
            ), self.assertRaisesRegex(ProtectionError, "simulated status update failure"):
                disable_protection(protection["target_id"], database)

            connection = connect(database)
            try:
                self.assertEqual(connection.execute(
                    "SELECT status FROM protected_targets WHERE target_id = ?", (protection["target_id"],)
                ).fetchone()[0], "ACTIVE")
            finally:
                connection.close()

    def test_cli_disable_and_enable_commands_dispatch_by_protection_id(self) -> None:
        with patch("sys.argv", ["sentinel", "disable", "7"]), patch(
            "core.cli.disable_protection",
            return_value={"target_id": 7, "status": "DISABLED"},
        ) as disable_target, redirect_stdout(StringIO()):
            self.assertEqual(cli_main(), 0)
        disable_target.assert_called_once_with(7)

        with patch("sys.argv", ["sentinel", "enable", "7"]), patch(
            "core.cli.enable_protection",
            return_value={"target_id": 7, "status": "ACTIVE"},
        ) as enable_target, redirect_stdout(StringIO()):
            self.assertEqual(cli_main(), 0)
        enable_target.assert_called_once_with(7)
