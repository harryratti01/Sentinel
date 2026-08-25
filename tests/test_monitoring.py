"""Real-filesystem integration tests for automatic protected-target monitoring."""

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from core.database import connect, list_security_findings
from core.monitoring import MonitoringCoordinator
from core.protection import create_protection


def wait_for(predicate: object, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.03)
    raise AssertionError("Timed out waiting for monitoring finding")


class MonitoringIntegrationTest(unittest.TestCase):
    def _findings(self, database: Path, target_id: int) -> list[dict[str, object]]:
        connection = connect(database)
        try:
            return [dict(row) for row in list_security_findings(connection, target_id)]
        finally:
            connection.close()

    def test_no_active_targets_starts_no_watchers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = MonitoringCoordinator(Path(temporary) / 'sentinel.db')
            self.assertEqual(coordinator.start(), 0)
            self.assertEqual(coordinator.watcher_count, 0)
            coordinator.stop()

    def test_discovers_active_targets_ignores_disabled_and_keeps_targets_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = root / 'sentinel.db'
            active_a, active_b, disabled = root / 'a', root / 'b', root / 'disabled'
            for directory in (active_a, active_b, disabled):
                directory.mkdir(); (directory / 'important.txt').write_text('trusted', encoding='utf-8')
            protected_a = create_protection(active_a, True, database)
            protected_b = create_protection(active_b, True, database)
            protected_disabled = create_protection(disabled, True, database)
            assert protected_a and protected_b and protected_disabled
            connection = connect(database)
            try:
                with connection:
                    connection.execute("UPDATE protected_targets SET status = 'DISABLED' WHERE target_id = ?", (protected_disabled['target_id'],))
            finally:
                connection.close()
            coordinator = MonitoringCoordinator(database, debounce_seconds=.06)
            try:
                self.assertEqual(coordinator.start(), 2)
                self.assertEqual(coordinator.start(), 2)
                self.assertEqual(coordinator.watcher_count, 2)
                self.assertEqual(coordinator.monitored_target_ids, {protected_a['target_id'], protected_b['target_id']})
                (active_a / 'important.txt').write_text('changed', encoding='utf-8')
                (disabled / 'important.txt').write_text('ignored', encoding='utf-8')
                (root / 'unprotected.txt').write_text('ignored', encoding='utf-8')
                wait_for(lambda: self._findings(database, protected_a['target_id']))
                self.assertFalse(self._findings(database, protected_b['target_id']))
                self.assertFalse(self._findings(database, protected_disabled['target_id']))
            finally:
                coordinator.stop()

    def test_real_changes_persist_without_mutating_baseline_and_monitoring_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = root / 'sentinel.db'; target = root / 'protected'
            target.mkdir(); original = target / 'important.txt'; original.write_text('trusted', encoding='utf-8')
            protection = create_protection(target, True, database)
            assert protection
            connection = connect(database)
            try:
                baseline_hash = connection.execute('SELECT sha256 FROM baseline_files').fetchone()[0]
            finally:
                connection.close()
            coordinator = MonitoringCoordinator(database, debounce_seconds=.08)
            try:
                coordinator.start()
                original.write_text('first modification', encoding='utf-8')
                wait_for(lambda: any(item['finding_type'] == 'MODIFIED' for item in self._findings(database, protection['target_id'])))
                renamed = target / 'renamed.txt'; original.rename(renamed)
                archive = target / 'archive'; archive.mkdir(); moved = archive / 'renamed.txt'; renamed.rename(moved)
                moved.write_text('compound modification', encoding='utf-8')
                wait_for(lambda: any(item['finding_type'] == 'MOVED_RENAMED_AND_MODIFIED' for item in self._findings(database, protection['target_id'])))
                (target / 'second.txt').write_text('new', encoding='utf-8')
                wait_for(lambda: any(item['finding_type'] == 'CREATED' for item in self._findings(database, protection['target_id'])))
                moved.unlink()
                wait_for(lambda: any(item['finding_type'] == 'DELETED' for item in self._findings(database, protection['target_id'])))
                connection = connect(database)
                try:
                    self.assertEqual(connection.execute('SELECT sha256 FROM baseline_files').fetchone()[0], baseline_hash)
                finally:
                    connection.close()
            finally:
                coordinator.stop()
            self.assertFalse(coordinator._started)
