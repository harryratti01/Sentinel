"""Real-filesystem integration tests for automatic protected-target monitoring."""

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core.database import DatabaseError, connect, list_evidence_observations, list_security_findings
from core.events import normalize_event
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

    def _observations(self, database: Path, target_id: int) -> list[dict[str, object]]:
        connection = connect(database)
        try:
            return [dict(row) for row in list_evidence_observations(connection, target_id)]
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
                    moves = [row for row in list_evidence_observations(connection, protection['target_id']) if row['event_type'] == 'MOVED']
                    self.assertTrue(moves)
                    self.assertTrue(any(row['old_path'] and row['new_path'] for row in moves))
                finally:
                    connection.close()
            finally:
                coordinator.stop()
            self.assertFalse(coordinator._started)

    def test_file_target_follows_identity_through_rename_move_and_modify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = root / 'sentinel.db'
            original = root / 'important.txt'; original.write_text('trusted', encoding='utf-8')
            protection = create_protection(original, True, database)
            assert protection
            coordinator = MonitoringCoordinator(database, debounce_seconds=.08)
            renamed = root / 'renamed.txt'; archive = root / 'archive'; moved = archive / 'renamed.txt'
            try:
                self.assertEqual(coordinator.start(), 1)
                original.rename(renamed)
                wait_for(lambda: any(
                    row['finding_type'] == 'RENAMED'
                    for row in self._findings(database, protection['target_id'])
                ))

                archive.mkdir()
                renamed.rename(moved)
                wait_for(lambda: any(
                    row['finding_type'] == 'MOVED_RENAMED'
                    for row in self._findings(database, protection['target_id'])
                ))

                moved.write_text('changed after move', encoding='utf-8')
                wait_for(lambda: any(
                    row['finding_type'] == 'MOVED_RENAMED_AND_MODIFIED'
                    for row in self._findings(database, protection['target_id'])
                ))

                unrelated = root / 'unrelated.txt'
                unrelated.write_text('not protected', encoding='utf-8')
                time.sleep(.2)

                connection = connect(database)
                try:
                    baseline = connection.execute(
                        'SELECT path, file_identity FROM baseline_files WHERE baseline_id = ?',
                        (protection['baseline_id'],),
                    ).fetchone()
                    self.assertEqual(baseline['path'], str(original.resolve()))
                    observations = list_evidence_observations(connection, protection['target_id'])
                    relevant_moves = [
                        row for row in observations
                        if row['event_type'] in {'MOVED', 'INFERRED_MOVED'}
                    ]
                    self.assertTrue(any(
                        Path(str(row['old_path'])).resolve(strict=False) == original.resolve()
                        and Path(str(row['new_path'])).resolve(strict=False) == renamed.resolve()
                        for row in relevant_moves
                    ))
                    moved_observations = [
                        row for row in relevant_moves
                        if Path(str(row['old_path'])).resolve(strict=False) == renamed.resolve()
                        and Path(str(row['new_path'])).resolve(strict=False) == moved.resolve()
                    ]
                    # Windows may surface a cross-directory move as a raw
                    # delete/create pair.  Sentinel keeps those callbacks and
                    # adds an explicitly inferred transition only when the
                    # protected baseline identity proves continuity.
                    self.assertTrue(moved_observations, [dict(row) for row in observations])
                    move_observation = moved_observations[0]
                    if move_observation['event_type'] == 'INFERRED_MOVED':
                        self.assertTrue(any(
                            row['event_type'] == 'CREATED'
                            and Path(str(row['path'])).resolve(strict=False) == moved.resolve()
                            for row in observations
                        ))
                    self.assertEqual(move_observation['file_identity'], baseline['file_identity'])
                    self.assertTrue(any(
                        row['event_type'] == 'MODIFIED'
                        and Path(str(row['path'])).resolve(strict=False) == moved.resolve()
                        for row in observations
                    ))
                    self.assertFalse(any(
                        Path(str(row['path'])).resolve(strict=False) == unrelated.resolve()
                        for row in observations
                    ))
                    self.assertTrue(all(row['target_id'] == protection['target_id'] for row in observations))
                    linked = connection.execute(
                        'SELECT finding_id FROM finding_observations WHERE observation_id = ?',
                        (move_observation['observation_id'],),
                    ).fetchall()
                    self.assertTrue(linked)
                    linked_findings = {
                        row['finding_type'] for row in connection.execute(
                            'SELECT finding_type FROM security_findings WHERE finding_id IN ('
                            + ', '.join('?' for _ in linked) + ')',
                            tuple(row['finding_id'] for row in linked),
                        )
                    }
                    self.assertIn('MOVED_RENAMED', linked_findings)
                finally:
                    connection.close()
            finally:
                coordinator.stop()

    def test_file_target_rediscovery_survives_restart_without_mutating_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = root / 'sentinel.db'
            original = root / 'important.txt'; original.write_text('trusted', encoding='utf-8')
            protection = create_protection(original, True, database)
            assert protection
            archive = root / 'archive'; renamed = root / 'renamed.txt'; moved = archive / 'renamed.txt'
            first = MonitoringCoordinator(database, debounce_seconds=.08)
            try:
                self.assertEqual(first.start(), 1)
                original.rename(renamed)
                wait_for(lambda: any(
                    row['finding_type'] == 'RENAMED'
                    for row in self._findings(database, protection['target_id'])
                ))
                archive.mkdir()
                renamed.rename(moved)
                wait_for(lambda: any(
                    row['finding_type'] == 'MOVED_RENAMED'
                    for row in self._findings(database, protection['target_id'])
                ))
            finally:
                first.stop()

            connection = connect(database)
            try:
                baseline_before = dict(connection.execute(
                    'SELECT path, sha256, file_identity FROM baseline_files WHERE baseline_id = ?',
                    (protection['baseline_id'],),
                ).fetchone())
            finally:
                connection.close()

            second = MonitoringCoordinator(database, debounce_seconds=.08)
            try:
                self.assertEqual(second.start(), 1)
                self.assertEqual(second.monitored_target_ids, {protection['target_id']})
                self.assertEqual(second._tracked_file_paths[protection['target_id']], {moved.resolve()})
                # A moved-but-unmodified file remains monitorable; startup does
                # not fabricate a new content finding or rebaseline it.
                findings_before_modify = self._findings(database, protection['target_id'])
                time.sleep(.15)
                self.assertEqual(self._findings(database, protection['target_id']), findings_before_modify)

                unrelated = root / 'unrelated.txt'
                unrelated.write_text('not protected', encoding='utf-8')
                time.sleep(.15)
                self.assertFalse(any(
                    Path(str(row['path'])).resolve(strict=False) == unrelated.resolve()
                    for row in self._observations(database, protection['target_id'])
                ))

                observation_count = len(self._observations(database, protection['target_id']))
                moved.write_text('changed after restart', encoding='utf-8')
                wait_for(lambda: len(self._observations(database, protection['target_id'])) > observation_count)
                wait_for(lambda: any(
                    row['finding_type'] == 'MOVED_RENAMED_AND_MODIFIED'
                    for row in self._findings(database, protection['target_id'])
                ))
                connection = connect(database)
                try:
                    baseline_after = dict(connection.execute(
                        'SELECT path, sha256, file_identity FROM baseline_files WHERE baseline_id = ?',
                        (protection['baseline_id'],),
                    ).fetchone())
                    protected_path = connection.execute(
                        'SELECT path FROM protected_targets WHERE target_id = ?',
                        (protection['target_id'],),
                    ).fetchone()['path']
                    self.assertEqual(baseline_after, baseline_before)
                    self.assertEqual(protected_path, str(original.resolve()))
                    observation = list_evidence_observations(connection, protection['target_id'])[-1]
                    self.assertEqual(Path(str(observation['path'])).resolve(strict=False), moved.resolve())
                    links = connection.execute(
                        'SELECT finding_id FROM finding_observations WHERE observation_id = ?',
                        (observation['observation_id'],),
                    ).fetchall()
                    self.assertTrue(links)
                    self.assertTrue(all(
                        connection.execute(
                            'SELECT target_id FROM security_findings WHERE finding_id = ?',
                            (row['finding_id'],),
                        ).fetchone()['target_id'] == protection['target_id']
                        for row in links
                    ))
                finally:
                    connection.close()
            finally:
                second.stop()

    def test_file_rediscovery_rejects_identity_mismatch_at_original_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = root / 'sentinel.db'
            original = root / 'important.txt'; original.write_text('trusted', encoding='utf-8')
            protection = create_protection(original, True, database)
            assert protection
            original.unlink()
            archive = root / 'archive'; archive.mkdir()
            # Matching name and content are insufficient; this is a distinct
            # filesystem object and must not be adopted during rediscovery.
            unrelated = archive / 'important.txt'
            unrelated.write_text('trusted', encoding='utf-8')
            coordinator = MonitoringCoordinator(database, debounce_seconds=.08)
            try:
                self.assertEqual(coordinator.start(), 0)
                self.assertNotIn(protection['target_id'], coordinator.monitored_target_ids)
                self.assertNotIn(protection['target_id'], coordinator._tracked_file_paths)
            finally:
                coordinator.stop()

    def test_watcher_observations_are_persisted_and_linked_before_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = root / 'sentinel.db'; target = root / 'protected'
            target.mkdir(); important = target / 'important.txt'; important.write_text('trusted', encoding='utf-8')
            protection = create_protection(target, True, database)
            assert protection
            coordinator = MonitoringCoordinator(database, debounce_seconds=.08)
            try:
                coordinator.start()
                important.write_text('changed', encoding='utf-8')
                wait_for(lambda: self._findings(database, protection['target_id']))
                connection = connect(database)
                try:
                    observations = list_evidence_observations(connection, protection['target_id'])
                    self.assertTrue(observations)
                    self.assertTrue(all(row['observation_id'] for row in observations))
                    self.assertGreater(connection.execute('SELECT COUNT(*) FROM finding_observations').fetchone()[0], 0)
                finally:
                    connection.close()
            finally:
                coordinator.stop()

    def test_observation_persistence_failure_is_visible_and_does_not_schedule_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = root / 'sentinel.db'; target = root / 'protected'
            target.mkdir(); important = target / 'important.txt'; important.write_text('trusted', encoding='utf-8')
            protection = create_protection(target, True, database)
            assert protection
            errors: list[Exception] = []
            coordinator = MonitoringCoordinator(database, debounce_seconds=.08, error_sink=errors.append)
            coordinator.start()
            try:
                with patch('core.monitoring.insert_evidence_observation', side_effect=DatabaseError('simulated evidence failure')):
                    coordinator._on_event(protection['target_id'], normalize_event('MODIFIED', str(important)))
                self.assertIsInstance(coordinator.last_persistence_error, DatabaseError)
                self.assertEqual(len(errors), 1)
                self.assertNotIn(protection['target_id'], coordinator._timers)
                connection = connect(database)
                try:
                    self.assertEqual(list_evidence_observations(connection, protection['target_id']), [])
                    self.assertEqual(list_security_findings(connection, protection['target_id']), [])
                finally:
                    connection.close()
            finally:
                coordinator.stop()

    def test_observation_history_continues_after_coordinator_restart(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); database = root / 'sentinel.db'; target = root / 'protected'
            target.mkdir(); important = target / 'important.txt'; important.write_text('trusted', encoding='utf-8')
            protection = create_protection(target, True, database)
            assert protection
            first = MonitoringCoordinator(database, debounce_seconds=.08)
            try:
                first.start()
                important.write_text('first change', encoding='utf-8')
                wait_for(lambda: self._findings(database, protection['target_id']))
            finally:
                first.stop()
            connection = connect(database)
            try:
                before_restart = list_evidence_observations(connection, protection['target_id'])
            finally:
                connection.close()
            self.assertTrue(before_restart)

            second = MonitoringCoordinator(database, debounce_seconds=.08)
            try:
                second.start()
                important.write_text('second change', encoding='utf-8')
                wait_for(lambda: len(self._observations(database, protection['target_id'])) > len(before_restart))
            finally:
                second.stop()
            connection = connect(database)
            try:
                timeline = list_evidence_observations(connection, protection['target_id'])
                self.assertGreater(len(timeline), len(before_restart))
                self.assertEqual([row['observation_id'] for row in timeline], sorted(row['observation_id'] for row in timeline))
            finally:
                connection.close()
