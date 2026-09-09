"""M6 evidence persistence and conservative interpretation tests."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from core.database import (
    connect,
    insert_evidence_observation,
    insert_security_finding,
    link_finding_observations,
)
from core.history import interpret_finding, target_timeline
from core.protection import create_protection


class EvidenceHistoryTest(unittest.TestCase):
    def _target(self, directory: Path) -> tuple[Path, Path, dict[str, object]]:
        target = directory / "protected"
        target.mkdir()
        (target / "important.txt").write_text("trusted", encoding="utf-8")
        database = directory / "sentinel.db"
        protection = create_protection(target, True, database)
        assert protection
        return target, database, protection

    def _finding(self, target_id: int, baseline: dict[str, object], current: dict[str, object]) -> dict[str, object]:
        return {
            "target_id": target_id,
            "detected_at": "2026-01-01T00:00:00+00:00",
            "finding_type": "MODIFIED",
            "current_path": current.get("path"),
            "previous_path": baseline.get("path"),
            "confidence": "HIGH",
            "evidence": "[]",
            "signature": json.dumps({"type": "MODIFIED", "baseline": baseline, "current": current}),
        }

    def test_evidence_order_and_many_to_many_linkage_survive_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target, database, protection = self._target(Path(temporary))
            baseline = {"path": str(target / "important.txt"), "sha256": "trusted", "modified_time_ns": 1}
            current = {"path": str(target / "important.txt"), "sha256": "changed", "modified_time_ns": 2}
            observation = {
                "target_id": protection["target_id"], "observed_at": "same-time", "event_type": "MODIFIED",
                "path": current["path"], "old_path": None, "new_path": None,
                "file_identity": "1:1", "sha256": "changed", "size": 7, "modified_time_ns": 2,
            }
            connection = connect(database)
            try:
                with connection:
                    first = insert_evidence_observation(connection, observation)
                    second = insert_evidence_observation(connection, {**observation, "event_type": "MOVED", "old_path": baseline["path"], "new_path": current["path"]})
                    first_finding = insert_security_finding(connection, self._finding(protection["target_id"], baseline, current))
                    second_finding = insert_security_finding(connection, self._finding(protection["target_id"], baseline, current))
                    link_finding_observations(connection, first_finding, [first, second])
                    link_finding_observations(connection, second_finding, [second])
            finally:
                connection.close()

            connection = connect(database)
            try:
                self.assertEqual([row["observation_id"] for row in target_timeline(connection, protection["target_id"])], [first, second])
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM finding_observations").fetchone()[0], 3)
            finally:
                connection.close()

    def test_interpretation_requires_persisted_prior_content_difference_for_return_claim(self) -> None:
        baseline = {"path": "C:/important.txt", "sha256": "trusted", "modified_time_ns": 1}
        changed = {"path": "C:/important.txt", "sha256": "changed", "modified_time_ns": 2}
        returned = {"path": "C:/important.txt", "sha256": "trusted", "modified_time_ns": 3}
        prior = self._finding(1, baseline, changed)
        current = self._finding(1, baseline, returned)
        self.assertNotIn("Historical evidence indicates content changed and later returned to the trusted baseline.", interpret_finding(current))
        interpretation = interpret_finding(current, [prior])
        self.assertIn("Current content matches the trusted baseline.", interpretation)
        self.assertIn("Supported metadata differs: modification time differs from the trusted baseline.", interpretation)
        self.assertIn("Historical evidence indicates content changed and later returned to the trusted baseline.", interpretation)

    def test_failed_evidence_write_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            _, database, protection = self._target(Path(temporary))
            connection = connect(database)
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    with connection:
                        connection.execute("INSERT INTO evidence_observations (target_id, observed_at, event_type, path) VALUES (?, ?, ?, ?)", (999, "now", "MODIFIED", "missing"))
            finally:
                connection.close()
            connection = connect(database)
            try:
                self.assertEqual(target_timeline(connection, protection["target_id"]), [])
            finally:
                connection.close()
