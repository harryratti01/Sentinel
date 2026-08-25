"""Deterministic human-verifiable reconciliation acceptance scenario."""

import shutil
import tempfile
import time
from pathlib import Path

from .baseline import create_baseline, reconcile, scan_directory
from .protection import create_protection, inspect_target
from .database import connect, list_security_findings
from .monitoring import MonitoringCoordinator


def run_acceptance_demo() -> None:
    """Run a real rename, move, and modify sequence in a temporary directory."""
    with tempfile.TemporaryDirectory(prefix="sentinel-acceptance-") as temporary_directory:
        protected_directory = Path(temporary_directory) / "protected"
        protected_directory.mkdir()
        important_file = protected_directory / "important.txt"
        important_file.write_text("trusted content\n", encoding="utf-8")

        baseline = create_baseline(protected_directory)
        renamed_file = protected_directory / "renamed.txt"
        important_file.rename(renamed_file)
        archive = protected_directory / "archive"
        archive.mkdir()
        moved_file = archive / "renamed.txt"
        shutil.move(str(renamed_file), moved_file)
        moved_file.write_text("trusted content changed\n", encoding="utf-8")

        current = scan_directory(protected_directory)
        finding = reconcile(baseline, protected_directory)[0]
        print(f"Protected directory: {protected_directory}")
        print(f"Baseline state: {baseline['files'][0]['relative_path']}")
        print(f"Current state: {current['files'][0]['relative_path']}")
        print(f"Detected finding: {finding['finding']}")
        print(f"Confidence: {finding['confidence']}")
        print(f"Baseline path: {finding['baseline']['path']}")
        print(f"Current path: {finding['current']['path']}")
        print("Content changed: yes")
        print("Evidence:")
        for item in finding["evidence"]:
            print(f"- {item}")


def run_protection_demo() -> None:
    """Create a real temporary protected target using the normal protection flow."""
    with tempfile.TemporaryDirectory(prefix="sentinel-protection-") as temporary_directory:
        directory = Path(temporary_directory) / "important"
        directory.mkdir()
        (directory / "important.txt").write_text("trusted content\n", encoding="utf-8")
        nested = directory / "archive"
        nested.mkdir()
        (nested / "records.txt").write_text("records\n", encoding="utf-8")
        database_path = Path(temporary_directory) / "sentinel.db"
        summary = inspect_target(directory)
        print(f"Target: {summary['path']}")
        print(f"Files discovered: {summary['file_count']}")
        print("User confirmation: yes")
        protection = create_protection(directory, confirmed=True, database_path=database_path)
        assert protection is not None
        print(f"Protection ID: {protection['target_id']}")
        print(f"Baseline association: {protection['baseline_id']}")
        print(f"Number of baseline files: {protection['baseline_files']}")
        print(f"Protection status: {protection['status']}")


def _findings(database: Path, target_id: int) -> list[dict[str, object]]:
    connection = connect(database)
    try:
        return [dict(row) for row in list_security_findings(connection, target_id)]
    finally:
        connection.close()


def _wait_for(predicate: object, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.03)
    raise RuntimeError("Timed out waiting for Sentinel monitoring")


def run_monitor_demo() -> None:
    """Exercise protection, watchdog events, reconciliation, and finding persistence."""
    with tempfile.TemporaryDirectory(prefix="sentinel-monitor-demo-") as temporary_directory:
        root = Path(temporary_directory)
        target_a, target_b = root / "target-a", root / "target-b"
        target_a.mkdir(); target_b.mkdir()
        (target_a / "important.txt").write_text("trusted A\n", encoding="utf-8")
        (target_b / "important.txt").write_text("trusted B\n", encoding="utf-8")
        database = root / "sentinel.db"
        protection_a = create_protection(target_a, True, database)
        protection_b = create_protection(target_b, True, database)
        assert protection_a and protection_b
        coordinator = MonitoringCoordinator(database, debounce_seconds=0.08)
        print("Protected targets and trusted baselines created.")
        try:
            coordinator.start()
            print(f"Monitoring started: {coordinator.watcher_count} targets.")
            (target_a / "important.txt").write_text("changed A\n", encoding="utf-8")
            _wait_for(lambda: len(_findings(database, protection_a['target_id'])) >= 1)
            renamed = target_a / "renamed.txt"
            (target_a / "important.txt").rename(renamed)
            archive = target_a / "archive"; archive.mkdir()
            moved = archive / "renamed.txt"; shutil.move(str(renamed), moved)
            moved.write_text("changed again A\n", encoding="utf-8")
            _wait_for(lambda: any(row['finding_type'] == 'MOVED_RENAMED_AND_MODIFIED' for row in _findings(database, protection_a['target_id'])))
            (target_a / "second.txt").write_text("another change\n", encoding="utf-8")
            _wait_for(lambda: len(_findings(database, protection_a['target_id'])) >= 3)
            assert not _findings(database, protection_b['target_id'])
            print("Finding persisted; monitoring continued; compound change detected.")
        finally:
            coordinator.stop()
            print("Monitoring stopped cleanly.")
