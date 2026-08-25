"""Coordinator for monitoring all ACTIVE protected targets."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from watchdog.observers import Observer

from .baseline import reconcile
from .database import (
    connect,
    active_protected_targets,
    insert_security_finding,
    load_baseline_files,
)
from .watcher import _SentinelEventHandler, WatcherError


FindingSink = Callable[[dict[str, object]], None]


class MonitoringCoordinator:
    """Own watchdog observers, debounce noisy events, and persist meaningful findings."""

    def __init__(
        self, database_path: str | Path | None = None, finding_sink: FindingSink | None = None,
        debounce_seconds: float = 0.15,
    ) -> None:
        self.database_path = database_path
        self.finding_sink = finding_sink or (lambda finding: print(
            f"Finding {finding['finding_id']}: target={finding['target_id']} "
            f"{finding['finding_type']} path={finding['current_path']}"
        ))
        self.debounce_seconds = debounce_seconds
        self._observer = Observer()
        self._targets: dict[int, dict[str, object]] = {}
        self._timers: dict[int, threading.Timer] = {}
        self._last_signatures: dict[int, set[str]] = {}
        self._lock = threading.RLock()
        self._started = False

    @property
    def monitored_target_ids(self) -> set[int]:
        return set(self._targets)

    @property
    def watcher_count(self) -> int:
        return len(self._targets)

    def start(self) -> int:
        """Discover ACTIVE targets and start exactly one recursive watcher for each."""
        if self._started:
            return self.watcher_count
        connection = connect(self.database_path)
        try:
            rows = active_protected_targets(connection)
            for row in rows:
                target = dict(row)
                path = Path(str(target['path']))
                if not path.exists():
                    continue
                target['baseline'] = {
                    'created_at': target['baseline_created'],
                    'files': [dict(item) for item in load_baseline_files(connection, int(target['baseline_id']))],
                }
                self._targets[int(target['target_id'])] = target
        finally:
            connection.close()
        if not self._targets:
            return 0
        for target_id, target in self._targets.items():
            path = Path(str(target['path']))
            watch_root = path if path.is_dir() else path.parent
            self._observer.schedule(_SentinelEventHandler(lambda event, ident=target_id: self._on_event(ident, event)), str(watch_root), recursive=True)
        self._observer.start()
        self._started = True
        return len(self._targets)

    def _on_event(self, target_id: int, event: dict[str, object]) -> None:
        target = self._targets[target_id]
        path = Path(str(target['path']))
        event_paths = [event.get('path'), event.get('old_path'), event.get('new_path')]
        if not any(self._belongs_to_target(target, candidate) for candidate in event_paths if candidate):
            return
        with self._lock:
            previous = self._timers.pop(target_id, None)
            if previous is not None:
                previous.cancel()
            timer = threading.Timer(self.debounce_seconds, self._reconcile_target, args=(target_id,))
            timer.daemon = True
            self._timers[target_id] = timer
            timer.start()

    @staticmethod
    def _belongs_to_target(target: dict[str, object], candidate: object) -> bool:
        target_path = Path(str(target['path']))
        candidate_path = Path(str(candidate)).resolve(strict=False)
        if target['target_type'] == 'FILE':
            return candidate_path == target_path
        try:
            candidate_path.relative_to(target_path)
            return True
        except ValueError:
            return False

    def _reconcile_target(self, target_id: int) -> None:
        with self._lock:
            self._timers.pop(target_id, None)
        target = self._targets[target_id]
        target_path = Path(str(target['path']))
        # Reconciliation operates on a directory root; a protected file uses its parent
        # and only accepts findings that concern the protected file.
        root = target_path if target['target_type'] == 'DIRECTORY' else target_path.parent
        findings = reconcile(dict(target['baseline']), root)
        if target['target_type'] == 'FILE':
            findings = [item for item in findings if any(
                str(record.get('path')) == str(target_path)
                for record in (item.get('baseline'), item.get('current')) if record
            )]
        meaningful = [item for item in findings if item['finding'] != 'UNCHANGED']
        signatures = {self._signature(item) for item in meaningful}
        new_signatures = signatures - self._last_signatures.get(target_id, set())
        self._last_signatures[target_id] = signatures
        if not new_signatures:
            return
        connection = connect(self.database_path)
        try:
            with connection:
                for finding in meaningful:
                    signature = self._signature(finding)
                    if signature not in new_signatures:
                        continue
                    stored = self._persistable(target_id, finding, signature)
                    stored['finding_id'] = insert_security_finding(connection, stored)
                    self.finding_sink(stored)
        finally:
            connection.close()

    @staticmethod
    def _signature(finding: dict[str, object]) -> str:
        return json.dumps({
            'type': finding['finding'], 'baseline': finding.get('baseline'), 'current': finding.get('current')
        }, sort_keys=True, default=str)

    @staticmethod
    def _persistable(target_id: int, finding: dict[str, object], signature: str) -> dict[str, object]:
        current = finding.get('current') or {}
        baseline = finding.get('baseline') or {}
        return {
            'target_id': target_id,
            'detected_at': datetime.now(timezone.utc).isoformat(),
            'finding_type': finding['finding'],
            'current_path': current.get('path'),
            'previous_path': baseline.get('path'),
            'confidence': finding['confidence'],
            'evidence': json.dumps(finding['evidence']),
            'signature': signature,
        }

    def stop(self) -> None:
        with self._lock:
            for timer in self._timers.values():
                timer.cancel()
            self._timers.clear()
        if self._started:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._started = False

    def run_forever(self) -> None:
        if not self.start():
            print('No ACTIVE protected targets to monitor.')
            return
        print(f'Monitoring {self.watcher_count} ACTIVE protected target(s).')
        try:
            while self._started:
                self._observer.join(1)
        except KeyboardInterrupt:
            print('Stopping Sentinel monitoring.')
        finally:
            self.stop()
