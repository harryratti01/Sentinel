"""Coordinator for monitoring all ACTIVE protected targets."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from watchdog.observers import Observer

from .baseline import reconcile
from .hasher import calculate_hash
from .database import (
    connect,
    active_protected_targets,
    DatabaseError,
    finding_ids_for_signatures,
    insert_evidence_observation,
    insert_security_finding,
    link_finding_observations,
    list_evidence_observations,
    load_baseline_files,
    unlinked_evidence_observation_ids,
)
from .watcher import _SentinelEventHandler, WatcherError


FindingSink = Callable[[dict[str, object]], None]
ErrorSink = Callable[[Exception], None]


class MonitoringCoordinator:
    """Own watchdog observers, debounce noisy events, and persist meaningful findings."""

    def __init__(
        self, database_path: str | Path | None = None, finding_sink: FindingSink | None = None,
        debounce_seconds: float = 0.15, error_sink: ErrorSink | None = None,
    ) -> None:
        self.database_path = database_path
        self.finding_sink = finding_sink or (lambda finding: print(
            f"Finding {finding['finding_id']}: target={finding['target_id']} "
            f"{finding['finding_type']} path={finding['current_path']}"
        ))
        self.debounce_seconds = debounce_seconds
        self.error_sink = error_sink or (lambda error: print(f"Sentinel evidence error: {error}"))
        self._observer = Observer()
        self._targets: dict[int, dict[str, object]] = {}
        self._timers: dict[int, threading.Timer] = {}
        self._last_signatures: dict[int, set[str]] = {}
        self._pending_observations: dict[int, list[int]] = {}
        # FILE targets watch their parent directory.  This is only a watcher
        # boundary: admission remains limited to the baseline file identity
        # (or a path already established for that identity).
        self._tracked_file_paths: dict[int, set[Path]] = {}
        self.last_persistence_error: Exception | None = None
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
                target['baseline'] = {
                    'created_at': target['baseline_created'],
                    'files': [dict(item) for item in load_baseline_files(connection, int(target['baseline_id']))],
                }
                runtime_path = path.resolve(strict=False)
                if target['target_type'] == 'FILE' and not path.exists():
                    runtime_path = self._rediscover_file_path(connection, target)
                    if runtime_path is None:
                        continue
                elif not path.exists():
                    # Preserve DIRECTORY-target startup behavior.
                    continue
                self._targets[int(target['target_id'])] = target
                if target['target_type'] == 'FILE':
                    self._tracked_file_paths[int(target['target_id'])] = {runtime_path}
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

    @staticmethod
    def _file_identity(path: Path) -> str | None:
        """Return the existing platform identity without inferring from file contents."""
        try:
            if not path.is_file() or path.is_symlink():
                return None
            stat = path.stat()
            return f"{stat.st_dev}:{stat.st_ino}"
        except OSError:
            return None

    def _rediscover_file_path(
        self, connection: sqlite3.Connection, target: dict[str, object]) -> Path | None:
        """Find a moved FILE target inside its original parent watcher boundary.

        Persisted evidence supplies likely runtime paths, but a current identity
        comparison with the immutable baseline is always required before a path
        can be adopted.  A bounded scan covers restart cases where evidence did
        not contain the final path.
        """
        scope = Path(str(target['path'])).parent.resolve(strict=False)
        if not scope.is_dir():
            return None
        identities = {str(item['file_identity']) for item in target['baseline']['files']}
        target_id = int(target['target_id'])
        candidates: list[Path] = []
        for observation in reversed(list_evidence_observations(connection, target_id)):
            for value in (observation['new_path'], observation['path']):
                if value:
                    candidates.append(Path(str(value)).resolve(strict=False))
        try:
            candidates.extend(path.resolve(strict=False) for path in scope.rglob('*') if path.is_file())
        except OSError:
            return None
        seen: set[Path] = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                candidate.relative_to(scope)
            except ValueError:
                continue
            if self._file_identity(candidate) in identities:
                return candidate
        return None

    def _on_event(self, target_id: int, event: dict[str, object]) -> None:
        target = self._targets[target_id]
        snapshot = self._snapshot(event.get('new_path') or event['path'])
        if not self._event_belongs_to_target(target_id, target, event, snapshot):
            return
        try:
            observation_id = self._persist_observation(target_id, event, snapshot)
        except DatabaseError as error:
            self.last_persistence_error = error
            self.error_sink(error)
            return
        observation_ids = [observation_id]
        inferred_move = self._infer_file_move(target_id, target, event, snapshot)
        if inferred_move is not None:
            try:
                observation_ids.append(self._persist_observation(target_id, inferred_move, snapshot))
            except DatabaseError as error:
                self.last_persistence_error = error
                self.error_sink(error)
                return
        self._record_file_path(target_id, target, inferred_move or event)
        with self._lock:
            self._pending_observations.setdefault(target_id, []).extend(observation_ids)
            previous = self._timers.pop(target_id, None)
            if previous is not None:
                previous.cancel()
            timer = threading.Timer(self.debounce_seconds, self._reconcile_target, args=(target_id,))
            timer.daemon = True
            self._timers[target_id] = timer
            timer.start()

    @staticmethod
    def _snapshot(path_value: object) -> dict[str, object | None]:
        """Capture only metadata available at callback time; deletion is valid evidence."""
        try:
            path = Path(str(path_value))
            if not path.is_file() or path.is_symlink():
                return {"file_identity": None, "sha256": None, "size": None, "modified_time_ns": None}
            stat = path.stat()
            return {
                "file_identity": f"{stat.st_dev}:{stat.st_ino}",
                "sha256": calculate_hash(path),
                "size": stat.st_size,
                "modified_time_ns": stat.st_mtime_ns,
            }
        except OSError:
            return {"file_identity": None, "sha256": None, "size": None, "modified_time_ns": None}

    def _persist_observation(
        self, target_id: int, event: dict[str, object], snapshot: dict[str, object | None] | None = None
    ) -> int:
        observation = {
            "target_id": target_id,
            "observed_at": event["timestamp"],
            "event_type": event["event_type"],
            "path": event["path"],
            "old_path": event.get("old_path"),
            "new_path": event.get("new_path"),
            **(snapshot or self._snapshot(event["new_path"] or event["path"])),
        }
        connection = connect(self.database_path)
        try:
            with connection:
                return insert_evidence_observation(connection, observation)
        finally:
            connection.close()

    def _event_belongs_to_target(
        self,
        target_id: int,
        target: dict[str, object],
        event: dict[str, object],
        snapshot: dict[str, object | None],
    ) -> bool:
        """Accept only events attributable to this protected target.

        A FILE target's baseline path is immutable evidence, not its only
        current location.  Once a file has moved, its Windows identity is the
        authoritative way to distinguish it from unrelated parent-directory
        activity.  A remembered accepted path handles events (notably delete)
        for which no identity can be sampled anymore.
        """
        event_paths = [event.get('path'), event.get('old_path'), event.get('new_path')]
        if target['target_type'] != 'FILE':
            return any(self._belongs_to_target(target, candidate) for candidate in event_paths if candidate)

        candidate_paths = {
            Path(str(candidate)).resolve(strict=False) for candidate in event_paths if candidate
        }
        baseline_path = Path(str(target['path'])).resolve(strict=False)
        baseline_identities = {
            str(item['file_identity']) for item in target['baseline']['files']
        }
        if snapshot['file_identity'] in baseline_identities:
            return True
        # A path with no sampleable file is deletion evidence.  Do not accept
        # an existing unrelated file merely because it occupies a stale
        # runtime path after the protected file moved away.
        if snapshot['file_identity'] is None:
            return bool(candidate_paths & self._tracked_file_paths.get(target_id, set()))
        return baseline_path in candidate_paths

    def _infer_file_move(
        self,
        target_id: int,
        target: dict[str, object],
        event: dict[str, object],
        snapshot: dict[str, object | None],
    ) -> dict[str, object] | None:
        """Represent a Windows delete/create relocation without relabeling raw events."""
        if target['target_type'] != 'FILE' or event['event_type'] != 'CREATED':
            return None
        identities = {str(item['file_identity']) for item in target['baseline']['files']}
        if snapshot['file_identity'] not in identities:
            return None
        new_path = Path(str(event['path'])).resolve(strict=False)
        missing_paths = [
            path for path in self._tracked_file_paths.get(target_id, set())
            if path != new_path and not path.exists()
        ]
        if len(missing_paths) != 1:
            return None
        old_path = missing_paths[0]
        return {
            **event,
            'event_type': 'INFERRED_MOVED',
            'path': str(new_path),
            'old_path': str(old_path),
            'new_path': str(new_path),
        }

    def _record_file_path(
        self, target_id: int, target: dict[str, object], event: dict[str, object]) -> None:
        """Remember an identity-confirmed path without changing baseline data."""
        if target['target_type'] != 'FILE' or event['event_type'] not in {'MOVED', 'INFERRED_MOVED'}:
            return
        old_path = event.get('old_path')
        new_path = event.get('new_path')
        if not new_path:
            return
        paths = self._tracked_file_paths.setdefault(target_id, set())
        if old_path:
            paths.discard(Path(str(old_path)).resolve(strict=False))
        paths.add(Path(str(new_path)).resolve(strict=False))

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
            pending = self._pending_observations.pop(target_id, [])
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
        stored_findings: list[dict[str, object]] = []
        try:
            connection = connect(self.database_path)
            try:
                with connection:
                    for finding in meaningful:
                        signature = self._signature(finding)
                        if signature not in new_signatures:
                            continue
                        stored = self._persistable(target_id, finding, signature)
                        stored['finding_id'] = insert_security_finding(connection, stored)
                        stored_findings.append(stored)
                    # Include observations persisted before a stop/restart as well as
                    # the current debounce batch.  The relation describes the
                    # reconciliation batch, not a claim that any one callback caused it.
                    observation_ids = sorted(set(pending + unlinked_evidence_observation_ids(connection, target_id)))
                    for finding_id in finding_ids_for_signatures(connection, target_id, signatures):
                        link_finding_observations(connection, finding_id, observation_ids)
            finally:
                connection.close()
        except (DatabaseError, sqlite3.Error) as error:
            self.last_persistence_error = error
            self.error_sink(error)
            return
        # Only a committed transaction advances deduplication or notifies consumers.
        self._last_signatures[target_id] = signatures
        for stored in stored_findings:
            self.finding_sink(stored)

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
