"""SQLite setup and persistence helpers for Sentinel."""

import sqlite3
from pathlib import Path
from typing import Any


DEFAULT_DATABASE_PATH = Path(__file__).resolve().parent.parent / "data" / "sentinel.db"


class DatabaseError(Exception):
    """Raised when Sentinel cannot read from or write to its database."""


def connect(database_path: Path | str | None = None) -> sqlite3.Connection:
    """Open the Sentinel database and ensure its required schema exists."""
    path = Path(database_path) if database_path is not None else DEFAULT_DATABASE_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        _create_schema(connection)
        return connection
    except (OSError, sqlite3.Error) as error:
        raise DatabaseError(f"Unable to open Sentinel database at {path}: {error}") from error


def _create_schema(connection: sqlite3.Connection) -> None:
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size INTEGER NOT NULL,
                modified_time TEXT NOT NULL,
                baseline_created TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS protected_targets (
                target_id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                path_key TEXT NOT NULL,
                target_type TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS protection_baselines (
                baseline_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY (target_id) REFERENCES protected_targets(target_id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS baseline_files (
                baseline_file_id INTEGER PRIMARY KEY AUTOINCREMENT,
                baseline_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_identity TEXT NOT NULL,
                modified_time_ns INTEGER NOT NULL,
                size INTEGER NOT NULL,
                FOREIGN KEY (baseline_id) REFERENCES protection_baselines(baseline_id)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_protected_targets_path_key "
            "ON protected_targets(path_key)"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_active_protected_target "
            "ON protected_targets(path_key) WHERE status = 'ACTIVE'"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS security_findings (
                finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                detected_at TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                current_path TEXT,
                previous_path TEXT,
                confidence TEXT NOT NULL,
                evidence TEXT NOT NULL,
                signature TEXT NOT NULL,
                FOREIGN KEY (target_id) REFERENCES protected_targets(target_id)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_security_findings_target "
            "ON security_findings(target_id, finding_id)"
        )
        # M6 evidence is deliberately additive.  M2's filesystem_events remains
        # an unscoped watcher log; these records retain the target association and
        # capture-time snapshot needed to investigate protected-target history.
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence_observations (
                observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                old_path TEXT,
                new_path TEXT,
                file_identity TEXT,
                sha256 TEXT,
                size INTEGER,
                modified_time_ns INTEGER,
                FOREIGN KEY (target_id) REFERENCES protected_targets(target_id)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_evidence_observations_target "
            "ON evidence_observations(target_id, observation_id)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_observations (
                finding_id INTEGER NOT NULL,
                observation_id INTEGER NOT NULL,
                PRIMARY KEY (finding_id, observation_id),
                FOREIGN KEY (finding_id) REFERENCES security_findings(finding_id),
                FOREIGN KEY (observation_id) REFERENCES evidence_observations(observation_id)
            )
            """
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(files)")}
        if "content" not in columns:
            connection.execute("ALTER TABLE files ADD COLUMN content TEXT")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS processing_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                character_count INTEGER NOT NULL,
                word_count INTEGER NOT NULL,
                line_count INTEGER NOT NULL,
                processed_at TEXT NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS filesystem_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                old_path TEXT,
                new_path TEXT
            )
            """
        )
        connection.commit()
    except sqlite3.Error as error:
        connection.rollback()
        raise DatabaseError(f"Unable to initialise Sentinel database: {error}") from error


def insert_file(connection: sqlite3.Connection, file_data: dict[str, Any]) -> int:
    try:
        cursor = connection.execute(
            """
            INSERT INTO files (path, sha256, size, modified_time, baseline_created, content)
            VALUES (:path, :sha256, :size, :modified_time, :baseline_created, :content)
            """,
            file_data,
        )
        return int(cursor.lastrowid)
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to save file: {error}") from error


def insert_processing_result(
    connection: sqlite3.Connection, file_id: int, result: dict[str, Any]
) -> None:
    try:
        connection.execute(
            """
            INSERT INTO processing_results
                (file_id, status, character_count, word_count, line_count, processed_at)
            VALUES
                (:file_id, :status, :character_count, :word_count, :line_count, :processed_at)
            """,
            {"file_id": file_id, **result},
        )
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to save processing result: {error}") from error


def insert_filesystem_event(connection: sqlite3.Connection, event: dict[str, Any]) -> int:
    """Persist one normalized filesystem event in the current transaction."""
    try:
        cursor = connection.execute(
            """
            INSERT INTO filesystem_events (timestamp, event_type, path, old_path, new_path)
            VALUES (:timestamp, :event_type, :path, :old_path, :new_path)
            """,
            event,
        )
        return int(cursor.lastrowid)
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to save filesystem event: {error}") from error


def insert_protected_target(connection: sqlite3.Connection, target: dict[str, Any]) -> int:
    try:
        cursor = connection.execute(
            """
            INSERT INTO protected_targets (path, path_key, target_type, status, created_at)
            VALUES (:path, :path_key, :target_type, :status, :created_at)
            """,
            target,
        )
        return int(cursor.lastrowid)
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to save protected target: {error}") from error


def insert_protection_baseline(connection: sqlite3.Connection, target_id: int, created_at: str) -> int:
    try:
        cursor = connection.execute(
            "INSERT INTO protection_baselines (target_id, created_at) VALUES (?, ?)",
            (target_id, created_at),
        )
        return int(cursor.lastrowid)
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to save protection baseline: {error}") from error


def insert_baseline_files(
    connection: sqlite3.Connection, baseline_id: int, files: list[dict[str, Any]]
) -> None:
    try:
        connection.executemany(
            """
            INSERT INTO baseline_files
                (baseline_id, path, relative_path, sha256, file_identity, modified_time_ns, size)
            VALUES
                (:baseline_id, :path, :relative_path, :sha256, :file_identity, :modified_time_ns, :size)
            """,
            [{"baseline_id": baseline_id, **file_data} for file_data in files],
        )
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to save baseline files: {error}") from error


def active_protected_target(connection: sqlite3.Connection, path_key: str) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM protected_targets WHERE path_key = ? AND status = 'ACTIVE'", (path_key,)
    ).fetchone()


def list_protected_targets(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT target_id, path, target_type, status, created_at FROM protected_targets ORDER BY target_id"
    ).fetchall()


def update_protected_target_status(
    connection: sqlite3.Connection, target_id: int, status: str
) -> sqlite3.Row | None:
    """Update one existing protected target's status in the caller's transaction."""
    try:
        cursor = connection.execute(
            "UPDATE protected_targets SET status = ? WHERE target_id = ?",
            (status, target_id),
        )
        if cursor.rowcount != 1:
            return None
        return connection.execute(
            "SELECT target_id, path, target_type, status, created_at "
            "FROM protected_targets WHERE target_id = ?",
            (target_id,),
        ).fetchone()
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to update protected target status: {error}") from error


def active_protected_targets(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    return connection.execute(
        """
        SELECT protected_targets.target_id, path, target_type, status,
               protected_targets.created_at, baseline_id,
               protection_baselines.created_at AS baseline_created
        FROM protected_targets
        JOIN protection_baselines USING (target_id)
        WHERE status = 'ACTIVE'
        ORDER BY protected_targets.target_id
        """
    ).fetchall()


def load_baseline_files(connection: sqlite3.Connection, baseline_id: int) -> list[sqlite3.Row]:
    return connection.execute(
        "SELECT path, relative_path, sha256, file_identity, modified_time_ns, size "
        "FROM baseline_files WHERE baseline_id = ? ORDER BY baseline_file_id",
        (baseline_id,),
    ).fetchall()


def insert_security_finding(connection: sqlite3.Connection, finding: dict[str, Any]) -> int:
    try:
        cursor = connection.execute(
            """
            INSERT INTO security_findings
                (target_id, detected_at, finding_type, current_path, previous_path,
                 confidence, evidence, signature)
            VALUES (:target_id, :detected_at, :finding_type, :current_path, :previous_path,
                    :confidence, :evidence, :signature)
            """,
            finding,
        )
        return int(cursor.lastrowid)
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to save security finding: {error}") from error


def insert_evidence_observation(connection: sqlite3.Connection, observation: dict[str, Any]) -> int:
    """Persist one target-scoped normalized watcher observation."""
    try:
        cursor = connection.execute(
            """
            INSERT INTO evidence_observations
                (target_id, observed_at, event_type, path, old_path, new_path,
                 file_identity, sha256, size, modified_time_ns)
            VALUES (:target_id, :observed_at, :event_type, :path, :old_path, :new_path,
                    :file_identity, :sha256, :size, :modified_time_ns)
            """,
            observation,
        )
        return int(cursor.lastrowid)
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to save evidence observation: {error}") from error


def link_finding_observations(
    connection: sqlite3.Connection, finding_id: int, observation_ids: list[int]
) -> None:
    """Link a finding to every persisted observation in its debounce batch."""
    try:
        connection.executemany(
            "INSERT OR IGNORE INTO finding_observations (finding_id, observation_id) VALUES (?, ?)",
            [(finding_id, observation_id) for observation_id in observation_ids],
        )
    except sqlite3.Error as error:
        raise DatabaseError(f"Unable to link finding evidence: {error}") from error


def unlinked_evidence_observation_ids(connection: sqlite3.Connection, target_id: int) -> list[int]:
    """Return persisted observations not yet associated with a reconciliation finding."""
    return [
        int(row["observation_id"])
        for row in connection.execute(
            """
            SELECT observation_id FROM evidence_observations
            WHERE target_id = ?
              AND NOT EXISTS (
                  SELECT 1 FROM finding_observations
                  WHERE finding_observations.observation_id = evidence_observations.observation_id
              )
            ORDER BY observation_id
            """,
            (target_id,),
        )
    ]


def finding_ids_for_signatures(
    connection: sqlite3.Connection, target_id: int, signatures: set[str]
) -> list[int]:
    """Find the persisted baseline-relative findings represented by current signatures."""
    if not signatures:
        return []
    placeholders = ", ".join("?" for _ in signatures)
    return [
        int(row["finding_id"])
        for row in connection.execute(
            f"SELECT finding_id FROM security_findings WHERE target_id = ? AND signature IN ({placeholders})",
            (target_id, *sorted(signatures)),
        )
    ]


def list_evidence_observations(
    connection: sqlite3.Connection, target_id: int
) -> list[sqlite3.Row]:
    """Return a deterministic target timeline, ordered by persistent sequence."""
    return connection.execute(
        "SELECT * FROM evidence_observations WHERE target_id = ? ORDER BY observation_id",
        (target_id,),
    ).fetchall()


def list_security_findings(connection: sqlite3.Connection, target_id: int | None = None) -> list[sqlite3.Row]:
    query = "SELECT * FROM security_findings"
    parameters: tuple[Any, ...] = ()
    if target_id is not None:
        query += " WHERE target_id = ?"
        parameters = (target_id,)
    return connection.execute(query + " ORDER BY finding_id", parameters).fetchall()
