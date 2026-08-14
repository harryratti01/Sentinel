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
