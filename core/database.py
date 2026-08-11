import sqlite3
from pathlib import Path

database_path = Path(__file__).resolve().parent.parent / "data" / "sentinel.db"

connection = sqlite3.connect(database_path)

connection.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    modified_time TEXT NOT NULL,
    baseline_created TEXT NOT NULL
)
""")

connection.commit()

cursor = connection.execute("""
SELECT name FROM sqlite_master
WHERE type = 'table'
""")

print(cursor.fetchall())