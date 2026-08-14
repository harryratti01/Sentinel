"""Command-line entry point for the Sentinel vertical slice."""

import argparse
import sqlite3
from pathlib import Path

from .database import DatabaseError, connect, insert_file, insert_processing_result
from .ingestion import IngestionError, ingest_text_file
from .processor import analyze_text


def run(file_path: str | Path, database_path: str | Path | None = None) -> tuple[int, dict[str, object] | None]:
    """Ingest, analyse, and persist one text file."""
    try:
        file_data = ingest_text_file(file_path)
        connection = connect(database_path)
        try:
            with connection:
                file_id = insert_file(connection, file_data)
                result = analyze_text(str(file_data["content"]))
                insert_processing_result(connection, file_id, result)
        finally:
            connection.close()
        return file_id, result
    except (IngestionError, DatabaseError, sqlite3.Error) as error:
        print(f"Sentinel error: {error}")
        return 1, None


def main() -> int:
    parser = argparse.ArgumentParser(description="Process a local UTF-8 text file with Sentinel.")
    parser.add_argument("file", help="Path to the text file to process")
    args = parser.parse_args()

    file_id, result = run(args.file)
    if result is None:
        return 1

    print(f"File processed: {Path(args.file).resolve()}")
    print(f"File ID: {file_id}")
    print(f"Processing status: {result['status']}")
    print(
        "Basic analysis: "
        f"{result['character_count']} characters, "
        f"{result['word_count']} words, "
        f"{result['line_count']} lines"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
