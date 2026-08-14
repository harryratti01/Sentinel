"""Reusable real-filesystem scenarios for reconciliation tests."""

import shutil
import os
from pathlib import Path
from typing import Callable


Operation = Callable[[Path], None]


def _rename(root: Path) -> None:
    (root / "important.txt").rename(root / "renamed.txt")


def _create(root: Path) -> None:
    (root / "created.txt").write_text("new content\n", encoding="utf-8")


def _modify_original(root: Path) -> None:
    _modify(root / "important.txt")


def _delete(root: Path) -> None:
    (root / "important.txt").unlink()


def _move(root: Path) -> None:
    archive = root / "archive"
    archive.mkdir(exist_ok=True)
    shutil.move(str(root / "important.txt"), archive / "important.txt")


def _modify(path: Path) -> None:
    path.write_text("changed content\n", encoding="utf-8")


def _rename_then_modify(root: Path) -> None:
    _rename(root)
    _modify(root / "renamed.txt")


def _move_then_modify(root: Path) -> None:
    _move(root)
    _modify(root / "archive" / "important.txt")


def _rename_then_move(root: Path) -> None:
    _rename(root)
    archive = root / "archive"
    archive.mkdir()
    shutil.move(str(root / "renamed.txt"), archive / "renamed.txt")


def _rename_move_modify(root: Path) -> None:
    _rename_then_move(root)
    _modify(root / "archive" / "renamed.txt")


def _delete_recreate_same(root: Path) -> None:
    (root / "important.txt").unlink()
    (root / "important.txt").write_text("replacement content\n", encoding="utf-8")


def _extension_change(root: Path) -> None:
    (root / "important.txt").rename(root / "important.pdf")


def _metadata_only_change(root: Path) -> None:
    path = root / "important.txt"
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))


def _modify_then_restore(root: Path) -> None:
    path = root / "important.txt"
    path.write_text("changed content\n", encoding="utf-8")
    path.write_text("trusted content\n", encoding="utf-8")
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))


def _move_then_move_back(root: Path) -> None:
    _move(root)
    shutil.move(str(root / "archive" / "important.txt"), root / "important.txt")


def _rename_with_extension_change(root: Path) -> None:
    (root / "important.txt").rename(root / "renamed.pdf")


def _delete_recreate_identical(root: Path) -> None:
    (root / "important.txt").unlink()
    (root / "important.txt").write_text("trusted content\n", encoding="utf-8")


def _ambiguous_identical_candidates(root: Path) -> None:
    (root / "important.txt").unlink()
    (root / "candidate-a.txt").write_text("trusted content\n", encoding="utf-8")
    (root / "candidate-b.txt").write_text("trusted content\n", encoding="utf-8")


SCENARIOS: list[tuple[str, Operation, str, str]] = [
    ("create", _create, "CREATED", "HIGH"),
    ("modify", _modify_original, "MODIFIED", "HIGH"),
    ("rename", _rename, "RENAMED", "HIGH"),
    ("move", _move, "MOVED", "HIGH"),
    ("rename_then_modify", _rename_then_modify, "RENAMED_AND_MODIFIED", "HIGH"),
    ("move_then_modify", _move_then_modify, "MOVED_AND_MODIFIED", "HIGH"),
    ("rename_then_move", _rename_then_move, "MOVED_RENAMED", "HIGH"),
    ("rename_move_modify", _rename_move_modify, "MOVED_RENAMED_AND_MODIFIED", "HIGH"),
    ("delete", _delete, "DELETED", "HIGH"),
    ("delete_recreate_same", _delete_recreate_same, "DELETED_AND_RECREATED_DIFFERENT", "HIGH"),
    ("extension_change", _extension_change, "RENAMED", "HIGH"),
    ("metadata_only_change", _metadata_only_change, "METADATA_CHANGED", "HIGH"),
    ("modify_then_restore", _modify_then_restore, "METADATA_CHANGED", "HIGH"),
    ("move_then_move_back", _move_then_move_back, "UNCHANGED", "HIGH"),
    ("rename_with_extension_change", _rename_with_extension_change, "RENAMED", "HIGH"),
    ("delete_recreate_identical", _delete_recreate_identical, "DELETED_AND_RECREATED_IDENTICAL", "HIGH"),
    ("ambiguous_identical_candidates", _ambiguous_identical_candidates, "AMBIGUOUS_IDENTICAL_CONTENT", "LOW"),
]
