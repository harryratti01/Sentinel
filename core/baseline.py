"""Trusted filesystem baselines and deterministic reconciliation."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .hasher import calculate_hash


def _file_record(path: Path, root: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "relative_path": str(path.relative_to(root)),
        "sha256": calculate_hash(path),
        "file_identity": f"{stat.st_dev}:{stat.st_ino}",
        "modified_time_ns": stat.st_mtime_ns,
        "size": stat.st_size,
    }


def scan_directory(directory: str | Path) -> dict[str, Any]:
    """Return the current regular-file state below a directory."""
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError(f"Directory not found: {root}")
    symlinks = [path for path in root.rglob("*") if path.is_symlink()]
    if symlinks:
        raise ValueError(f"Refusing to baseline symlink or junction: {symlinks[0]}")
    return {
        "root": str(root),
        "files": [_file_record(path, root) for path in sorted(root.rglob("*")) if path.is_file()],
    }


def scan_target(target: str | Path) -> dict[str, Any]:
    """Scan one directory or one regular file without following symlinks."""
    path = Path(target).expanduser().resolve(strict=True)
    if path.is_symlink():
        raise ValueError(f"Refusing to baseline symlink or junction: {path}")
    if path.is_dir():
        return scan_directory(path)
    if path.is_file():
        return {"root": str(path.parent), "files": [_file_record(path, path.parent)]}
    raise ValueError(f"Target is not a file or directory: {path}")


def create_baseline(directory: str | Path) -> dict[str, Any]:
    """Capture a trusted baseline for a directory's current files."""
    baseline = scan_target(directory)
    baseline["created_at"] = datetime.now(timezone.utc).isoformat()
    return baseline


def _path_change(baseline_file: dict[str, Any], current_file: dict[str, Any]) -> tuple[bool, bool]:
    old_path = Path(str(baseline_file["relative_path"]))
    new_path = Path(str(current_file["relative_path"]))
    return old_path.name != new_path.name, old_path.parent != new_path.parent


def _finding_for_matched_file(
    baseline_file: dict[str, Any], current_file: dict[str, Any]
) -> tuple[str, list[str]]:
    renamed, moved = _path_change(baseline_file, current_file)
    modified = baseline_file["sha256"] != current_file["sha256"]
    metadata_changed = baseline_file["modified_time_ns"] != current_file["modified_time_ns"]
    if not renamed and not moved:
        if modified:
            return "MODIFIED", []
        return ("METADATA_CHANGED" if metadata_changed else "UNCHANGED"), []

    parts: list[str] = []
    if moved:
        parts.append("MOVED")
    if renamed:
        parts.append("RENAMED")
    if modified:
        return "_".join(parts) + "_AND_MODIFIED", [
            "original baseline file no longer exists at its original path",
            "matching baseline file identity found at the current path",
        ]
    return "_".join(parts), [
        "original baseline file no longer exists at its original path",
        "matching baseline file identity found at the current path",
    ]


def reconcile(baseline: dict[str, Any], directory: str | Path) -> list[dict[str, Any]]:
    """Compare the current directory state against a trusted baseline."""
    current = scan_directory(directory)
    current_by_path = {item["relative_path"]: item for item in current["files"]}
    current_by_identity = {item["file_identity"]: item for item in current["files"]}
    matched_current_paths: set[str] = set()
    findings: list[dict[str, Any]] = []

    for baseline_file in baseline["files"]:
        current_file = current_by_path.get(baseline_file["relative_path"])
        identity_match = current_by_identity.get(baseline_file["file_identity"])
        if identity_match is not None:
            current_file = identity_match
        if current_file is None:
            identical_candidates = [
                item for item in current["files"] if item["sha256"] == baseline_file["sha256"]
            ]
            if len(identical_candidates) > 1:
                matched_current_paths.update(
                    str(item["relative_path"]) for item in identical_candidates
                )
                findings.append(
                    {
                        "finding": "AMBIGUOUS_IDENTICAL_CONTENT",
                        "confidence": "LOW",
                        "baseline": baseline_file,
                        "current": None,
                        "evidence": [
                            "multiple current files match the baseline SHA-256",
                            "filesystem identity does not identify the original file",
                        ],
                    }
                )
                continue
            findings.append(
                {
                    "finding": "DELETED",
                    "confidence": "HIGH",
                    "baseline": baseline_file,
                    "current": None,
                    "evidence": ["baseline file is absent from the current state"],
                }
            )
            continue

        matched_current_paths.add(str(current_file["relative_path"]))
        if current_file["file_identity"] != baseline_file["file_identity"]:
            content_relation = (
                "IDENTICAL"
                if current_file["sha256"] == baseline_file["sha256"]
                else "DIFFERENT"
            )
            findings.append(
                {
                    "finding": f"DELETED_AND_RECREATED_{content_relation}",
                    "confidence": "HIGH",
                    "baseline": baseline_file,
                    "current": current_file,
                    "evidence": [
                        "a file exists at the baseline path",
                        "its filesystem identity differs from the baseline file",
                    ],
                }
            )
            continue

        finding, evidence = _finding_for_matched_file(baseline_file, current_file)
        if baseline_file["sha256"] != current_file["sha256"]:
            evidence.append("current SHA-256 differs from baseline SHA-256")
        findings.append(
            {
                "finding": finding,
                "confidence": "HIGH",
                "baseline": baseline_file,
                "current": current_file,
                "evidence": evidence,
            }
        )

    for current_file in current["files"]:
        if current_file["relative_path"] not in matched_current_paths:
            findings.append(
                {
                    "finding": "CREATED",
                    "confidence": "HIGH",
                    "baseline": None,
                    "current": current_file,
                    "evidence": ["file is not present in the trusted baseline"],
                }
            )
    return findings
