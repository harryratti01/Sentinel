"""Deterministic human-verifiable reconciliation acceptance scenario."""

import shutil
import tempfile
from pathlib import Path

from .baseline import create_baseline, reconcile, scan_directory


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
