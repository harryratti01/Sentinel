"""Table-driven integration tests for real filesystem reconciliation."""

import tempfile
import unittest
from pathlib import Path

from core.baseline import create_baseline, reconcile, scan_directory
from tests.scenario_framework import SCENARIOS


class ReconciliationIntegrationTest(unittest.TestCase):
    def test_real_filesystem_scenarios(self) -> None:
        for scenario_name, operation, expected_finding, expected_confidence in SCENARIOS:
            with self.subTest(scenario=scenario_name), tempfile.TemporaryDirectory() as temporary_directory:
                protected_directory = Path(temporary_directory) / "protected"
                protected_directory.mkdir()
                (protected_directory / "important.txt").write_text("trusted content\n", encoding="utf-8")
                baseline = create_baseline(protected_directory)

                operation(protected_directory)
                findings = reconcile(baseline, protected_directory)
                integrity_findings = findings if expected_finding == "UNCHANGED" else [
                    finding for finding in findings if finding["finding"] != "UNCHANGED"
                ]

                self.assertEqual(len(integrity_findings), 1)
                self.assertEqual(integrity_findings[0]["finding"], expected_finding)
                self.assertEqual(integrity_findings[0]["confidence"], expected_confidence)
                if expected_finding == "METADATA_CHANGED":
                    self.assertEqual(
                        integrity_findings[0]["baseline"]["sha256"],
                        integrity_findings[0]["current"]["sha256"],
                    )
                if expected_finding == "AMBIGUOUS_IDENTICAL_CONTENT":
                    self.assertIsNone(integrity_findings[0]["current"])
                    self.assertIn("multiple current files", integrity_findings[0]["evidence"][0])

    def test_windows_file_identity_lifecycle(self) -> None:
        scenarios_by_name = {name: operation for name, operation, _, _ in SCENARIOS}
        identity_cases = [
            ("rename", True),
            ("move", True),
            ("rename_then_modify", True),
            ("delete_recreate_same", False),
            ("delete_recreate_identical", False),
        ]
        for scenario_name, identity_should_match in identity_cases:
            with self.subTest(scenario=scenario_name), tempfile.TemporaryDirectory() as temporary_directory:
                protected_directory = Path(temporary_directory) / "protected"
                protected_directory.mkdir()
                (protected_directory / "important.txt").write_text("trusted content\n", encoding="utf-8")
                baseline = create_baseline(protected_directory)

                scenarios_by_name[scenario_name](protected_directory)
                current = scan_directory(protected_directory)

                self.assertEqual(len(current["files"]), 1)
                self.assertEqual(
                    current["files"][0]["file_identity"] == baseline["files"][0]["file_identity"],
                    identity_should_match,
                )
