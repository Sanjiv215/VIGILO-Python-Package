"""Unit tests for Vigilo core data models."""

from pathlib import Path
import unittest

from vigilo.models import DetectorMeta, Finding, Location, Severity


class TestModels(unittest.TestCase):
    def test_severity_ranks_and_comparisons(self) -> None:
        self.assertEqual(Severity.LOW.rank, 1)
        self.assertEqual(Severity.MEDIUM.rank, 2)
        self.assertEqual(Severity.HIGH.rank, 3)

        self.assertTrue(Severity.HIGH > Severity.MEDIUM)
        self.assertTrue(Severity.MEDIUM > Severity.LOW)
        self.assertTrue(Severity.LOW < Severity.HIGH)
        self.assertTrue(Severity.HIGH >= Severity.HIGH)
        self.assertTrue(Severity.MEDIUM >= Severity.LOW)
        self.assertTrue(Severity.LOW <= Severity.MEDIUM)

        # String comparison support
        self.assertTrue(Severity.HIGH >= "medium")
        self.assertTrue(Severity.LOW <= "high")

    def test_location(self) -> None:
        loc = Location(file=Path("test.py"), line=10, col=4, end_line=10, end_col=20)
        self.assertEqual(str(loc), "test.py:10:4")
        self.assertEqual(loc.file, Path("test.py"))
        self.assertEqual(loc.line, 10)
        self.assertEqual(loc.col, 4)

    def test_detector_meta(self) -> None:
        meta = DetectorMeta(
            id="VIGILO-001",
            name="SQL Injection",
            cwe=89,
            description="Detects SQL injection vulnerabilities",
            severity=Severity.HIGH,
        )
        self.assertEqual(meta.id, "VIGILO-001")
        self.assertEqual(meta.cwe, 89)
        self.assertEqual(meta.severity, Severity.HIGH)

    def test_finding_immutability(self) -> None:
        meta = DetectorMeta(
            id="VIGILO-001",
            name="SQL Injection",
            cwe=89,
            description="SQL Injection",
            severity=Severity.HIGH,
        )
        loc = Location(file=Path("app.py"), line=5, col=2)
        finding = Finding(
            detector=meta,
            location=loc,
            message="Untrusted SQL query",
            fix_hint="Use parameterized query",
            severity=Severity.HIGH,
            confidence="high",
            source_line="db.execute(query)",
        )

        self.assertEqual(finding.detector.id, "VIGILO-001")
        self.assertEqual(finding.location.line, 5)
        self.assertEqual(finding.source_line, "db.execute(query)")

        # Verify frozen immutability
        with self.assertRaises(Exception):
            finding.message = "New message"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
