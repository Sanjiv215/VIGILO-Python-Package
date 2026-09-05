"""Unit tests for Vigilo report formatters (Text & JSON)."""

import json
import unittest
from pathlib import Path

from vigilo.models import DetectorMeta, Finding, Location, Severity
from vigilo.reporter import format_json_report, format_report, format_text_report


class TestReporter(unittest.TestCase):
    def setUp(self) -> None:
        self.meta = DetectorMeta(
            id="VIGILO-001",
            name="SQL Injection",
            cwe=89,
            description="SQL Injection",
            severity=Severity.HIGH,
        )
        self.finding = Finding(
            detector=self.meta,
            location=Location(file=Path("app.py"), line=10, col=4),
            message="Possible SQL injection in execute()",
            fix_hint="Use parameterized query",
            severity=Severity.HIGH,
            confidence="high",
            source_line="db.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        )

    def test_text_report_clean(self) -> None:
        report = format_text_report([], use_color=False)
        self.assertIn("No security vulnerabilities or correctness issues found", report)

    def test_text_report_with_finding(self) -> None:
        report = format_text_report([self.finding], use_color=False)
        self.assertIn("app.py:10:4", report)
        self.assertIn("HIGH", report)
        self.assertIn("VIGILO-001 SQL Injection (CWE-89)", report)
        self.assertIn("Fix: Use parameterized query", report)
        self.assertIn("1 vulnerabilities found (1 high, 0 medium, 0 low)", report)

    def test_json_report(self) -> None:
        report = format_json_report([self.finding])
        data = json.loads(report)

        self.assertEqual(data["version"], "0.2.2")
        self.assertEqual(data["summary"]["total"], 1)
        self.assertEqual(data["summary"]["high"], 1)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["id"], "VIGILO-001")
        self.assertEqual(data["findings"][0]["location"]["line"], 10)

    def test_format_report_dispatch(self) -> None:
        text_out = format_report([self.finding], output_format="text", use_color=False)
        json_out = format_report([self.finding], output_format="json")

        self.assertIn("app.py:10:4", text_out)
        self.assertTrue(json_out.startswith("{"))

    def test_terminal_escape_injection_sanitized(self) -> None:
        malicious_finding = Finding(
            detector=self.meta,
            location=Location(file=Path("\033[2J\033[Hevil.py"), line=1, col=1),
            message="Error \033[31;1mINJECTION\033[0m",
            fix_hint="Fix \033]0;Title\007",
            severity=Severity.HIGH,
            confidence="high",
            source_line="eval('\033[2Jmalicious\033[0m')",
        )
        report = format_text_report([malicious_finding], use_color=False)
        self.assertNotIn("\033[2J", report)
        self.assertNotIn("\033[H", report)
        self.assertNotIn("\033]0;", report)
        self.assertIn("evil.py:1:1", report)
        self.assertIn("Error INJECTION", report)
        self.assertIn("eval('malicious')", report)

    def test_json_report_special_characters_encoded(self) -> None:
        tricky_finding = Finding(
            detector=self.meta,
            location=Location(file=Path('quote"file\\name\n.py'), line=1, col=1),
            message='Message with "quotes" and \\backslashes\\ and \ttabs',
            fix_hint="Fix hint with 'single' and \"double\" quotes",
            severity=Severity.HIGH,
            confidence="high",
            source_line='x = "some\\"string\\n"',
        )
        report_json = format_json_report([tricky_finding])
        data = json.loads(report_json)
        self.assertEqual(data["findings"][0]["location"]["file"], 'quote"file\\name\n.py')
        self.assertIn("quotes", data["findings"][0]["message"])


if __name__ == "__main__":
    unittest.main()
