"""Unit tests for Vigilo scanner orchestrator."""

import ast
import tempfile
import unittest
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.models import DetectorMeta, Finding, Severity
from vigilo.scanner import ScanConfig, Scanner


class DummyDetector(BaseDetector):
    meta = DetectorMeta(
        id="DUMMY-001",
        name="Dummy Detector",
        cwe=100,
        description="Flags dummy calls",
        severity=Severity.HIGH,
    )

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "insecure_call":
                    findings.append(
                        self.create_finding(
                            node=node,
                            file_path=file_path,
                            source=source,
                            message="Insecure call found",
                            fix_hint="Do not use insecure_call",
                        )
                    )
        return findings


class TestScanner(unittest.TestCase):
    def test_parse_valid_and_invalid_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tmp:
            tmp.write("x = 1\n")
            tmp_path = Path(tmp.name)

        try:
            tree, source, error = Scanner.parse_file(tmp_path)
            self.assertIsNotNone(tree)
            self.assertIsNone(error)
            self.assertEqual(source, "x = 1\n")
        finally:
            tmp_path.unlink()

        # Syntax error file
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tmp:
            tmp.write("def broken(\n")
            tmp_path = Path(tmp.name)

        try:
            tree, source, error = Scanner.parse_file(tmp_path)
            self.assertIsNone(tree)
            self.assertIsNotNone(error)
            self.assertTrue(isinstance(error, SyntaxError) or "Syntax error" in str(error))
        finally:
            tmp_path.unlink()

    def test_scanner_orchestration_and_sorting(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            f1 = tmp_path / "a.py"
            f1.write_text("insecure_call()\n")

            f2 = tmp_path / "b.py"
            f2.write_text("# safe\nx = 1\n")

            config = ScanConfig(
                paths=[tmp_path],
                detectors=[DummyDetector],
                min_severity=Severity.LOW,
            )
            scanner = Scanner(config)
            findings = scanner.scan()

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "DUMMY-001")
            self.assertEqual(findings[0].location.line, 1)
            self.assertEqual(findings[0].source_line, "insecure_call()")

    def test_min_severity_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            f1 = tmp_path / "a.py"
            f1.write_text("insecure_call()\n")

            # High finding with min_severity=HIGH -> returned
            config = ScanConfig(
                paths=[tmp_path],
                detectors=[DummyDetector],
                min_severity=Severity.HIGH,
            )
            self.assertEqual(len(Scanner(config).scan()), 1)

    def test_config_and_env_secrets_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            stripe_key = "sk_test_51MxzT2vK8qL1wM9p0X4yZ7aB2cD5eF8gH1iJ3kL5mN7oP9qR"
            (tmp / ".env").write_text(f"STRIPE_KEY={stripe_key}\n")
            (tmp / "settings.json").write_text('{"api_secret": "my_super_secret_token_123"}\n')
            (tmp / "config.yaml").write_text("aws_key: AKIAIOSFODNN7EXAMPLE\n")
            (tmp / "package-lock.json").write_text(f'{{"fake": "{stripe_key}"}}\n')

            config = ScanConfig(paths=[tmp], include_correctness=False)
            findings = Scanner(config).scan()

            # Should detect .env, settings.json, config.yaml, but NOT package-lock.json
            self.assertEqual(len(findings), 3)
            files_found = {f.location.file.name for f in findings}
            self.assertEqual(files_found, {".env", "settings.json", "config.yaml"})
            self.assertTrue(all(f.detector.id == "VIGILO-006" for f in findings))


if __name__ == "__main__":
    unittest.main()
