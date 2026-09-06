"""Unit tests for Vigilo CLI and top-level public API."""

import io
import sys
import tempfile
import unittest
from pathlib import Path

from vigilo import scan
from vigilo.cli import main


class TestCLI(unittest.TestCase):
    def test_cli_clean_exit_code_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "safe.py").write_text("x = 1\n")

            out = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = out
                code = main(["scan", str(tmp_path), "--no-color"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code, 0)
            self.assertIn("No security vulnerabilities or correctness issues found", out.getvalue())

    def test_cli_vulnerability_exit_code_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "vuln.py").write_text("def run(cmd):\n    eval(cmd)\n")

            out = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = out
                code = main(["scan", str(tmp_path), "--no-color"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code, 1)
            self.assertIn("Code Injection", out.getvalue())

    def test_cli_alias_support(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "vuln.py").write_text("def run(cmd):\n    eval(cmd)\n")

            out = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = out
                code = main([str(tmp_path), "--no-color"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code, 1)
            self.assertIn("Code Injection", out.getvalue())

    def test_cli_bare_scan_command(self) -> None:
        out = io.StringIO()
        old_stdout = sys.stdout
        try:
            sys.stdout = out
            code = main(["scan", "--no-color"])
        finally:
            sys.stdout = old_stdout

        # Should scan current working directory without crashing
        self.assertIn(code, (0, 1))

    def test_cli_json_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "safe.py").write_text("x = 1\n")

            stdout_capture = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = stdout_capture
                code = main(["scan", str(tmp_path), "--format", "json"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code, 0)
            self.assertIn('"version": "0.3.0"', stdout_capture.getvalue())

    def test_cli_non_existent_path(self) -> None:
        stderr_capture = io.StringIO()
        old_stderr = sys.stderr
        try:
            sys.stderr = stderr_capture
            code = main(["scan", "/path/that/does/not/exist/for/sure"])
        finally:
            sys.stderr = old_stderr

        self.assertEqual(code, 2)
        self.assertIn("Error: Target path does not exist", stderr_capture.getvalue())

    def test_cli_mode_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            # File with both security (eval) and correctness (undefined var)
            payload = "def run(cmd):\n    eval(cmd)\n    print(typo_var)\n"
            (tmp_path / "mixed.py").write_text(payload)

            # 1. Mode: all (default) -> reports both
            out_all = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = out_all
                code_all = main(["scan", str(tmp_path), "--no-color"])
            finally:
                sys.stdout = old_stdout
            self.assertEqual(code_all, 1)
            self.assertIn("VIGILO-003", out_all.getvalue())
            self.assertIn("VIGILO-C02", out_all.getvalue())

            # 2. Mode: security -> reports only security
            out_sec = io.StringIO()
            try:
                sys.stdout = out_sec
                code_sec = main(["scan", str(tmp_path), "--mode", "security", "--no-color"])
            finally:
                sys.stdout = old_stdout
            self.assertEqual(code_sec, 1)
            self.assertIn("VIGILO-003", out_sec.getvalue())
            self.assertNotIn("VIGILO-C02", out_sec.getvalue())

            # 3. Mode: correctness -> reports only correctness
            out_corr = io.StringIO()
            try:
                sys.stdout = out_corr
                code_corr = main(["scan", str(tmp_path), "-m", "correctness", "--no-color"])
            finally:
                sys.stdout = old_stdout
            self.assertEqual(code_corr, 1)
            self.assertNotIn("VIGILO-003", out_corr.getvalue())
            self.assertIn("VIGILO-C02", out_corr.getvalue())

            # 4. Shortcut: --security-only / -S
            out_shortcut = io.StringIO()
            try:
                sys.stdout = out_shortcut
                code_shortcut = main(["scan", str(tmp_path), "-S", "--no-color"])
            finally:
                sys.stdout = old_stdout
            self.assertEqual(code_shortcut, 1)
            self.assertIn("VIGILO-003", out_shortcut.getvalue())
            self.assertNotIn("VIGILO-C02", out_shortcut.getvalue())

    def test_top_level_scan_api(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            (tmp_path / "vuln.py").write_text("def run(cmd):\n    eval(cmd)\n")

            findings = scan(tmp_path)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "VIGILO-003")


if __name__ == "__main__":
    unittest.main()
