"""Unit and integration tests for Code Correctness Diagnostics (v0.2.0)."""

import io
import sys
import tempfile
import unittest
from pathlib import Path

from vigilo import scan
from vigilo.cli import main
from vigilo.detectors.bare_except import BareExceptDetector
from vigilo.scanner import ScanConfig, Scanner


class TestCorrectnessDiagnostics(unittest.TestCase):
    def test_syntax_error_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "bad_syntax.py").write_text("def broken_function(\n    pass\n")

            # Default security scan should safely skip
            sec_findings = scan(tmp, include_correctness=False)
            self.assertEqual(len(sec_findings), 0)

            # Correctness scan should report VIGILO-C01
            corr_findings = scan(tmp, include_correctness=True)
            self.assertEqual(len(corr_findings), 1)
            self.assertEqual(corr_findings[0].detector.id, "VIGILO-C01")
            self.assertEqual(corr_findings[0].category, "correctness")
            self.assertIn("Syntax error", corr_findings[0].message)

    def test_indentation_error_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "bad_indent.py").write_text("def test():\npass\n")

            findings = scan(tmp, include_correctness=True)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "VIGILO-C01")
            self.assertIn("Syntax error", findings[0].message)

    def test_undefined_name_detection(self) -> None:
        code = """
def calculate(value):
    total = value + unknown_variable_typo
    return total
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "sample.py").write_text(code)

            findings = scan(tmp, include_correctness=True)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "VIGILO-C02")
            self.assertIn("unknown_variable_typo", findings[0].message)

    def test_defined_names_and_builtins_not_flagged(self) -> None:
        code = """
import sys
from os import path

GLOBAL_VAL = 42

def process(item: int) -> int:
    local_arr = [x * 2 for x in range(item)]
    print(len(local_arr), GLOBAL_VAL, sys.version, path.exists("."))
    return sum(local_arr)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "safe_sample.py").write_text(code)

            findings = scan(tmp, include_correctness=True)
            # No undefined names or unclosed resources
            self.assertEqual(len(findings), 0)

    def test_unused_import_detection(self) -> None:
        code = """
import math
import sys

def area(r):
    return math.pi * r * r
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "unused.py").write_text(code)

            findings = scan(tmp, include_correctness=True)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "VIGILO-C03")
            self.assertIn("sys", findings[0].message)

    def test_init_file_imports_not_flagged_as_unused(self) -> None:
        code = """
from vigilo.models import Finding, Severity
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "__init__.py").write_text(code)

            findings = scan(tmp, include_correctness=True)
            self.assertEqual(len(findings), 0)

    def test_unclosed_resource_detection(self) -> None:
        code = """
def read_data():
    f = open("data.txt", "r")
    content = f.read()
    return content

def safe_read():
    with open("data.txt", "r") as f:
        return f.read()
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "resource.py").write_text(code)

            findings = scan(tmp, include_correctness=True)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "VIGILO-C04")
            self.assertEqual(findings[0].location.line, 3)

    def test_bare_except_detection(self) -> None:
        code = """
def run_task():
    try:
        do_something()
    except:
        pass

def safe_task():
    try:
        do_something()
    except Exception:
        pass
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "except_test.py").write_text(code)

            # Ignore undefined name for do_something to focus on BareExcept
            config = ScanConfig(paths=[tmp], detectors=[BareExceptDetector])
            findings = Scanner(config).scan()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "VIGILO-C05")
            self.assertEqual(findings[0].location.line, 5)

    def test_cli_diagnose_and_correctness_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "broken.py").write_text("def test():\n    return typo_var\n")

            # 1. `vigilo scan` (default security only) -> clean
            out_sec = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = out_sec
                code_sec = main(["scan", str(tmp), "--no-color"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_sec, 0)
            clean_msg = "No security vulnerabilities or correctness issues found"
            self.assertIn(clean_msg, out_sec.getvalue())

            # 2. `vigilo scan --correctness` -> reports VIGILO-C02
            out_corr = io.StringIO()
            try:
                sys.stdout = out_corr
                code_corr = main(["scan", str(tmp), "--correctness", "--no-color"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_corr, 1)
            self.assertIn("VIGILO-C02", out_corr.getvalue())
            self.assertIn("CORRECTNESS", out_corr.getvalue())

            # 3. `vigilo diagnose` -> reports VIGILO-C02
            out_diag = io.StringIO()
            try:
                sys.stdout = out_diag
                code_diag = main(["diagnose", str(tmp), "--no-color"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_diag, 1)
            self.assertIn("VIGILO-C02", out_diag.getvalue())


if __name__ == "__main__":
    unittest.main()
