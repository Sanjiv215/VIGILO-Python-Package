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
            self.assertIn("Indentation error", findings[0].message)

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

    def test_cli_security_only_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "broken.py").write_text("def test():\n    return typo_var\n")

            # 1. `vigilo scan` (default includes correctness) -> reports VIGILO-C02
            out_default = io.StringIO()
            old_stdout = sys.stdout
            try:
                sys.stdout = out_default
                code_default = main(["scan", str(tmp), "--no-color"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_default, 1)
            self.assertIn("VIGILO-C02", out_default.getvalue())

            # 2. `vigilo scan --security-only` -> clean (0 security findings)
            out_sec = io.StringIO()
            try:
                sys.stdout = out_sec
                code_sec = main(["scan", str(tmp), "--security-only", "--no-color"])
            finally:
                sys.stdout = old_stdout

            self.assertEqual(code_sec, 0)
            clean_msg = "No security vulnerabilities or correctness issues found"
            self.assertIn(clean_msg, out_sec.getvalue())

    def test_fixtures_diagnostics(self) -> None:
        fixture_dir = Path(__file__).parent / "fixtures" / "diagnostics"

        # Syntax errors
        res = scan(fixture_dir / "syntax_missing_colon.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C01" for f in res))

        res = scan(fixture_dir / "syntax_unclosed_paren.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C01" for f in res))

        res = scan(fixture_dir / "syntax_invalid.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C01" for f in res))

        # Indentation errors
        res = scan(fixture_dir / "indent_mismatched.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C01" for f in res))

        res = scan(fixture_dir / "indent_unexpected.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C01" for f in res))

        res = scan(fixture_dir / "indent_mixed_tabs.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C01" for f in res))

        # Undefined names / typos
        res = scan(fixture_dir / "undef_print_typo.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C02" and "PRint" in f.message for f in res))

        res = scan(fixture_dir / "undef_var_typo.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C02" and "total" in f.message for f in res))

        res = scan(fixture_dir / "undef_unimported_func.py")
        self.assertTrue(
            any(
                f.detector.id == "VIGILO-C02" and "fetch_data_from_remote_api" in f.message
                for f in res
            )
        )

        res = scan(fixture_dir / "undef_cross_scope.py")
        self.assertTrue(
            any(f.detector.id == "VIGILO-C02" and "secret_value" in f.message for f in res)
        )

        # Unused imports & unused variables
        res = scan(fixture_dir / "unused_import.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C03" and "math" in f.message for f in res))

        res = scan(fixture_dir / "unused_variable.py")
        self.assertTrue(
            any(f.detector.id == "VIGILO-C03" and "unused_val" in f.message for f in res)
        )

        # File resources & bare except
        res = scan(fixture_dir / "resource_unclosed_open.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C04" for f in res))

        res = scan(fixture_dir / "resource_bare_except.py")
        self.assertTrue(any(f.detector.id == "VIGILO-C05" for f in res))

        # Security regression
        res = scan(fixture_dir / "security_sql_injection.py")
        self.assertTrue(any(f.detector.id == "VIGILO-001" for f in res))

        res = scan(fixture_dir / "security_command_injection.py")
        self.assertTrue(any(f.detector.id == "VIGILO-002" for f in res))

        res = scan(fixture_dir / "security_code_injection.py")
        self.assertTrue(any(f.detector.id == "VIGILO-003" for f in res))

        res = scan(fixture_dir / "security_deserialization.py")
        self.assertTrue(any(f.detector.id == "VIGILO-004" for f in res))

        res = scan(fixture_dir / "security_path_traversal.py")
        self.assertTrue(any(f.detector.id == "VIGILO-005" for f in res))


if __name__ == "__main__":
    unittest.main()
