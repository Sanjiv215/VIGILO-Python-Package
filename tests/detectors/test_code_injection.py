"""Unit tests for Code Injection detector (VIGILO-003 / CWE-94)."""

import ast
import unittest
from pathlib import Path

from vigilo.detectors.code_injection import CodeInjectionDetector
from vigilo.models import Finding


class TestCodeInjectionDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = CodeInjectionDetector()

    def _scan(self, code: str) -> list[Finding]:
        tree = ast.parse(code)
        return self.detector.run(tree, Path("test.py"), code)

    def test_eval_dynamic_flagged(self) -> None:
        code = """
def calc(expr):
    return eval(expr)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-003")

    def test_exec_dynamic_flagged(self) -> None:
        code = """
def run_custom(payload):
    exec(payload)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)

    def test_compile_dynamic_flagged(self) -> None:
        code = """
def compile_user_code(user_script):
    code_obj = compile(user_script, "<dynamic>", "exec")
    return code_obj
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)

    def test_eval_constant_not_flagged(self) -> None:
        code = """
def test_static():
    val = eval("2 + 2")
    exec("x = 10")
    compile("y = 20", "<string>", "exec")
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
