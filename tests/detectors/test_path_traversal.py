"""Unit tests for Path Traversal detector (VIGILO-005 / CWE-22)."""

import ast
import unittest
from pathlib import Path

from vigilo.detectors.path_traversal import PathTraversalDetector
from vigilo.models import Finding


class TestPathTraversalDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = PathTraversalDetector()

    def _scan(self, code: str) -> list[Finding]:
        tree = ast.parse(code)
        return self.detector.run(tree, Path("test.py"), code)

    def test_open_dynamic_path_flagged(self) -> None:
        code = """
def read_file(filename):
    with open(f"/var/log/{filename}", "r") as f:
        return f.read()
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-005")

    def test_os_open_dynamic_path_flagged(self) -> None:
        code = """
import os

def open_log(user_path):
    return os.open(user_path, os.O_RDONLY)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)

    def test_open_constant_path_not_flagged(self) -> None:
        code = """
def read_config():
    with open("config.json", "r") as f:
        return f.read()

    path = "/etc/os-release"
    with open(path, "r") as f:
        return f.read()
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
