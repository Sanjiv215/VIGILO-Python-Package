"""Unit tests for OS Command Injection detector (OJO-002 / CWE-78)."""

import ast
import unittest
from pathlib import Path

from ojo.detectors.command_injection import CommandInjectionDetector


class TestCommandInjectionDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = CommandInjectionDetector()

    def _scan(self, code: str) -> list:
        tree = ast.parse(code)
        return self.detector.run(tree, Path("test.py"), code)

    def test_os_system_dynamic_flagged(self) -> None:
        code = """
import os

def ping(host):
    os.system(f"ping -c 1 {host}")
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "OJO-002")

    def test_os_popen_dynamic_flagged(self) -> None:
        code = """
import os

def run_cmd(user_cmd):
    os.popen(user_cmd)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)

    def test_subprocess_shell_true_dynamic_flagged(self) -> None:
        code = """
import subprocess

def run_script(script_name):
    subprocess.run(f"python {script_name}", shell=True)
    subprocess.Popen("cat " + script_name, shell=True)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 2)

    def test_subprocess_shell_false_safe_list_not_flagged(self) -> None:
        code = """
import subprocess

def ping(host):
    subprocess.run(["ping", "-c", "1", host], shell=False)
    subprocess.run(["ls", "-la"])
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)

    def test_os_system_constant_not_flagged(self) -> None:
        code = """
import os

def clear_screen():
    os.system("clear")
    cmd = "cls"
    os.system(cmd)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
