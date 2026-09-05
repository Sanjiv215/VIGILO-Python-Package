"""Unit tests for Unsafe Deserialization detector (VIGILO-004 / CWE-502)."""

import ast
import unittest
from pathlib import Path

from vigilo.detectors.unsafe_deserialization import UnsafeDeserializationDetector


class TestUnsafeDeserializationDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = UnsafeDeserializationDetector()

    def _scan(self, code: str) -> list:
        tree = ast.parse(code)
        return self.detector.run(tree, Path("test.py"), code)

    def test_pickle_loads_dynamic_flagged(self) -> None:
        code = """
import pickle

def load_payload(data):
    return pickle.loads(data)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-004")

    def test_yaml_load_unsafe_flagged(self) -> None:
        code = """
import yaml

def parse_config(raw_yaml):
    return yaml.load(raw_yaml)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-004")

    def test_yaml_safe_load_not_flagged(self) -> None:
        code = """
import yaml
from yaml import SafeLoader

def parse_config(raw_yaml):
    cfg1 = yaml.safe_load(raw_yaml)
    cfg2 = yaml.load(raw_yaml, Loader=yaml.SafeLoader)
    cfg3 = yaml.load(raw_yaml, Loader=SafeLoader)
    return cfg1, cfg2, cfg3
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)

    def test_pickle_constant_not_flagged(self) -> None:
        code = """
import pickle

def load_static():
    return pickle.loads(b"cos\\nsystem\\n(S'ls'\\ntR.")
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
