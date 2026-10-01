"""Unit tests for Python HardcodedSecretsDetector (VIGILO-006 / CWE-798)."""

import ast
import unittest
from pathlib import Path

from vigilo.detectors.hardcoded_secrets import HardcodedSecretsDetector
from vigilo.models import Finding


class TestHardcodedSecretsDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = HardcodedSecretsDetector()

    def _scan(self, code: str) -> list[Finding]:
        tree = ast.parse(code)
        return self.detector.run(tree, Path("test.py"), code)

    def test_aws_key_and_stripe_secret_patterns(self) -> None:
        code = """
aws_id = "AKIAIOSFODNN7EXAMPLE"
stripe_key = "sk_test_51MxzT2vK8qL1wM9p0X4yZ7aB2cD5eF8gH1iJ3kL5mN7oP9qR"
openai_key = "sk-1234567890abcdef1234567890abcdef"
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 3)
        self.assertTrue(all(f.detector.id == "VIGILO-006" for f in findings))
        self.assertTrue(all(f.detector.cwe == 798 for f in findings))

    def test_sensitive_name_heuristics(self) -> None:
        code = """
SECRET_TOKEN = "custom_secret_value_123456"
db_password: str = "P@ssw0rd!VerySecure99"
config = {"auth_token": "bearer_custom_token_abc123"}
connect(client_secret="app_secret_value_456")
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 4)
        self.assertTrue(all(f.detector.id == "VIGILO-006" for f in findings))

    def test_false_positive_elimination(self) -> None:
        code = """
import os

api_key = os.environ.get("API_KEY")
db_pass = os.getenv("DB_PASSWORD")
dummy_token = "placeholder"
sample_secret = "your-api-key-here"
url_token = "https://auth.example.com/token"
short = "abc"
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
