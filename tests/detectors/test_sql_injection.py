"""Unit tests for SQL Injection detector (OJO-001 / CWE-89)."""

import ast
import unittest
from pathlib import Path

from ojo.detectors.sql_injection import SQLInjectionDetector


class TestSQLInjectionDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = SQLInjectionDetector()

    def _scan(self, code: str) -> list:
        tree = ast.parse(code)
        return self.detector.run(tree, Path("test.py"), code)

    def test_fstring_sql_injection(self) -> None:
        code = """
def get_user(user_id):
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "OJO-001")
        self.assertEqual(findings[0].location.line, 3)

    def test_concat_sql_injection(self) -> None:
        code = """
def search(query):
    cursor.execute("SELECT * FROM items WHERE name = '" + query + "'")
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "OJO-001")

    def test_percent_formatting_sql_injection(self) -> None:
        code = """
def filter_by_role(role):
    cursor.execute("SELECT * FROM users WHERE role = '%s'" % role)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)

    def test_safe_parameterized_query_not_flagged(self) -> None:
        code = """
def get_user(user_id):
    db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)

    def test_constant_query_not_flagged(self) -> None:
        code = """
def list_all():
    db.execute("SELECT * FROM settings")
    query = "SELECT id, name FROM categories"
    cursor.execute(query)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
