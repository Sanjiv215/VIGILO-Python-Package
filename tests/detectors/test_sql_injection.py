"""Unit tests for SQL Injection detector (VIGILO-001 / CWE-89)."""

import ast
import unittest
from pathlib import Path

from vigilo.detectors.sql_injection import SQLInjectionDetector
from vigilo.models import Finding


class TestSQLInjectionDetector(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = SQLInjectionDetector()

    def _scan(self, code: str) -> list[Finding]:
        tree = ast.parse(code)
        return self.detector.run(tree, Path("test.py"), code)

    def test_fstring_sql_injection(self) -> None:
        code = """
def get_user(user_id):
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-001")
        self.assertEqual(findings[0].location.line, 3)

    def test_concat_sql_injection(self) -> None:
        code = """
def search(query):
    cursor.execute("SELECT * FROM items WHERE name = '" + query + "'")
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-001")

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

    def test_multiline_conditional_query_building(self) -> None:
        code = """
def filter_tasks(status, search):
    query = "SELECT * FROM tasks WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if search:
        query += f" AND (title LIKE '%{search}%')"
    cursor.execute(query, params)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-001")
        self.assertEqual(findings[0].location.line, 10)

    def test_sqlalchemy_text_injection(self) -> None:
        code = """
from sqlalchemy import text

def get_records(db_session, user_input):
    stmt = text(f"SELECT * FROM items WHERE category = '{user_input}'")
    db_session.execute(stmt)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-001")

    def test_django_raw_and_extra_injection(self) -> None:
        code = """
def django_queries(user_input):
    User.objects.raw(f"SELECT * FROM myapp_user WHERE username = '{user_input}'")
    Entry.objects.extra(where=[f"headline = '{user_input}'"])
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.detector.id == "VIGILO-001" for f in findings))

    def test_driver_executemany_injection(self) -> None:
        code = """
def batch_insert(table_name, rows):
    cursor.executemany(f"INSERT INTO {table_name} VALUES (?, ?)", rows)
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-001")


if __name__ == "__main__":
    unittest.main()
