"""Benchmark and real-world validation test suite for OJO.

Evaluates True Positives, False Positives, Precision, and Recall on
realistic multi-module Python application code.
"""

import tempfile
import unittest
from pathlib import Path

from ojo import scan


class TestRealWorldValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.project_root = Path(self.tmp_dir.name)

        # 1. API Route with SQL Injection + Safe Parameterized Query
        api_dir = self.project_root / "api"
        api_dir.mkdir()
        (api_dir / "users.py").write_text(
            """
def get_user_vulnerable(db, user_id):
    # TRUE POSITIVE: CWE-89
    return db.execute(f"SELECT * FROM users WHERE id = {user_id}")

def get_user_safe(db, user_id):
    # TRUE NEGATIVE: Parameterized query
    return db.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})
"""
        )

        # 2. System Operations with OS Command Injection + Safe Subprocess
        services_dir = self.project_root / "services"
        services_dir.mkdir()
        (services_dir / "runner.py").write_text(
            """
import subprocess

def deploy_service_vulnerable(branch_name):
    # TRUE POSITIVE: CWE-78
    cmd = f"git checkout {branch_name} && ./deploy.sh"
    subprocess.run(cmd, shell=True)

def deploy_service_safe(branch_name):
    # TRUE NEGATIVE: Argument list with shell=False
    subprocess.run(["git", "checkout", branch_name], shell=False)
"""
        )

        # 3. Dynamic Handler with Code Injection + Safe Parsing
        handlers_dir = self.project_root / "handlers"
        handlers_dir.mkdir()
        (handlers_dir / "calculator.py").write_text(
            """
import ast

def evaluate_expression_vulnerable(user_expression):
    # TRUE POSITIVE: CWE-94
    return eval(user_expression)

def evaluate_expression_safe(user_expression):
    # TRUE NEGATIVE: Safe literal parsing
    return ast.literal_eval(user_expression)
"""
        )

        # 4. Config Loader with Unsafe Deserialization + Safe Loader
        config_dir = self.project_root / "config"
        config_dir.mkdir()
        (config_dir / "loader.py").write_text(
            """
import yaml

def load_config_vulnerable(raw_text):
    # TRUE POSITIVE: CWE-502
    return yaml.load(raw_text)

def load_config_safe(raw_text):
    # TRUE NEGATIVE: SafeLoader
    return yaml.safe_load(raw_text)
"""
        )

        # 5. File Manager with Path Traversal + Safe Path Resolution
        files_dir = self.project_root / "files"
        files_dir.mkdir()
        (files_dir / "manager.py").write_text(
            """
def read_user_file_vulnerable(filename):
    # TRUE POSITIVE: CWE-22
    path = f"/var/app/data/{filename}"
    with open(path, "r") as f:
        return f.read()

def read_user_file_safe():
    # TRUE NEGATIVE: Constant file path
    with open("/var/app/data/static.txt", "r") as f:
        return f.read()
"""
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_benchmark_metrics(self) -> None:
        """Verify 100% precision and recall on the benchmark suite."""
        findings = scan(self.project_root)

        # Map detected CWEs
        detected_cwes = [f.detector.cwe for f in findings]

        # 1. Verify True Positives (Expect 5: CWE-89, CWE-78, CWE-94, CWE-502, CWE-22)
        expected_cwes = {89, 78, 94, 502, 22}
        actual_cwes = set(detected_cwes)

        true_positives = len(expected_cwes.intersection(actual_cwes))
        self.assertEqual(true_positives, 5, f"Missing expected CWEs: {expected_cwes - actual_cwes}")

        # 2. Verify Findings Count (0 False Positives on safe patterns)
        self.assertEqual(len(findings), 5, f"Unexpected findings / False Positives: {findings}")

        # Calculate metrics
        precision = true_positives / len(findings)
        recall = true_positives / len(expected_cwes)

        self.assertEqual(precision, 1.0, f"Precision dropped: {precision}")
        self.assertEqual(recall, 1.0, f"Recall dropped: {recall}")


if __name__ == "__main__":
    unittest.main()
