"""Edge-case tests for Vigilo scanner resilience and error tolerance."""

import os
import tempfile
import unittest
from pathlib import Path

from vigilo import scan
from vigilo.scanner import ScanConfig, Scanner


class TestEdgeCases(unittest.TestCase):
    def test_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = scan(tmpdir)
            self.assertEqual(findings, [])

    def test_non_python_files_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "data.json").write_text('{"key": "value"}')
            (tmp / "notes.txt").write_text("subprocess.run(cmd, shell=True)")
            (tmp / "README.md").write_text("# Documentation")

            findings = scan(tmp)
            self.assertEqual(len(findings), 0)

    def test_syntax_error_file_gracefully_handled(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "broken.py").write_text("def unclosed_func(:\n    pass\n")
            (tmp / "valid_vuln.py").write_text("def run(cmd):\n    eval(cmd)\n")

            # Security scan should skip broken.py and detect valid_vuln.py
            sec_findings = scan(tmp, include_correctness=False)
            self.assertEqual(len(sec_findings), 1)
            self.assertEqual(sec_findings[0].detector.id, "VIGILO-003")

            # Full scan detects both syntax error on broken.py and code injection on valid_vuln.py
            all_findings = scan(tmp)
            self.assertEqual(len(all_findings), 2)
            detector_ids = {f.detector.id for f in all_findings}
            self.assertEqual(detector_ids, {"VIGILO-C01", "VIGILO-003"})

    def test_latin1_encoding_handling(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            # Create a file with latin-1 encoded text containing vulnerability
            file_path = tmp / "latin_encoded.py"
            content = "# -*- coding: latin-1 -*-\n# Café\ndef run(cmd):\n    eval(cmd)\n"
            file_path.write_bytes(content.encode("latin-1"))

            findings = scan(tmp, include_correctness=False)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "VIGILO-003")

    def test_large_file_stress_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            large_file = tmp / "large.py"

            # Generate 2,000 lines of safe constant assignments
            lines = [f"x_{i} = 'constant_{i}'" for i in range(2000)]
            # Add one vulnerable function in the middle
            lines.insert(1000, "def handler(q):\n    db.execute(f'SELECT {q}')")
            large_file.write_text("\n".join(lines))

            findings = scan(tmp, include_correctness=False)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].detector.id, "VIGILO-001")

    def test_comments_and_docstrings_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            doc_content = (
                '"""Module docstring explaining eval()."""\n# Comment about pickle.loads()\n'
            )
            (tmp / "docs.py").write_text(doc_content)
            findings = scan(tmp)
            self.assertEqual(len(findings), 0)

    def test_multiple_findings_in_single_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "multi_vuln.py").write_text(
                """
import os
import subprocess

def do_everything(user_input):
    eval(user_input)
    os.system(user_input)
    subprocess.run(user_input, shell=True)
    with open(user_input, "r") as f:
        pass
"""
            )
            findings = scan(tmp, include_correctness=False)
            # Detects Code Injection, 2x Command Injection, Path Traversal
            self.assertEqual(len(findings), 4)

    def test_symlink_handling(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            real_dir = tmp / "real"
            real_dir.mkdir()
            (real_dir / "target.py").write_text("x = 1\n")

            link_path = tmp / "linked_dir"
            try:
                os.symlink(real_dir, link_path, target_is_directory=True)
            except (OSError, NotImplementedError):
                return

            config = ScanConfig(paths=[tmp], follow_symlinks=False)
            findings = Scanner(config).scan()
            self.assertEqual(len(findings), 0)

    def test_false_positive_elimination(self) -> None:
        """Verify detectors do not report false positives on safe and standard idioms."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)

            # 1. Non-SQL execute() and text()
            (tmp / "service.py").write_text(
                """
def run_task(executor, widget, task_id, username):
    executor.execute(f"Processing batch {task_id}")
    widget.text(f"Welcome {username}!")
"""
            )

            # 2. Sanitized file open() paths
            (tmp / "files.py").write_text(
                """
import os
from pathlib import Path

def read_user_file(raw_name):
    safe_name = os.path.basename(raw_name)
    with open(f"/data/{safe_name}") as f:
        return f.read()

def read_path_file(raw_path):
    filename = Path(raw_path).name
    with open(filename) as f:
        return f.read()
"""
            )

            # 3. Modern typed Python __all__ and conditional imports
            (tmp / "module.py").write_text(
                """
try:
    import tomllib
except ImportError:
    import tomli as tomllib

__all__: list[str] = ["parse_data"]

def parse_data(raw: str) -> "tomllib":
    return tomllib.loads(raw)
"""
            )

            # 4. JS 2D matrix assignment and safe configuration
            (tmp / "matrix.js").write_text(
                """
function setCell(grid, row, col, val) {
    grid[row][col] = val;
}

const apiKey = "production";
const authToken = "https://auth.example.com/oauth/token";
"""
            )

            config = ScanConfig(paths=[tmp])
            findings = Scanner(config).scan()
            msg_list = [f.message for f in findings]
            self.assertEqual(
                len(findings),
                0,
                f"Expected 0 false positive findings, got {len(findings)}: {msg_list}",
            )


if __name__ == "__main__":
    unittest.main()
