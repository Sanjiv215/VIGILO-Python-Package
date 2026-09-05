"""Unit tests for file discovery and exclusion logic."""

import tempfile
import unittest
from pathlib import Path

from vigilo.discovery import discover_files, should_exclude


class TestDiscovery(unittest.TestCase):
    def test_should_exclude(self) -> None:
        self.assertTrue(should_exclude(Path(".git/config"), [".git"]))
        self.assertTrue(
            should_exclude(Path("src/__pycache__/module.cpython-310.pyc"), ["__pycache__"])
        )
        self.assertTrue(should_exclude(Path("venv/lib/python3.10/site-packages/pkg.py"), ["venv"]))
        self.assertTrue(should_exclude(Path("tests/test_file.pyc"), ["*.pyc"]))
        self.assertFalse(should_exclude(Path("src/main.py"), [".git", "venv", "__pycache__"]))

    def test_discover_files_in_temp_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Create sample folder hierarchy
            (tmp_path / "src").mkdir()
            (tmp_path / "src" / "app.py").write_text("print('hello')")
            (tmp_path / "src" / "util.py").write_text("x = 1")
            (tmp_path / "src" / "readme.txt").write_text("info")

            # Create ignored directory
            (tmp_path / ".git").mkdir()
            (tmp_path / ".git" / "hook.py").write_text("# hook")

            (tmp_path / "venv").mkdir()
            (tmp_path / "venv" / "lib.py").write_text("# lib")

            discovered = discover_files(tmp_path)
            discovered_rel = [p.relative_to(tmp_path).as_posix() for p in discovered]

            self.assertEqual(discovered_rel, ["src/app.py", "src/util.py"])

    def test_discover_single_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".py") as tmp:
            discovered = discover_files(Path(tmp.name))
            self.assertEqual(len(discovered), 1)
            self.assertEqual(discovered[0], Path(tmp.name))

    def test_discover_non_existent_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            discover_files(Path("/non/existent/path/for/vigilo/testing"))


if __name__ == "__main__":
    unittest.main()
