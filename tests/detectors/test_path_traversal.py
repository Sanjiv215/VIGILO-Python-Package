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

    def test_flask_bug_hunt_regression_fixture(self) -> None:
        fixture_path = Path(__file__).parent.parent / "fixtures" / "path_traversal_bug_hunt.py"
        code = fixture_path.read_text()
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.detector.id, "VIGILO-005")
        self.assertIn("Possible path traversal: dynamic path in `send_file()`.", finding.message)
        expected_hint = (
            "Replace send_file(os.path.join(DIR, name)) with:\n"
            "  from flask import send_from_directory\n"
            "  return send_from_directory(DIR, name, as_attachment=True)\n"
            "or sanitize the filename first with werkzeug.utils.secure_filename(name)."
        )
        self.assertEqual(finding.fix_hint, expected_hint)

    def test_os_path_exists_does_not_suppress_traversal(self) -> None:
        code = """
import os
from flask import send_file

def download_file(user_file):
    target = os.path.join("/var/data", user_file)
    if os.path.exists(target):
        return send_file(target)
    return "Not found", 404
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-005")

    def test_all_expanded_sinks_flagged(self) -> None:
        code = """
import flask
from flask import send_file
import werkzeug.wsgi
from starlette.responses import FileResponse as StarletteFileResponse
from fastapi.responses import FileResponse as FastAPIFileResponse
import django.http
import django.views.static
import io
import os
from pathlib import Path

def handle_requests(untrusted_path, req, env):
    flask.send_file(untrusted_path)
    send_file(untrusted_path)
    werkzeug.wsgi.wrap_file(env, untrusted_path)
    StarletteFileResponse(untrusted_path)
    FastAPIFileResponse(untrusted_path)
    django.http.FileResponse(untrusted_path)
    django.views.static.serve(req, untrusted_path)
    io.open(untrusted_path)
    os.open(untrusted_path, os.O_RDONLY)
    Path(untrusted_path).read_bytes()
    Path(untrusted_path).read_text()

    p = Path(untrusted_path)
    p.read_text()
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 12)
        for f in findings:
            self.assertEqual(f.detector.id, "VIGILO-005")


    def test_reproduction_false_positives(self) -> None:
        code = """
import contextlib
from pathlib import Path

SAFE_DIR = "/var/app/uploads"

def read_fixed_file_safe():
    path = Path(SAFE_DIR) / "readme.txt"
    with open(path) as f:
        return f.read()

def resource_managed_safe(path):
    with contextlib.closing(open(path)) as f:
        return f.read()
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detector.id, "VIGILO-005")
        # Ensure it flags resource_managed_safe because `path` is an argument
        self.assertEqual(findings[0].location.line, 13)

    def test_safe_framework_sinks_not_flagged(self) -> None:
        code = """
import os
from pathlib import Path
from flask import send_file
from fastapi.responses import FileResponse
from werkzeug.utils import secure_filename

UPLOAD_DIR = "/uploads"

def safe_download(raw_name):
    # 1. secure_filename sanitized join
    safe_name = secure_filename(raw_name)
    safe_path = os.path.join(UPLOAD_DIR, safe_name)
    send_file(safe_path)

    # 2. Constant literal paths
    send_file("/etc/safe.txt")
    FileResponse("static/bundle.js")
    Path("README.md").read_text()

    # 3. Path joinpath with constant
    Path("/safe/dir").joinpath("manifest.json").read_bytes()
"""
        findings = self._scan(code)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
