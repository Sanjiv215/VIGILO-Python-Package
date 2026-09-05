"""Detector for unclosed file resources and missing with context managers (VIGILO-C04)."""

from __future__ import annotations

import ast
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.models import DetectorMeta, Finding, Severity


class UnclosedResourceDetector(BaseDetector):
    """Detects open() calls executed without a `with` context manager."""

    meta = DetectorMeta(
        id="VIGILO-C04",
        name="Unclosed File Resource",
        cwe=None,
        description="Detects `open()` calls without a `with` context manager.",
        severity=Severity.MEDIUM,
        category="correctness",
    )

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []
        with_open_calls: set[ast.Call] = set()

        # Collect open() calls that are safely wrapped in `with open(...)`
        for node in ast.walk(tree):
            if isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if isinstance(item.context_expr, ast.Call):
                        with_open_calls.add(item.context_expr)

        # Check for open() calls that are not in with_open_calls
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute) and node.func.attr == "open":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in ("os", "io"):
                        func_name = f"{node.func.value.id}.open"

                if func_name in ("open", "io.open"):
                    if node not in with_open_calls:
                        msg = f"`{func_name}()` called without a `with` context manager."
                        hint = "Use `with open(...) as f:` to ensure the file is closed."
                        finding = self.create_finding(
                            node=node,
                            file_path=file_path,
                            source=source,
                            message=msg,
                            fix_hint=hint,
                            confidence="high",
                        )
                        findings.append(finding)

        return findings
