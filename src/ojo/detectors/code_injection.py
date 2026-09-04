"""Detector for Code Injection vulnerabilities (CWE-94 / OJO-003)."""

from __future__ import annotations

import ast
from pathlib import Path

from ojo.detectors.base import BaseDetector
from ojo.flow import FlowAnalyzer
from ojo.models import DetectorMeta, Finding, Severity

CODE_EXEC_FUNCTIONS = {"eval", "exec", "compile"}


class CodeInjectionDetector(BaseDetector):
    """Detects dangerous evaluation or execution of dynamically constructed code."""

    meta = DetectorMeta(
        id="OJO-003",
        name="Code Injection",
        cwe=94,
        description="Detects dynamic expressions passed to eval(), exec(), or compile()",
        severity=Severity.HIGH,
    )

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []
        parent_map = self.build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "builtins":
                    func_name = node.func.attr

            if func_name in CODE_EXEC_FUNCTIONS and node.args:
                code_arg = node.args[0]
                scope = self.get_enclosing_function(node, parent_map)

                if FlowAnalyzer.is_dynamic(code_arg, scope):
                    msg = f"Possible code injection: dynamic expression passed to `{func_name}()`."
                    hint = (
                        "Avoid executing arbitrary code. Use `ast.literal_eval()` for safely "
                        "parsing literals, or use `json.loads()` for structured data."
                    )
                    findings.append(
                        self.create_finding(
                            node=node,
                            file_path=file_path,
                            source=source,
                            message=msg,
                            fix_hint=hint,
                            severity=self.meta.severity,
                            confidence="high",
                        )
                    )

        return findings
