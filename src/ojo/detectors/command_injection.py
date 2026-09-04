"""Detector for OS Command Injection vulnerabilities (CWE-78 / OJO-002)."""

from __future__ import annotations

import ast
from pathlib import Path

from ojo.detectors.base import BaseDetector
from ojo.flow import FlowAnalyzer
from ojo.models import DetectorMeta, Finding, Severity

SUBPROCESS_METHODS = {
    "run",
    "Popen",
    "call",
    "check_call",
    "check_output",
}


class CommandInjectionDetector(BaseDetector):
    """Detects dangerous OS command executions with dynamic or unsanitized input."""

    meta = DetectorMeta(
        id="OJO-002",
        name="OS Command Injection",
        cwe=78,
        description="Detects dynamic shell commands passed to execution functions",
        severity=Severity.HIGH,
    )

    def _has_shell_true(self, node: ast.Call) -> bool:
        """Check if shell=True is present in keyword arguments."""
        for kw in node.keywords:
            if kw.arg == "shell":
                val = FlowAnalyzer.get_constant_value(kw.value)
                return bool(val is True)
        return False

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []
        parent_map = self.build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            scope = self.get_enclosing_function(node, parent_map)

            # Check os.system(...) and os.popen(...)
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "os" and node.func.attr in ("system", "popen"):
                    if node.args and FlowAnalyzer.is_dynamic(node.args[0], scope):
                        attr = node.func.attr
                        msg = f"Possible OS command injection: dynamic command in `os.{attr}()`."
                        hint = (
                            "Use `subprocess.run([...], shell=False)` with an argument list "
                            "instead of invoking shell commands."
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
                        continue

            # Check subprocess methods with shell=True and dynamic input
            is_subprocess = False
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    is_subprocess = True
                    func_name = node.func.attr
            elif isinstance(node.func, ast.Name) and node.func.id in SUBPROCESS_METHODS:
                is_subprocess = True
                func_name = node.func.id

            if is_subprocess and func_name in SUBPROCESS_METHODS and node.args:
                cmd_arg = node.args[0]
                if self._has_shell_true(node) and FlowAnalyzer.is_dynamic(cmd_arg, scope):
                    msg = (
                        f"Possible OS command injection: dynamic command in "
                        f"`subprocess.{func_name}(shell=True)`."
                    )
                    hint = (
                        "Avoid `shell=True`. Pass a list of command arguments with `shell=False` "
                        "(e.g., subprocess.run(['cmd', arg], shell=False))."
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
