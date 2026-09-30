"""Detector for Path Traversal vulnerabilities (CWE-22 / VIGILO-005)."""

from __future__ import annotations

import ast
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.flow import FlowAnalyzer
from vigilo.models import DetectorMeta, Finding, Severity

PATH_OPEN_FUNCTIONS = {"open"}
PATH_MODULE_FUNCTIONS = {("os", "open"), ("io", "open")}


class PathTraversalDetector(BaseDetector):
    """Detects unsafe file path construction that may allow directory traversal."""

    meta = DetectorMeta(
        id="VIGILO-005",
        name="Path Traversal",
        cwe=22,
        description="Detects dynamic or user-controlled paths passed to file open functions",
        severity=Severity.HIGH,
    )

    @staticmethod
    def _is_sanitized_path(node: ast.AST) -> bool:
        """Check if path expression is protected by a sanitizer function or attribute."""
        if isinstance(node, ast.Call):
            sanitizers = ("basename", "secure_filename")
            if isinstance(node.func, ast.Attribute) and node.func.attr in sanitizers:
                return True
            if isinstance(node.func, ast.Name) and node.func.id in sanitizers:
                return True
        if isinstance(node, ast.Attribute) and node.attr == "name":
            # e.g., Path(p).name
            return True
        return False

    def _is_dynamic_path(
        self,
        node: ast.AST,
        scope: ast.FunctionDef | ast.AsyncFunctionDef | None,
    ) -> bool:
        """Check if an expression represents an unsafe dynamic path."""
        if FlowAnalyzer.is_constant(node) or self._is_sanitized_path(node):
            return False

        # Dynamic string concatenation (e.g., "/base/" + filename)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if self._is_sanitized_path(node.left) or self._is_sanitized_path(node.right):
                return False
            return FlowAnalyzer.is_dynamic(node, scope)

        # Dynamic f-string (e.g., f"/base/{filename}")
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    sub_expr = val.value
                    if isinstance(sub_expr, ast.Name) and scope:
                        body = getattr(scope, "body", [])
                        lineno = getattr(sub_expr, "lineno", 999999)
                        assigned = FlowAnalyzer.trace_assignment_in_body(sub_expr.id, body, lineno)
                        if assigned is not None:
                            sub_expr = assigned
                    if self._is_sanitized_path(sub_expr):
                        continue
                    if FlowAnalyzer.is_dynamic(val.value, scope):
                        return True
            return False

        # String formatting with % or .format()
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if self._is_sanitized_path(node.right):
                return False
            return FlowAnalyzer.is_dynamic(node, scope)

        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                return any(
                    FlowAnalyzer.is_dynamic(arg, scope)
                    for arg in node.args
                    if not self._is_sanitized_path(arg)
                )

        # Path passed directly from dynamic variable / parameter
        if isinstance(node, ast.Name):
            if scope:
                body = getattr(scope, "body", [])
                lineno = getattr(node, "lineno", 999999)
                assigned = FlowAnalyzer.trace_assignment_in_body(node.id, body, lineno)
                if assigned is not None:
                    if self._is_sanitized_path(assigned):
                        return False
                    return self._is_dynamic_path(assigned, scope)
            return FlowAnalyzer.is_dynamic(node, scope)

        return False

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []
        parent_map = self.build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            scope = self.get_enclosing_function(node, parent_map)
            is_file_open = False
            func_name = ""

            # Check built-in open(...)
            if isinstance(node.func, ast.Name) and node.func.id in PATH_OPEN_FUNCTIONS:
                is_file_open = True
                func_name = node.func.id

            # Check os.open(...), io.open(...)
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                method_name = node.func.attr
                if (module_name, method_name) in PATH_MODULE_FUNCTIONS:
                    is_file_open = True
                    func_name = f"{module_name}.{method_name}"

            if is_file_open and node.args:
                path_arg = node.args[0]
                if self._is_dynamic_path(path_arg, scope):
                    msg = f"Possible path traversal: dynamic path in `{func_name}()`."
                    hint = (
                        "Sanitize file paths using `os.path.basename()` or verify that "
                        "the resolved path starts with the intended base directory."
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
