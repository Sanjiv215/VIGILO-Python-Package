"""Detector for SQL Injection vulnerabilities (CWE-89 / VIGILO-001)."""

from __future__ import annotations

import ast
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.flow import FlowAnalyzer
from vigilo.models import DetectorMeta, Finding, Severity

SQL_METHOD_NAMES = {
    "execute",
    "executemany",
    "raw",
    "text",
}


class SQLInjectionDetector(BaseDetector):
    """Detects SQL queries built with dynamic string formatting or concatenation."""

    meta = DetectorMeta(
        id="VIGILO-001",
        name="SQL Injection",
        cwe=89,
        description="Detects unparameterized SQL queries built via dynamic string formatting",
        severity=Severity.HIGH,
    )

    def _is_sql_like_string(self, text: str) -> bool:
        """Check if string contains common SQL keywords."""
        upper = text.upper()
        keywords = (
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "ALTER",
            "CREATE",
            "WHERE",
            "FROM",
        )
        return any(kw in upper for kw in keywords)

    def _extract_binop_strings(self, node: ast.AST) -> list[str]:
        """Extract all constant string components in an addition chain."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._extract_binop_strings(node.left) + self._extract_binop_strings(node.right)
        val = FlowAnalyzer.get_constant_value(node)
        if isinstance(val, str):
            return [val]
        return []

    def _is_dynamic_sql(
        self,
        node: ast.AST,
        scope: ast.FunctionDef | ast.AsyncFunctionDef | None,
    ) -> bool:
        """Determine if an expression is a dynamically constructed SQL query."""
        if FlowAnalyzer.is_constant(node):
            return False

        # F-string containing dynamic variables
        if isinstance(node, ast.JoinedStr):
            text_parts = [
                str(val.value)
                for val in node.values
                if isinstance(val, ast.Constant) and isinstance(val.value, str)
            ]
            if not self._is_sql_like_string(" ".join(text_parts)):
                return False
            return FlowAnalyzer.is_dynamic(node, scope)

        # String formatting via % operator (e.g. "SELECT ... %s" % val)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left_val = FlowAnalyzer.get_constant_value(node.left)
            if isinstance(left_val, str) and self._is_sql_like_string(left_val):
                return FlowAnalyzer.is_dynamic(node.right, scope)
            return False

        # String concatenation via + operator (e.g. "SELECT ... " + val)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            strings = self._extract_binop_strings(node)
            if any(self._is_sql_like_string(s) for s in strings):
                return FlowAnalyzer.is_dynamic(node, scope)
            return False

        # str.format() calls (e.g. "SELECT ... {}".format(val))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format":
                val = FlowAnalyzer.get_constant_value(node.func.value)
                if isinstance(val, str) and self._is_sql_like_string(val):
                    return any(FlowAnalyzer.is_dynamic(arg, scope) for arg in node.args)
                return False

        # Traced variable
        if isinstance(node, ast.Name):
            if scope:
                body = getattr(scope, "body", [])
                lineno = getattr(node, "lineno", 999999)
                assigned = FlowAnalyzer.trace_assignment_in_body(node.id, body, lineno)
                if assigned is not None:
                    return self._is_dynamic_sql(assigned, scope)
            return False

        return False

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []
        parent_map = self.build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            method_name = None
            if isinstance(node.func, ast.Attribute):
                method_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                method_name = node.func.id

            if method_name in SQL_METHOD_NAMES and node.args:
                query_arg = node.args[0]
                scope = self.get_enclosing_function(node, parent_map)

                if self._is_dynamic_sql(query_arg, scope):
                    msg = f"Possible SQL injection: unparameterized query in `{method_name}()`."
                    hint = (
                        "Use parameterized query placeholders or ORM parameter binding "
                        "instead of dynamic string concatenation/formatting."
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
