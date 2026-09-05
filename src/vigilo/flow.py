"""Lightweight local data flow and AST analysis utilities for Vigilo."""

from __future__ import annotations

import ast
from typing import Any


class FlowAnalyzer:
    """Utilities for local scope analysis, constant evaluation, and taint tracking."""

    @staticmethod
    def is_constant(node: ast.AST | None) -> bool:
        """Check if an AST expression evaluates to a compile-time constant."""
        if node is None:
            return False

        if isinstance(node, ast.Constant):
            return True

        if isinstance(node, ast.JoinedStr):
            # An f-string is constant only if all formatted values are themselves constant
            for val in node.values:
                if isinstance(val, ast.Constant):
                    continue
                if isinstance(val, ast.FormattedValue):
                    if not FlowAnalyzer.is_constant(val.value):
                        return False
                else:
                    return False
            return True

        if isinstance(node, ast.BinOp):
            return FlowAnalyzer.is_constant(node.left) and FlowAnalyzer.is_constant(node.right)

        if isinstance(node, ast.UnaryOp):
            return FlowAnalyzer.is_constant(node.operand)

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return all(FlowAnalyzer.is_constant(elt) for elt in node.elts)

        if isinstance(node, ast.Dict):
            return all(
                (k is None or FlowAnalyzer.is_constant(k)) and FlowAnalyzer.is_constant(v)
                for k, v in zip(node.keys, node.values, strict=False)
            )

        return False

    @staticmethod
    def get_constant_value(node: ast.AST | None) -> Any:
        """Attempt to extract literal value from a constant AST node.

        Returns the value if statically resolvable, or None.
        """
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts: list[str] = []
            for val in node.values:
                if isinstance(val, ast.Constant):
                    parts.append(str(val.value))
                elif isinstance(val, ast.FormattedValue):
                    const_val = FlowAnalyzer.get_constant_value(val.value)
                    if const_val is not None:
                        parts.append(str(const_val))
                    else:
                        return None
                else:
                    return None
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = FlowAnalyzer.get_constant_value(node.left)
            right = FlowAnalyzer.get_constant_value(node.right)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        return None

    @staticmethod
    def is_parameter(name: str, func_node: ast.FunctionDef | ast.AsyncFunctionDef | None) -> bool:
        """Check if a variable name is an argument/parameter to the enclosing function."""
        if func_node is None:
            return False

        args = func_node.args
        all_args = list(args.args) + list(args.posonlyargs) + list(args.kwonlyargs)
        if any(arg.arg == name for arg in all_args):
            return True
        if args.vararg and args.vararg.arg == name:
            return True
        if args.kwarg and args.kwarg.arg == name:
            return True
        return False

    @staticmethod
    def trace_assignment_in_body(
        name: str,
        body: list[ast.stmt],
        before_lineno: int,
    ) -> ast.expr | None:
        """Find the latest assignment to `name` in body occurring before `before_lineno`."""
        last_assigned_expr: ast.expr | None = None

        for stmt in body:
            lineno = getattr(stmt, "lineno", 0)
            if lineno >= before_lineno:
                break

            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == name:
                        last_assigned_expr = stmt.value
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and stmt.target.id == name:
                    if stmt.value is not None:
                        last_assigned_expr = stmt.value
            elif isinstance(stmt, ast.AugAssign):
                if isinstance(stmt.target, ast.Name) and stmt.target.id == name:
                    last_assigned_expr = stmt.value

        return last_assigned_expr

    @staticmethod
    def is_dynamic(
        node: ast.AST | None,
        scope: ast.FunctionDef | ast.AsyncFunctionDef | ast.Module | None = None,
        visited_names: set[str] | None = None,
    ) -> bool:
        """Check if an expression is dynamic (untrusted or non-constant).

        Args:
            node: Expression AST node to check.
            scope: Enclosing function or module AST.
            visited_names: Cycle detection guard.

        Returns:
            True if dynamic/untrusted, False if verified constant.
        """
        if node is None:
            return False

        if FlowAnalyzer.is_constant(node):
            return False

        if visited_names is None:
            visited_names = set()

        if isinstance(node, ast.Name):
            name = node.id
            if name in visited_names:
                return True
            visited_names.add(name)

            # Check if name is parameter of function scope
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if FlowAnalyzer.is_parameter(name, scope):
                    return True

            # Trace assignment in scope body if available
            body = getattr(scope, "body", []) if scope else []
            node_lineno = getattr(node, "lineno", 999999)
            assigned = FlowAnalyzer.trace_assignment_in_body(name, body, node_lineno)
            if assigned is not None:
                return FlowAnalyzer.is_dynamic(assigned, scope, visited_names)

            # Variable not traced to constant assignment -> consider dynamic
            return True

        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    if FlowAnalyzer.is_dynamic(val.value, scope, visited_names):
                        return True
                elif not isinstance(val, ast.Constant):
                    return True
            return False

        if isinstance(node, ast.BinOp):
            return FlowAnalyzer.is_dynamic(
                node.left, scope, visited_names
            ) or FlowAnalyzer.is_dynamic(node.right, scope, visited_names)

        if isinstance(node, ast.Call):
            # Function calls (e.g. req.get(), os.getenv()) produce dynamic values
            return True

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            # Attribute/index access (e.g. data['param'], obj.val) are dynamic unless on constant
            return True

        return True
