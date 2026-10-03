"""Detector for Path Traversal vulnerabilities (CWE-22 / VIGILO-005)."""

from __future__ import annotations

import ast
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.flow import FlowAnalyzer
from vigilo.models import DetectorMeta, Finding, Severity

FLASK_FIX_HINT = (
    "Replace send_file(os.path.join(DIR, name)) with:\n"
    "  from flask import send_from_directory\n"
    "  return send_from_directory(DIR, name, as_attachment=True)\n"
    "or sanitize the filename first with werkzeug.utils.secure_filename(name)."
)

DEFAULT_FIX_HINT = (
    "Sanitize file paths using `os.path.basename()` or verify that "
    "the resolved path starts with the intended base directory."
)


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
    def _get_call_name(node: ast.AST) -> str | None:
        """Resolve dotted or bare function call name from AST node."""
        parts: list[str] = []
        curr: ast.AST | None = node
        while isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            parts.append(curr.id)
            return ".".join(reversed(parts))
        return None

    def _identify_sink(self, node: ast.Call) -> tuple[str | None, ast.expr | None]:
        """Identify if a call is a dangerous file path sink and extract the path argument."""
        # pathlib Path().read_text() / Path().read_bytes()
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("read_text", "read_bytes"):
            attr = node.func.attr
            receiver = node.func.value
            return f"Path.{attr}", receiver

        call_name = self._get_call_name(node.func)
        if not call_name:
            return None, None

        short_name = call_name.split(".")[-1]

        # 1. Standard open functions: open(), os.open(), io.open()
        if call_name in ("open", "os.open", "io.open"):
            if node.args:
                return call_name, node.args[0]
            for kw in node.keywords:
                if kw.arg in ("file", "path"):
                    return call_name, kw.value
            return None, None

        # 2. Flask / Werkzeug send_file: flask.send_file(), send_file()
        if short_name == "send_file" and call_name in ("send_file", "flask.send_file"):
            if node.args:
                return call_name, node.args[0]
            for kw in node.keywords:
                if kw.arg in ("path_or_file", "filename_or_fp", "file", "path"):
                    return call_name, kw.value
            return None, None

        # 3. Werkzeug wrap_file: werkzeug.wsgi.wrap_file(environ, file)
        if call_name in ("werkzeug.wsgi.wrap_file", "wsgi.wrap_file") or (
            short_name == "wrap_file"
            and (len(node.args) >= 2 or any(k.arg == "file" for k in node.keywords))
        ):
            for kw in node.keywords:
                if kw.arg == "file":
                    return call_name, kw.value
            if len(node.args) >= 2:
                return call_name, node.args[1]
            if len(node.args) == 1:
                return call_name, node.args[0]
            return None, None

        # 4. FastAPI / Starlette / Django FileResponse
        if short_name.endswith("FileResponse"):
            if node.args:
                return call_name, node.args[0]
            for kw in node.keywords:
                if kw.arg in ("path", "open_file", "streaming_content"):
                    return call_name, kw.value
            return None, None

        # 5. Django static serve: django.views.static.serve(request, path, document_root=...)
        if call_name in ("django.views.static.serve", "static.serve") or (
            short_name == "serve"
            and (len(node.args) >= 2 or any(k.arg == "path" for k in node.keywords))
        ):
            for kw in node.keywords:
                if kw.arg == "path":
                    return call_name, kw.value
            if len(node.args) >= 2:
                return call_name, node.args[1]
            if len(node.args) == 1:
                return call_name, node.args[0]
            return None, None

        return None, None

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
        scope: ast.FunctionDef | ast.AsyncFunctionDef | ast.Module | None,
        visited_names: set[str] | None = None,
        known_constants: dict[str, bool] | None = None,
    ) -> bool:
        if visited_names is None:
            visited_names = set()
        if known_constants is None:
            known_constants = {}
        """Check if an expression represents an unsafe dynamic path."""
        if FlowAnalyzer.is_constant(node) or self._is_sanitized_path(node):
            return False

        if isinstance(node, ast.Name) and (
            node.id.isupper() or known_constants.get(node.id, False)
        ):
            return False
        if isinstance(node, ast.Name):
            if node.id in visited_names:
                return True
            visited_names.add(node.id)

        # Dynamic string concatenation or pathlib path construction (e.g., base / filename)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            if self._is_sanitized_path(node.left) or self._is_sanitized_path(node.right):
                return False
            return self._is_dynamic_path(
                node.left, scope, visited_names, known_constants
            ) or self._is_dynamic_path(node.right, scope, visited_names, known_constants)

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
                    if self._is_dynamic_path(val.value, scope, visited_names, known_constants):
                        return True
            return False

        # String formatting with %
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            if self._is_sanitized_path(node.right):
                return False
            return self._is_dynamic_path(node.right, scope, visited_names, known_constants)

        # Method/function calls
        if isinstance(node, ast.Call):
            if self._is_sanitized_path(node):
                return False
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return any(
                    self._is_dynamic_path(arg, scope, visited_names, known_constants)
                    for arg in node.args
                    if not self._is_sanitized_path(arg)
                )
            # Handle join/joinpath calls (e.g., os.path.join, Path.joinpath)
            if (
                isinstance(node.func, ast.Attribute) and node.func.attr in ("join", "joinpath")
            ) or (isinstance(node.func, ast.Name) and node.func.id == "join"):
                return any(
                    self._is_dynamic_path(arg, scope, visited_names, known_constants)
                    for arg in node.args
                    if not self._is_sanitized_path(arg)
                )
            # Handle Path(p) or pathlib.Path(p) constructor
            if (isinstance(node.func, ast.Name) and node.func.id == "Path") or (
                isinstance(node.func, ast.Attribute) and node.func.attr == "Path"
            ):
                return any(
                    self._is_dynamic_path(arg, scope, visited_names, known_constants)
                    for arg in node.args
                    if not self._is_sanitized_path(arg)
                )
            # Common path normalization wrappers: if arguments are safe/constant, call is safe
            if isinstance(node.func, ast.Attribute) and node.func.attr in (
                "abspath",
                "realpath",
                "relpath",
                "normpath",
                "expanduser",
            ):
                return any(
                    self._is_dynamic_path(arg, scope, visited_names, known_constants)
                    for arg in node.args
                    if not self._is_sanitized_path(arg)
                )
            return FlowAnalyzer.is_dynamic(node, scope, visited_names)

        # Path passed directly from dynamic variable / parameter
        if isinstance(node, ast.Name):
            if scope:
                body = getattr(scope, "body", [])
                lineno = getattr(node, "lineno", 999999)
                assigned = FlowAnalyzer.trace_assignment_in_body(node.id, body, lineno)
                if assigned is not None:
                    if self._is_sanitized_path(assigned):
                        return False
                    return self._is_dynamic_path(assigned, scope, visited_names, known_constants)
            return FlowAnalyzer.is_dynamic(node, scope, visited_names)

        return False

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []
        known_constants = FlowAnalyzer.resolve_module_constants(tree)
        parent_map = self.build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            scope = self.get_enclosing_function(node, parent_map) or tree
            func_name, path_arg = self._identify_sink(node)

            if func_name and path_arg is not None:
                if self._is_dynamic_path(path_arg, scope, known_constants=known_constants):
                    msg = f"Possible path traversal: dynamic path in `{func_name}()`."
                    hint = FLASK_FIX_HINT if "send_file" in func_name else DEFAULT_FIX_HINT
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
