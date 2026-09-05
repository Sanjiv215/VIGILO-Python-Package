"""Detector for undefined name / unbound variable usage (VIGILO-C02)."""

from __future__ import annotations

import ast
import builtins
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.models import DetectorMeta, Finding, Severity

BUILTIN_NAMES = set(dir(builtins)) | {
    "__name__",
    "__doc__",
    "__file__",
    "__package__",
    "__loader__",
    "__spec__",
    "__path__",
    "__all__",
    "__annotations__",
    "__builtins__",
    "__debug__",
}


class ScopeVisitor(ast.NodeVisitor):
    """Tracks nested lexical scopes and finds referenced names that are not defined."""

    def __init__(self) -> None:
        self.scopes: list[set[str]] = [set(BUILTIN_NAMES)]
        self.undefined_nodes: list[tuple[ast.Name, str]] = []
        self.has_star_import = False

    def push_scope(self) -> None:
        self.scopes.append(set())

    def pop_scope(self) -> None:
        self.scopes.pop()

    def add_name(self, name: str) -> None:
        self.scopes[-1].add(name)

    def is_defined(self, name: str) -> bool:
        if self.has_star_import:
            return True
        for scope in reversed(self.scopes):
            if name in scope:
                return True
        return False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.add_name(name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                self.has_star_import = True
            else:
                name = alias.asname or alias.name
                self.add_name(name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.add_name(node.name)
        self.push_scope()
        # Add function arguments to local scope
        for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            self.add_name(arg.arg)
        if node.args.vararg:
            self.add_name(node.args.vararg.arg)
        if node.args.kwarg:
            self.add_name(node.args.kwarg.arg)
        self.generic_visit(node)
        self.pop_scope()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.add_name(node.name)
        self.push_scope()
        self.generic_visit(node)
        self.pop_scope()

    def visit_Global(self, node: ast.Global) -> None:
        for name in node.names:
            self.scopes[0].add(name)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        pass

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.add_name(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.add_name(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.add_name(node.name)
        self.generic_visit(node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.add_name(node.rest)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.add_name(node.id)
        elif isinstance(node.ctx, ast.Load):
            if not self.is_defined(node.id):
                self.undefined_nodes.append((node, node.id))
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.push_scope()
        for gen in node.generators:
            for target_name in _extract_target_names(gen.target):
                self.add_name(target_name)
        self.generic_visit(node)
        self.pop_scope()

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self.push_scope()
        for gen in node.generators:
            for target_name in _extract_target_names(gen.target):
                self.add_name(target_name)
        self.generic_visit(node)
        self.pop_scope()

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.push_scope()
        for gen in node.generators:
            for target_name in _extract_target_names(gen.target):
                self.add_name(target_name)
        self.generic_visit(node)
        self.pop_scope()

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self.push_scope()
        for gen in node.generators:
            for target_name in _extract_target_names(gen.target):
                self.add_name(target_name)
        self.generic_visit(node)
        self.pop_scope()


def _extract_target_names(target: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_extract_target_names(elt))
    return names


class UndefinedNameDetector(BaseDetector):
    """Detects undefined names and unbound variable usage."""

    meta = DetectorMeta(
        id="VIGILO-C02",
        name="Undefined Name Usage",
        cwe=None,
        description="Detects referenced variables/functions not defined in enclosing scopes.",
        severity=Severity.MEDIUM,
        category="correctness",
    )

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        visitor = ScopeVisitor()
        visitor.visit(tree)

        findings: list[Finding] = []
        seen_locations: set[tuple[int, int]] = set()

        for node, name in visitor.undefined_nodes:
            loc_key = (node.lineno, node.col_offset)
            if loc_key in seen_locations:
                continue
            seen_locations.add(loc_key)

            finding = self.create_finding(
                node=node,
                file_path=file_path,
                source=source,
                message=f"Undefined name `{name}` is referenced without being defined or imported.",
                fix_hint=f"Define or import `{name}` before referencing it, or check for typos.",
                confidence="high",
            )
            findings.append(finding)

        return findings
