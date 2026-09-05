"""Detector for unused imports and unused local variables (VIGILO-C03)."""

from __future__ import annotations

import ast
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.models import DetectorMeta, Finding, Severity


class UnusedCodeDetector(BaseDetector):
    """Detects unused imported modules and unused local variables."""

    meta = DetectorMeta(
        id="VIGILO-C03",
        name="Unused Import / Variable",
        cwe=None,
        description="Detects imported modules or local variables that are defined but never used.",
        severity=Severity.LOW,
        category="correctness",
    )

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []

        # Do not flag unused imports in __init__.py files (standard re-export idiom)
        is_init_file = file_path.name == "__init__.py"

        # 1. Collect all imported names and their AST nodes
        imports: dict[str, tuple[ast.AST, str]] = {}
        if not is_init_file:
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        as_name = alias.asname or alias.name.split(".")[0]
                        imports[as_name] = (node, alias.name)
                elif isinstance(node, ast.ImportFrom):
                    # Do not flag compiler directives like `from __future__ import ...`
                    if node.module == "__future__":
                        continue
                    if node.names and node.names[0].name != "*":
                        for alias in node.names:
                            as_name = alias.asname or alias.name
                            imports[as_name] = (node, alias.name)

        # 2. Check which names are loaded in the AST
        referenced_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                referenced_names.add(node.id)

        # Check __all__ definitions in module
        all_exported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__all__":
                        if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                            for elt in node.value.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    all_exported.add(elt.value)

        # Flag unused imports
        for name, (node, orig_name) in imports.items():
            if name not in referenced_names and name not in all_exported:
                findings.append(
                    self.create_finding(
                        node=node,
                        file_path=file_path,
                        source=source,
                        message=f"Imported name `{name}` is never used.",
                        fix_hint=f"Remove unused import `{orig_name}`.",
                        confidence="high",
                    )
                )

        # 3. Check for unused local variables in functions
        for func_node in ast.walk(tree):
            if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Find global / nonlocal names in this function
                globals_nonlocals: set[str] = set()
                for child in ast.walk(func_node):
                    if isinstance(child, (ast.Global, ast.Nonlocal)):
                        globals_nonlocals.update(child.names)

                # Collect local assignments and loads within this function
                local_assignments: dict[str, ast.AST] = {}
                local_loads: set[str] = set()

                for child in ast.walk(func_node):
                    if child is func_node:
                        continue
                    if isinstance(child, ast.Name):
                        if isinstance(child.ctx, ast.Store):
                            if not child.id.startswith("_") and child.id not in globals_nonlocals:
                                if child.id not in local_assignments:
                                    local_assignments[child.id] = child
                        elif isinstance(child.ctx, ast.Load):
                            local_loads.add(child.id)

                for var_name, assign_node in local_assignments.items():
                    if var_name not in local_loads:
                        findings.append(
                            self.create_finding(
                                node=assign_node,
                                file_path=file_path,
                                source=source,
                                message=f"Local variable `{var_name}` is assigned but never used.",
                                fix_hint=(
                                    f"Remove unused variable `{var_name}` or "
                                    "prefix with `_` if intentional."
                                ),
                                confidence="high",
                            )
                        )

        return findings
