"""Base classes and interfaces for vulnerability detectors in Vigilo."""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from pathlib import Path

from vigilo.models import DetectorMeta, Finding, Location, Severity


class BaseDetector(ABC):
    """Abstract base class for all Vigilo vulnerability detectors."""

    meta: DetectorMeta

    @abstractmethod
    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        """Scan a parsed Python AST module for vulnerability patterns.

        Args:
            tree: Parsed AST module node.
            file_path: Path to the scanned file.
            source: Raw string content of the source file.

        Returns:
            List of findings discovered in this file.
        """
        ...

    def create_finding(
        self,
        node: ast.AST,
        file_path: Path,
        source: str,
        message: str,
        fix_hint: str,
        severity: Severity | None = None,
        confidence: str = "high",
    ) -> Finding:
        """Create a standardized Finding instance from an AST node."""
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)
        end_lineno = getattr(node, "end_lineno", None)
        end_col_offset = getattr(node, "end_col_offset", None)

        source_lines = source.splitlines()
        source_line = ""
        if 1 <= lineno <= len(source_lines):
            source_line = source_lines[lineno - 1]

        location = Location(
            file=file_path,
            line=lineno,
            col=col_offset,
            end_line=end_lineno,
            end_col=end_col_offset,
        )

        return Finding(
            detector=self.meta,
            location=location,
            message=message,
            fix_hint=fix_hint,
            severity=severity or self.meta.severity,
            confidence=confidence,
            source_line=source_line,
            category=self.meta.category,
        )

    @staticmethod
    def build_parent_map(tree: ast.Module) -> dict[ast.AST, ast.AST]:
        """Build a mapping of child AST nodes to their parent nodes."""
        parent_map: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_map[child] = parent
        return parent_map

    @staticmethod
    def get_enclosing_function(
        node: ast.AST, parent_map: dict[ast.AST, ast.AST]
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        """Find the enclosing function definition for a given AST node."""
        curr: ast.AST | None = node
        while curr is not None:
            if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return curr
            curr = parent_map.get(curr)
        return None
