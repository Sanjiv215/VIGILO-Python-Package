"""Base class and common interfaces for Tree-Sitter JavaScript/TypeScript detectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

import tree_sitter

from vigilo.discovery import get_file_language
from vigilo.models import DetectorMeta, Finding, Severity
from vigilo.parsers.js_parser import get_location


class BaseJSDetector(ABC):
    """Abstract base class for all Tree-Sitter based JS/TS/React detectors."""

    meta: DetectorMeta

    @abstractmethod
    def run(
        self,
        tree: tree_sitter.Tree,
        file_path: Path,
        source_str: str,
        source_bytes: bytes,
    ) -> list[Finding]:
        """Execute detector on a parsed JS/TS syntax tree.

        Args:
            tree: Parsed tree-sitter Tree.
            file_path: Path to target source file.
            source_str: Decoded source code string.
            source_bytes: Raw source code bytes.

        Returns:
            List of detected findings.
        """
        ...

    def extract_source_line(self, source_str: str, line_no: int) -> str:
        """Extract a single 1-indexed line of source code."""
        lines = source_str.splitlines()
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1]
        return ""

    def create_finding(
        self,
        node: tree_sitter.Node,
        file_path: Path,
        source_str: str,
        message: str,
        fix_hint: str,
        confidence: str = "high",
        severity: Severity | None = None,
    ) -> Finding:
        """Construct a strongly typed Finding object from an AST node."""
        loc = get_location(node, file_path)
        src_line = self.extract_source_line(source_str, loc.line)
        lang = get_file_language(file_path)

        return Finding(
            detector=self.meta,
            location=loc,
            message=message,
            fix_hint=fix_hint,
            severity=severity or self.meta.severity,
            confidence=confidence,
            source_line=src_line,
            category=self.meta.category,
            language=lang,
        )
