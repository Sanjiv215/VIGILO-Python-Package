"""Detector for Python syntax, indentation, and structure errors (VIGILO-C01)."""

from __future__ import annotations

import ast
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.models import DetectorMeta, Finding, Location, Severity


class SyntaxErrorDetector(BaseDetector):
    """Detects unparseable syntax, indentation, and structure errors."""

    meta = DetectorMeta(
        id="VIGILO-C01",
        name="Syntax & Indentation Error",
        cwe=None,
        description="Detects Python syntax, indentation, and structural parsing errors.",
        severity=Severity.HIGH,
        category="correctness",
    )

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        """AST is already parsed for valid files; no syntax error present."""
        return []

    def check_syntax_error(self, error: SyntaxError, file_path: Path, source: str) -> Finding:
        """Create a Finding from a caught SyntaxError / IndentationError."""
        lineno = error.lineno or 1
        col_offset = error.offset or 1

        source_lines = source.splitlines()
        source_line = ""
        if 1 <= lineno <= len(source_lines):
            source_line = source_lines[lineno - 1]

        location = Location(
            file=file_path,
            line=lineno,
            col=col_offset,
        )

        if isinstance(error, (IndentationError, TabError)):
            msg = f"Indentation error: {error.msg}"
            fix_hint = f"Fix indentation or spacing at line {lineno}."
        else:
            msg = f"Syntax error: {error.msg}"
            fix_hint = f"Fix syntax error at line {lineno}."

        return Finding(
            detector=self.meta,
            location=location,
            message=msg,
            fix_hint=fix_hint,
            severity=self.meta.severity,
            confidence="high",
            source_line=source_line,
            category=self.meta.category,
            language="python",
        )

    def check_js_syntax_error(
        self,
        file_path: Path,
        source: str,
        error_msg: str = "",
        line: int = 1,
        col: int = 1,
        language: str = "javascript",
    ) -> Finding:
        """Create a Finding from a JavaScript or TypeScript syntax/parse error."""
        source_lines = source.splitlines()
        source_line = ""
        if 1 <= line <= len(source_lines):
            source_line = source_lines[line - 1]

        location = Location(
            file=file_path,
            line=line,
            col=col,
        )

        if error_msg:
            msg = f"Syntax error: {error_msg}"
        else:
            msg = "Syntax error: invalid or unexpected token"
        fix_hint = f"Fix JavaScript/TypeScript syntax error at line {line}."

        meta = DetectorMeta(
            id=self.meta.id,
            name=self.meta.name,
            cwe=self.meta.cwe,
            description="Detects syntax, indentation, and structural parsing errors.",
            severity=self.meta.severity,
            category=self.meta.category,
            language=language,
        )

        return Finding(
            detector=meta,
            location=location,
            message=msg,
            fix_hint=fix_hint,
            severity=self.meta.severity,
            confidence="high",
            source_line=source_line,
            category=self.meta.category,
            language=language,
        )
