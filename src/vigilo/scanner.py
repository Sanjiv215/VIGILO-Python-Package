"""Scanner orchestrator for executing detectors across discovered files in Vigilo."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from vigilo.detectors import (
    ALL_DETECTORS,
    JS_DETECTORS,
    PYTHON_DETECTORS,
    PYTHON_SECURITY_DETECTORS,
    BaseDetector,
    BaseJSDetector,
)
from vigilo.detectors.syntax_error import SyntaxErrorDetector
from vigilo.discovery import discover_files, get_file_language
from vigilo.models import Finding, Severity
from vigilo.parsers.js_parser import parse_js_ts


@dataclass
class ScanConfig:
    """Configuration options for a scan run."""

    paths: Sequence[Path | str]
    exclude_patterns: Sequence[str] | None = None
    min_severity: Severity = Severity.LOW
    detectors: Sequence[type[BaseDetector] | type[BaseJSDetector]] | None = None
    follow_symlinks: bool = False
    include_correctness: bool = True
    categories: Sequence[str] | None = None


class Scanner:
    """Orchestrates file discovery, multi-language AST parsing, and detector execution."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

        self.py_detectors: list[BaseDetector] = []
        self.js_detectors: list[BaseJSDetector] = []

        if config.detectors is not None:
            for cls in config.detectors:
                if issubclass(cls, BaseJSDetector):
                    self.js_detectors.append(cls())
                elif issubclass(cls, BaseDetector):
                    self.py_detectors.append(cls())
        elif config.categories is not None:
            self.py_detectors = [
                d() for d in PYTHON_DETECTORS if d.meta.category in config.categories
            ]
            self.js_detectors = [d() for d in JS_DETECTORS if d.meta.category in config.categories]
        elif config.include_correctness:
            self.py_detectors = [d() for d in ALL_DETECTORS]
            self.js_detectors = [d() for d in JS_DETECTORS]
        else:
            self.py_detectors = [d() for d in PYTHON_SECURITY_DETECTORS]
            self.js_detectors = [d() for d in JS_DETECTORS if d.meta.category == "security"]

        # Maintain legacy property self.detectors for backwards compatibility
        self.detectors: list[BaseDetector] = self.py_detectors

    @staticmethod
    def parse_python_file(
        file_path: Path,
    ) -> tuple[ast.Module | None, str, SyntaxError | str | None]:
        """Safely read and parse a Python source file into an AST module."""
        try:
            source = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                source = file_path.read_text(encoding="latin-1")
            except Exception as e:
                return None, "", f"Failed to read file: {e}"
        except Exception as e:
            return None, "", f"Failed to read file: {e}"

        try:
            tree = ast.parse(source, filename=str(file_path))
            return tree, source, None
        except SyntaxError as e:
            return None, source, e
        except Exception as e:
            return None, source, f"Failed to parse AST: {e}"

    # Alias for backward compatibility
    parse_file = parse_python_file

    def scan_python_file(self, file_path: Path) -> list[Finding]:
        """Scan a single Python file using configured Python detectors."""
        tree, source, error = self.parse_python_file(file_path)
        if tree is None:
            if isinstance(error, SyntaxError):
                for detector in self.py_detectors:
                    if isinstance(detector, SyntaxErrorDetector):
                        return [detector.check_syntax_error(error, file_path, source)]
            return []

        findings: list[Finding] = []
        for detector in self.py_detectors:
            try:
                results = detector.run(tree, file_path, source)
                findings.extend(results)
            except Exception:  # noqa: S112
                continue

        return findings

    def scan_js_file(self, file_path: Path) -> list[Finding]:
        """Scan a JavaScript or TypeScript file using Tree-Sitter detectors."""
        try:
            source_bytes = file_path.read_bytes()
        except Exception:
            return []

        tree, source_str, raw_bytes, error = parse_js_ts(source_bytes, file_path)
        if tree is None:
            return []

        findings: list[Finding] = []
        for detector in self.js_detectors:
            try:
                results = detector.run(tree, file_path, source_str, raw_bytes)
                findings.extend(results)
            except Exception:  # noqa: S112
                continue

        return findings

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Route file to appropriate language scanner based on extension."""
        lang = get_file_language(file_path)
        if lang == "python":
            return self.scan_python_file(file_path)
        if lang in ("javascript", "typescript"):
            return self.scan_js_file(file_path)
        return []

    def scan(self) -> list[Finding]:
        """Run the full scanning pipeline across all target paths.

        Returns:
            Sorted and filtered list of findings.
        """
        all_files: set[Path] = set()
        for target in self.config.paths:
            try:
                discovered = discover_files(
                    target=target,
                    exclude_patterns=self.config.exclude_patterns,
                    follow_symlinks=self.config.follow_symlinks,
                )
                all_files.update(discovered)
            except FileNotFoundError:
                continue

        all_findings: list[Finding] = []
        for file_path in sorted(all_files):
            findings = self.scan_file(file_path)
            all_findings.extend(findings)

        # Filter by minimum severity threshold
        filtered_findings = [f for f in all_findings if f.severity >= self.config.min_severity]

        # Sort findings: Highest severity first, then by file, line, and column
        filtered_findings.sort(
            key=lambda f: (
                -f.severity.rank,
                str(f.location.file),
                f.location.line,
                f.location.col,
            )
        )

        return filtered_findings
