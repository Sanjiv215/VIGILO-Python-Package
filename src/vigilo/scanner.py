"""Scanner orchestrator for executing detectors across discovered files in Vigilo."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from vigilo.detectors import ALL_DETECTORS, SECURITY_DETECTORS, BaseDetector
from vigilo.detectors.syntax_error import SyntaxErrorDetector
from vigilo.discovery import discover_files
from vigilo.models import Finding, Severity


@dataclass
class ScanConfig:
    """Configuration options for a scan run."""

    paths: Sequence[Path | str]
    exclude_patterns: Sequence[str] | None = None
    min_severity: Severity = Severity.LOW
    detectors: Sequence[type[BaseDetector]] | None = None
    follow_symlinks: bool = False
    include_correctness: bool = False
    categories: Sequence[str] | None = None


class Scanner:
    """Orchestrates file discovery, AST parsing, and detector execution."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        if config.detectors is not None:
            detector_classes = config.detectors
        elif config.categories is not None:
            detector_classes = [d for d in ALL_DETECTORS if d.meta.category in config.categories]
        elif config.include_correctness:
            detector_classes = ALL_DETECTORS
        else:
            detector_classes = SECURITY_DETECTORS
        self.detectors: list[BaseDetector] = [cls() for cls in detector_classes]

    @staticmethod
    def parse_file(file_path: Path) -> tuple[ast.Module | None, str, SyntaxError | str | None]:
        """Safely read and parse a Python source file into an AST module.

        Returns:
            Tuple of (ast.Module or None, source_code, SyntaxError/error_message or None).
        """
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

    def scan_file(self, file_path: Path) -> list[Finding]:
        """Scan a single Python file using all configured detectors."""
        tree, source, error = self.parse_file(file_path)
        if tree is None:
            if isinstance(error, SyntaxError):
                for detector in self.detectors:
                    if isinstance(detector, SyntaxErrorDetector):
                        return [detector.check_syntax_error(error, file_path, source)]
            return []

        findings: list[Finding] = []
        for detector in self.detectors:
            try:
                results = detector.run(tree, file_path, source)
                findings.extend(results)
            except Exception:  # noqa: S112
                # Detector errors on a single file should not crash the entire scan
                continue

        return findings

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
