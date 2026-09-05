"""Vigilo — A static, security-focused code scanner for Python."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from vigilo._version import __version__
from vigilo.detectors import ALL_DETECTORS, CORRECTNESS_DETECTORS, SECURITY_DETECTORS
from vigilo.models import DetectorMeta, Finding, Location, Severity
from vigilo.scanner import ScanConfig, Scanner


def scan(
    path: Path | str = ".",
    min_severity: Severity | str = Severity.LOW,
    exclude_patterns: Sequence[str] | None = None,
    include_correctness: bool = True,
    categories: Sequence[str] | None = None,
) -> list[Finding]:
    """Scan a target path for security vulnerabilities (and optionally correctness diagnostics).

    Args:
        path: Directory or file path to scan (defaults to current directory).
        min_severity: Minimum severity threshold ("low", "medium", "high").
        exclude_patterns: Glob patterns to exclude during file discovery.
        include_correctness: Whether to include code correctness diagnostics.
        categories: Specific finding categories to include (e.g., ["security"]).

    Returns:
        List of Finding objects discovered during scan.
    """
    if isinstance(min_severity, str):
        min_severity = Severity(min_severity.lower())

    config = ScanConfig(
        paths=[path],
        min_severity=min_severity,
        exclude_patterns=exclude_patterns,
        include_correctness=include_correctness,
        categories=categories,
    )
    scanner = Scanner(config)
    return scanner.scan()


__all__ = [
    "__version__",
    "scan",
    "Scanner",
    "ScanConfig",
    "Finding",
    "Severity",
    "Location",
    "DetectorMeta",
    "SECURITY_DETECTORS",
    "CORRECTNESS_DETECTORS",
    "ALL_DETECTORS",
]
