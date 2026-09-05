"""Vigilo — A static, security-focused code scanner for Python."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from vigilo.models import DetectorMeta, Finding, Location, Severity
from vigilo.scanner import ScanConfig, Scanner

__version__ = "0.1.0"


def scan(
    path: Path | str = ".",
    min_severity: Severity | str = Severity.LOW,
    exclude_patterns: Sequence[str] | None = None,
) -> list[Finding]:
    """Scan a target path for known security vulnerabilities.

    Args:
        path: Directory or file path to scan (defaults to current directory).
        min_severity: Minimum severity threshold ("low", "medium", "high").
        exclude_patterns: Glob patterns to exclude during file discovery.

    Returns:
        List of Finding objects discovered during scan.
    """
    if isinstance(min_severity, str):
        min_severity = Severity(min_severity.lower())

    config = ScanConfig(
        paths=[path],
        min_severity=min_severity,
        exclude_patterns=exclude_patterns,
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
]
