"""CLI entry point and command-line parser for Vigilo."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from vigilo import __version__
from vigilo.models import Severity
from vigilo.reporter import format_report
from vigilo.scanner import ScanConfig, Scanner


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="vigilo",
        description="Vigilo — A static, security-focused code scanner for Python.",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"vigilo {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a directory or file for security vulnerabilities",
    )
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to directory or file to scan (default: '.')",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Output report format (default: 'text')",
    )
    scan_parser.add_argument(
        "--min-severity",
        "-s",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity threshold to report (default: 'low')",
    )
    scan_parser.add_argument(
        "--exclude",
        "-e",
        action="append",
        default=[],
        help="Exclude files/directories matching glob pattern (repeatable)",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI color codes in output",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Main execution entrypoint for Vigilo CLI."""
    if argv is None:
        argv = sys.argv[1:]

    args_list = list(argv)

    # Normalize alias: `vigilo <path>` -> `vigilo scan <path>`
    if not args_list:
        args_list = ["scan", "."]
    elif args_list[0] not in ("scan", "-h", "--help", "-V", "--version"):
        args_list = ["scan"] + args_list

    parser = build_parser()

    try:
        args = parser.parse_args(args_list)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 2

    if getattr(args, "command", None) != "scan":
        parser.print_help()
        return 0

    target_str = getattr(args, "target", ".")
    target_path = Path(target_str)
    if not target_path.exists():
        sys.stderr.write(f"Error: Target path does not exist: {target_str}\n")
        return 2

    out_format = getattr(args, "format", "text")
    min_sev_str = getattr(args, "min_severity", "low")
    excludes = getattr(args, "exclude", [])
    no_color = getattr(args, "no_color", False)

    min_severity = Severity(min_sev_str.lower())
    use_color = not no_color and sys.stdout.isatty() and out_format == "text"

    try:
        config = ScanConfig(
            paths=[target_path],
            min_severity=min_severity,
            exclude_patterns=excludes if excludes else None,
        )
        scanner = Scanner(config)
        findings = scanner.scan()
    except Exception as e:
        sys.stderr.write(f"Scan error: {e}\n")
        return 2

    report_str = format_report(findings, output_format=out_format, use_color=use_color)
    print(report_str)

    # Exit code: 1 if findings present, 0 if clean
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
