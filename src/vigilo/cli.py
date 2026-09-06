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
        description=(
            "Vigilo — Fast static security and correctness scanner for Python, "
            "JavaScript, and TypeScript."
        ),
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"vigilo {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. `vigilo scan`
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a directory or file for security vulnerabilities and code correctness",
    )
    _add_common_arguments(scan_parser)
    scan_parser.add_argument(
        "--mode",
        "-m",
        choices=["all", "security", "correctness"],
        default="all",
        help=(
            "Scan mode: 'all' (security + correctness), 'security' (security only), "
            "'correctness' (diagnostics only) (default: all)"
        ),
    )
    scan_parser.add_argument(
        "--security-only",
        "-S",
        action="store_true",
        default=False,
        help="Shortcut for --mode security (only report security vulnerabilities)",
    )

    # 2. `vigilo diagnose`
    diagnose_parser = subparsers.add_parser(
        "diagnose",
        help="Run code correctness diagnostics (syntax, undefined names, resources)",
    )
    _add_common_arguments(diagnose_parser)

    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to directory or file to scan (default: '.')",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Output report format (default: 'text')",
    )
    parser.add_argument(
        "--min-severity",
        "-s",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum severity threshold to report (default: 'low')",
    )
    parser.add_argument(
        "--exclude",
        "-e",
        action="append",
        default=[],
        help="Exclude files/directories matching glob pattern (repeatable)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI color codes in output",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Main execution entrypoint for Vigilo CLI."""
    if argv is None:
        argv = sys.argv[1:]

    args_list = list(argv)

    # Normalize alias: `vigilo <path>` -> `vigilo scan <path>`
    if not args_list:
        args_list = ["scan", "."]
    elif args_list[0] not in ("scan", "diagnose", "-h", "--help", "-V", "--version"):
        args_list = ["scan", *args_list]

    parser = build_parser()

    try:
        args = parser.parse_args(args_list)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 2

    command = getattr(args, "command", None)
    if command not in ("scan", "diagnose"):
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
    mode = getattr(args, "mode", "all")
    security_only = getattr(args, "security_only", False)

    # Determine categories
    if command == "diagnose" or mode == "correctness":
        categories: list[str] | None = ["correctness"]
        include_correctness = True
    elif security_only or mode == "security":
        categories = ["security"]
        include_correctness = False
    else:
        categories = None
        include_correctness = True

    min_severity = Severity(min_sev_str.lower())
    use_color = not no_color and sys.stdout.isatty() and out_format == "text"

    try:
        config = ScanConfig(
            paths=[target_path],
            min_severity=min_severity,
            exclude_patterns=excludes if excludes else None,
            include_correctness=include_correctness,
            categories=categories,
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
