"""Reporters for formatting finding results into text or JSON output in Vigilo."""

from __future__ import annotations

import json
from collections.abc import Sequence

from vigilo.models import Finding, Severity

# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREEN = "\033[32m"


def _severity_color(sev: Severity, use_color: bool) -> str:
    if not use_color:
        return ""
    if sev == Severity.HIGH:
        return f"{BOLD}{RED}"
    if sev == Severity.MEDIUM:
        return f"{BOLD}{YELLOW}"
    return f"{BOLD}{CYAN}"


def format_text_report(findings: Sequence[Finding], use_color: bool = True) -> str:
    """Format findings as human-readable CLI text output."""
    if not findings:
        prefix = f"{BOLD}{GREEN}✓{RESET} " if use_color else "✓ "
        return f"\n{prefix}No security vulnerabilities found.\n"

    lines: list[str] = [""]
    counts = {"high": 0, "medium": 0, "low": 0}

    dim = DIM if use_color else ""
    reset = RESET if use_color else ""
    bold = BOLD if use_color else ""

    for finding in findings:
        sev = finding.severity
        counts[sev.value] += 1
        sev_colored = f"{_severity_color(sev, use_color)}{sev.value.upper()}{reset}"
        loc_str = f"{bold}{finding.location}{reset}"
        conf_str = f"{dim}[confidence: {finding.confidence}]{reset}"
        meta = finding.detector

        header = (
            f"  {loc_str}  {sev_colored}  "
            f"{bold}{meta.id} {meta.name}{reset} (CWE-{meta.cwe}) {conf_str}"
        )
        lines.append(header)

        # Message
        lines.append(f"  {dim}│{reset} {finding.message}")

        # Code snippet if present
        if finding.source_line:
            clean_source = finding.source_line.strip()
            lines.append(f"  {dim}│{reset}   {clean_source}")

        # Fix guidance
        lines.append(f"  {dim}│{reset} {bold}Fix:{reset} {finding.fix_hint}")
        lines.append("")

    total = len(findings)
    sum_color = f"{BOLD}{RED}" if use_color else ""
    summary = (
        f"  {sum_color}✖ {total} vulnerabilities found{reset} "
        f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)\n"
    )
    lines.append(summary)

    return "\n".join(lines)


def format_json_report(findings: Sequence[Finding]) -> str:
    """Format findings as structured JSON string."""
    data = {
        "version": "0.1.0",
        "findings": [
            {
                "id": f.detector.id,
                "name": f.detector.name,
                "cwe": f.detector.cwe,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "message": f.message,
                "fix_hint": f.fix_hint,
                "location": {
                    "file": str(f.location.file),
                    "line": f.location.line,
                    "col": f.location.col,
                    "end_line": f.location.end_line,
                    "end_col": f.location.end_col,
                },
                "source_line": f.source_line,
            }
            for f in findings
        ],
        "summary": {
            "total": len(findings),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
        },
    }
    return json.dumps(data, indent=2)


def format_report(
    findings: Sequence[Finding],
    output_format: str = "text",
    use_color: bool = True,
) -> str:
    """Format findings according to specified format."""
    if output_format.lower() == "json":
        return format_json_report(findings)
    return format_text_report(findings, use_color=use_color)
