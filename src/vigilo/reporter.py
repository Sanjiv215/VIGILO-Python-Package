"""Reporters for formatting finding results into text or JSON output in Vigilo."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence

from vigilo._version import __version__
from vigilo.models import Finding, Severity

# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREEN = "\033[32m"

# Pattern matching ANSI escape sequences and non-printable control characters
_ANSI_OR_CONTROL_RE = re.compile(
    r"\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)


def sanitize_terminal_text(text: str) -> str:
    """Sanitize text to prevent ANSI escape sequence injection and terminal manipulation."""
    return _ANSI_OR_CONTROL_RE.sub("", text)


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
        return f"\n{prefix}No security vulnerabilities or correctness issues found.\n"

    lines: list[str] = [""]
    counts = {"high": 0, "medium": 0, "low": 0}
    cat_counts = {"security": 0, "correctness": 0}

    dim = DIM if use_color else ""
    reset = RESET if use_color else ""
    bold = BOLD if use_color else ""

    for finding in findings:
        sev = finding.severity
        counts[sev.value] += 1
        cat_counts[finding.category] = cat_counts.get(finding.category, 0) + 1

        sev_colored = f"{_severity_color(sev, use_color)}{sev.value.upper()}{reset}"
        loc_str = f"{bold}{sanitize_terminal_text(str(finding.location))}{reset}"
        conf_str = f"{dim}[confidence: {finding.confidence}]{reset}"
        meta = finding.detector

        cwe_tag = f" (CWE-{meta.cwe})" if meta.cwe is not None else ""
        cat_badge = f"{dim}[{meta.category.upper()}]{reset} " if meta.category != "security" else ""

        header = (
            f"  {loc_str}  {sev_colored}  "
            f"{cat_badge}{bold}{meta.id} {meta.name}{reset}{cwe_tag} {conf_str}"
        )
        lines.append(header)

        # Message
        sanitized_msg = sanitize_terminal_text(finding.message)
        lines.append(f"  {dim}│{reset} {sanitized_msg}")

        # Code snippet if present
        if finding.source_line:
            clean_source = sanitize_terminal_text(finding.source_line.strip())
            lines.append(f"  {dim}│{reset}   {clean_source}")

        # Fix guidance
        sanitized_hint = sanitize_terminal_text(finding.fix_hint)
        lines.append(f"  {dim}│{reset} {bold}Fix:{reset} {sanitized_hint}")
        lines.append("")

    total = len(findings)
    sum_color = f"{BOLD}{RED}" if use_color else ""
    sec = cat_counts.get("security", 0)
    corr = cat_counts.get("correctness", 0)

    if corr > 0 and sec > 0:
        counts_str = f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low"
        breakdown = f"({sec} security, {corr} correctness | {counts_str})"
    elif corr > 0:
        breakdown = f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)"
    else:
        breakdown = f"({counts['high']} high, {counts['medium']} medium, {counts['low']} low)"

    label = "issues" if corr > 0 else "vulnerabilities"
    summary = f"  {sum_color}✖ {total} {label} found{reset} {breakdown}\n"
    lines.append(summary)

    return "\n".join(lines)


def format_json_report(findings: Sequence[Finding]) -> str:
    """Format findings as structured JSON string."""
    data = {
        "version": __version__,
        "findings": [
            {
                "id": f.detector.id,
                "name": f.detector.name,
                "cwe": f.detector.cwe,
                "category": f.category,
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
            "security": sum(1 for f in findings if f.category == "security"),
            "correctness": sum(1 for f in findings if f.category == "correctness"),
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
