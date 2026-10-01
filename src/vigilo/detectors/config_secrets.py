"""Scanner for secrets in configuration and environment files (.env, .json, .yaml, .yml, .toml)."""

from __future__ import annotations

import re
from pathlib import Path

from vigilo.detectors.hardcoded_secrets import (
    COMMON_SECRET_PATTERNS,
    PLACEHOLDER_REGEX,
    SENSITIVE_VARIABLE_NAMES,
)
from vigilo.models import DetectorMeta, Finding, Location, Severity

CONFIG_META = DetectorMeta(
    id="VIGILO-006",
    name="Hardcoded Secrets & Credentials",
    cwe=798,
    description="Hardcoded API keys, tokens, or credentials in config files.",
    severity=Severity.HIGH,
    category="security",
    language="config",
)

# Regex to match key-value pairs across .env, YAML, TOML, and JSON
KEY_VALUE_REGEX = re.compile(
    r"""(?:^|[{,\s])["']?(?P<key>[a-zA-Z0-9_\-\.]+)["']?\s*(?::|=)\s*(?P<val>["']?[^#\r\n,;}\]]*["']?)"""
)


def scan_config_file(file_path: Path) -> list[Finding]:
    """Scan a config or env file for hardcoded credentials and high-entropy secrets."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    findings: list[Finding] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*")):
            continue

        # 1. First check explicit pattern matches across the line
        pattern_found = False
        for pattern_name, regex in COMMON_SECRET_PATTERNS:
            match = regex.search(stripped)
            if match:
                loc = Location(
                    file=file_path,
                    line=idx,
                    col=line.find(match.group(0)) + 1,
                )
                findings.append(
                    Finding(
                        detector=CONFIG_META,
                        location=loc,
                        message=f"Hardcoded {pattern_name} detected in configuration file.",
                        fix_hint="Store secrets in secure vault managers or injection mechanisms.",
                        severity=Severity.HIGH,
                        confidence="high",
                        source_line=line,
                        category="security",
                        language="config",
                    )
                )
                pattern_found = True
                break

        if pattern_found:
            continue

        # 2. Key-value parsing for sensitive names
        kv_match = KEY_VALUE_REGEX.search(stripped)
        if kv_match:
            key = kv_match.group("key").strip()
            raw_val = kv_match.group("val").strip().rstrip(",;").strip("'\"`")

            if SENSITIVE_VARIABLE_NAMES.match(key):
                prefixes = ("http://", "https://", "/", "./", "../", "${", "$", "%")
                if (
                    len(raw_val) >= 8
                    and not PLACEHOLDER_REGEX.match(raw_val)
                    and not raw_val.startswith(prefixes)
                    and not (raw_val.startswith("{{") and raw_val.endswith("}}"))
                ):
                    loc = Location(
                        file=file_path,
                        line=idx,
                        col=line.find(key) + 1,
                    )
                    findings.append(
                        Finding(
                            detector=CONFIG_META,
                            location=loc,
                            message=f"Hardcoded secret assigned to sensitive key '{key}'.",
                            fix_hint=(
                                "Load sensitive credentials dynamically from environment "
                                "variables or secret vaults."
                            ),
                            severity=Severity.HIGH,
                            confidence="high",
                            source_line=line,
                            category="security",
                            language="config",
                        )
                    )

    return findings
