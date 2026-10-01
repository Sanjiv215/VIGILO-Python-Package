"""Detector for hardcoded secrets, keys, and credentials in Python (VIGILO-006 / CWE-798)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.models import DetectorMeta, Finding, Severity

COMMON_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "GitHub Personal Access Token",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}"),
    ),
    ("Stripe API Key", re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}")),
    (
        "JWT Authentication Token",
        re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ),
    (
        "Private Cryptographic Key",
        re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP)? PRIVATE KEY-----"),
    ),
    (
        "Database Connection String with Credentials",
        re.compile(
            r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:[^@\s]+@[^/\s]+/[^?\s]+"
        ),
    ),
    ("OpenAI API Key", re.compile(r"sk-[a-zA-Z0-9]{32,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z-_]{35}")),
    ("SendGrid API Key", re.compile(r"SG\.[a-zA-Z0-9_\-\.]{66}")),
]

SENSITIVE_VARIABLE_NAMES = re.compile(
    r"(?:(?:api|secret|auth|jwt|private|client|db|database|admin|service|access|master|encryption|token|session)[-_]?(?:key|secret|token|password|pass|cred|credential)s?|"
    r"^(?:password|passwd|secret|token|api_?key)$|"
    r".*_(?:key|secret|token|password|credential|apikey)$)",
    re.IGNORECASE,
)

PLACEHOLDER_REGEX = re.compile(
    r"^(?:placeholder|your[-_]?.*|test[-_]?.*|demo[-_]?.*|mock[-_]?.*|fake[-_]?.*|"
    r"sample[-_]?.*|dummy.*|changeme.*|replace[-_]?.*|example.*|none|undefined|null|"
    r"x{3,}|\*{3,}|production|development|staging|localhost|standard|default|"
    r"authorized|unauthorized|true|false|Bearer\s?)$",
    re.IGNORECASE,
)


class HardcodedSecretsDetector(BaseDetector):
    """Detects hardcoded API keys, tokens, and credentials in Python source code."""

    meta = DetectorMeta(
        id="VIGILO-006",
        name="Hardcoded Secrets & Credentials",
        cwe=798,
        description="Hardcoded API keys, passwords, private keys, or tokens in source code.",
        severity=Severity.HIGH,
    )

    def _check_string_val(
        self,
        val: str,
        node: ast.AST,
        file_path: Path,
        source: str,
        name_hint: str | None = None,
    ) -> Finding | None:
        val = val.strip()
        # 1. Check known high-entropy / signature patterns
        for pattern_name, regex in COMMON_SECRET_PATTERNS:
            if regex.search(val):
                return self.create_finding(
                    node=node,
                    file_path=file_path,
                    source=source,
                    message=f"Hardcoded {pattern_name} detected in source code.",
                    fix_hint=(
                        "Store secrets in environment variables (e.g. os.environ) or "
                        "vault managers."
                    ),
                    confidence="high",
                )

        # 2. Check sensitive variable / key names
        if name_hint and SENSITIVE_VARIABLE_NAMES.match(name_hint):
            prefixes = ("http://", "https://", "/", "./", "../")
            if len(val) >= 8 and not PLACEHOLDER_REGEX.match(val) and not val.startswith(prefixes):
                return self.create_finding(
                    node=node,
                    file_path=file_path,
                    source=source,
                    message=f"Hardcoded secret assigned to sensitive variable '{name_hint}'.",
                    fix_hint=(
                        "Load sensitive credentials dynamically from environment variables "
                        "(e.g. os.getenv) or secret managers."
                    ),
                    confidence="high",
                )

        return None

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []
        reported_lines: set[int] = set()

        for node in ast.walk(tree):
            # Check variable assignments: foo = "secret"
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    var_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                    name_hint = var_names[0] if var_names else None
                    finding = self._check_string_val(
                        val, node.value, file_path, source, name_hint=name_hint
                    )
                    if finding and finding.location.line not in reported_lines:
                        reported_lines.add(finding.location.line)
                        findings.append(finding)

            # Check annotated assignments: foo: str = "secret"
            elif isinstance(node, ast.AnnAssign) and node.value:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    name_hint = node.target.id if isinstance(node.target, ast.Name) else None
                    finding = self._check_string_val(
                        val, node.value, file_path, source, name_hint=name_hint
                    )
                    if finding and finding.location.line not in reported_lines:
                        reported_lines.add(finding.location.line)
                        findings.append(finding)

            # Check dictionary key-value literals: {"api_key": "secret"}
            elif isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values, strict=False):
                    if isinstance(v, ast.Constant) and isinstance(v.value, str):
                        name_hint = None
                        if isinstance(k, ast.Constant) and isinstance(k.value, str):
                            name_hint = k.value
                        finding = self._check_string_val(
                            v.value, v, file_path, source, name_hint=name_hint
                        )
                        if finding and finding.location.line not in reported_lines:
                            reported_lines.add(finding.location.line)
                            findings.append(finding)

            # Check keyword arguments in function calls: connect(password="secret")
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        finding = self._check_string_val(
                            kw.value.value, kw.value, file_path, source, name_hint=kw.arg
                        )
                        if finding and finding.location.line not in reported_lines:
                            reported_lines.add(finding.location.line)
                            findings.append(finding)

            # Check general standalone string literals that match explicit secret patterns
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                lineno = getattr(node, "lineno", 0)
                if lineno not in reported_lines:
                    for pattern_name, regex in COMMON_SECRET_PATTERNS:
                        if regex.search(node.value):
                            finding = self.create_finding(
                                node=node,
                                file_path=file_path,
                                source=source,
                                message=f"Hardcoded {pattern_name} detected in source code.",
                                fix_hint=(
                                    "Store secrets in environment variables or vault managers."
                                ),
                                confidence="high",
                            )
                            reported_lines.add(lineno)
                            findings.append(finding)
                            break

        return findings
