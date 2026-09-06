"""Hardcoded Secrets and Credentials detector in JS/TS (VIGILO-JS-005)."""

from __future__ import annotations

import re
from pathlib import Path

import tree_sitter

from vigilo.detectors.js.base import BaseJSDetector
from vigilo.models import DetectorMeta, Finding, Severity
from vigilo.parsers.js_parser import get_node_text, walk_tree


class JSHardcodedSecretsDetector(BaseJSDetector):
    """Detects hardcoded API keys, authentication tokens, private keys, and database passwords."""

    meta = DetectorMeta(
        id="VIGILO-JS-005",
        name="Hardcoded Secrets & Credentials",
        cwe=798,
        description="Hardcoded API keys, JWT tokens, private keys, or credentials found in code.",
        severity=Severity.HIGH,
        category="security",
        language="javascript",
    )

    # Specific credential patterns
    PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
        (
            "GitHub Personal Access Token",
            re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}"),
        ),
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
    ]

    # Sensitive key/variable names
    SENSITIVE_NAMES = re.compile(
        r"^(?:api_?key|secret_?key|auth_?token|jwt_?secret|private_?key|client_?secret|db_?password|access_?token)$",
        re.IGNORECASE,
    )

    # Common dummy / placeholder strings to ignore
    PLACEHOLDERS = re.compile(
        r"^(?:placeholder|your[-_]?.*|test[-_]?.*|dummy|changeme|replace[-_]?.*|example|none|undefined|null|x{3,}|\*{3,})$",
        re.IGNORECASE,
    )

    def _strip_quotes(self, s: str) -> str:
        s = s.strip()
        if (
            (s.startswith('"') and s.endswith('"'))
            or (s.startswith("'") and s.endswith("'"))
            or (s.startswith("`") and s.endswith("`"))
        ):
            return s[1:-1]
        return s

    def run(
        self,
        tree: tree_sitter.Tree,
        file_path: Path,
        source_str: str,
        source_bytes: bytes,
    ) -> list[Finding]:
        findings: list[Finding] = []
        all_nodes = walk_tree(tree.root_node)

        for node in all_nodes:
            # Check string literals and template literals for specific regex patterns
            if node.type in ("string", "template_string"):
                raw_text = get_node_text(node, source_bytes)
                val = self._strip_quotes(raw_text)

                for name, pattern in self.PATTERNS:
                    if pattern.search(val):
                        findings.append(
                            self.create_finding(
                                node=node,
                                file_path=file_path,
                                source_str=source_str,
                                message=f"Hardcoded {name} detected in source code.",
                                fix_hint=(
                                    "Store secrets in environment variables (process.env) or "
                                    "vault managers."
                                ),
                                confidence="high",
                            )
                        )
                        break

            # Check variable / property declarations with sensitive names
            elif node.type in (
                "variable_declarator",
                "pair",
                "property",
                "assignment_expression",
            ):
                key_node = None
                val_node = None

                if node.type == "variable_declarator":
                    key_node = node.child_by_field_name("name")
                    val_node = node.child_by_field_name("value")
                elif node.type in ("pair", "property"):
                    key_node = node.child_by_field_name("key")
                    val_node = node.child_by_field_name("value")
                elif node.type == "assignment_expression":
                    key_node = node.child_by_field_name("left")
                    val_node = node.child_by_field_name("right")

                if key_node is not None and val_node is not None:
                    key_name = get_node_text(key_node, source_bytes).strip("'\"`")
                    if self.SENSITIVE_NAMES.match(key_name):
                        if val_node.type in ("string", "template_string"):
                            raw_val = self._strip_quotes(get_node_text(val_node, source_bytes))
                            if len(raw_val) >= 8 and not self.PLACEHOLDERS.match(raw_val):
                                if not any(p[1].search(raw_val) for p in self.PATTERNS):
                                    findings.append(
                                        self.create_finding(
                                            node=node,
                                            file_path=file_path,
                                            source_str=source_str,
                                            message=(
                                                f"Hardcoded secret assigned to sensitive variable "
                                                f"'{key_name}'."
                                            ),
                                            fix_hint=(
                                                "Load sensitive credentials dynamically using "
                                                "process.env or secret managers."
                                            ),
                                            confidence="high",
                                        )
                                    )

        return findings
