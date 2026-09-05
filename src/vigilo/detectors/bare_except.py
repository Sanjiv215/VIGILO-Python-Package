"""Detector for bare except clauses that swallow all errors (VIGILO-C05)."""

from __future__ import annotations

import ast
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.models import DetectorMeta, Finding, Severity


class BareExceptDetector(BaseDetector):
    """Detects bare `except:` clauses that catch BaseException, hiding bugs and interrupts."""

    meta = DetectorMeta(
        id="VIGILO-C05",
        name="Bare Except Clause",
        cwe=None,
        description="Detects bare `except:` clauses that swallow KeyboardInterrupt and SystemExit.",
        severity=Severity.MEDIUM,
        category="correctness",
    )

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                for handler in node.handlers:
                    if handler.type is None:
                        msg = (
                            "Bare `except:` clause catches BaseException, swallowing "
                            "interrupts and masking bugs."
                        )
                        hint = (
                            "Catch specific exceptions (e.g., `except Exception:`) "
                            "instead of bare `except:`."
                        )
                        finding = self.create_finding(
                            node=handler,
                            file_path=file_path,
                            source=source,
                            message=msg,
                            fix_hint=hint,
                            confidence="high",
                        )
                        findings.append(finding)

        return findings
