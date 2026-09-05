"""Detector for Unsafe Deserialization vulnerabilities (CWE-502 / VIGILO-004)."""

from __future__ import annotations

import ast
from pathlib import Path

from vigilo.detectors.base import BaseDetector
from vigilo.flow import FlowAnalyzer
from vigilo.models import DetectorMeta, Finding, Severity

SAFE_YAML_LOADERS = {
    "SafeLoader",
    "CSafeLoader",
    "BaseLoader",
    "FullLoader",
}

PICKLE_MODULES = {"pickle", "_pickle", "cPickle", "marshal"}
PICKLE_METHODS = {"loads", "load"}


class UnsafeDeserializationDetector(BaseDetector):
    """Detects unsafe deserialization using pickle, marshal, or PyYAML without SafeLoader."""

    meta = DetectorMeta(
        id="VIGILO-004",
        name="Unsafe Deserialization",
        cwe=502,
        description="Detects insecure deserialization with pickle, marshal, or unsafe PyYAML",
        severity=Severity.HIGH,
    )

    def _is_safe_yaml_loader(self, node: ast.Call) -> bool:
        """Check if yaml.load specifies a safe loader via keyword or positional argument."""
        # Check keyword argument Loader=...
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute) and kw.value.attr in SAFE_YAML_LOADERS:
                    return True
                if isinstance(kw.value, ast.Name) and kw.value.id in SAFE_YAML_LOADERS:
                    return True

        # Check positional argument (yaml.load(stream, SafeLoader))
        if len(node.args) >= 2:
            second_arg = node.args[1]
            if isinstance(second_arg, ast.Attribute) and second_arg.attr in SAFE_YAML_LOADERS:
                return True
            if isinstance(second_arg, ast.Name) and second_arg.id in SAFE_YAML_LOADERS:
                return True

        return False

    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        findings: list[Finding] = []
        parent_map = self.build_parent_map(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            scope = self.get_enclosing_function(node, parent_map)

            # Check pickle.loads / pickle.load / _pickle / marshal
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                method_name = node.func.attr

                if module_name in PICKLE_MODULES and method_name in PICKLE_METHODS:
                    if node.args and FlowAnalyzer.is_dynamic(node.args[0], scope):
                        msg = f"Insecure deserialization: `{module_name}.{method_name}()` used."
                        hint = (
                            "Avoid unpickling untrusted data. Use safer data formats "
                            "like JSON (`json.loads()`) or use signed serialization."
                        )
                        findings.append(
                            self.create_finding(
                                node=node,
                                file_path=file_path,
                                source=source,
                                message=msg,
                                fix_hint=hint,
                                severity=self.meta.severity,
                                confidence="high",
                            )
                        )
                        continue

                # Check yaml.load (without SafeLoader)
                if module_name == "yaml" and method_name == "load":
                    if not self._is_safe_yaml_loader(node) and node.args:
                        if FlowAnalyzer.is_dynamic(node.args[0], scope):
                            msg = "Insecure YAML deserialization: `yaml.load()` without SafeLoader."
                            hint = (
                                "Use `yaml.safe_load(data)` or pass `Loader=yaml.SafeLoader` "
                                "to prevent arbitrary code execution during parsing."
                            )
                            findings.append(
                                self.create_finding(
                                    node=node,
                                    file_path=file_path,
                                    source=source,
                                    message=msg,
                                    fix_hint=hint,
                                    severity=self.meta.severity,
                                    confidence="high",
                                )
                            )

        return findings
