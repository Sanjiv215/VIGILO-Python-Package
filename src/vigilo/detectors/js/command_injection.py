"""OS Command Injection detector in Node.js / JavaScript (VIGILO-JS-003)."""

from __future__ import annotations

from pathlib import Path

import tree_sitter

from vigilo.detectors.js.base import BaseJSDetector
from vigilo.models import DetectorMeta, Finding, Severity
from vigilo.parsers.js_parser import get_node_text, is_literal_node, walk_tree


class JSCommandInjectionDetector(BaseJSDetector):
    """Detects OS command injection via Node.js child_process with dynamic arguments."""

    meta = DetectorMeta(
        id="VIGILO-JS-003",
        name="OS Command Injection",
        cwe=78,
        description="Executing OS commands with dynamic string concatenation or template literals.",
        severity=Severity.HIGH,
        category="security",
        language="javascript",
    )

    EXEC_METHODS = {"exec", "execSync"}

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
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")

                if fn is not None and args is not None:
                    fn_name = ""
                    obj_name = ""

                    if fn.type == "member_expression":
                        obj = fn.child_by_field_name("object")
                        prop = fn.child_by_field_name("property")
                        if obj:
                            obj_name = get_node_text(obj, source_bytes)
                        if prop:
                            fn_name = get_node_text(prop, source_bytes)
                    elif fn.type == "identifier":
                        fn_name = get_node_text(fn, source_bytes)

                    # Check child_process.exec / child_process.execSync
                    is_exec_call = False
                    if fn_name in self.EXEC_METHODS:
                        if obj_name in ("", "child_process", "cp", "childProcess"):
                            is_exec_call = True

                    if is_exec_call:
                        named_args = args.named_children
                        if named_args:
                            first_arg = named_args[0]
                            if not is_literal_node(first_arg, source_bytes):
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=(
                                            f"Executing OS command via '{fn_name}()' with dynamic "
                                            "input allows command injection."
                                        ),
                                        fix_hint=(
                                            "Use child_process.execFile() or child_process.spawn() "
                                            "with argument arrays."
                                        ),
                                        confidence="high",
                                    )
                                )

                    # Check spawn / spawnSync with { shell: true } and dynamic command
                    elif fn_name in ("spawn", "spawnSync", "execFile", "execFileSync"):
                        named_args = args.named_children
                        if len(named_args) >= 2:
                            options_arg = named_args[-1]
                            has_shell_true = False
                            if options_arg.type == "object":
                                for prop in options_arg.named_children:
                                    if prop.type in ("pair", "property"):
                                        k = prop.child_by_field_name("key")
                                        v = prop.child_by_field_name("value")
                                        if (
                                            k
                                            and v
                                            and get_node_text(k, source_bytes) == "shell"
                                            and get_node_text(v, source_bytes) in ("true", "1")
                                        ):
                                            has_shell_true = True
                                            break

                            if has_shell_true and not is_literal_node(named_args[0], source_bytes):
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=(
                                            f"Invoking '{fn_name}()' with shell: true and dynamic "
                                            "command enables command injection."
                                        ),
                                        fix_hint=(
                                            "Disable 'shell: true' and pass arguments as separate "
                                            "array elements."
                                        ),
                                        confidence="high",
                                    )
                                )

        return findings
