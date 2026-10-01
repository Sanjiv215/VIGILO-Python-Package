"""Code Injection detector in JavaScript/TypeScript (VIGILO-JS-002)."""

from __future__ import annotations

from pathlib import Path

import tree_sitter

from vigilo.detectors.js.base import BaseJSDetector
from vigilo.models import DetectorMeta, Finding, Severity
from vigilo.parsers.js_parser import get_node_text, is_literal_node, walk_tree


class JSCodeInjectionDetector(BaseJSDetector):
    """Detects dynamic code execution via eval(), new Function(), and string timers."""

    meta = DetectorMeta(
        id="VIGILO-JS-002",
        name="Code Injection",
        cwe=94,
        description="Dynamic code execution via eval(), new Function(), or string timers.",
        severity=Severity.HIGH,
        category="security",
        language="javascript",
    )

    TIMER_FUNCTIONS = {"setTimeout", "setInterval", "setImmediate"}

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
            # 1. Call Expressions: eval(...) and string-based setTimeout/setInterval
            if node.type == "call_expression":
                fn = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")

                if fn is not None and args is not None:
                    fn_name = ""
                    if fn.type == "identifier":
                        fn_name = get_node_text(fn, source_bytes)
                    elif fn.type == "member_expression":
                        prop = fn.child_by_field_name("property")
                        if prop:
                            fn_name = get_node_text(prop, source_bytes)

                    # eval(dynamicExpression)
                    if fn_name == "eval":
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
                                            "Use of eval() with dynamic argument enables "
                                            "arbitrary code execution."
                                        ),
                                        fix_hint=(
                                            "Avoid dynamic code evaluation; parse structured data "
                                            "with JSON.parse()."
                                        ),
                                        confidence="high",
                                    )
                                )

                    # Function(...args) without 'new' keyword
                    elif fn_name == "Function":
                        named_args = args.named_children
                        if named_args:
                            last_arg = named_args[-1]
                            if not is_literal_node(last_arg, source_bytes):
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=(
                                            "Invoking Function constructor with dynamic body "
                                            "allows arbitrary code execution."
                                        ),
                                        fix_hint=(
                                            "Use static functions or closures instead of "
                                            "dynamically constructing code."
                                        ),
                                        confidence="high",
                                    )
                                )

                    # setTimeout("code", 1000) / setInterval("code", 1000)
                    elif fn_name in self.TIMER_FUNCTIONS:
                        named_args = args.named_children
                        if named_args:
                            first_arg = named_args[0]
                            if first_arg.type in ("string", "template_string", "binary_expression"):
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=(
                                            f"Passing string expression to {fn_name}() triggers "
                                            "implicit eval()."
                                        ),
                                        fix_hint=(
                                            f"Pass a callback function reference to {fn_name}() "
                                            "instead of a string."
                                        ),
                                        confidence="medium",
                                    )
                                )

            # 2. New Expressions: new Function(...args, dynamicCode)
            elif node.type == "new_expression":
                constructor = node.child_by_field_name("constructor")
                args = node.child_by_field_name("arguments")

                if constructor is not None and args is not None:
                    c_name = get_node_text(constructor, source_bytes)
                    if c_name == "Function":
                        named_args = args.named_children
                        if named_args:
                            last_arg = named_args[-1]
                            if not is_literal_node(last_arg, source_bytes):
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=(
                                            "Constructing 'new Function()' with dynamic code body "
                                            "enables arbitrary code execution."
                                        ),
                                        fix_hint=(
                                            "Avoid dynamic code generation; use static helper "
                                            "functions and closures."
                                        ),
                                        confidence="high",
                                    )
                                )

        return findings
