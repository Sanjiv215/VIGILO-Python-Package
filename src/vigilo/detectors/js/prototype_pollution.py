"""Prototype Pollution detector in JavaScript/TypeScript (VIGILO-JS-004)."""

from __future__ import annotations

from pathlib import Path

import tree_sitter

from vigilo.detectors.js.base import BaseJSDetector
from vigilo.models import DetectorMeta, Finding, Severity
from vigilo.parsers.js_parser import get_node_text, is_literal_node, walk_tree


class JSPrototypePollutionDetector(BaseJSDetector):
    """Detects prototype pollution vulnerabilities in JavaScript and TypeScript."""

    meta = DetectorMeta(
        id="VIGILO-JS-004",
        name="Prototype Pollution",
        cwe=1321,
        description="Unguarded modification of Object.prototype via __proto__ or unsafe merge.",
        severity=Severity.HIGH,
        category="security",
        language="javascript",
    )

    DANGEROUS_KEYS = {"__proto__", "prototype", "constructor"}

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
            # 1. Direct Assignment Expressions to __proto__ or constructor.prototype
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                if left is not None:
                    left_text = get_node_text(left, source_bytes)

                    # Direct assignment to __proto__
                    if "__proto__" in left_text:
                        findings.append(
                            self.create_finding(
                                node=node,
                                file_path=file_path,
                                source_str=source_str,
                                message=(
                                    "Direct modification of '__proto__' can pollute the global "
                                    "Object prototype."
                                ),
                                fix_hint=(
                                    "Use Object.create(null) or Map instead of modifying prototype "
                                    "chains."
                                ),
                                confidence="high",
                            )
                        )

                    # Direct assignment to constructor.prototype
                    elif (
                        "constructor.prototype" in left_text
                        or '["constructor"]["prototype"]' in left_text
                    ):
                        findings.append(
                            self.create_finding(
                                node=node,
                                file_path=file_path,
                                source_str=source_str,
                                message=(
                                    "Modifying 'constructor.prototype' directly risks prototype "
                                    "pollution."
                                ),
                                fix_hint=(
                                    "Freeze object prototypes using Object.freeze() or avoid "
                                    "modifying prototype properties."
                                ),
                                confidence="high",
                            )
                        )

                    # Dynamic nested subscript assignment: target[key][subKey] = val
                    elif left.type == "subscript_expression":
                        inner_obj = left.child_by_field_name("object")
                        index = left.child_by_field_name("index")
                        if inner_obj is not None and inner_obj.type == "subscript_expression":
                            inner_index = inner_obj.child_by_field_name("index")
                            if inner_index is not None and index is not None:
                                inner_txt = get_node_text(inner_index, source_bytes).strip()
                                index_txt = get_node_text(index, source_bytes).strip()
                                numeric_index_names = {
                                    "i",
                                    "j",
                                    "k",
                                    "x",
                                    "y",
                                    "z",
                                    "r",
                                    "c",
                                    "row",
                                    "col",
                                    "index",
                                    "idx",
                                    "offset",
                                    "pos",
                                    "step",
                                    "n",
                                    "m",
                                }
                                safe_suffixes = (
                                    "id",
                                    "_id",
                                    "date",
                                    "_date",
                                    "year",
                                    "month",
                                    "uuid",
                                )
                                is_safe_index = (
                                    inner_txt in numeric_index_names
                                    or index_txt in numeric_index_names
                                    or inner_index.type in ("number", "member_expression")
                                    or index.type in ("number", "member_expression")
                                    or inner_txt.lower().endswith(safe_suffixes)
                                    or index_txt.lower().endswith(safe_suffixes)
                                    or is_literal_node(inner_index, source_bytes)
                                    or is_literal_node(index, source_bytes)
                                )
                                if not is_safe_index:
                                    # Scope guard check to nearest function/block, not entire file
                                    scope_node = node.parent
                                    while scope_node is not None and scope_node.type not in (
                                        "function_declaration",
                                        "arrow_function",
                                        "method_definition",
                                        "function",
                                        "program",
                                    ):
                                        scope_node = scope_node.parent
                                    scope_text = (
                                        get_node_text(scope_node, source_bytes)
                                        if scope_node is not None
                                        else ""
                                    )
                                    if not any(
                                        guard in scope_text
                                        for guard in (
                                            "__proto__",
                                            "hasOwnProperty",
                                            "constructor",
                                            "Object.create(null)",
                                        )
                                    ):
                                        msg = (
                                            "Unvalidated dynamic nested property assignment allows "
                                            "prototype pollution."
                                        )
                                        hint = (
                                            "Validate keys against '__proto__', 'constructor', and "
                                            "'prototype' before assigning."
                                        )
                                        findings.append(
                                            self.create_finding(
                                                node=node,
                                                file_path=file_path,
                                                source_str=source_str,
                                                message=msg,
                                                fix_hint=hint,
                                                confidence="medium",
                                            )
                                        )

            # 2. Object.assign / Object.defineProperty on Object.prototype or __proto__
            elif node.type == "call_expression":
                fn = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")
                if fn is not None and args is not None:
                    fn_text = get_node_text(fn, source_bytes)
                    if fn_text in ("Object.assign", "Object.merge", "Object.defineProperty"):
                        named_args = args.named_children
                        if named_args:
                            first_arg_text = get_node_text(named_args[0], source_bytes)
                            if any(d in first_arg_text for d in ("Object.prototype", "__proto__")):
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=(
                                            f"Modifying prototype target in {fn_text}() causes "
                                            "global prototype pollution."
                                        ),
                                        fix_hint=(
                                            "Target a plain object created with "
                                            "Object.create(null) or a fresh object literal."
                                        ),
                                        confidence="high",
                                    )
                                )

        return findings
