"""XSS via dynamic HTML and React dangerouslySetInnerHTML detector (VIGILO-JS-001)."""

from __future__ import annotations

from pathlib import Path

import tree_sitter

from vigilo.detectors.js.base import BaseJSDetector
from vigilo.models import DetectorMeta, Finding, Severity
from vigilo.parsers.js_parser import get_node_text, is_literal_node, walk_tree


class JSXSSDetector(BaseJSDetector):
    """Detects Cross-Site Scripting via innerHTML/outerHTML and dangerouslySetInnerHTML."""

    meta = DetectorMeta(
        id="VIGILO-JS-001",
        name="Cross-Site Scripting (XSS)",
        cwe=79,
        description="Unsanitized dynamic content rendered via innerHTML or React HTML props.",
        severity=Severity.HIGH,
        category="security",
        language="javascript",
    )

    UNSAFE_DOM_PROPERTIES = {"innerHTML", "outerHTML"}
    UNSAFE_DOM_METHODS = {"write", "writeln"}
    SANITIZER_NAMES = {"sanitize", "DOMPurify", "escapeHtml", "cleanHtml"}

    def _is_sanitized(self, node: tree_sitter.Node, source_bytes: bytes) -> bool:
        """Check if an expression is wrapped in a known sanitizer call."""
        text = get_node_text(node, source_bytes)
        return any(sanitizer in text for sanitizer in self.SANITIZER_NAMES)

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
            # 1. Check Assignment Expressions: el.innerHTML = dynamicValue
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")

                if left is not None and right is not None:
                    prop_name = None
                    if left.type == "member_expression":
                        property_node = left.child_by_field_name("property")
                        if property_node:
                            prop_name = get_node_text(property_node, source_bytes)
                    elif left.type == "subscript_expression":
                        # el["innerHTML"] = ...
                        index_node = left.child_by_field_name("index")
                        if index_node:
                            prop_name = get_node_text(index_node, source_bytes).strip("'\"`")

                    if prop_name in self.UNSAFE_DOM_PROPERTIES:
                        if not is_literal_node(right, source_bytes) and not self._is_sanitized(
                            right, source_bytes
                        ):
                            msg = (
                                f"Direct assignment of dynamic unescaped content to '{prop_name}' "
                                "can lead to Cross-Site Scripting (XSS)."
                            )
                            hint = (
                                "Use textContent/innerText, or sanitize input with "
                                "DOMPurify.sanitize() before assigning."
                            )
                            findings.append(
                                self.create_finding(
                                    node=node,
                                    file_path=file_path,
                                    source_str=source_str,
                                    message=msg,
                                    fix_hint=hint,
                                    confidence="high",
                                )
                            )

            # 2. Check DOM Method Invocations: document.write(...) / insertAdjacentHTML
            elif node.type == "call_expression":
                fn = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")

                if fn is not None and args is not None:
                    fn_name = ""
                    if fn.type == "member_expression":
                        prop = fn.child_by_field_name("property")
                        if prop:
                            fn_name = get_node_text(prop, source_bytes)
                    elif fn.type == "identifier":
                        fn_name = get_node_text(fn, source_bytes)

                    # document.write(arg) / document.writeln(arg)
                    if fn_name in self.UNSAFE_DOM_METHODS:
                        named_args = args.named_children
                        if named_args and not is_literal_node(named_args[0], source_bytes):
                            if not self._is_sanitized(named_args[0], source_bytes):
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=f"Use of document.{fn_name}() enables XSS.",
                                        fix_hint=(
                                            "Avoid document.write(); use modern DOM manipulation "
                                            "with textContent or React components."
                                        ),
                                        confidence="high",
                                    )
                                )

                    # element.insertAdjacentHTML('beforeend', payload)
                    elif fn_name == "insertAdjacentHTML":
                        named_args = args.named_children
                        if len(named_args) >= 2 and not is_literal_node(
                            named_args[1], source_bytes
                        ):
                            if not self._is_sanitized(named_args[1], source_bytes):
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=(
                                            "Call to insertAdjacentHTML() with dynamic HTML string "
                                            "allows XSS injection."
                                        ),
                                        fix_hint=(
                                            "Sanitize HTML payload with DOMPurify before inserting."
                                        ),
                                        confidence="high",
                                    )
                                )

            # 3. Check React JSX / TSX: dangerouslySetInnerHTML={{ __html: payload }}
            elif node.type in ("jsx_attribute", "jsx_attribute_expression"):
                attr_name_node = node.child_by_field_name("name")
                if attr_name_node is None and node.children:
                    attr_name_node = node.children[0]
                if attr_name_node:
                    attr_name = get_node_text(attr_name_node, source_bytes)
                    if attr_name == "dangerouslySetInnerHTML":
                        value_node = node.child_by_field_name("value")
                        if value_node is None and len(node.children) > 2:
                            value_node = node.children[2]
                        if value_node is not None:
                            is_safe_literal = False
                            for sub in walk_tree(value_node):
                                if sub.type in ("pair", "property"):
                                    key = sub.child_by_field_name("key")
                                    val = sub.child_by_field_name("value")
                                    if (
                                        key
                                        and get_node_text(key, source_bytes).strip("'\"")
                                        == "__html"
                                    ):
                                        if val and is_literal_node(val, source_bytes):
                                            is_safe_literal = True
                                        break

                            if not is_safe_literal and not self._is_sanitized(
                                value_node, source_bytes
                            ):
                                msg = (
                                    "React 'dangerouslySetInnerHTML' with dynamic content can "
                                    "cause Cross-Site Scripting (XSS)."
                                )
                                hint = (
                                    "Sanitize content with DOMPurify.sanitize() or render "
                                    "React children directly instead of raw HTML."
                                )
                                findings.append(
                                    self.create_finding(
                                        node=node,
                                        file_path=file_path,
                                        source_str=source_str,
                                        message=msg,
                                        fix_hint=hint,
                                        confidence="high",
                                    )
                                )

        return findings
