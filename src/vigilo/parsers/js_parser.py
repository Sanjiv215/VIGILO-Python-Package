"""Tree-sitter parser wrapper and AST utilities for JavaScript and TypeScript."""

from __future__ import annotations

from pathlib import Path

import tree_sitter
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts

from vigilo.models import Location

# Lazy language objects
_JS_LANG: tree_sitter.Language | None = None
_TS_LANG: tree_sitter.Language | None = None
_TSX_LANG: tree_sitter.Language | None = None


def get_javascript_language() -> tree_sitter.Language:
    """Return initialized JavaScript tree-sitter Language."""
    global _JS_LANG
    if _JS_LANG is None:
        _JS_LANG = tree_sitter.Language(tsjs.language())
    return _JS_LANG


def get_typescript_language() -> tree_sitter.Language:
    """Return initialized TypeScript tree-sitter Language."""
    global _TS_LANG
    if _TS_LANG is None:
        _TS_LANG = tree_sitter.Language(tsts.language_typescript())
    return _TS_LANG


def get_tsx_language() -> tree_sitter.Language:
    """Return initialized TSX tree-sitter Language."""
    global _TSX_LANG
    if _TSX_LANG is None:
        _TSX_LANG = tree_sitter.Language(tsts.language_tsx())
    return _TSX_LANG


def select_language_for_file(file_path: Path | str) -> tree_sitter.Language:
    """Select the appropriate tree-sitter language grammar based on file extension."""
    path = Path(file_path)
    suffix = path.suffix.lower()

    if suffix in (".tsx", ".jsx"):
        return get_tsx_language()
    if suffix == ".ts":
        return get_typescript_language()
    return get_javascript_language()


def parse_js_ts(
    source: str | bytes,
    file_path: Path,
) -> tuple[tree_sitter.Tree | None, str, bytes, str | None]:
    """Parse a JavaScript or TypeScript file into a tree-sitter syntax tree.

    Args:
        source: Source code string or bytes.
        file_path: Path to the target file (used to select grammar).

    Returns:
        Tuple of (Tree or None, source_str, source_bytes, error_message or None).
    """
    if isinstance(source, str):
        source_str = source
        source_bytes = source.encode("utf-8")
    else:
        source_bytes = source
        try:
            source_str = source.decode("utf-8")
        except UnicodeDecodeError:
            source_str = source.decode("latin-1", errors="replace")

    try:
        lang = select_language_for_file(file_path)
        parser = tree_sitter.Parser(lang)
        tree = parser.parse(source_bytes)
        return tree, source_str, source_bytes, None
    except Exception as e:
        return None, source_str, source_bytes, f"Failed to parse JS/TS syntax tree: {e}"


def get_node_text(node: tree_sitter.Node, source_bytes: bytes) -> str:
    """Extract and decode the raw text of a tree-sitter node."""
    raw = source_bytes[node.start_byte : node.end_byte]
    return raw.decode("utf-8", errors="replace")


def get_location(node: tree_sitter.Node, file_path: Path) -> Location:
    """Convert tree-sitter node start/end points into a Vigilo Location object."""
    return Location(
        file=file_path,
        line=node.start_point.row + 1,
        col=node.start_point.column + 1,
        end_line=node.end_point.row + 1,
        end_col=node.end_point.column + 1,
    )


def is_literal_node(node: tree_sitter.Node, source_bytes: bytes) -> bool:
    """Check if an AST node is an immutable literal value."""
    node_type = node.type

    # Primitive literals
    if node_type in (
        "string",
        "number",
        "true",
        "false",
        "null",
        "undefined",
        "regex",
        "string_fragment",
    ):
        return True

    # Template literal without variable interpolation (no template_substitution)
    if node_type == "template_string":
        for child in node.children:
            if child.type in ("template_substitution", "substitution"):
                return False
        return True

    # Binary expressions of pure literals (e.g. "a" + "b")
    if node_type == "binary_expression":
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is not None and right is not None:
            return is_literal_node(left, source_bytes) and is_literal_node(right, source_bytes)

    # Parenthesized expressions (e.g. ("hello"))
    if node_type == "parenthesized_expression":
        for child in node.named_children:
            return is_literal_node(child, source_bytes)

    return False


def walk_tree(root: tree_sitter.Node) -> list[tree_sitter.Node]:
    """Recursively traverse all nodes in a syntax tree."""
    nodes: list[tree_sitter.Node] = []
    stack = [root]
    while stack:
        curr = stack.pop()
        nodes.append(curr)
        for child in reversed(curr.children):
            stack.append(child)
    return nodes
