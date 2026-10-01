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
        valid_suffixes = (".js", ".mjs", ".cjs", ".ts")
        if tree.root_node.has_error and Path(file_path).suffix.lower() in valid_suffixes:
            tsx_parser = tree_sitter.Parser(get_tsx_language())
            tsx_tree = tsx_parser.parse(source_bytes)
            if not tsx_tree.root_node.has_error:
                return tsx_tree, source_str, source_bytes, None
        return tree, source_str, source_bytes, None
    except Exception as e:
        return None, source_str, source_bytes, f"Failed to parse JS/TS syntax tree: {e}"


def get_node_text(node: tree_sitter.Node, source_bytes: bytes) -> str:
    """Extract and decode the raw text of a tree-sitter node."""
    raw = source_bytes[node.start_byte : node.end_byte]
    return raw.decode("utf-8", errors="replace")


def get_location(
    node: tree_sitter.Node,
    file_path: Path,
    source_bytes: bytes | str | None = None,
) -> Location:
    """Convert tree-sitter node start/end points into a Vigilo Location object."""
    if source_bytes is not None:
        try:
            raw = source_bytes if isinstance(source_bytes, bytes) else source_bytes.encode("utf-8")
            start_byte = node.start_byte
            prefix = raw[:start_byte]
            line = prefix.count(b"\n") + 1
            last_nl = prefix.rfind(b"\n")
            col = (start_byte - last_nl) if last_nl != -1 else (start_byte + 1)

            end_byte = node.end_byte
            end_prefix = raw[:end_byte]
            end_line = end_prefix.count(b"\n") + 1
            end_last_nl = end_prefix.rfind(b"\n")
            end_col = (end_byte - end_last_nl) if end_last_nl != -1 else (end_byte + 1)

            return Location(
                file=file_path,
                line=line,
                col=col,
                end_line=end_line,
                end_col=end_col,
            )
        except Exception:  # noqa: S110
            pass

    try:
        return Location(
            file=file_path,
            line=node.start_point.row + 1,
            col=node.start_point.column + 1,
            end_line=node.end_point.row + 1,
            end_col=node.end_point.column + 1,
        )
    except Exception:
        return Location(
            file=file_path,
            line=1,
            col=1,
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


def walk_tree(root: tree_sitter.Node, skip_errors: bool = True) -> list[tree_sitter.Node]:
    """Recursively traverse all nodes in a syntax tree."""
    nodes: list[tree_sitter.Node] = []
    stack = [root]
    while stack:
        curr = stack.pop()
        nodes.append(curr)
        if skip_errors and (curr.type == "ERROR" or curr.is_missing):
            continue
        try:
            for child in reversed(curr.children):
                stack.append(child)
        except Exception:  # noqa: S112
            continue
    return nodes


def find_first_syntax_error(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
) -> tuple[int, int, str] | None:
    """Safely locate the first syntax error without allocating unnecessary node lists.

    Returns:
        (line, col, snippet) or None if no syntax error found.
    """
    if not tree.root_node.has_error:
        return None

    cursor = tree.walk()
    try:
        while True:
            node = cursor.node
            if node is not None and (node.type == "ERROR" or node.is_missing):
                parent = node.parent
                raw = source_bytes[node.start_byte : node.end_byte]
                # Tree-sitter JSX grammar expects XML entity references for ampersands,
                # but bare ampersands in JSX text (e.g. <p>Terms & Conditions</p>) are valid
                # React JSX. Skip bare ampersands inside JSX elements to avoid false positives.
                if (
                    parent is not None
                    and parent.type in ("jsx_element", "jsx_fragment")
                    and raw.strip().startswith(b"&")
                ):
                    pass
                else:
                    start_byte = node.start_byte
                    prefix = source_bytes[:start_byte]
                    line = prefix.count(b"\n") + 1
                    last_nl = prefix.rfind(b"\n")
                    col = (start_byte - last_nl) if last_nl != -1 else (start_byte + 1)
                    snippet = raw.decode("utf-8", errors="replace").strip()
                    return line, col, snippet

            if cursor.goto_first_child():
                continue
            if cursor.goto_next_sibling():
                continue

            retracing = True
            while retracing:
                if not cursor.goto_parent():
                    return None
                if cursor.goto_next_sibling():
                    retracing = False
    finally:
        del cursor
