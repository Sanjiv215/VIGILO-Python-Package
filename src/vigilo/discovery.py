"""File discovery and filtering utilities for Vigilo."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Sequence
from pathlib import Path

DEFAULT_EXCLUDES: tuple[str, ...] = (
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".bzr",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "env",
    ".eggs",
    "*.egg-info",
    "*.egg",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
)


def should_exclude(path: Path, exclude_patterns: Sequence[str]) -> bool:
    """Check if a path matches any exclusion pattern.

    Args:
        path: Path to check.
        exclude_patterns: List of glob patterns to match against path parts or string.

    Returns:
        True if the path should be excluded, False otherwise.
    """
    path_str = str(path)
    parts = path.parts

    for pattern in exclude_patterns:
        # Check against any component in the path (e.g. "venv", ".git")
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
        # Check against relative/full path string
        if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern):
            return True
    return False


def discover_files(
    target: Path | str,
    exclude_patterns: Sequence[str] | None = None,
    follow_symlinks: bool = False,
) -> list[Path]:
    """Discover all Python source files under target path.

    Args:
        target: A file or directory path to scan.
        exclude_patterns: Patterns to exclude (defaults to DEFAULT_EXCLUDES).
        follow_symlinks: Whether to follow symbolic links during traversal.

    Returns:
        Sorted list of resolved/normalized Python file paths.
    """
    target_path = Path(target)
    excludes = tuple(exclude_patterns) if exclude_patterns is not None else DEFAULT_EXCLUDES

    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    if target_path.is_file():
        if target_path.suffix == ".py" and not should_exclude(target_path, excludes):
            return [target_path]
        return []

    discovered: list[Path] = []

    for root, dirs, files in os.walk(target_path, followlinks=follow_symlinks):
        root_path = Path(root)

        # Filter directories in-place to avoid descending into excluded dirs
        dirs[:] = [d for d in dirs if not should_exclude(root_path / d, excludes)]

        for file_name in files:
            if file_name.endswith(".py"):
                file_path = root_path / file_name
                if not should_exclude(file_path, excludes):
                    discovered.append(file_path)

    return sorted(discovered)
