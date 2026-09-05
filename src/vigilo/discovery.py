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
    visited_dirs: set[tuple[int, int]] = set()

    # Track root directory inode to avoid cyclic descent
    try:
        root_stat = target_path.stat()
        visited_dirs.add((root_stat.st_dev, root_stat.st_ino))
    except OSError:
        pass

    for root, dirs, files in os.walk(target_path, followlinks=follow_symlinks):
        root_path = Path(root)

        # Prevent symlink directory loops when followlinks=True
        if follow_symlinks:
            pruned_dirs: list[str] = []
            for d in dirs:
                dir_path = root_path / d
                if should_exclude(dir_path, excludes):
                    continue
                try:
                    st = dir_path.stat()
                    key = (st.st_dev, st.st_ino)
                    if key in visited_dirs:
                        continue  # Cycle detected, skip
                    visited_dirs.add(key)
                    pruned_dirs.append(d)
                except OSError:
                    continue
            dirs[:] = pruned_dirs
        else:
            dirs[:] = [d for d in dirs if not should_exclude(root_path / d, excludes)]

        for file_name in files:
            if file_name.endswith(".py"):
                file_path = root_path / file_name
                # If follow_symlinks is False, do not follow file symlinks
                if not follow_symlinks and file_path.is_symlink():
                    continue
                if not should_exclude(file_path, excludes):
                    try:
                        # Ensure it is a regular file (not a fifo/device)
                        if file_path.is_file():
                            discovered.append(file_path)
                    except OSError:
                        continue

    return sorted(discovered)
