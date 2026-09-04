# Tech Stack

Every runtime and dev dependency, with version constraints and justification.

---

## Runtime Dependencies

**None.** OJO uses only Python stdlib modules (see ADR-005).

| stdlib Module | Purpose |
|---|---|
| `ast` | Python source code parsing and AST traversal |
| `argparse` | CLI argument parsing (see ADR-006) |
| `pathlib` | Filesystem path handling |
| `json` | JSON output format |
| `dataclasses` | Data model (Finding, Severity, etc.) |
| `typing` | Type annotations |
| `re` | Pattern matching in detectors |
| `os` | Filesystem operations, environment |
| `sys` | Exit codes, stderr |
| `textwrap` | Output formatting |

---

## Dev Dependencies

| Dependency | Version | Purpose | Why this, not the alternative |
|---|---|---|---|
| `pytest` | `>=7.0` | Test runner | Industry standard for Python. `unittest` is stdlib but verbose and less ergonomic. |
| `mypy` | `>=1.0` | Static type checker | Strictest type checking for Python. `pyright` is faster but `mypy` has broader ecosystem integration and plugin support. |
| `ruff` | `>=0.4` | Linter + formatter | Replaces `flake8` + `black` + `isort` in a single Rust-based tool. Orders of magnitude faster. |
| `coverage` | `>=7.0` | Test coverage measurement | Standard; integrates with pytest via `pytest-cov`. |
| `pytest-cov` | `>=4.0` | Coverage plugin for pytest | Convenience wrapper around `coverage` for pytest integration. |

---

## Packaging & Build

| Tool | Purpose | Why this, not the alternative |
|---|---|---|
| `hatchling` | Build backend | Modern, fast, PEP 621 native. `setuptools` works but `hatchling` is simpler for pure-Python packages with `src/` layout. `flit` is simpler but less flexible for entry points. |
| `build` | Build frontend | PyPA standard (`python -m build`). |
| `twine` | Package upload verification | `twine check` validates dist before upload. |

---

## CI Platform

| Platform | Purpose | Why this, not the alternative |
|---|---|---|
| GitHub Actions | CI/CD | Repo is on GitHub. Native integration, free for public repos, supports matrix builds and Trusted Publishing to PyPI. |

---

## Python Version

| Constraint | Value | Rationale |
|---|---|---|
| Floor | 3.10 | `match`/`case`, `X \| Y` unions (see ADR-004) |
| CI matrix | 3.10, 3.11, 3.12, 3.13 | Cover all actively supported Python versions |
