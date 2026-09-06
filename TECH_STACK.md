# Tech Stack

Every runtime and dev dependency, with version constraints and justification.

---

## Runtime Dependencies

Vigilo uses Python stdlib modules for core orchestrations and `tree-sitter` native grammar bindings for multi-language AST parsing (see ADR-011).

| Module / Package | Version | Purpose | Why this, not the alternative |
|---|---|---|---|
| `tree-sitter` | `>=0.22.0,<1.0.0` | Core tree-sitter AST parser binding | High-speed C-based parser with Python bindings; no external runtime needed. |
| `tree-sitter-javascript` | `>=0.21.0,<1.0.0` | JavaScript grammar & queries | Official tree-sitter grammar for `.js`, `.mjs`, `.cjs`, `.jsx`. Precompiled wheels on all OSes. |
| `tree-sitter-typescript` | `>=0.21.0,<1.0.0` | TypeScript & TSX grammars | Official tree-sitter grammar for `.ts`, `.tsx`. Rejects Node/Babel dependency. |
| `ast` (stdlib) | — | Python source code parsing and AST traversal | Zero runtime overhead for Python analysis. |
| `argparse` (stdlib) | — | CLI argument parsing (see ADR-006) | Standard library, no external CLI dependency. |
| `pathlib` (stdlib) | — | Filesystem path handling | Cross-platform path abstraction. |
| `json` (stdlib) | — | JSON output format | Native serialization. |
| `dataclasses` (stdlib) | — | Data model (`Finding`, `Severity`, `Location`, etc.) | Clean, strongly-typed immutable records. |
| `typing` (stdlib) | — | Type annotations | Strict static type guarantees. |
| `re` (stdlib) | — | Pattern matching / secrets detection | Standard library regex. |
| `os` (stdlib) | — | Filesystem operations, environment | Cross-platform system calls. |
| `sys` (stdlib) | — | Exit codes, stderr | Standard stream handling. |
| `textwrap` (stdlib) | — | Output formatting | Terminal text alignment. |

### Rejected Runtime Alternatives
- **Node.js + Babel / TypeScript CLI**: Rejected because requiring Node.js on the host breaks Vigilo's standalone binary and zero-external-runtime guarantee.
- **Pure-Python JS Parsers (`esprima`, `pyjsparser`)**: Rejected because they are abandoned and fail on modern TypeScript, JSX, and TSX syntax.

---


## Dev Dependencies

| Dependency | Version | Purpose | Why this, not the alternative |
|---|---|---|---|
| `pytest` | `>=7.0,<10.0` | Test runner | Industry standard for Python. `unittest` is stdlib but verbose and less ergonomic. |
| `mypy` | `>=1.0,<2.0` | Static type checker | Strictest type checking for Python. `pyright` is faster but `mypy` has broader ecosystem integration. |
| `ruff` | `>=0.4,<1.0` | Linter + formatter | Replaces `flake8` + `black` + `isort` in a single Rust-based tool. Orders of magnitude faster. |
| `coverage` | `>=7.0,<8.0` | Test coverage measurement | Standard; integrates with pytest via `pytest-cov`. |
| `pytest-cov` | `>=4.0,<7.0` | Coverage plugin for pytest | Convenience wrapper around `coverage` for pytest integration. |
| `bandit` | `>=1.7,<2.0` | SAST cross-check | Security linter for Python codebases. |
| `pip-audit` | `>=2.7,<3.0` | Dependency vulnerability auditing | Official PyPA advisory database scanner. |
| `hypothesis` | `>=6.0,<7.0` | Property-based fuzzing | Generates adversarial and boundary test cases for AST parsers. |

### Version Pinning Strategy
- **Runtime Dependencies:** Strictly zero runtime dependencies (only standard library).
- **Dev Dependencies:** Bounded major version pins (`>=X.Y,<(X+1).0`) to guard against unexpected API breakages and supply chain alterations while permitting security and patch updates.

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
