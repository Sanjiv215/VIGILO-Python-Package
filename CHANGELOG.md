# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.2] - 2026-09-05

### Security & Hardening (20-Technique Audit)
- **Terminal Escape Injection Mitigation (CWE-150):**
  - Added `sanitize_terminal_text()` in `src/vigilo/reporter.py` to sanitize ANSI escape codes and dangerous non-printable control characters from user source snippets, file paths, and messages before CLI rendering.
- **Symlink Loop & Special Device Protection:**
  - Added inode cycle detection (`visited_dirs`) in `discover_files()` to prevent infinite loops during symlink traversal, correctly skip non-regular files (`/dev/null`, fifos, character devices), and enforce non-traversal when `follow_symlinks=False`.
- **Compiler Directive & Scope Hardening:**
  - `UnusedCodeDetector` now ignores `from __future__ import ...` compiler directives.
  - `ScopeVisitor` pre-populates module top-level function/class symbols and supports `ast.Lambda` arguments to avoid false-positive undefined name warnings on lambdas and module forward references.
- **Bounded Dev Dependency Pins:**
  - Pinned upper bounds on dev dependencies in `pyproject.toml` to guard against supply chain vulnerabilities.
- **Continuous Security Integration:**
  - Added CodeQL automated SAST workflow (`.github/workflows/codeql.yml`).
  - Added property-based fuzz test suite (`tests/test_fuzz.py`) using `hypothesis`.
  - Wired `mypy --strict`, expanded `ruff`, `bandit`, and `pip-audit` into CI gates.

---

## [0.2.1] - 2026-09-05

### Fixed
- **Pipeline Wiring & Default Invocation:**
  - Correctness diagnostics are now executed by default in `vigilo scan` and `vigilo.scan()` without requiring explicit opt-in flags, ensuring syntax errors, indentation errors, and typos like `PRint(...)` are immediately surfaced. Added `--security-only` (`-S`) flag to allow running only security detectors when desired.
- **Unused Local Variables (VIGILO-C03):**
  - Implemented missing unused local variable detection inside functions (previously only unused imports were checked).
- **Undefined Name Scope Resolution (VIGILO-C02):**
  - Added `visit_ExceptHandler` and pattern matching visitor methods (`MatchAs`, `MatchStar`, `MatchMapping`) to `ScopeVisitor` to prevent false positives on exception bindings (e.g. `except Exception as e:`).
- **Indentation Error Messaging (VIGILO-C01):**
  - Differentiated `IndentationError` and `TabError` with specific messages and fix hints rather than generic syntax error text.
- **Permanent Fixtures:**
  - Added comprehensive fixture test suite in `tests/fixtures/diagnostics/` covering all 6 diagnostic and security categories.

---

## [0.2.0] - 2026-09-05

### Added
- **Code Correctness Diagnostics (Opt-In):**
  - Added `--correctness` / `-c` flag to `vigilo scan` and dedicated `vigilo diagnose` subcommand.
  - Default `vigilo scan .` remains strictly security-focused (zero false alarms from style/formatting).
- **Correctness Detectors:**
  - `VIGILO-C01`: Syntax & Indentation Error detector (captures parse failures and bad indentation).
  - `VIGILO-C02`: Undefined Name Usage detector (catches variable/function typos and unbound names).
  - `VIGILO-C03`: Unused Import / Variable detector (flags dead imports and assigned but unused local variables).
  - `VIGILO-C04`: Unclosed File Resource detector (identifies raw `open()` calls without `with` context management).
  - `VIGILO-C05`: Bare `except:` Clause detector (flags blanket exception catching that masks errors).
- **API & Reporting Enhancements:**
  - Added `category` field (`"security"` | `"correctness"`) to `DetectorMeta` and `Finding`.
  - Added `include_correctness` and `categories` parameters to `vigilo.scan()` and `ScanConfig`.
  - Enhanced text reporter with category headers when multiple categories are scanned.

---

## [0.1.1] - 2026-09-05

### Fixed
- Fixed ruff per-file-ignore glob not matching nested test paths, causing false lint failures on Ubuntu/macOS CI runners.
- Fixed `Sequence` import from `collections.abc` and sorted imports across test suite.
- Gated release pipeline to require 100% success of the full cross-platform test matrix before building or publishing packages.

---

## [0.1.0] - 2026-09-05

### Added
- **Core Engine:**
  - Fast AST parsing and safe file discovery with default exclude rules.
  - `FlowAnalyzer` providing local scope tracking, constant evaluation, and parameter taint discrimination.
  - Extensible `BaseDetector` architecture.
- **Vulnerability Detectors:**
  - `VIGILO-001` (CWE-89): SQL Injection detector for raw, formatted, and unparameterized SQL queries.
  - `VIGILO-002` (CWE-78): OS Command Injection detector for `subprocess.*(shell=True)` and `os.system`/`os.popen`.
  - `VIGILO-003` (CWE-94): Code Injection detector for `eval()`, `exec()`, and `compile()`.
  - `VIGILO-004` (CWE-502): Unsafe Deserialization detector for `pickle`, `marshal`, and unsafe `yaml.load()`.
  - `VIGILO-005` (CWE-22): Path Traversal detector for dynamic file opening and filesystem access.
- **Command-Line Interface:**
  - `vigilo scan <path>` and `vigilo <path>` alias commands.
  - ANSI colored text output report with line markers, confidence tags, and fix guidance.
  - Structured `--format json` output option for CI/CD integrations.
  - Severity threshold filtering (`--min-severity`).
  - Glob exclusion flags (`--exclude`).
  - Standard exit codes (0 = clean, 1 = vulnerabilities found, 2 = error).
- **Public Python API:**
  - `vigilo.scan(path, min_severity, exclude_patterns)` convenience function.
  - Re-exported data models: `Scanner`, `ScanConfig`, `Finding`, `Severity`, `Location`, `DetectorMeta`.
