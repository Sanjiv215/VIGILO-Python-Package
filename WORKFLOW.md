# Vigilo Development Workflow & Stage Log

This document tracks stage-by-stage development progress, validation criteria, and release gates.

---

## 1. Historical Stages Summary

> **Note on Early Stages:** Early development stages (Stage 1 through Stage 6: MVP, Initial Detectors, CI/CD, Correctness Diagnostics, and Security Audits) were implemented and released across v0.1.0–v0.2.2. However, internal tracking documents were previously excluded from version control via `.gitignore`. Going forward from v0.3.0, all architectural decisions, dependency changes, and stage completions are tracked as living documents directly in the repository.

| Stage | Focus Area | Delivered Capabilities | Validation Method |
|---|---|---|---|
| **Stage 1–3** | Core Security Engine | Python AST parser, data flow analysis, 5 security detectors (`VIGILO-001` to `VIGILO-005`), CLI interface. | Unit tests, mock injection payloads. |
| **Stage 4** | CI/CD & Cross-Platform | 12-job CI matrix (Ubuntu, macOS, Windows × Python 3.10–3.13), PyInstaller binary automation. | GitHub Actions matrix runs, SHA256 checksums. |
| **Stage 5** | Rebranding & Release Gating | Rebranded to `vigilo` (PyPI package & CLI), fixed CI glob syntax, enforced matrix testing before PyPI release. | Yanked v0.1.0, published v0.1.1. |
| **Stage 6** | Code Correctness Diagnostics | Added syntax error, undefined name, unused code, unclosed resource, and bare except detectors (`VIGILO-C01` to `VIGILO-C05`). | Standalone broken fixtures, false-positive verification. |
| **Stage 7** | Codebase Security Audit | 20-technique audit: `mypy --strict`, ANSI injection sanitization, symlink loop protection, property fuzzing. | 100% mutation test kill, 87% coverage. |
| **Stage 8** | Lifecycle Stress Testing | 2,000x install/uninstall idempotent package lifecycle verification on local wheel and live PyPI. | 2,005/2,005 passes, 0 leaked bytes. |
| **Stage 9** | JavaScript & TypeScript Support | Tree-sitter multi-language integration, 5 JS/TS/React detectors (`VIGILO-JS-001` to `VIGILO-JS-005`), standalone binary support. | 86/86 tests passed, 0% false positives on clean fixtures. |
| **Stage 10** | JS/TS Syntax Error & Reporter Fixes | Surfaced unparseable JS/TS files as `VIGILO-C01`, resolved reporter spacing bugs, standardized rule names. | 88/88 tests passed, 89% statement coverage. |

---

## 2. Active Development & Stage Gates (v0.3.0+)

For every new stage, feature, or detector added:
1. **Architecture & Design Review**: Evaluate alternatives (e.g. runtime vs embedded), log decision in `DECISIONS.md`.
2. **Dependency Justification**: Record any new dependencies with bounded version pins in `pyproject.toml` and `TECH_STACK.md`.
3. **Independent Test Fixtures**: Write both vulnerable and clean fixture files. Run false-positive rate measurements.
4. **Static Quality Verification**: Ensure `mypy --strict src tests`, `ruff check`, `ruff format --check`, and `bandit` all pass with zero errors.
5. **CI Matrix & Standalone Binary Verification**: Confirm the 12-job cross-platform CI matrix passes and PyInstaller standalone binaries build and run properly.
6. **Documentation Sync**: Update `README.md`, `ROADMAP.md`, `TIMELINE.md`, `WORKFLOW.md`, and `CHANGELOG.md` in the same commit.
