# Workflow Log

Stage-by-stage build log for OJO.

---

## Stage 1 — Setup & GitHub Repo Initialization

**Date:** 2026-09-04
**Decisions made:**
- Package name: `ojo-scan` (PyPI), `ojo` (import + CLI)
- License: None (trial/dev phase — must add before Stage 9)
- Python floor: 3.10
- Repo: public, trunk-based on `main`
- Primary interface: CLI-first

**What was created:**
- GitHub repo: [Sanjiv215/OJO-Python-Package](https://github.com/Sanjiv215/OJO-Python-Package)
- `README.md` — one-line stub
- `.gitignore` — Python-specific

**Commit:** `9d246cd` — `chore: initial commit — README stub, .gitignore`

---

## Stage 2 — Product Definition

**Date:** 2026-09-04
**Decisions made:**
- Domain: security-focused code scanner (CWE patterns in first-party Python code)
- Detection: AST + lightweight local data flow (not full taint analysis in MVP)
- 5 initial detectors: SQL injection (CWE-89), OS command injection (CWE-78), code injection (CWE-94), unsafe deserialization (CWE-502), path traversal (CWE-22)
- Zero runtime dependencies (stdlib only)
- CLI framework: `argparse` (stdlib)
- Competitive positioning: between Bandit (noisy AST linter) and CodeQL (heavy deep SAST)

**What was created:**
- `DECISIONS.md` — ADR-001 through ADR-006
- `WORKFLOW.md` — this file
- `TIMELINE.md` — initialized
- `TECH_STACK.md` — initial skeleton

**Prior art cited:** Bandit, Semgrep, CodeQL, Pysa, Grype, Trivy, Safety, pip-audit, Bearer, Snyk Code, SonarQube, aletheore

**Commit:** _(pending)_

---

## Stage 3 — Architecture & Data Model
_(pending)_

## Stage 4 — Repository Scaffolding
_(pending)_

## Stage 5 — Core Engine Implementation
_(pending)_

## Stage 6 — Extension System + First Features
_(pending)_

## Stage 7 — Public API & CLI
_(pending)_

## Stage 8 — Testing & Real-World Validation
_(pending)_

## Stage 9 — Documentation & GitHub Community Files
_(pending)_

## Stage 10 — CI/CD, Packaging & Release
_(pending)_
