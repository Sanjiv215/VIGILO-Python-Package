# Decisions Log

Lightweight Architecture Decision Records (ADRs) for OJO.

---

## ADR-001: Package Name

**Date:** 2026-09-04
**Context:** Need a unique, available name for PyPI distribution, Python import, and CLI command. The bare name `ojo` is taken on PyPI (a dead placeholder package, v0.1.0, from the "setup.py for humans" template project).
**Options considered:**
1. `ojo` on PyPI — blocked; would require PEP 541 name claim (slow, uncertain).
2. `ojo-scan` on PyPI — available, descriptive ("scan" communicates purpose at install time), allows `ojo` as import name and CLI command.
3. `ojo-cli` on PyPI — available, but "cli" is less descriptive of what the tool does.
**Decision:** Use `ojo-scan` as the PyPI distribution name. Import name is `ojo`, CLI command is `ojo`.
**Consequences:** Users run `pip install ojo-scan` but `import ojo` and `ojo scan .`. The slight name mismatch between install and import is a common Python pattern (e.g., `Pillow` → `import PIL`).

---

## ADR-002: Domain Positioning

**Date:** 2026-09-04
**Context:** The Python security tooling ecosystem has multiple categories: general linters (Ruff, Pylint), security linters (Bandit), SCA/dependency scanners (pip-audit, Grype, Trivy), deep SAST engines (CodeQL, Pysa, Semgrep Pro), and repo auditors (aletheore).
**Options considered:**
1. General-purpose linter with security rules — crowded space (Ruff is dominant), no differentiation.
2. SCA / dependency scanner — already well-served by pip-audit (open, free, PyPA-backed).
3. Security-focused code scanner targeting CWE patterns in first-party code — underserved gap between Bandit's noise and CodeQL's complexity.
**Decision:** OJO is a security vulnerability scanner that detects known CWE patterns in first-party Python code. Not a general linter, not an SCA tool, not a secrets scanner.
**Consequences:** Complementary to (not competing with) pip-audit, Ruff, and Gitleaks. Clear messaging: "OJO scans your code, pip-audit scans your dependencies."

---

## ADR-003: Detection Approach

**Date:** 2026-09-04
**Context:** Security scanners range from pure AST pattern matching (fast, noisy) to full inter-procedural taint analysis (precise, slow/complex). Bandit's high false-positive rate stems from having zero data flow awareness.
**Options considered:**
1. Pure AST pattern matching (like Bandit) — fast but noisy; doesn't solve the core problem.
2. Lightweight local data flow (constant vs. dynamic input discrimination, intra-function + one-hop tracking) — meaningfully reduces false positives without the complexity of a full taint engine.
3. Full inter-procedural taint analysis (like CodeQL/Pysa) — most precise but requires call graph construction, type inference infrastructure, and complex model files.
**Decision:** MVP uses AST parsing + lightweight local data flow. The scanner can distinguish between a string literal passed to `eval()` (suppress) and a variable derived from user input passed to `eval()` (flag). Cross-file taint analysis is a post-MVP goal (v0.2.0).
**Consequences:** OJO will have meaningfully fewer false positives than Bandit without requiring any setup. Some true positives that require cross-function analysis will be missed in v0.1.0 — this is an acceptable tradeoff for shipping a useful tool quickly.

---

## ADR-004: Python Version Floor

**Date:** 2026-09-04
**Context:** Need to balance access to modern language features against user compatibility.
**Options considered:**
1. Python 3.10 — `match`/`case` (useful for AST node dispatch), `X | Y` union type syntax, broad CI availability.
2. Python 3.11 — adds `tomllib` (useful for `pyproject.toml` config), `ExceptionGroup`, better error messages.
3. Python 3.12 — adds `type` statement, better generics, but cuts off more users.
**Decision:** Python 3.10 as the floor. If `pyproject.toml`-based configuration is added post-MVP, we'll vendor or conditionally import `tomllib` (backport: `tomli`) rather than bumping the floor.
**Consequences:** Broad compatibility. `match`/`case` available for detector dispatch logic.

---

## ADR-005: Dependency Policy

**Date:** 2026-09-04
**Context:** A security tool should minimize its own attack surface and install friction.
**Options considered:**
1. Zero runtime dependencies (stdlib only) — smallest attack surface, fastest install, but limits functionality to what stdlib provides.
2. Minimal curated dependencies (e.g., `rich` for output, `click` for CLI) — nicer UX but adds supply chain surface and install weight.
**Decision:** Zero runtime dependencies for MVP. OJO uses only stdlib modules (`ast`, `argparse`, `pathlib`, `json`, `dataclasses`, `typing`, `re`, `os`). Dev dependencies (pytest, mypy, ruff) are justified individually in TECH_STACK.md.
**Consequences:** `pip install ojo-scan` installs exactly one package. No transitive dependency risk. Output formatting is simpler than `rich` but adequate.

---

## ADR-006: CLI Framework

**Date:** 2026-09-04
**Context:** OJO is CLI-first. Need a framework for argument parsing and subcommands.
**Options considered:**
1. `argparse` (stdlib) — zero dependencies, well-understood, sufficient for OJO's simple command structure (`ojo scan <path>`), built-in help generation.
2. `click` — popular, decorator-based, but adds a runtime dependency (contradicts ADR-005).
3. `typer` — modern, type-hint-based, but depends on `click` + `typing-extensions` (two transitive deps).
**Decision:** `argparse` from stdlib. OJO's CLI surface is small enough that `argparse` handles it cleanly.
**Consequences:** No external dependency for CLI. Help text and error messages are functional but less polished than Click/Typer — acceptable for a security tool where correctness matters more than CLI aesthetics.
