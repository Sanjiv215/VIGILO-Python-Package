# Decisions Log

Lightweight Architecture Decision Records (ADRs) for Vigilo.

---

## ADR-001: Package Name

**Date:** 2026-09-05
**Context:** Need a unique, available name for PyPI distribution, Python import, CLI command, and GitHub repository.
**Options considered:**
1. `ojo` / `ojo-scan` — `ojo` was taken on PyPI; `ojo-scan` had install/import mismatch.
2. `vigilo` on PyPI and GitHub — 100% available, Latin for "to watch / guard / stay vigilant", short, memorable, perfect alignment across PyPI package name (`vigilo`), Python import (`import vigilo`), and CLI (`vigilo scan .`).
**Decision:** Rebrand to `vigilo` for PyPI package distribution, Python import, CLI binary, and GitHub repository `Sanjiv215/VIGILO-Python-Package`.
**Consequences:** Seamless user experience with `pip install vigilo`, `import vigilo`, and `vigilo scan .`.

---

## ADR-002: Domain Positioning

**Date:** 2026-09-04
**Context:** The Python security tooling ecosystem has multiple categories: general linters (Ruff, Pylint), security linters (Bandit), SCA/dependency scanners (pip-audit, Grype, Trivy), deep SAST engines (CodeQL, Pysa, Semgrep Pro), and repo auditors (aletheore).
**Options considered:**
1. General-purpose linter with security rules — crowded space (Ruff is dominant), no differentiation.
2. SCA / dependency scanner — already well-served by pip-audit (open, free, PyPA-backed).
3. Security-focused code scanner targeting CWE patterns in first-party code — underserved gap between Bandit's noise and CodeQL's complexity.
**Decision:** Vigilo is a security vulnerability scanner that detects known CWE patterns in first-party Python code. Not a general linter, not an SCA tool, not a secrets scanner.
**Consequences:** Complementary to (not competing with) pip-audit, Ruff, and Gitleaks. Clear messaging: "Vigilo scans your code, pip-audit scans your dependencies."

---

## ADR-003: Detection Approach

**Date:** 2026-09-04
**Context:** Security scanners range from pure AST pattern matching (fast, noisy) to full inter-procedural taint analysis (precise, slow/complex). Bandit's high false-positive rate stems from having zero data flow awareness.
**Options considered:**
1. Pure AST pattern matching (like Bandit) — fast but noisy; doesn't solve the core problem.
2. Lightweight local data flow (constant vs. dynamic input discrimination, intra-function + one-hop tracking) — meaningfully reduces false positives without the complexity of a full taint engine.
3. Full inter-procedural taint analysis (like CodeQL/Pysa) — most precise but requires call graph construction, type inference infrastructure, and complex model files.
**Decision:** MVP uses AST parsing + lightweight local data flow. The scanner can distinguish between a string literal passed to `eval()` (suppress) and a variable derived from user input passed to `eval()` (flag). Cross-file taint analysis is a post-MVP goal (v0.2.0).
**Consequences:** Vigilo will have meaningfully fewer false positives than Bandit without requiring any setup. Some true positives that require cross-function analysis will be missed in v0.1.0 — this is an acceptable tradeoff for shipping a useful tool quickly.

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
**Decision:** Zero runtime dependencies for MVP. Vigilo uses only stdlib modules (`ast`, `argparse`, `pathlib`, `json`, `dataclasses`, `typing`, `re`, `os`). Dev dependencies (pytest, mypy, ruff) are justified individually in TECH_STACK.md.
**Consequences:** `pip install vigilo` installs exactly one package. No transitive dependency risk. Output formatting is simpler than `rich` but adequate.

---

## ADR-006: CLI Framework

**Date:** 2026-09-04
**Context:** Vigilo is CLI-first. Need a framework for argument parsing and subcommands.
**Options considered:**
1. `argparse` (stdlib) — zero dependencies, well-understood, sufficient for Vigilo's simple command structure (`vigilo scan <path>`), built-in help generation.
2. `click` — popular, decorator-based, but adds a runtime dependency (contradicts ADR-005).
3. `typer` — modern, type-hint-based, but depends on `click` + `typing-extensions` (two transitive deps).
**Decision:** `argparse` from stdlib. Vigilo's CLI surface is small enough that `argparse` handles it cleanly.
**Consequences:** No external dependency for CLI. Help text and error messages are functional but less polished than Click/Typer — acceptable for a security tool where correctness matters more than CLI aesthetics.

---

## ADR-007: Confidence Display

**Date:** 2026-09-04
**Context:** The `Finding` model includes a `confidence` field ("high", "medium", "low"). Need to decide whether to show it in output.
**Options considered:**
1. Show in JSON only, keep text output clean.
2. Show in both text and JSON output.
**Decision:** Show confidence in both text and JSON output. Users should see confidence levels regardless of output format.
**Consequences:** Text output is slightly more verbose but more informative.

---

## ADR-008: CLI Alias

**Date:** 2026-09-04
**Context:** The canonical CLI form is `vigilo scan <path>`. Should `vigilo <path>` work as a shortcut?
**Options considered:**
1. Require `vigilo scan <path>` always — explicit, but verbose for the most common operation.
2. Allow `vigilo <path>` as alias for `vigilo scan <path>` — ergonomic, follows `ruff .` / `bandit -r .` patterns.
**Decision:** `vigilo .` works as an alias for `vigilo scan .`. The `scan` subcommand remains canonical, leaving room for future subcommands (`vigilo list-rules`, etc.).
**Consequences:** Slightly more complex argparse setup, but better ergonomics for the primary use case.

---

## ADR-009: Code Correctness Diagnostics & Unified Pipeline

**Date:** 2026-09-05
**Context:** In v0.2.0+, Vigilo introduces code correctness diagnostics (syntax/indentation errors, undefined variable usage, unclosed file resources, bare except clauses) in addition to CWE security vulnerability detectors.
**Options considered:**
1. Default to security-only and require `--correctness` — caused silent 0-findings when scanning broken files without flags.
2. Unified scan by default (`vigilo scan` runs security + correctness) with `--security-only` flag to isolate security checks.
**Decision:** Enable all detectors by default in `vigilo scan` and provide `--security-only` (`-S`) flag. Maintain `category` field on `Finding` for clear visual distinction.
**Consequences:** Zero-config discovery of syntax errors, typos, and security flaws out of the box.

---

## ADR-010: Codebase Security Hardening & CI Gates

**Date:** 2026-09-05
**Context:** Auditing Vigilo's own codebase across 20 static analysis, supply chain, fuzzing, CLI output, and test suite techniques to ensure robustness against adversarial inputs and supply chain risks.
**Decision:**
1. Enforce `mypy --strict src tests` and expanded Ruff rules (`ANN`, `PL`, `C90`, `RUF`) across the repository.
2. Sanitize ANSI escape sequences and non-printable control characters in CLI text reporting (`sanitize_terminal_text`) to prevent terminal escape injection attacks (CWE-150).
3. Add cycle protection in `discover_files` to guard against runaway symlink recursion and skip non-regular files.
4. Add bounded dev dependency pins in `pyproject.toml` and wire `bandit`, `pip-audit`, and CodeQL into CI permanently.
**Consequences:** Guaranteed resilience against adversarial repository files, terminal hijacking, and dependency vulnerabilities.

---

## ADR-011: JavaScript & TypeScript AST Parsing with Tree-Sitter

**Date:** 2026-09-06
**Context:** Expanding Vigilo v0.3.0 to support JavaScript, TypeScript, JSX, and TSX files (Node.js backend and React frontend). Python's native `ast` module only parses Python. Need an architecture for parsing modern JS/TS code without breaking Vigilo's zero-external-runtime standalone binary distribution.
**Options considered:**
1. **Shell out to Node.js + Babel/TypeScript parser**: Returns exact Babel/TS ASTs, but requires the end-user to have Node.js and npm dependencies installed on their machine. *Rejected:* This breaks the standalone, zero-external-runtime executable guarantee (PyInstaller binaries) that Vigilo provides.
2. **Pure-Python JS parsers (`esprima`, `pyjsparser`)**: Pure Python without external binaries, but unmaintained and lack support for modern ECMAScript, TypeScript types, and JSX/TSX syntax. *Rejected:* Causes parser crashes and unacceptable false-negative rates on modern codebases.
3. **`tree-sitter` with Python bindings (`tree-sitter`, `tree-sitter-javascript`, `tree-sitter-typescript`)**: High-performance, incremental parser used by GitHub and modern IDEs. Grammars compile to native libraries distributed as precompiled wheels on PyPI. No Node.js runtime required at scan time. Fully supports modern ES2024, TypeScript, JSX, and TSX. Furthermore, tree-sitter offers grammars for future roadmap languages (Java, HTML, CSS).
**Decision:** Adopt **Option 3 (`tree-sitter`)** using `tree-sitter-javascript` and `tree-sitter-typescript`.
**Consequences:** Fast, robust parsing of JavaScript, TypeScript, React JSX, and TSX with zero Node.js runtime requirement. Requires testing and maintaining PyInstaller build hooks for native grammar extensions across Linux, macOS, and Windows. Sets up an architecture that seamlessly scales to future languages on the roadmap.

---

## ADR-012: CLI Scan Mode Control & Dead Code Removal

**Date:** 2026-09-06
**Context:** In earlier revisions, `--correctness` (`-c`) was configured with `default=True` and `action="store_true"`, rendering it dead code (passing it had no effect). Only `--security-only` disabled correctness checks.
**Options considered:**
1. **Option A (Minimal)**: Remove `--correctness` entirely and retain only `--security-only`.
2. **Option B (Recommended)**: Introduce `--mode` (`-m`) with choices `all`, `security`, and `correctness` (default: `all`), while retaining `--security-only` (`-S`) as a convenient shortcut.
**Decision:** Adopt **Option B**. Provides explicit, structured scan mode selection (`--mode {all,security,correctness}`) and eliminates dead code while preserving backward-compatible `--security-only` shorthand.
**Consequences:** Clear, non-ambiguous CLI interface with full test coverage for all scan modes.

---

## ADR-013: Code Snippet Truncation & Terminal DoS Protection

**Date:** 2026-09-06
**Context:** When scanning files with extremely long lines (e.g., 30KB minified code or deeply nested syntax), the reporter previously printed the entire un-truncated raw line in findings output, risking terminal log-flooding and CI storage bloat.
**Decision:** Enforce a strict snippet length bound (`MAX_SNIPPET_LENGTH = 200` characters) in both text and JSON report formatters. When a line exceeds 200 characters, truncate it and append `... [truncated, N chars total]`.
**Consequences:** Prevents terminal flooding and memory bloat on pathological/minified files while retaining actionable context for developers.

---

## ADR-014: Deferred Multi-Statement Taint Tracking Engine & Declarative YAML Rule DSL

**Date:** 2026-10-01
**Context:** Following a real-world bug-hunt finding where Vigilo missed a path-traversal vulnerability in Flask (`os.path.join` + `os.path.exists` + `send_file`), a post-mortem proposed transitioning Vigilo from call-site AST pattern matching with local assignment resolution to a generalized dataflow taint-tracking engine (sources, propagators, sanitizers, sinks) defined via a declarative, Semgrep-style YAML rule DSL.
**Problem Analysis:**
Every current Vigilo detector (`VIGILO-001` through `VIGILO-005` in Python, plus JS/TS detectors) is implemented as a dedicated Python class using local single-file AST inspection and one-hop assignment resolution (`FlowAnalyzer`). A true taint engine requires constructing and traversing inter-statement control-flow (CFG) and data-flow graphs (DFG), tracking taint propagation through arbitrary functions/operations, and clearing taint when values pass through certified sanitizers.
**Options Considered:**
1. **Option 1: Patch-Sized Sink & Pattern Expansion (Adopted for v0.3.4):**
   - Expand sink lists in Python and framework response methods (`send_file`, `FileResponse`, `wrap_file`, `serve`, `Path.read_*`).
   - Treat path combiners (`os.path.join`, `Path.joinpath`, `/`) and path sanitizers (`secure_filename`, `basename`) within the existing local flow model.
   - *Pros:* Zero runtime dependency additions, fast execution (<1ms per file), preserves simple architecture, ships immediately.
   - *Cons:* Does not generalize across arbitrary multi-statement data flow chains across functions or files.
2. **Option 2: Minimal Intra-Procedural Taint Graph Engine (Target: v0.4.0+):**
   - Implement an explicit Data Flow Graph (DFG) engine tracking untrusted source nodes (e.g. `request.args`, `os.environ`), propagation edges (e.g. `os.path.join`, string concat, function returns), sanitization filter nodes (`secure_filename`, boundary checks), and reachability to dangerous sinks.
   - *Pros:* Eliminates class-by-class data-flow edge cases, dramatically improves precision and true-positive recall on multi-statement flows.
   - *Cons:* Major architectural rewrite of the core analysis pipeline; requires rewriting all 5 core Python security detectors; adds runtime complexity and memory footprint.
3. **Option 3: Declarative Semgrep-Style YAML Rule DSL (Target: v0.4.0+ or v0.5.0):**
   - Introduce a declarative schema (`pattern-sources`, `pattern-propagators`, `pattern-sanitizers`, `pattern-sinks`) allowing rules to be authored in YAML files instead of Python classes.
   - *Pros:* Decouples rule authoring from engine internals, enables community rule contributions without Python code changes.
   - *Cons:* Requires building or embedding a YAML parser / query evaluation runtime; creates two competing ways to define detectors unless all existing Python detectors are ported; increases architectural surface area.
**Decision:**
- **In Scope for v0.3.4:** Ship Option 1. Expand sink list in `VIGILO-005`, ensure `os.path.exists()` does not neutralize traversal findings, and improve Flask fix hint.
- **Explicitly Deferred:** Defer Options 2 and 3 to **v0.4.0+**. Do NOT implement taint tracking or YAML DSL in v0.3.4.
- **Architectural Prerequisite:** Prior to implementing Option 2 or 3, alignment and explicit confirmation from the human maintainer is required to determine whether:
  1. The taint engine should remain internal Python-first vs. YAML-DSL-driven.
  2. Vigilo should maintain pure standard library execution or consider external graph libraries.
  3. Existing detector classes will be preserved alongside graph queries or migrated entirely.
**Consequences:** v0.3.4 remains lean, fast, zero-dependency, and backward compatible. The roadmap for v0.4.0 establishes a clear technical blueprint for deep dataflow analysis.

