# Vigilo

[![CI](https://github.com/Sanjiv215/VIGILO-Python-Package/actions/workflows/ci.yml/badge.svg)](https://github.com/Sanjiv215/VIGILO-Python-Package/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/vigilo.svg)](https://pypi.org/project/vigilo/)

**Vigilo** is a fast, zero-configuration static security scanner for Python, JavaScript, and TypeScript (Node.js & React). It detects exploitable vulnerability patterns (CWEs) in first-party code using AST traversal combined with local data-flow analysis to minimize false positives.

Runs across **Linux**, **macOS**, and **Windows** — either via `pip` or as a standalone binary with **no Python installation required**.

---

## Supported Languages

| Language / Framework | Status | File Extensions | Engine |
|---|---|---|---|
| **Python** | **Stable** | `.py` | Native Python AST + Data Flow |
| **JavaScript** | **New in v0.3.0** | `.js`, `.mjs`, `.cjs`, `.jsx` | Tree-Sitter (`tree-sitter-javascript`) |
| **TypeScript / React** | **New in v0.3.0** | `.ts`, `.tsx` | Tree-Sitter (`tree-sitter-typescript`) |

> See [ROADMAP.md](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/ROADMAP.md) for planned languages (Java, HTML, CSS).

---

## Why Vigilo?

- **High-Signal over High-Noise:** Traditional linters flag safe string constants and standard library calls indiscriminately. Vigilo uses local data-flow analysis to distinguish harmless constants from untrusted dynamic inputs.
- **Zero Configuration:** Drop it directly into your workflow or CI pipeline with `vigilo scan .` or `vigilo .`. No YAML rule authoring or database setup required.
- **No Node.js Runtime Required:** Multi-language parsing is powered by embeddable Tree-Sitter grammars compiled to native libraries — you do not need Node.js installed to scan JS/TS/React codebases.
- **First-Party Code Focus:** While tools like `pip-audit` scan third-party dependencies for CVEs, Vigilo scans *your* code for logic and injection flaws.

---

## Installation & Quickstart

### Option A: Install via PyPI (Python 3.10+)

```bash
pip install vigilo
```

### Option B: Standalone Executable (No Python Required)

Pre-built standalone single-file executables are available for Linux, macOS, and Windows on the [Releases Page](https://github.com/Sanjiv215/VIGILO-Python-Package/releases):

- **Linux (x86_64):** `vigilo-linux-x86_64`
- **macOS:** `vigilo-macos`
- **Windows (x86_64):** `vigilo-windows-x86_64.exe`

#### Verifying Checksums

Every release includes a `SHA256SUMS.txt` file to verify binary integrity:

```bash
# Verify checksum on Linux/macOS
sha256sum -c SHA256SUMS.txt
```

> **Note on Antivirus Alerts:** Standalone executables are bundled with PyInstaller. Some heuristic antivirus engines or Windows SmartScreen may occasionally flag newly published PyInstaller binaries as unfamiliar. This is a known false positive with packed binaries. You can verify the integrity using the SHA256 checksum or install via `pip install vigilo` to run from source.

---

## Usage

Scan the current directory:

```bash
vigilo scan .
```

Or use the shortcut alias:

```bash
vigilo .
```

Generate structured JSON output for CI/CD pipelines:

```bash
vigilo scan . --format json
```

Filter by scan mode (security only, correctness diagnostics only, or all):

```bash
# Security scan only (skips correctness diagnostics)
vigilo scan . --security-only
# or:
vigilo scan . --mode security

# Correctness diagnostics only (syntax errors, undefined names, unclosed resources)
vigilo scan . --mode correctness
# or use the dedicated diagnose subcommand:
vigilo diagnose .

# All checks: Security + Correctness (Default)
vigilo scan .
```

Filter by minimum severity:

```bash
vigilo scan . --min-severity high
```

Exclude specific directories or glob patterns:

```bash
vigilo scan . --exclude "tests/*" --exclude "node_modules/*" --exclude "dist/*"
```

### Python API

```python
from vigilo import scan

# Security scan (default)
findings = scan("src/")

# Security + Correctness scan
all_findings = scan("src/", include_correctness=True)

for finding in findings:
    print(
        f"[{finding.severity.upper()}] {finding.detector.id} {finding.detector.name} ({finding.detector.category})"
    )
    print(f"  Location: {finding.location}")
    print(f"  Fix: {finding.fix_hint}")
```

---

## Supported Detectors

### Python Security Vulnerabilities

| ID | CWE | Vulnerability | Severity | Target APIs |
|---|---|---|---|---|
| **`VIGILO-001`** | CWE-89 | SQL Injection | `HIGH` | `db.execute()`, `cursor.execute()`, `text()`, `raw()` |
| **`VIGILO-002`** | CWE-78 | OS Command Injection | `HIGH` | `subprocess.*(shell=True)`, `os.system()`, `os.popen()` |
| **`VIGILO-003`** | CWE-94 | Code Injection | `HIGH` | `eval()`, `exec()`, `compile()` |
| **`VIGILO-004`** | CWE-502 | Unsafe Deserialization | `HIGH` | `pickle.loads()`, `yaml.load()`, `marshal.loads()` |
| **`VIGILO-005`** | CWE-22 | Path Traversal | `HIGH` | `open()`, `os.open()`, `io.open()` |

### JavaScript / TypeScript / React Security Detectors (New in v0.3.0)

| ID | CWE | Vulnerability | Severity | Target Patterns / APIs |
|---|---|---|---|---|
| **`VIGILO-JS-001`** | CWE-79 | Cross-Site Scripting (XSS) | `HIGH` | `innerHTML`/`outerHTML`, `document.write()`, React `dangerouslySetInnerHTML` |
| **`VIGILO-JS-002`** | CWE-94 | Code Injection | `HIGH` | `eval()`, `new Function()`, string-based `setTimeout`/`setInterval` |
| **`VIGILO-JS-003`** | CWE-78 | OS Command Injection | `HIGH` | `child_process.exec()`, `execSync()`, `spawn()` with `shell: true` |
| **`VIGILO-JS-004`** | CWE-1321 | Prototype Pollution | `HIGH` | `__proto__`, `constructor.prototype` direct mutation, unsafe deep merge |
| **`VIGILO-JS-005`** | CWE-798 | Hardcoded Secrets & Credentials | `HIGH` | AWS keys, GitHub PATs, Slack tokens, JWTs, DB connection strings |

### Python Code Correctness Diagnostics (Included in Default Scan or `diagnose`)

| ID | Issue | Severity | Description |
|---|---|---|---|
| **`VIGILO-C01`** | Syntax & Indentation Error | `HIGH` | Python parse failure or bad indentation |
| **`VIGILO-C02`** | Undefined Name Usage | `MEDIUM` | Use of unbound or misspelled variable/name |
| **`VIGILO-C03`** | Unused Import / Variable | `LOW` | Unused imported module or assigned local variable |
| **`VIGILO-C04`** | Unclosed File Resource | `MEDIUM` | Raw `open()` call without context manager (`with`) |
| **`VIGILO-C05`** | Bare Except Clause | `MEDIUM` | Blanket `except:` catch masking critical errors |

---

## CLI Reference

```
usage: vigilo scan [-h] [--format {text,json}]
                   [--min-severity {low,medium,high}] [--exclude EXCLUDE]
                   [--no-color] [--mode {all,security,correctness}]
                   [--security-only]
                   [target]

positional arguments:
  target                Path to directory or file to scan (default: '.')

options:
  -h, --help            show this help message and exit
  --format, -f {text,json}
                        Output report format (default: 'text')
  --min-severity, -s {low,medium,high}
                        Minimum severity threshold to report (default: 'low')
  --exclude, -e EXCLUDE
                        Exclude files/directories matching glob pattern (repeatable)
  --no-color            Disable ANSI color codes in output
  --mode, -m {all,security,correctness}
                        Scan mode: 'all' (security + correctness), 'security'
                        (security only), 'correctness' (diagnostics only) (default: all)
  --security-only, -S   Shortcut for --mode security (only report security vulnerabilities)
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no vulnerabilities found at or above `--min-severity` |
| `1` | Vulnerabilities detected |
| `2` | Execution or path error |

---

## Architecture & Project Documentation

- [**DECISIONS.md**](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/DECISIONS.md) — Architecture Decision Records (ADRs) detailing package design, parser selection, and CLI ergonomics.
- [**ROADMAP.md**](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/ROADMAP.md) — Supported and planned language roadmap (Python, JS, TS, React active; Java, HTML, CSS planned).
- [**TECH_STACK.md**](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/TECH_STACK.md) — Detailed runtime and dev dependency matrix with justifications.
- [**WORKFLOW.md**](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/WORKFLOW.md) — Development workflow, verification gates, and stage logs.
- [**TIMELINE.md**](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/TIMELINE.md) — Historical milestone release logs and timestamps.
- [**CHANGELOG.md**](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/CHANGELOG.md) — Detailed version history adhering to Keep a Changelog.

---

## Contributing

We welcome contributions! Please review our [Contributing Guide](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/CONTRIBUTING.md), [Code of Conduct](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/CODE_OF_CONDUCT.md), and [Security Policy](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/SECURITY.md).

---

## License

Distributed under the [MIT License](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/LICENSE). Copyright (c) 2026 Sanjiv - Vigilo.
