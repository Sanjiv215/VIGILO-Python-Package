# Vigilo

[![CI](https://github.com/Sanjiv215/VIGILO-Python-Package/actions/workflows/ci.yml/badge.svg)](https://github.com/Sanjiv215/VIGILO-Python-Package/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/vigilo.svg)](https://pypi.org/project/vigilo/)

**Vigilo** is a fast, zero-configuration static security scanner for Python. It detects exploitable vulnerability patterns (CWEs) in first-party code using AST traversal combined with local data-flow analysis to minimize false positives.

Runs across **Linux**, **macOS**, and **Windows** — either via `pip` or as a standalone binary with **no Python installation required**.

---

## Why Vigilo?

- **High-Signal over High-Noise:** Traditional linters (like Bandit) flag safe string constants and standard library calls indiscriminately. Vigilo uses local data-flow analysis to distinguish harmless constants from untrusted dynamic inputs.
- **Zero Configuration:** Drop it directly into your workflow or CI pipeline with `vigilo scan .` or `vigilo .`. No YAML rule authoring or database setup required.
- **Zero Runtime Dependencies:** Built strictly on Python's standard library. Lightweight and instantaneous.
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

Filter by minimum severity:

```bash
vigilo scan . --min-severity high
```

Exclude specific directories or glob patterns:

```bash
vigilo scan . --exclude "tests/*" --exclude "migrations/*"
```

### Python API

```python
from vigilo import scan

findings = scan("src/")

for finding in findings:
    print(f"[{finding.severity.upper()}] {finding.detector.id} {finding.detector.name}")
    print(f"  Location: {finding.location}")
    print(f"  Fix: {finding.fix_hint}")
```

---

## Supported Detectors

| ID | CWE | Vulnerability | Severity | Target APIs |
|---|---|---|---|---|
| **`VIGILO-001`** | CWE-89 | SQL Injection | `HIGH` | `db.execute()`, `cursor.execute()`, `text()`, `raw()` |
| **`VIGILO-002`** | CWE-78 | OS Command Injection | `HIGH` | `subprocess.*(shell=True)`, `os.system()`, `os.popen()` |
| **`VIGILO-003`** | CWE-94 | Code Injection | `HIGH` | `eval()`, `exec()`, `compile()` |
| **`VIGILO-004`** | CWE-502 | Unsafe Deserialization | `HIGH` | `pickle.loads()`, `yaml.load()`, `marshal.loads()` |
| **`VIGILO-005`** | CWE-22 | Path Traversal | `HIGH` | `open()`, `os.open()`, `io.open()` |

---

## CLI Reference

```
usage: vigilo [-h] [--version] {scan} ... [target] [--format {text,json}]
              [--min-severity {low,medium,high}] [--exclude EXCLUDE] [--no-color]

Options:
  target                Directory or file to scan (default: '.')
  --format, -f          Output report format: 'text' or 'json' (default: 'text')
  --min-severity, -s    Minimum severity threshold: 'low', 'medium', 'high' (default: 'low')
  --exclude, -e         Exclude path matching glob pattern (repeatable)
  --no-color            Disable ANSI terminal coloring
  --version, -V         Show version and exit
  --help, -h            Show help and exit
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean — no vulnerabilities found at or above `--min-severity` |
| `1` | Vulnerabilities detected |
| `2` | Execution or path error |

---

## Contributing

We welcome contributions! Please review our [Contributing Guide](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/CONTRIBUTING.md), [Code of Conduct](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/CODE_OF_CONDUCT.md), and [Security Policy](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/SECURITY.md).

---

## License

Distributed under the [MIT License](https://github.com/Sanjiv215/VIGILO-Python-Package/blob/main/LICENSE). Copyright (c) 2026 Sanjiv - Vigilo.
