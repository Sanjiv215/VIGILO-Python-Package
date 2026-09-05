# OJO

[![CI](https://github.com/Sanjiv215/OJO-Python-Package/actions/workflows/ci.yml/badge.svg)](https://github.com/Sanjiv215/OJO-Python-Package/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**OJO** is a fast, zero-configuration static security scanner for Python. It identifies exploitable vulnerability patterns (CWEs) in first-party code using AST traversal combined with local data-flow analysis to minimize false positives.

---

## Why OJO?

- **High-Signal over High-Noise:** Traditional linters (like Bandit) flag safe string constants and standard library calls indiscriminately. OJO uses local data-flow analysis to distinguish harmless constants from untrusted dynamic inputs.
- **Zero Configuration:** Drop it directly into your workflow or CI pipeline with `ojo scan .`. No YAML rule authoring or database setup required.
- **Zero Runtime Dependencies:** Uses only Python's standard library. Lightweight and instantaneous.
- **First-Party Code Focus:** While tools like `pip-audit` scan your dependencies for CVEs, OJO scans *your* code for logic and injection vulnerabilities.

---

## Quickstart

### Installation

Install via PyPI:

```bash
pip install ojo-scan
```

### CLI Usage

Scan the current directory:

```bash
ojo .
```

Or use the canonical command:

```bash
ojo scan src/
```

Generate structured JSON output for CI pipelines:

```bash
ojo scan . --format json
```

Filter by minimum severity:

```bash
ojo scan . --min-severity high
```

Exclude specific directories or glob patterns:

```bash
ojo scan . --exclude "tests/*" --exclude "migrations/*"
```

### Python API

```python
from ojo import scan

# Run a scan on a path
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
| **`OJO-001`** | CWE-89 | SQL Injection | `HIGH` | `db.execute()`, `cursor.execute()`, `text()`, `raw()` |
| **`OJO-002`** | CWE-78 | OS Command Injection | `HIGH` | `subprocess.*(shell=True)`, `os.system()`, `os.popen()` |
| **`OJO-003`** | CWE-94 | Code Injection | `HIGH` | `eval()`, `exec()`, `compile()` |
| **`OJO-004`** | CWE-502 | Unsafe Deserialization | `HIGH` | `pickle.loads()`, `yaml.load()`, `marshal.loads()` |
| **`OJO-005`** | CWE-22 | Path Traversal | `HIGH` | `open()`, `os.open()`, `io.open()` |

---

## CLI Reference

```
usage: ojo [-h] [--version] {scan} ... [target] [--format {text,json}]
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

We welcome contributions! Please review our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

---

## License

Released under the [MIT License](LICENSE).
