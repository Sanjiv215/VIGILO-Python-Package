# OJO

A static, security-focused code scanner that detects known vulnerability patterns in Python codebases. CLI-first, zero-config, high-signal.

## Overview

OJO scans Python codebases for common and dangerous vulnerability patterns (CWEs) using AST analysis combined with local data-flow tracking to minimize false positives.

## Status

| Feature | Status |
|---|---|
| Core AST Scanner | Planned (Stage 5) |
| CWE-89 SQL Injection Detector | Planned (Stage 6) |
| CWE-78 OS Command Injection Detector | Planned (Stage 6) |
| CWE-94 Code Injection Detector | Planned (Stage 6) |
| CWE-502 Unsafe Deserialization Detector | Planned (Stage 6) |
| CWE-22 Path Traversal Detector | Planned (Stage 6) |
| CLI Interface (`ojo scan`) | Planned (Stage 7) |
| JSON / Text Reporters | Planned (Stage 7) |

## Quickstart

```bash
# Installation (PyPI distribution: ojo-scan)
pip install ojo-scan

# Scan current directory
ojo scan .

# Scan specific path with JSON output
ojo scan src/ --format json
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for architectural overview and data models.

## Development

```bash
# Clone the repository
git clone https://github.com/Sanjiv215/OJO-Python-Package.git
cd OJO-Python-Package

# Install in editable mode with development dependencies
pip install -e .[dev]

# Run tests
pytest

# Run linter & type checker
ruff check .
mypy src
```
