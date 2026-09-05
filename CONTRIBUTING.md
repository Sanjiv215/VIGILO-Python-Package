# Contributing to Vigilo

Thank you for contributing to Vigilo! This document outlines our development workflows and guidelines.

---

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Sanjiv215/VIGILO-Python-Package.git
   cd VIGILO-Python-Package
   ```

2. **Create a virtual environment (Python 3.10+):**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install in editable mode with development dependencies:**
   ```bash
   pip install -e .[dev]
   ```

---

## Running Tests & Quality Checks

Ensure all tests, linters, and type checkers pass before submitting a Pull Request:

```bash
# Run unit tests
python -m unittest discover -s tests

# Run linter and check formatting
ruff check .
ruff format --check .

# Run static type checker
mypy src
```

---

## Adding a New Vulnerability Detector

To add a new vulnerability detector:

1. **Create a new detector file** in `src/vigilo/detectors/<detector_name>.py`:
   - Subclass `BaseDetector` from `vigilo.detectors.base`.
   - Define class attribute `meta = DetectorMeta(id="VIGILO-XXX", name="...", cwe=..., description="...", severity=Severity.HIGH)`.
   - Implement `run(tree, file_path, source) -> list[Finding]`.
   - Use `FlowAnalyzer.is_dynamic()` or `FlowAnalyzer.is_constant()` to eliminate false positives.

2. **Register the detector** in `src/vigilo/detectors/__init__.py`:
   - Add the detector class to `ALL_DETECTORS`.

3. **Add comprehensive unit tests** in `tests/detectors/test_<detector_name>.py`:
   - Include test cases for **True Positives** (flawed code that must trigger).
   - Include test cases for **True Negatives** (safe idioms that must NOT trigger).

---

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New features or detectors
- `fix:` Bug fixes
- `docs:` Documentation updates
- `test:` Adding or updating tests
- `chore:` Maintenance, dependency updates, packaging
- `ci:` CI/CD workflow updates
- `refactor:` Code improvements without feature changes
