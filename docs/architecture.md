# OJO Architecture

## Scanning Pipeline

```
Discovery → Parser → Detectors → Collector → Reporter
 (files)     (AST)    (rules)    (findings)   (output)
```

| Stage | Input | Output |
|---|---|---|
| **Discovery** | Root path + exclude patterns | `list[Path]` of `.py` files |
| **Parser** | `Path` | `ast.Module` (or skip + warning) |
| **Detectors** | `ast.Module` + file metadata | `list[Finding]` |
| **Collector** | Findings from all detectors | Sorted, deduplicated `list[Finding]` |
| **Reporter** | `list[Finding]` + format config | Formatted output → stdout |

## Data Model

- **`Severity`** — enum: `LOW`, `MEDIUM`, `HIGH`
- **`Location`** — file path, line, col, end_line, end_col
- **`DetectorMeta`** — detector ID (`OJO-001`), name, CWE number, description, default severity
- **`Finding`** — detector meta + location + message + fix hint + severity + confidence + source line

All models are frozen dataclasses (immutable, hashable).

## Detector Interface

```python
class BaseDetector(ABC):
    meta: DetectorMeta

    @abstractmethod
    def run(self, tree: ast.Module, file_path: Path, source: str) -> list[Finding]:
        ...
```

Add a detector: subclass `BaseDetector`, set `meta`, implement `run()`, add to registry.

## Local Data Flow

`FlowAnalyzer` distinguishes constant vs. dynamic arguments to reduce false positives:
- `is_constant(node)` — is this a literal value?
- `trace_name(name, scope)` — where does this variable come from?
- `is_from_parameter(name, scope)` — is this a function parameter?

## CLI

```
ojo scan <path>       # canonical
ojo <path>            # alias for ojo scan <path>

Options: --format {text,json}, --min-severity {low,medium,high},
         --exclude PATTERN, --no-color, --version
Exit: 0 = clean, 1 = findings, 2 = error
```

## Public API

```python
from ojo import scan, Scanner, ScanConfig, Finding, Severity
findings = scan(".")
```
