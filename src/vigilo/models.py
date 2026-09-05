"""Core data models for Vigilo."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    """Vulnerability severity levels ordered from lowest to highest."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (1=LOW, 2=MEDIUM, 3=HIGH)."""
        ranks = {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
        }
        return ranks[self]

    def __ge__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            try:
                other = Severity(other.lower())
            except ValueError:
                return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            try:
                other = Severity(other.lower())
            except ValueError:
                return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            try:
                other = Severity(other.lower())
            except ValueError:
                return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            try:
                other = Severity(other.lower())
            except ValueError:
                return NotImplemented
        return self.rank < other.rank


@dataclass(frozen=True)
class Location:
    """Exact source code location of a finding."""

    file: Path
    line: int
    col: int
    end_line: int | None = None
    end_col: int | None = None

    def __str__(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"


@dataclass(frozen=True)
class DetectorMeta:
    """Identity, classification, and metadata for a detector."""

    id: str  # e.g., "VIGILO-001" or "VIGILO-C01"
    name: str  # e.g., "SQL Injection"
    cwe: int | None  # e.g., 89 or None for correctness
    description: str
    severity: Severity
    category: str = "security"  # "security" or "correctness"


@dataclass(frozen=True)
class Finding:
    """A vulnerability or correctness finding reported by a detector."""

    detector: DetectorMeta
    location: Location
    message: str
    fix_hint: str
    severity: Severity
    confidence: str = "high"  # "high", "medium", "low"
    source_line: str = ""
    category: str = "security"  # "security" or "correctness"
