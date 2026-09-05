"""Detector registry and public interface for Vigilo."""

from __future__ import annotations

from vigilo.detectors.base import BaseDetector
from vigilo.detectors.code_injection import CodeInjectionDetector
from vigilo.detectors.command_injection import CommandInjectionDetector
from vigilo.detectors.path_traversal import PathTraversalDetector
from vigilo.detectors.sql_injection import SQLInjectionDetector
from vigilo.detectors.unsafe_deserialization import UnsafeDeserializationDetector

ALL_DETECTORS: list[type[BaseDetector]] = [
    SQLInjectionDetector,
    CommandInjectionDetector,
    CodeInjectionDetector,
    UnsafeDeserializationDetector,
    PathTraversalDetector,
]

__all__ = [
    "BaseDetector",
    "ALL_DETECTORS",
    "SQLInjectionDetector",
    "CommandInjectionDetector",
    "CodeInjectionDetector",
    "UnsafeDeserializationDetector",
    "PathTraversalDetector",
]
