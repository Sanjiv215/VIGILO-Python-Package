"""Detector registry and public interface."""

from __future__ import annotations

from ojo.detectors.base import BaseDetector
from ojo.detectors.code_injection import CodeInjectionDetector
from ojo.detectors.command_injection import CommandInjectionDetector
from ojo.detectors.path_traversal import PathTraversalDetector
from ojo.detectors.sql_injection import SQLInjectionDetector
from ojo.detectors.unsafe_deserialization import UnsafeDeserializationDetector

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
