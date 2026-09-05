"""Detector registry and public interface for Vigilo."""

from __future__ import annotations

from vigilo.detectors.bare_except import BareExceptDetector
from vigilo.detectors.base import BaseDetector
from vigilo.detectors.code_injection import CodeInjectionDetector
from vigilo.detectors.command_injection import CommandInjectionDetector
from vigilo.detectors.path_traversal import PathTraversalDetector
from vigilo.detectors.sql_injection import SQLInjectionDetector
from vigilo.detectors.syntax_error import SyntaxErrorDetector
from vigilo.detectors.unclosed_resource import UnclosedResourceDetector
from vigilo.detectors.undefined_name import UndefinedNameDetector
from vigilo.detectors.unsafe_deserialization import UnsafeDeserializationDetector
from vigilo.detectors.unused_code import UnusedCodeDetector

SECURITY_DETECTORS: list[type[BaseDetector]] = [
    SQLInjectionDetector,
    CommandInjectionDetector,
    CodeInjectionDetector,
    UnsafeDeserializationDetector,
    PathTraversalDetector,
]

CORRECTNESS_DETECTORS: list[type[BaseDetector]] = [
    SyntaxErrorDetector,
    UndefinedNameDetector,
    UnusedCodeDetector,
    UnclosedResourceDetector,
    BareExceptDetector,
]

ALL_DETECTORS: list[type[BaseDetector]] = SECURITY_DETECTORS + CORRECTNESS_DETECTORS

__all__ = [
    "ALL_DETECTORS",
    "CORRECTNESS_DETECTORS",
    "SECURITY_DETECTORS",
    "BareExceptDetector",
    "BaseDetector",
    "CodeInjectionDetector",
    "CommandInjectionDetector",
    "PathTraversalDetector",
    "SQLInjectionDetector",
    "SyntaxErrorDetector",
    "UnclosedResourceDetector",
    "UndefinedNameDetector",
    "UnsafeDeserializationDetector",
    "UnusedCodeDetector",
]
