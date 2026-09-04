"""Detector registry and public interface."""

from __future__ import annotations

from ojo.detectors.base import BaseDetector

ALL_DETECTORS: list[type[BaseDetector]] = []

__all__ = ["BaseDetector", "ALL_DETECTORS"]
