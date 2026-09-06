"""JavaScript, TypeScript, and React security detectors."""

from vigilo.detectors.js.base import BaseJSDetector
from vigilo.detectors.js.code_injection import JSCodeInjectionDetector
from vigilo.detectors.js.command_injection import JSCommandInjectionDetector
from vigilo.detectors.js.hardcoded_secrets import JSHardcodedSecretsDetector
from vigilo.detectors.js.prototype_pollution import JSPrototypePollutionDetector
from vigilo.detectors.js.xss import JSXSSDetector

JS_DETECTORS: tuple[type[BaseJSDetector], ...] = (
    JSXSSDetector,
    JSCodeInjectionDetector,
    JSCommandInjectionDetector,
    JSPrototypePollutionDetector,
    JSHardcodedSecretsDetector,
)

__all__ = [
    "BaseJSDetector",
    "JSCodeInjectionDetector",
    "JSCommandInjectionDetector",
    "JSHardcodedSecretsDetector",
    "JSPrototypePollutionDetector",
    "JSXSSDetector",
    "JS_DETECTORS",
]
