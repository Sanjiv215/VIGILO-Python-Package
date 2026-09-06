"""Tests for JavaScript, TypeScript, and React security detectors."""

from pathlib import Path

from vigilo.detectors.js.base import BaseJSDetector
from vigilo.detectors.js.code_injection import JSCodeInjectionDetector
from vigilo.detectors.js.command_injection import JSCommandInjectionDetector
from vigilo.detectors.js.hardcoded_secrets import JSHardcodedSecretsDetector
from vigilo.detectors.js.prototype_pollution import JSPrototypePollutionDetector
from vigilo.detectors.js.xss import JSXSSDetector
from vigilo.models import Finding
from vigilo.parsers.js_parser import parse_js_ts
from vigilo.scanner import ScanConfig, Scanner

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
JS_VULN_DIR = FIXTURES_DIR / "js_vulnerable"
JS_CLEAN_DIR = FIXTURES_DIR / "js_clean"


def _run_js_detector(detector_cls: type[BaseJSDetector], file_path: Path) -> list[Finding]:
    source_bytes = file_path.read_bytes()
    tree, source_str, raw_bytes, err = parse_js_ts(source_bytes, file_path)
    assert tree is not None, f"Parse failed for {file_path}: {err}"
    detector = detector_cls()
    return detector.run(tree, file_path, source_str, raw_bytes)


class TestJSXSSDetector:
    def test_react_tsx_and_dom_xss(self) -> None:
        file_path = JS_VULN_DIR / "xss_react.tsx"
        findings = _run_js_detector(JSXSSDetector, file_path)
        assert len(findings) >= 2

        rule_ids = {f.detector.id for f in findings}
        assert "VIGILO-JS-001" in rule_ids

        # Check languages and messages
        for f in findings:
            assert f.language == "typescript"
            assert f.detector.cwe == 79
            assert (
                "XSS" in f.message
                or "dangerouslySetInnerHTML" in f.message
                or "innerHTML" in f.message
            )

    def test_clean_react_tsx_no_findings(self) -> None:
        file_path = JS_CLEAN_DIR / "safe_react.tsx"
        findings = _run_js_detector(JSXSSDetector, file_path)
        assert len(findings) == 0


class TestJSCodeInjectionDetector:
    def test_eval_and_function_constructors(self) -> None:
        file_path = JS_VULN_DIR / "code_injection.js"
        findings = _run_js_detector(JSCodeInjectionDetector, file_path)
        assert len(findings) >= 3

        for f in findings:
            assert f.detector.id == "VIGILO-JS-002"
            assert f.detector.cwe == 94
            assert f.language == "javascript"

    def test_clean_eval_and_timers(self) -> None:
        file_path = JS_CLEAN_DIR / "safe_eval_timers.js"
        findings = _run_js_detector(JSCodeInjectionDetector, file_path)
        assert len(findings) == 0


class TestJSCommandInjectionDetector:
    def test_node_child_process_exec(self) -> None:
        file_path = JS_VULN_DIR / "command_injection.ts"
        findings = _run_js_detector(JSCommandInjectionDetector, file_path)
        assert len(findings) >= 3

        for f in findings:
            assert f.detector.id == "VIGILO-JS-003"
            assert f.detector.cwe == 78
            assert f.language == "typescript"

    def test_clean_node_commands(self) -> None:
        file_path = JS_CLEAN_DIR / "safe_command.ts"
        findings = _run_js_detector(JSCommandInjectionDetector, file_path)
        assert len(findings) == 0


class TestJSPrototypePollutionDetector:
    def test_proto_and_constructor_assignments(self) -> None:
        file_path = JS_VULN_DIR / "prototype_pollution.js"
        findings = _run_js_detector(JSPrototypePollutionDetector, file_path)
        assert len(findings) >= 2

        for f in findings:
            assert f.detector.id == "VIGILO-JS-004"
            assert f.detector.cwe == 1321
            assert f.language == "javascript"

    def test_clean_object_manipulation(self) -> None:
        file_path = JS_CLEAN_DIR / "safe_objects.js"
        findings = _run_js_detector(JSPrototypePollutionDetector, file_path)
        assert len(findings) == 0


class TestJSHardcodedSecretsDetector:
    def test_tokens_and_connection_strings(self) -> None:
        file_path = JS_VULN_DIR / "hardcoded_secrets.ts"
        findings = _run_js_detector(JSHardcodedSecretsDetector, file_path)
        assert len(findings) >= 4

        for f in findings:
            assert f.detector.id == "VIGILO-JS-005"
            assert f.detector.cwe == 798
            assert f.language == "typescript"

    def test_clean_env_secrets(self) -> None:
        file_path = JS_CLEAN_DIR / "safe_secrets.ts"
        findings = _run_js_detector(JSHardcodedSecretsDetector, file_path)
        assert len(findings) == 0


class TestJSScannerIntegration:
    def test_scan_full_js_vulnerable_fixtures(self) -> None:
        scanner = Scanner(ScanConfig(paths=[JS_VULN_DIR]))
        findings = scanner.scan()
        assert len(findings) >= 14

        detector_ids = {f.detector.id for f in findings}
        expected_ids = {
            "VIGILO-JS-001",
            "VIGILO-JS-002",
            "VIGILO-JS-003",
            "VIGILO-JS-004",
            "VIGILO-JS-005",
        }
        assert expected_ids.issubset(detector_ids)

    def test_scan_full_js_clean_fixtures_zero_false_positives(self) -> None:
        scanner = Scanner(ScanConfig(paths=[JS_CLEAN_DIR]))
        findings = scanner.scan()
        assert len(findings) == 0, f"Unexpected false positives: {[f.message for f in findings]}"

    def test_malformed_js_ts_surfaces_syntax_error_not_silently_skipped(self) -> None:
        malformed_ts = FIXTURES_DIR / "diagnostics" / "js_syntax_malformed.ts"
        unclosed_tsx = FIXTURES_DIR / "diagnostics" / "jsx_syntax_unclosed.tsx"

        scanner = Scanner(ScanConfig(paths=[malformed_ts, unclosed_tsx]))
        findings = scanner.scan()

        # Both malformed files must produce visible findings
        assert len(findings) == 2
        for f in findings:
            assert f.detector.id == "VIGILO-C01"
            assert f.category == "correctness"
            assert "Syntax error" in f.message
            assert f.language == "typescript"
            assert f.location.line >= 1
