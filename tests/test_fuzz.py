"""Property-based fuzz testing using Hypothesis."""

import tempfile
import unittest
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from vigilo.scanner import ScanConfig, Scanner


class TestFuzzing(unittest.TestCase):
    @settings(max_examples=100, deadline=None)  # type: ignore[untyped-decorator]
    @given(st.binary(min_size=0, max_size=3000))  # type: ignore[untyped-decorator]
    def test_fuzz_arbitrary_bytes(self, data: bytes) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "fuzz.py"
            p.write_bytes(data)
            config = ScanConfig(paths=[p])
            scanner = Scanner(config)
            findings = scanner.scan()
            self.assertIsInstance(findings, list)

    @settings(max_examples=100, deadline=None)  # type: ignore[untyped-decorator]
    @given(st.text(min_size=0, max_size=3000))  # type: ignore[untyped-decorator]
    def test_fuzz_arbitrary_text(self, text: str) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "fuzz.py"
            p.write_text(text, encoding="utf-8", errors="replace")
            config = ScanConfig(paths=[p])
            scanner = Scanner(config)
            findings = scanner.scan()
            self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
