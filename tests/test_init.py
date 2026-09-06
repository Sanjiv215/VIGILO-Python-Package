"""Basic package test for Vigilo."""

import unittest

import vigilo


class TestInit(unittest.TestCase):
    def test_version(self) -> None:
        self.assertEqual(vigilo.__version__, "0.3.1")


if __name__ == "__main__":
    unittest.main()
