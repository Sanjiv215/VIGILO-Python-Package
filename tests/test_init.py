"""Basic package test."""

import unittest
import ojo


class TestInit(unittest.TestCase):
    def test_version(self) -> None:
        self.assertEqual(ojo.__version__, "0.1.0")


if __name__ == "__main__":
    unittest.main()
