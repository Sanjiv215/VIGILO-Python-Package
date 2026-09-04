"""Unit tests for AST local data-flow analysis."""

import ast
import unittest

from ojo.flow import FlowAnalyzer


class TestFlowAnalyzer(unittest.TestCase):
    def test_is_constant_literals(self) -> None:
        tree = ast.parse("x = 'hello'; y = 123; z = True; n = None; l = [1, 2]; d = {'k': 'v'}")
        for stmt in tree.body:
            assert isinstance(stmt, ast.Assign)
            self.assertTrue(
                FlowAnalyzer.is_constant(stmt.value),
                f"Failed for {ast.dump(stmt.value)}",
            )

    def test_is_constant_fstrings(self) -> None:
        # Constant f-string (literal inner values)
        tree1 = ast.parse('f"count: {10}"')
        expr1 = tree1.body[0].value  # type: ignore[attr-defined]
        self.assertTrue(FlowAnalyzer.is_constant(expr1))

        # Dynamic f-string (variable inner value)
        tree2 = ast.parse('f"user: {username}"')
        expr2 = tree2.body[0].value  # type: ignore[attr-defined]
        self.assertFalse(FlowAnalyzer.is_constant(expr2))

    def test_is_constant_binop(self) -> None:
        tree = ast.parse('"SELECT * FROM " + "users"')
        expr = tree.body[0].value  # type: ignore[attr-defined]
        self.assertTrue(FlowAnalyzer.is_constant(expr))
        self.assertEqual(FlowAnalyzer.get_constant_value(expr), "SELECT * FROM users")

    def test_is_parameter(self) -> None:
        code = "def handler(req, id: int, *args, **kwargs): pass"
        tree = ast.parse(code)
        func = tree.body[0]
        assert isinstance(func, ast.FunctionDef)

        self.assertTrue(FlowAnalyzer.is_parameter("req", func))
        self.assertTrue(FlowAnalyzer.is_parameter("id", func))
        self.assertTrue(FlowAnalyzer.is_parameter("args", func))
        self.assertTrue(FlowAnalyzer.is_parameter("kwargs", func))
        self.assertFalse(FlowAnalyzer.is_parameter("other", func))

    def test_trace_assignment_and_is_dynamic(self) -> None:
        code = """
def test_func(user_input):
    safe_var = "SELECT 1"
    dynamic_var = user_input
    alias_var = dynamic_var
    eval(safe_var)
    eval(dynamic_var)
    eval(alias_var)
"""
        tree = ast.parse(code)
        func = tree.body[0]
        assert isinstance(func, ast.FunctionDef)

        # safe_var is constant
        safe_call = func.body[3].value  # type: ignore[attr-defined]
        self.assertFalse(FlowAnalyzer.is_dynamic(safe_call.args[0], func))

        # dynamic_var is from parameter
        dyn_call = func.body[4].value  # type: ignore[attr-defined]
        self.assertTrue(FlowAnalyzer.is_dynamic(dyn_call.args[0], func))

        # alias_var traces to dynamic_var which traces to user_input parameter
        alias_call = func.body[5].value  # type: ignore[attr-defined]
        self.assertTrue(FlowAnalyzer.is_dynamic(alias_call.args[0], func))


if __name__ == "__main__":
    unittest.main()
