import pytest
from codesentinel.analyzer.ast_parser import PythonASTScoper


def test_ast_scoper_extracts_function():
    code = """
def calculate_discount(price, is_member):
    if is_member:
        return price * 0.9
    return price

def log_activity(msg):
    print(msg)
"""
    scoper = PythonASTScoper()
    # Modify line 3 (inside calculate_discount)
    result = scoper.extract_modified_scopes("pricing.py", code, modified_lines={3})

    assert len(result.scopes) == 1
    assert result.scopes[0].name == "calculate_discount"
    assert result.scopes[0].cyclomatic_complexity == 2
    assert result.token_reduction_pct > 0


def test_ast_complexity_calculation():
    code = """
def complex_logic(x, y, z):
    if x > 0:
        for i in range(y):
            if z:
                while x > 10:
                    x -= 1
    return x
"""
    scoper = PythonASTScoper()
    scopes = scoper.parse_scopes(code)
    assert len(scopes) == 1
    # Base complexity (1) + if (1) + for (1) + if (1) + while (1) = 5
    assert scopes[0][0].cyclomatic_complexity == 5
