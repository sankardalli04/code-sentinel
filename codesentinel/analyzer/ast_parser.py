import ast
from typing import List, Set, Tuple
from codesentinel.analyzer.models import ASTScope, ScopedDiffResult
from codesentinel.core.logger import logger


class ComplexityVisitor(ast.NodeVisitor):
    """Calculates McCabe Cyclomatic Complexity of an AST node."""
    def __init__(self):
        self.complexity = 1

    def visit_If(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_With(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncWith(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        self.complexity += len(node.values) - 1
        self.generic_visit(node)


class PythonASTScoper:
    """
    Extracts precise AST scopes (functions, classes, methods) enclosing modified line numbers.
    Drastically reduces context window usage and eliminates hallucination.
    """

    @staticmethod
    def calculate_complexity(node: ast.AST) -> int:
        visitor = ComplexityVisitor()
        visitor.visit(node)
        return visitor.complexity

    def parse_scopes(self, source_code: str) -> List[Tuple[ASTScope, ast.AST]]:
        """Parses all top-level and method scopes in the source file."""
        scopes: List[Tuple[ASTScope, ast.AST]] = []
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            logger.warning(f"Failed to parse AST (SyntaxError): {e}")
            return []

        lines = source_code.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start_line = node.lineno
                end_line = getattr(node, "end_lineno", start_line)
                scope_type = (
                    "class" if isinstance(node, ast.ClassDef)
                    else "async_function" if isinstance(node, ast.AsyncFunctionDef)
                    else "function"
                )
                scope_code = "\n".join(lines[start_line - 1 : end_line])
                complexity = self.calculate_complexity(node)

                scope = ASTScope(
                    name=node.name,
                    scope_type=scope_type,
                    start_line=start_line,
                    end_line=end_line,
                    source_code=scope_code,
                    cyclomatic_complexity=complexity
                )
                scopes.append((scope, node))

        return scopes

    def extract_modified_scopes(
        self,
        file_path: str,
        source_code: str,
        modified_lines: Set[int]
    ) -> ScopedDiffResult:
        """
        Filters scopes to only those enclosing the modified lines.
        Calculates token/line reduction percentage.
        """
        all_scopes = self.parse_scopes(source_code)
        selected_scopes: List[ASTScope] = []
        covered_lines: Set[int] = set()

        for scope, _ in all_scopes:
            # Check if any modified line intersects with this scope
            scope_lines = set(range(scope.start_line, scope.end_line + 1))
            if modified_lines.intersection(scope_lines):
                # Avoid adding child functions if already captured, or add distinct scopes
                selected_scopes.append(scope)
                covered_lines.update(scope_lines)

        total_lines = len(source_code.splitlines())
        scoped_lines_count = len(covered_lines) if selected_scopes else total_lines

        if not selected_scopes and total_lines > 0:
            # Fallback if no specific function was touched (e.g. module-level script)
            reduction_pct = 0.0
        else:
            reduction_pct = max(0.0, round((1.0 - (scoped_lines_count / max(total_lines, 1))) * 100, 2))

        return ScopedDiffResult(
            file_path=file_path,
            total_file_lines=total_lines,
            scoped_lines_count=scoped_lines_count,
            token_reduction_pct=reduction_pct,
            scopes=selected_scopes
        )
