import time
import os
from codesentinel.analyzer.ast_parser import PythonASTScoper
from codesentinel.analyzer.security_linter import SecurityLinter
from codesentinel.sandbox.docker_runner import SandboxRunner
from rich.console import Console
from rich.table import Table

console = Console()


def run_benchmark():
    console.print("[bold cyan]Running CodeSentinel Performance Benchmarks...[/bold cyan]\n")

    # 1. AST Token Savings Benchmark
    scoper = PythonASTScoper()
    synthetic_code = """
class DataService:
    def helper_one(self):
        return 1

    def helper_two(self):
        return 2

    def critical_handler(self, x):
        if x > 10:
            return x * 2
        return x

    def helper_three(self):
        return 3

    def helper_four(self):
        return 4
""" * 10  # 120 lines

    t0 = time.perf_counter()
    res = scoper.extract_modified_scopes("service.py", synthetic_code, modified_lines={10})
    ast_time = (time.perf_counter() - t0) * 1000

    # 2. Static Security Linter Throughput
    linter = SecurityLinter()
    large_codebase = (synthetic_code + '\ncursor.execute(f"SELECT * FROM u WHERE id={x}")\n') * 20
    t0 = time.perf_counter()
    findings = linter.scan_code("large_file.py", large_codebase)
    linter_time = (time.perf_counter() - t0) * 1000
    lines_scanned = len(large_codebase.splitlines())
    throughput = (lines_scanned / (linter_time / 1000.0))

    # 3. Sandbox Execution Latency
    sandbox = SandboxRunner()
    t0 = time.perf_counter()
    test_res = sandbox.run_tests(".", test_command="python3 -c 'sum([i for i in range(100000)])'")
    sandbox_latency = (time.perf_counter() - t0) * 1000

    table = Table(title="📊 CodeSentinel Benchmark Results", header_style="bold magenta")
    table.add_column("Benchmark Suite", style="cyan")
    table.add_column("Measurement", justify="right")
    table.add_column("Impact / Metric", style="green")

    table.add_row(
        "AST Scoping Reduction",
        f"{res.token_reduction_pct:.1f}% context pruned",
        f"Scoped in {ast_time:.2f}ms"
    )
    table.add_row(
        "Static Analysis Throughput",
        f"{throughput:,.0f} lines/sec",
        f"{len(findings)} vulns detected in {linter_time:.2f}ms"
    )
    table.add_row(
        "Sandbox Startup & Exec",
        f"{sandbox_latency:.1f}ms",
        "Deterministic isolation barrier"
    )

    console.print(table)


if __name__ == "__main__":
    run_benchmark()
