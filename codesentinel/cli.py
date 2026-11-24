import click
import uvicorn
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

from codesentinel.agent.auditor import CodeSentinelAuditor
from codesentinel.core.config import settings

console = Console()


@click.group()
def main():
    """CodeSentinel: Autonomous Agentic Code Auditor & Sandbox Remediator."""
    pass


@main.command()
@click.option("--path", "-p", default=".", help="Path to codebase directory to audit.")
@click.option("--test-cmd", "-t", default="pytest -v", help="Command to run tests.")
def audit(path: str, test_cmd: str):
    """Run security audit and sandboxed self-healing remediation on a local codebase."""
    console.print(Panel.fit("[bold cyan]CodeSentinel[/bold cyan] [green]Autonomous Auditor[/green]", subtitle="v0.1.0"))
    if not os.path.exists(path):
        console.print(f"[bold red]Error:[/bold red] Path '{path}' does not exist.")
        sys.exit(1)

    auditor = CodeSentinelAuditor()
    with console.status("[bold green]Auditing codebase and checking sandbox..."):
        report = auditor.audit_workspace(workspace_dir=path, test_command=test_cmd)

    # Render Findings Table
    if report.security_findings:
        table = Table(title="🚨 Detected Security Vulnerabilities", header_style="bold red")
        table.add_column("Severity", justify="center")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Location", style="yellow")
        table.add_column("Description")

        for f in report.security_findings:
            table.add_row(f.severity.value, f.rule_id, f"{f.file_path}:{f.line_number}", f.title)
        console.print(table)
    else:
        console.print("[bold green]✔ No security vulnerabilities found![/bold green]")

    # Render Applied Patches
    if report.applied_patches:
        console.print("\n[bold green]🛠️ Verified Remediation Patches Applied:[/bold green]")
        for patch in report.applied_patches:
            console.print(f"[bold yellow]File:[/bold yellow] {patch.file_path} (Attempt {patch.remediation_iteration})")
            syntax = Syntax(patch.unified_diff, "diff", theme="monokai", line_numbers=True)
            console.print(syntax)

    status_color = "green" if report.is_fully_remediated else "yellow"
    console.print(f"\n[{status_color}]Result: {report.summary_markdown.splitlines()[1]}[/{status_color}]")


@main.command()
@click.option("--host", default=settings.HOST, help="Host to bind server to.")
@click.option("--port", default=settings.PORT, help="Port to listen on.")
def serve(host: str, port: int):
    """Start the CodeSentinel FastAPI Webhook Server."""
    console.print(f"[bold green]Starting CodeSentinel Server on http://{host}:{port}...[/bold green]")
    uvicorn.run("codesentinel.api.server:app", host=host, port=port, reload=False)


@main.command()
def demo():
    """Run an end-to-end interactive self-healing demonstration on an example repository."""
    console.print(Panel.fit("[bold magenta]CodeSentinel Self-Healing Demo[/bold magenta]\nSimulating PR with SQL Injection vulnerability...", border_style="magenta"))
    demo_dir = os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable_repo")
    abs_demo_dir = os.path.abspath(demo_dir)

    if not os.path.exists(abs_demo_dir):
        console.print(f"[bold red]Demo repo not found at {abs_demo_dir}[/bold red]")
        sys.exit(1)

    auditor = CodeSentinelAuditor()
    report = auditor.audit_workspace(workspace_dir=abs_demo_dir, test_command="pytest")

    console.print(f"\n[bold cyan]Audit Summary:[/bold cyan]")
    console.print(report.summary_markdown)


if __name__ == "__main__":
    main()
