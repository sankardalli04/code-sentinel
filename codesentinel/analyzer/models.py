from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ASTScope(BaseModel):
    """Represents a specific syntactic scope (function, class, method) parsed from an AST."""
    name: str
    scope_type: str  # "function", "class", "async_function"
    start_line: int
    end_line: int
    source_code: str
    cyclomatic_complexity: int = 1


class ScopedDiffResult(BaseModel):
    """Result of scoping a file's diff to its enclosing AST boundaries."""
    file_path: str
    total_file_lines: int
    scoped_lines_count: int
    token_reduction_pct: float
    scopes: List[ASTScope] = Field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    """Represents a static or semantic security finding."""
    rule_id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    file_path: str
    line_number: int
    code_snippet: str
    cwe_id: Optional[str] = None
    suggested_fix: Optional[str] = None


class SandboxTestResult(BaseModel):
    """Output from executing tests within the isolated sandbox."""
    passed: bool
    exit_code: int
    stdout: str
    stderr: str
    execution_time_seconds: float
    total_tests: int = 0
    failed_tests: int = 0
    error_summary: Optional[str] = None


class PatchProposal(BaseModel):
    """Proposed remediation patch for a specific file."""
    file_path: str
    original_snippet: str
    remediated_snippet: str
    unified_diff: str
    explanation: str
    remediation_iteration: int = 1
    verified_in_sandbox: bool = False


class AuditReport(BaseModel):
    """Complete end-to-end audit and remediation report."""
    repository: str
    pull_request_number: Optional[int] = None
    commit_sha: str
    security_findings: List[VulnerabilityFinding] = Field(default_factory=list)
    initial_sandbox_test: Optional[SandboxTestResult] = None
    applied_patches: List[PatchProposal] = Field(default_factory=list)
    final_sandbox_test: Optional[SandboxTestResult] = None
    is_fully_remediated: bool = False
    token_savings_pct: float = 0.0
    summary_markdown: str = ""
