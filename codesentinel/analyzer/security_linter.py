import re
import ast
import shutil
import subprocess
import json
from typing import List, Optional
from codesentinel.analyzer.models import VulnerabilityFinding, VulnerabilitySeverity
from codesentinel.core.logger import logger


class SecurityLinter:
    """
    Dual-engine security analyzer:
    1. Built-in AST and Semantic rules for OWASP Top 10 vulnerabilities.
    2. Semgrep / Bandit integration if installed on host.
    """

    SECRET_PATTERNS = [
        (r"(?i)(api[_-]?key|secret|token|password|auth[_-]?key)\s*=\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]", "HARDCODED-SECRET", "Potential hardcoded secret or API credential detected", VulnerabilitySeverity.CRITICAL, "CWE-798"),
        (r"(?i)ghp_[A-Za-z0-9]{36}", "GITHUB-PAT", "GitHub Personal Access Token exposed", VulnerabilitySeverity.CRITICAL, "CWE-798"),
        (r"(?i)sk-[A-Za-z0-9]{32,}", "OPENAI-KEY", "OpenAI / LLM API Key exposed", VulnerabilitySeverity.CRITICAL, "CWE-798"),
        (r"eval\s*\((.*?)\)", "INSECURE-EVAL", "Dynamic code evaluation via eval() allows arbitrary code execution", VulnerabilitySeverity.CRITICAL, "CWE-95"),
        (r"exec\s*\((.*?)\)", "INSECURE-EXEC", "Dynamic code execution via exec() allows arbitrary code execution", VulnerabilitySeverity.CRITICAL, "CWE-95"),
        (r"(os\.system|subprocess\.Popen|subprocess\.call|subprocess\.run)\s*\([^)]*shell\s*=\s*True[^)]*\)", "COMMAND-INJECTION", "Subprocess invocation with shell=True enables OS command injection", VulnerabilitySeverity.HIGH, "CWE-78"),
        (r"(?i)f['\"][^'\"]*?\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b.*?\{.*?\}", "SQL-INJECTION-FORMAT", "SQL query constructed with f-string interpolation exposes database to SQL injection", VulnerabilitySeverity.HIGH, "CWE-89"),
        (r"(?i)[\'\"][^\'\"]*?\b(SELECT|INSERT|UPDATE|DELETE)\b.*?[\'\"]\s*%\s*\(", "SQL-INJECTION-PERCENT", "SQL query formatted using % operator exposes database to SQL injection", VulnerabilitySeverity.HIGH, "CWE-89"),
        (r"(?i)[\'\"][^\'\"]*?\b(SELECT|INSERT|UPDATE|DELETE)\b.*?[\'\"]\s*\+\s*[a-zA-Z_]", "SQL-INJECTION-CONCAT", "SQL query constructed with string concatenation exposes database to SQL injection", VulnerabilitySeverity.HIGH, "CWE-89"),
        (r"cursor\.execute\s*\(\s*f['\"].*?\{.*?\}", "SQL-INJECTION-FORMAT", "SQL query constructed with f-string interpolation exposes database to SQL injection", VulnerabilitySeverity.HIGH, "CWE-89"),
        (r"cursor\.execute\s*\(\s*['\"].*?%\s*\(", "SQL-INJECTION-PERCENT", "SQL query formatted using % operator exposes database to SQL injection", VulnerabilitySeverity.HIGH, "CWE-89"),
        (r"pickle\.loads\s*\(", "INSECURE-DESERIALIZATION", "Unpickling untrusted data leads to remote code execution", VulnerabilitySeverity.HIGH, "CWE-502"),
        (r"hashlib\.(md5|sha1)\s*\(", "WEAK-CRYPTO-HASH", "Use of MD5/SHA1 is cryptographically broken; use SHA256 or bcrypt/argon2", VulnerabilitySeverity.MEDIUM, "CWE-328"),
        (r"open\s*\(\s*f['\"].*?\{.*?\}", "PATH-TRAVERSAL", "Dynamic path construction in open() exposes application to path traversal", VulnerabilitySeverity.HIGH, "CWE-22"),
        (r"random\.(random|randint|choice)\s*\(", "INSECURE-RANDOM", "Pseudo-random generator used; use secrets module for secure tokens", VulnerabilitySeverity.MEDIUM, "CWE-338"),
        (r"(?i)debug\s*=\s*True", "DEBUG-MODE-ENABLED", "Debug mode enabled exposes internal stack traces in production", VulnerabilitySeverity.LOW, "CWE-489"),
    ]

    def scan_code(self, file_path: str, source_code: str) -> List[VulnerabilityFinding]:
        """Runs the built-in rule scanner across the source code."""
        findings: List[VulnerabilityFinding] = []
        lines = source_code.splitlines()

        for idx, line in enumerate(lines, start=1):
            # Ignore comments so comments like '# no eval()' never trigger false positives
            code_line = line.split("#")[0].strip()
            if not code_line:
                continue

            for pattern, rule_id, desc, severity, cwe in self.SECRET_PATTERNS:
                if re.search(pattern, code_line):
                    finding = VulnerabilityFinding(
                        rule_id=rule_id,
                        title=f"{rule_id}: {desc.split(';')[0]}",
                        description=desc,
                        severity=severity,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=line.strip(),
                        cwe_id=cwe,
                        suggested_fix="Parametrize queries, use environment variables, or replace with secure equivalents."
                    )
                    findings.append(finding)

        # AST-level deep check for SQL injections in execute calls and variable assignments
        try:
            tree = ast.parse(source_code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                        if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                            findings.append(
                                VulnerabilityFinding(
                                    rule_id="AST-SQL-INJECTION",
                                    title="Dynamic SQL Query in DB Cursor Execution",
                                    description="Found dynamic string concatenation/interpolation in database query call. Use query parameters.",
                                    severity=VulnerabilitySeverity.HIGH,
                                    file_path=file_path,
                                    line_number=node.lineno,
                                    code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                    cwe_id="CWE-89",
                                    suggested_fix="Use parameterized queries e.g., cursor.execute('SELECT * FROM t WHERE id = %s', (id,))"
                                )
                            )
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        target_name = getattr(target, "id", "")
                        if any(kw in target_name.lower() for kw in ("query", "sql", "stmt", "statement")):
                            if isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
                                if not any(f.line_number == node.lineno for f in findings):
                                    findings.append(
                                        VulnerabilityFinding(
                                            rule_id="AST-SQL-INJECTION",
                                            title="Dynamic SQL Query in Variable Assignment",
                                            description="Found dynamic string concatenation/interpolation in SQL statement variable. Use parameterized queries.",
                                            severity=VulnerabilitySeverity.HIGH,
                                            file_path=file_path,
                                            line_number=node.lineno,
                                            code_snippet=lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                                            cwe_id="CWE-89",
                                            suggested_fix="Use parameterized queries e.g., cursor.execute('SELECT * FROM t WHERE id = %s', (id,))"
                                        )
                                    )
        except SyntaxError:
            pass

        return findings

    def scan_with_semgrep(self, repo_dir: str) -> List[VulnerabilityFinding]:
        """Optional Semgrep integration when binary is present in path."""
        if not shutil.which("semgrep"):
            return []

        findings: List[VulnerabilityFinding] = []
        try:
            cmd = ["semgrep", "--config=auto", "--json", repo_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode in (0, 1) and result.stdout:
                data = json.loads(result.stdout)
                for item in data.get("results", []):
                    sev_map = {
                        "ERROR": VulnerabilitySeverity.HIGH,
                        "WARNING": VulnerabilitySeverity.MEDIUM,
                        "INFO": VulnerabilitySeverity.LOW
                    }
                    finding = VulnerabilityFinding(
                        rule_id=item.get("check_id", "SEMGREP-RULE"),
                        title=item.get("extra", {}).get("message", "Semgrep Security Finding"),
                        description=item.get("extra", {}).get("message", ""),
                        severity=sev_map.get(item.get("extra", {}).get("severity"), VulnerabilitySeverity.MEDIUM),
                        file_path=item.get("path", ""),
                        line_number=item.get("start", {}).get("line", 1),
                        code_snippet=item.get("extra", {}).get("lines", ""),
                        cwe_id=item.get("extra", {}).get("metadata", {}).get("cwe", [None])[0] if isinstance(item.get("extra", {}).get("metadata", {}).get("cwe"), list) else None
                    )
                    findings.append(finding)
        except Exception as e:
            logger.warning(f"Semgrep execution skipped/failed: {e}")

        return findings
