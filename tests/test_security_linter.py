from codesentinel.analyzer.security_linter import SecurityLinter
from codesentinel.analyzer.models import VulnerabilitySeverity


def test_linter_detects_sqli():
    linter = SecurityLinter()
    code = 'cursor.execute(f"SELECT * FROM accounts WHERE id = {account_id}")'
    findings = linter.scan_code("accounts.py", code)
    assert len(findings) > 0
    assert any("SQL" in f.rule_id for f in findings)
    assert findings[0].severity == VulnerabilitySeverity.HIGH


def test_linter_detects_hardcoded_secrets():
    linter = SecurityLinter()
    code = 'api_key = "sk-proj-1234567890abcdef1234567890abcdef"'
    findings = linter.scan_code("config.py", code)
    assert len(findings) > 0
    assert any("SECRET" in f.rule_id or "KEY" in f.rule_id for f in findings)


def test_linter_detects_insecure_eval():
    linter = SecurityLinter()
    code = 'result = eval(user_input)'
    findings = linter.scan_code("calc.py", code)
    assert any("INSECURE-EVAL" == f.rule_id for f in findings)


def test_linter_detects_command_injection():
    linter = SecurityLinter()
    code = 'subprocess.run(f"rm -rf {path}", shell=True)'
    findings = linter.scan_code("cleaner.py", code)
    assert any("COMMAND-INJECTION" == f.rule_id for f in findings)


def test_linter_ignores_comments():
    linter = SecurityLinter()
    code = """
    # This is a comment mentioning eval() and exec()
    # Also mentioning shell=True and api_key = 'fake'
    x = 10 + 20
    """
    findings = linter.scan_code("clean.py", code)
    assert len(findings) == 0
