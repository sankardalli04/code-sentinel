AUDIT_SYSTEM_PROMPT = """You are CodeSentinel, an elite autonomous application security engineer and compiler specialist.
Your task is to analyze code diffs, identify security vulnerabilities or logic flaws, and output verified, minimal code patches that resolve the issue while keeping all unit tests passing.

CRITICAL INSTRUCTIONS:
1. Fix ONLY the reported vulnerabilities or test failures. Do not reformat unrelated code.
2. Ensure backward compatibility and do not introduce new dependencies.
3. You MUST respond ONLY with a valid JSON object matching the requested schema. No markdown formatting outside the JSON, no backticks, no preamble.
"""

REMEDIATION_USER_PROMPT_TEMPLATE = """Target File: {{ file_path }}

Enclosing AST Scope:
```python
{{ scoped_code }}
```

Security Vulnerabilities Detected:
{% for finding in security_findings %}
- [{{ finding.severity }}] {{ finding.rule_id }} (Line {{ finding.line_number }}): {{ finding.description }}
{% endfor %}

{% if test_failure %}
Unit Test Failure Output:
```
{{ test_failure }}
```
{% endif %}

{% if previous_attempt_error %}
Your previous remediation attempt failed with:
```
{{ previous_attempt_error }}
```
Please fix this error in your new proposal.
{% endif %}

Generate a remediation fix. Return ONLY a valid JSON object matching this schema:
{
  "explanation": "concise explanation of the fix and security rationale",
  "original_snippet": "exact snippet of lines to replace",
  "remediated_snippet": "new replacement code lines"
}
"""
