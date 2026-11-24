import os
import shutil
import tempfile
from codesentinel.agent.auditor import CodeSentinelAuditor
from codesentinel.agent.llm_client import LLMClient


def test_agentic_remediation_on_sample_repo():
    # Setup isolated test repo
    with tempfile.TemporaryDirectory() as tmpdir:
        sample_file = os.path.join(tmpdir, "db.py")
        with open(sample_file, "w") as fh:
            fh.write('''
class Database:
    def find_user(self, cursor, username):
        cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
        return True
''')

        # Add unit test
        test_file = os.path.join(tmpdir, "test_db.py")
        with open(test_file, "w") as fh:
            fh.write('''
from db import Database

class DummyCursor:
    def execute(self, q, p=None):
        pass

def test_find_user():
    db = Database()
    assert db.find_user(DummyCursor(), "alice") is True
''')

        auditor = CodeSentinelAuditor(llm_client=LLMClient(provider="mock"))
        report = auditor.audit_workspace(tmpdir, test_command="pytest")

        # Initial vulnerability should have been caught
        assert len(report.security_findings) > 0
        assert any("SQL" in f.rule_id for f in report.security_findings)

        # Patch should have been generated and applied
        assert len(report.applied_patches) > 0
        assert report.applied_patches[0].verified_in_sandbox is True

        # Read back modified file and verify fix was actually written
        with open(sample_file, "r") as fh:
            fixed_code = fh.read()
        assert "%s" in fixed_code
