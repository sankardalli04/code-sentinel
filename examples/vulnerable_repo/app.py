"""
Vulnerable Application Mock for CodeSentinel Demo.
Contains intentional security flaws to showcase automated AST scoping & sandboxed remediation.
"""

class MockCursor:
    def __init__(self):
        self.last_query = None
        self.last_params = None

    def execute(self, query: str, params=None):
        self.last_query = query
        self.last_params = params
        if "'; DROP TABLE" in query:
            raise ValueError("SQL Injection attack detected in mock DB!")
        return [("admin", "admin_hash")]


class UserDatabase:
    def __init__(self):
        self.cursor = MockCursor()

    def get_user_by_username(self, username: str):
        # VULNERABLE: Direct f-string interpolation into SQL statement (CWE-89)
        cursor = self.cursor
        cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
        return self.cursor.last_query
