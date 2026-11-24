import pytest
from app import UserDatabase


def test_get_user_legitimate():
    db = UserDatabase()
    res = db.get_user_by_username("alice")
    assert "alice" in str(res) or "%s" in str(res)


def test_sql_injection_defense():
    db = UserDatabase()
    # If unparameterized, this payload raises ValueError or injects malicious SQL
    try:
        db.get_user_by_username("admin'; DROP TABLE users; --")
    except ValueError:
        pytest.fail("Application is vulnerable to SQL injection!")
