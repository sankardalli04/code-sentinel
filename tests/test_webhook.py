import hmac
import hashlib
import json
from fastapi.testclient import TestClient
from codesentinel.api.server import app
from codesentinel.core.security import verify_github_signature

client = TestClient(app)


def test_signature_verification():
    secret = "my-secret-key"
    payload = b'{"action": "opened"}'
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    assert verify_github_signature(payload, secret, sig) is True
    assert verify_github_signature(payload, secret, "sha256=invalid") is False
    assert verify_github_signature(payload, secret, None) is False


def test_dashboard_ui_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "CodeSentinel" in response.text
    assert "AST Scope Pruning" in response.text


def test_audit_snippet_endpoint():
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    response = client.post("/api/v1/audit/snippet", json={"code": code})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert len(data["findings"]) > 0
    assert data["patch"] is not None


def test_webhook_enqueues_valid_pr():
    payload = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "head": {"sha": "abcdef123456", "ref": "feature/fix-sql"},
            "base": {"ref": "main"}
        },
        "repository": {
            "full_name": "sankardalli04/demo-repo",
            "clone_url": "https://github.com/sankardalli04/demo-repo.git"
        }
    }
    response = client.post(
        "/webhook/github",
        json=payload,
        headers={"X-GitHub-Event": "pull_request"}
    )
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "enqueued"
    assert res["pr"] == 42
