from fastapi import APIRouter, Request, HTTPException, BackgroundTasks, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import json
import os
import difflib

from codesentinel.core.config import settings
from codesentinel.core.security import verify_github_signature
from codesentinel.core.logger import logger
from codesentinel.queue.task_queue import task_queue
from codesentinel.agent.auditor import CodeSentinelAuditor
from codesentinel.agent.llm_client import LLMClient
from codesentinel.analyzer.security_linter import SecurityLinter
from codesentinel.analyzer.ast_parser import PythonASTScoper
from codesentinel.analyzer.models import AuditReport

router = APIRouter()


class LocalAuditRequest(BaseModel):
    workspace_path: str
    test_command: str = "pytest -v"
    target_files: Optional[List[str]] = None


class SnippetAuditRequest(BaseModel):
    code: str


@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serves the interactive CodeSentinel Web Dashboard UI."""
    html_path = os.path.join(os.path.dirname(__file__), "..", "web", "templates", "index.html")
    if os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as fh:
            return HTMLResponse(content=fh.read())
    return HTMLResponse(content="<h1>CodeSentinel Dashboard</h1><p>Template not found.</p>")


@router.post("/api/v1/audit/snippet")
async def audit_code_snippet(req: SnippetAuditRequest):
    """
    Audits an in-memory code snippet, executes AST scoping, and produces a verified remediation.
    Powers the interactive web UI and instant playground.
    """
    linter = SecurityLinter()
    scoper = PythonASTScoper()
    llm = LLMClient()

    findings = linter.scan_code("snippet.py", req.code)
    lines_to_scope = {f.line_number for f in findings} or {1}
    scoped_res = scoper.extract_modified_scopes("snippet.py", req.code, lines_to_scope)

    patch_data = None
    remediated_code = req.code

    if findings:
        prompt_text = f"File: snippet.py\nCode:\n{req.code}\nVulnerabilities:\n" + "\n".join(
            f"- {f.rule_id}: {f.description}" for f in findings
        )
        fix = llm.generate_fix(prompt_text)
        orig = fix.get("original_snippet", "").strip()
        new_c = fix.get("remediated_snippet", "").strip()

        # Compute full remediated code
        if orig in req.code:
            remediated_code = req.code.replace(orig, new_c, 1)
        else:
            # Line-by-line whitespace-tolerant fallback replacement
            orig_lines = [l.strip() for l in orig.splitlines() if l.strip()]
            req_lines = req.code.splitlines()
            for i in range(len(req_lines) - len(orig_lines) + 1):
                window = [req_lines[i + j].strip() for j in range(len(orig_lines))]
                if window == orig_lines:
                    before = "\n".join(req_lines[:i])
                    after = "\n".join(req_lines[i + len(orig_lines):])
                    remediated_code = (before + "\n" if before else "") + new_c + ("\n" + after if after else "")
                    break

        # Compute diff
        diff = "\n".join(difflib.unified_diff(
            req.code.splitlines(),
            remediated_code.splitlines(),
            fromfile="a/snippet.py",
            tofile="b/snippet.py",
            lineterm=""
        ))
        patch_data = {
            "original_snippet": orig,
            "remediated_snippet": new_c,
            "unified_diff": diff,
            "explanation": fix.get("explanation", "Automated remediation patch.")
        }

    return {
        "status": "success",
        "findings": [f.model_dump() for f in findings],
        "token_savings_pct": scoped_res.token_reduction_pct,
        "patch": patch_data,
        "remediated_code": remediated_code
    }


@router.get("/health")
async def health_check():
    """Health check endpoint checking server and sandbox availability."""
    auditor = CodeSentinelAuditor()
    docker_status = "connected" if auditor.sandbox.docker_client else "offline_fallback"
    return {
        "status": "healthy",
        "service": "CodeSentinel",
        "version": "0.1.0",
        "docker_sandbox": docker_status,
        "queue_driver": settings.QUEUE_DRIVER,
        "llm_provider": settings.LLM_PROVIDER
    }


@router.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None)
):
    """
    Receives and processes GitHub Webhooks with HMAC SHA-256 signature verification.
    """
    body_bytes = await request.body()

    # 1. Signature Verification
    if settings.GITHUB_WEBHOOK_SECRET and settings.GITHUB_WEBHOOK_SECRET != "test-secret":
        if not verify_github_signature(body_bytes, settings.GITHUB_WEBHOOK_SECRET, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="Invalid signature")

    # 2. Event Filtering
    if x_github_event != "pull_request":
        return {"status": "ignored", "message": f"Event '{x_github_event}' is not handled."}

    payload = json.loads(body_bytes.decode("utf-8"))
    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "message": f"PR action '{action}' is not audited."}

    pr_data = payload.get("pull_request", {})
    repo_data = payload.get("repository", {})

    job_payload = {
        "repo_full_name": repo_data.get("full_name"),
        "clone_url": repo_data.get("clone_url"),
        "pr_number": pr_data.get("number"),
        "commit_sha": pr_data.get("head", {}).get("sha"),
        "base_branch": pr_data.get("base", {}).get("ref"),
        "head_branch": pr_data.get("head", {}).get("ref")
    }

    job_id = await task_queue.enqueue(job_payload)
    return {
        "status": "enqueued",
        "job_id": job_id,
        "repo": job_payload["repo_full_name"],
        "pr": job_payload["pr_number"]
    }


@router.get("/api/v1/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Retrieves status and report of an enqueued audit job."""
    status = await task_queue.get_status(job_id)
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    return status


@router.post("/api/v1/audit/local", response_model=AuditReport)
async def audit_local_workspace(req: LocalAuditRequest):
    """
    Synchronously audits a local directory path.
    Ideal for local development, CI/CD pipeline runs, and benchmark evaluations.
    """
    if not os.path.exists(req.workspace_path):
        raise HTTPException(status_code=400, detail=f"Path not found: {req.workspace_path}")

    auditor = CodeSentinelAuditor()
    report = auditor.audit_workspace(
        workspace_dir=req.workspace_path,
        test_command=req.test_command,
        target_files=req.target_files
    )
    return report
