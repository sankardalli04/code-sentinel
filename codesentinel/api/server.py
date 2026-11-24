import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from codesentinel.api.routes import router
from codesentinel.queue.task_queue import task_queue, MemoryTaskQueue
from codesentinel.agent.auditor import CodeSentinelAuditor
from codesentinel.integrations.github import GitHubClient
from codesentinel.core.logger import logger
from codesentinel.core.config import settings


async def process_job(payload: dict) -> dict:
    """Async background worker job processor."""
    logger.info(f"Processing webhook job for {payload.get('repo_full_name')} PR #{payload.get('pr_number')}")
    # In a full git environment, this would clone the PR branch into a temp directory
    # and run the auditor.
    auditor = CodeSentinelAuditor()
    # For demonstration / local simulation:
    report = auditor.audit_workspace(workspace_dir=".", test_command="pytest")

    # Post back to GitHub
    gh = GitHubClient()
    if payload.get("repo_full_name") and payload.get("pr_number"):
        await gh.report_audit_to_github(
            report=report,
            repo_full_name=payload["repo_full_name"],
            pr_number=payload["pr_number"]
        )

    return report.model_dump()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Start background queue worker
    worker_task = asyncio.create_task(task_queue.start_worker(process_job))
    logger.info("CodeSentinel API service initialized.")
    yield
    # Shutdown
    worker_task.cancel()
    logger.info("CodeSentinel API service shutting down.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="CodeSentinel",
        description="Autonomous Agentic Code Auditor & Isolated Sandbox Remediator",
        version="0.1.0",
        lifespan=lifespan
    )
    app.include_router(router)
    return app


app = create_app()
