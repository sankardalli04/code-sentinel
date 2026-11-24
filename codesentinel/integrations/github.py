import httpx
from typing import Optional, Dict, Any, List
from codesentinel.core.config import settings
from codesentinel.core.logger import logger
from codesentinel.analyzer.models import AuditReport


class GitHubClient:
    """Interacts with GitHub REST API to post PR comments and submit reviews."""

    def __init__(self, token: str = settings.GITHUB_TOKEN):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CodeSentinel-Audit-Bot"
        }
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"

    async def post_pr_comment(self, repo_full_name: str, pr_number: int, body: str) -> bool:
        """Posts a general comment to a Pull Request or Issue."""
        if not self.token:
            logger.info(f"[DRY-RUN] Would post PR comment to {repo_full_name}#{pr_number}:\n{body[:300]}...")
            return True

        url = f"{self.base_url}/repos/{repo_full_name}/issues/{pr_number}/comments"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(url, headers=self.headers, json={"body": body})
                res.raise_for_status()
                logger.info(f"Successfully posted PR comment to {repo_full_name}#{pr_number}")
                return True
        except Exception as e:
            logger.error(f"Failed to post PR comment to GitHub: {e}")
            return False

    async def post_review(
        self,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
        body: str,
        event: str = "COMMENT",
        comments: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """Submits a formal PR Review with optional inline code comments."""
        if not self.token:
            logger.info(f"[DRY-RUN] Would submit {event} review to {repo_full_name}#{pr_number}")
            return True

        url = f"{self.base_url}/repos/{repo_full_name}/pulls/{pr_number}/reviews"
        payload = {
            "commit_id": commit_sha,
            "body": body,
            "event": event,
            "comments": comments or []
        }
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post(url, headers=self.headers, json=payload)
                res.raise_for_status()
                logger.info(f"Submitted PR review to {repo_full_name}#{pr_number}")
                return True
        except Exception as e:
            logger.error(f"Failed to submit PR review: {e}")
            return False

    async def report_audit_to_github(self, report: AuditReport, repo_full_name: str, pr_number: int) -> bool:
        """Convenience method to post the complete AuditReport to GitHub."""
        event = "APPROVE" if report.is_fully_remediated and not report.security_findings else "REQUEST_CHANGES"
        if not report.security_findings:
            event = "APPROVE"

        return await self.post_pr_comment(
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            body=report.summary_markdown
        )
