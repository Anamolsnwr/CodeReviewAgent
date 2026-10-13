"""GitHub API Client for fetching PR metadata, changed files, and contents."""

import base64
import logging
import os
import requests
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv

from codereview.models import PRMetadata, PRFileChange
from codereview.github.diff_parser import parse_patch_changed_lines
from codereview.utils.security import (
    redact_sensitive_text,
    validate_repo_identifier,
    validate_pull_number,
)

logger = logging.getLogger(__name__)


class GitHubClient:
    """REST API Client for GitHub with secure authentication, timeouts, and pagination."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: Optional[str] = None, timeout: int = 15):
        load_dotenv()
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.timeout = timeout
        self.session = requests.Session()

        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "CodeReviewAgent/2.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        self.session.headers.update(headers)

    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        url = f"{self.BASE_URL}{endpoint}" if endpoint.startswith("/") else endpoint
        kwargs.setdefault("timeout", self.timeout)

        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            safe_msg = redact_sensitive_text(str(exc))
            logger.error(f"GitHub network request failed: {safe_msg}")
            raise RuntimeError(f"Network error connecting to GitHub: {safe_msg}")

        if resp.status_code == 401:
            raise PermissionError("GitHub authentication failed: Bad credentials or expired token.")
        elif resp.status_code == 403:
            msg = resp.json().get("message", "Forbidden or rate limit exceeded.") if resp.content else "Forbidden"
            raise PermissionError(f"GitHub API forbidden / rate limited: {redact_sensitive_text(msg)}")
        elif resp.status_code == 404:
            raise FileNotFoundError(f"Requested GitHub resource not found at {endpoint}.")
        elif not resp.ok:
            err_text = redact_sensitive_text(resp.text[:200])
            raise RuntimeError(f"GitHub API error ({resp.status_code}): {err_text}")

        return resp

    def get_pull_request(self, owner: str, repo: str, pull_number: int) -> PRMetadata:
        """Fetches PR metadata."""
        valid_repo, repo_err = validate_repo_identifier(owner, repo)
        if not valid_repo:
            raise ValueError(repo_err)

        valid_pr, pr_num, pr_err = validate_pull_number(pull_number)
        if not valid_pr:
            raise ValueError(pr_err)

        resp = self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_num}")
        data = resp.json()

        return PRMetadata(
            owner=owner,
            repo=repo,
            pull_number=pr_num,
            title=data.get("title", ""),
            author=data.get("user", {}).get("login", "unknown"),
            base_branch=data.get("base", {}).get("ref", "main"),
            head_branch=data.get("head", {}).get("ref", ""),
            head_sha=data.get("head", {}).get("sha", ""),
            state=data.get("state", "open"),
            changed_files_count=data.get("changed_files", 0),
            html_url=data.get("html_url", ""),
        )

    def get_pull_request_files(self, owner: str, repo: str, pull_number: int, max_files: int = 150) -> List[PRFileChange]:
        """Fetches all changed files in a pull request with pagination."""
        valid_repo, repo_err = validate_repo_identifier(owner, repo)
        if not valid_repo:
            raise ValueError(repo_err)

        valid_pr, pr_num, pr_err = validate_pull_number(pull_number)
        if not valid_pr:
            raise ValueError(pr_err)

        changed_files: List[PRFileChange] = []
        page = 1
        per_page = 50

        while len(changed_files) < max_files:
            resp = self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{pr_num}/files",
                params={"page": page, "per_page": per_page},
            )
            items = resp.json()
            if not items:
                break

            for item in items:
                filename = item.get("filename", "")
                status = item.get("status", "modified")
                patch = item.get("patch")
                is_bin = patch is None and status != "removed"

                changed_lines = []
                if patch:
                    changed_lines, _ = parse_patch_changed_lines(patch)

                changed_files.append(PRFileChange(
                    filename=filename,
                    status=status,
                    additions=item.get("additions", 0),
                    deletions=item.get("deletions", 0),
                    patch=patch,
                    changed_lines=changed_lines,
                    old_filename=item.get("previous_filename"),
                    is_binary=is_bin,
                ))

                if len(changed_files) >= max_files:
                    break

            # Check next page via Link header
            link_header = resp.headers.get("Link", "")
            if 'rel="next"' not in link_header:
                break

            page += 1

        return changed_files

    def get_file_content(self, owner: str, repo: str, path: str, ref: str) -> str:
        """Fetches the raw text content of a file at a specific Git ref."""
        resp = self._request(
            "GET",
            f"/repos/{owner}/{repo}/contents/{path}",
            params={"ref": ref},
        )
        data = resp.json()

        if isinstance(data, dict) and "content" in data:
            encoding = data.get("encoding", "base64")
            raw_bytes = data["content"].encode("utf-8")
            if encoding == "base64":
                return base64.b64decode(raw_bytes).decode("utf-8", errors="replace")
            return raw_bytes.decode("utf-8", errors="replace")

        # If data is list or other structure, fallback
        raise ValueError(f"Unable to read file content for path {path}")
