"""GitHub review publisher with diff validation, deduplication, and mandatory user authorization."""

import logging
from typing import Any, Dict, List, Optional
from codereview.models import Finding, PRFileChange
from codereview.github.client import GitHubClient
from codereview.github.diff_parser import parse_patch_changed_lines
from codereview.utils.security import redact_sensitive_text

logger = logging.getLogger(__name__)


def get_existing_comments(
    client: GitHubClient, owner: str, repo: str, pull_number: int
) -> List[Dict[str, Any]]:
    """Fetches existing pull request review comments to prevent duplicate submissions."""
    try:
        resp = client._request("GET", f"/repos/{owner}/{repo}/pulls/{pull_number}/comments")
        return resp.json()
    except Exception as e:
        logger.warning(f"Could not fetch existing comments for PR #{pull_number}: {redact_sensitive_text(str(e))}")
        return []


def post_pr_summary_comment(
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
    summary_markdown: str,
    user_confirmed: bool = False,
) -> Dict[str, Any]:
    """Posts an executive review summary comment to a pull request.

    REQUIRES explicit user confirmation.
    """
    if not user_confirmed:
        raise PermissionError("Explicit user authorization is required before publishing comments to GitHub.")

    # Deduplication check: check recent issue comments
    try:
        existing = client._request("GET", f"/repos/{owner}/{repo}/issues/{pull_number}/comments").json()
        for comm in existing:
            # Check if this exact summary or fingerprint was already posted
            if "Automated Pull Request Review Summary" in comm.get("body", "") and summary_markdown.strip() in comm.get("body", ""):
                logger.info("PR summary already exists. Skipping duplicate post.")
                return {"status": "skipped", "reason": "duplicate", "comment_id": comm.get("id")}
    except Exception as e:
        logger.debug(f"Could not verify existing issue comments: {e}")

    payload = {"body": summary_markdown}
    resp = client._request(
        "POST",
        f"/repos/{owner}/{repo}/issues/{pull_number}/comments",
        json=payload,
    )
    return resp.json()


def post_pr_review_comments(
    client: GitHubClient,
    owner: str,
    repo: str,
    pull_number: int,
    commit_sha: str,
    findings: List[Finding],
    file_changes: List[PRFileChange],
    summary_text: str = "CodeReviewAgent Findings",
    user_confirmed: bool = False,
) -> Dict[str, Any]:
    """Publishes inline diff review comments on changed files.

    Validates that each line corresponds to an active hunk in the diff before submitting,
    and filters out findings that have already been commented on.
    """
    if not user_confirmed:
        raise PermissionError("Explicit user authorization is required before publishing review comments to GitHub.")

    existing_comments = get_existing_comments(client, owner, repo, pull_number)
    existing_comment_keys = set()
    for c in existing_comments:
        path = c.get("path", "")
        line = c.get("line") or c.get("original_line")
        body = c.get("body", "")
        existing_comment_keys.add(f"{path}:{line}")

    # Map filename to set of changed lines in diff
    file_diff_map: Dict[str, Tuple[List[int], Dict[int, int]]] = {}
    for fc in file_changes:
        if fc.patch:
            changed_lines, pos_map = parse_patch_changed_lines(fc.patch)
            file_diff_map[fc.filename] = (changed_lines, pos_map)

    valid_comments: List[Dict[str, Any]] = []
    skipped_not_in_diff = 0
    skipped_duplicate = 0

    for f in findings:
        diff_info = file_diff_map.get(f.file_path)
        if not diff_info:
            skipped_not_in_diff += 1
            continue

        changed_lines, pos_map = diff_info
        # GitHub review API requires the comment line to be part of the diff
        if f.line_number not in pos_map:
            skipped_not_in_diff += 1
            continue

        comment_key = f"{f.file_path}:{f.line_number}"
        if comment_key in existing_comment_keys:
            skipped_duplicate += 1
            continue

        comment_body = (
            f"**[{f.severity.value}] {f.rule_id}**: {f.message}\n\n"
            f"{f.explanation}\n\n"
            f"💡 **Recommendation**: {f.suggestion or 'Review and address this issue.'}\n\n"
            f"*(Reported by CodeReviewAgent - ID: `{f.fingerprint}`)*"
        )

        valid_comments.append({
            "path": f.file_path,
            "line": f.line_number,
            "side": "RIGHT",
            "body": comment_body,
        })
        existing_comment_keys.add(comment_key)

    if not valid_comments and not summary_text:
        return {
            "status": "noop",
            "message": "No new comments to post (all findings either outside diff or already commented).",
            "skipped_not_in_diff": skipped_not_in_diff,
            "skipped_duplicate": skipped_duplicate,
        }

    # Submit review as COMMENT event (never automatically approve or request changes)
    payload = {
        "commit_id": commit_sha,
        "body": summary_text,
        "event": "COMMENT",
        "comments": valid_comments,
    }

    resp = client._request(
        "POST",
        f"/repos/{owner}/{repo}/pulls/{pull_number}/reviews",
        json=payload,
    )
    res_data = resp.json()
    res_data["posted_inline_count"] = len(valid_comments)
    res_data["skipped_not_in_diff"] = skipped_not_in_diff
    res_data["skipped_duplicate"] = skipped_duplicate
    return res_data
