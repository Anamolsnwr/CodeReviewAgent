"""Unit and integration tests for GitHub client and review posting."""

import unittest
from unittest.mock import MagicMock, patch
import requests

from codereview.models import Finding, PRFileChange, Severity
from codereview.github.client import GitHubClient
from codereview.github.review_poster import post_pr_review_comments, post_pr_summary_comment


class TestGitHubIntegration(unittest.TestCase):

    def setUp(self):
        self.client = GitHubClient(token="ghp_testfaketoken12345678901234567890123456")

    def test_invalid_repo_identifiers(self):
        with self.assertRaises(ValueError):
            self.client.get_pull_request("invalid/owner", "repo", 1)

        with self.assertRaises(ValueError):
            self.client.get_pull_request("owner", "repo; rm -rf", 1)

        with self.assertRaises(ValueError):
            self.client.get_pull_request("owner", "repo", -5)

    @patch.object(requests.Session, "request")
    def test_get_pull_request_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "title": "Add secure auth",
            "user": {"login": "alice"},
            "base": {"ref": "main"},
            "head": {"ref": "feature-auth", "sha": "c0ffee1234567890"},
            "state": "open",
            "changed_files": 3,
            "html_url": "https://github.com/org/repo/pull/42",
        }
        mock_request.return_value = mock_resp

        pr = self.client.get_pull_request("org", "repo", 42)
        self.assertEqual(pr.title, "Add secure auth")
        self.assertEqual(pr.author, "alice")
        self.assertEqual(pr.head_sha, "c0ffee1234567890")
        self.assertEqual(pr.changed_files_count, 3)

    @patch.object(requests.Session, "request")
    def test_get_pull_request_rate_limited(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 403
        mock_resp.content = b'{"message": "API rate limit exceeded"}'
        mock_resp.json.return_value = {"message": "API rate limit exceeded"}
        mock_request.return_value = mock_resp

        with self.assertRaises(PermissionError):
            self.client.get_pull_request("org", "repo", 1)

    @patch.object(requests.Session, "request")
    def test_pagination_pull_request_files(self, mock_request):
        # Page 1 returns 2 files, Link header indicates next page
        resp_page1 = MagicMock()
        resp_page1.ok = True
        resp_page1.status_code = 200
        resp_page1.headers = {"Link": '<https://api.github.com/repo/files?page=2>; rel="next"'}
        resp_page1.json.return_value = [
            {"filename": "app.py", "status": "modified", "patch": "@@ -1,2 +1,3 @@\n+print('hi')"},
            {"filename": "test.py", "status": "added", "patch": "@@ -0,0 +1,2 @@\n+pass"},
        ]

        # Page 2 returns 1 file, no next link
        resp_page2 = MagicMock()
        resp_page2.ok = True
        resp_page2.status_code = 200
        resp_page2.headers = {}
        resp_page2.json.return_value = [
            {"filename": "utils.py", "status": "modified", "patch": "@@ -5,2 +5,3 @@\n+# doc"},
        ]

        mock_request.side_effect = [resp_page1, resp_page2]

        files = self.client.get_pull_request_files("org", "repo", 1)
        self.assertEqual(len(files), 3)
        self.assertEqual(files[0].filename, "app.py")
        self.assertEqual(files[2].filename, "utils.py")

    def test_post_review_requires_explicit_confirmation(self):
        with self.assertRaises(PermissionError):
            post_pr_summary_comment(
                self.client, "owner", "repo", 1, "Summary", user_confirmed=False
            )

        with self.assertRaises(PermissionError):
            post_pr_review_comments(
                self.client, "owner", "repo", 1, "sha", [], [], user_confirmed=False
            )

    @patch.object(requests.Session, "request")
    def test_post_inline_review_filters_outside_diff_and_duplicates(self, mock_request):
        # Mock get_existing_comments returning an already posted comment on line 11
        resp_existing = MagicMock()
        resp_existing.ok = True
        resp_existing.status_code = 200
        resp_existing.json.return_value = [
            {"path": "main.py", "line": 11, "body": "Previous comment"}
        ]

        # Mock review creation POST
        resp_create = MagicMock()
        resp_create.ok = True
        resp_create.status_code = 200
        resp_create.json.return_value = {"id": 999, "status": "submitted"}

        mock_request.side_effect = [resp_existing, resp_create]

        file_change = PRFileChange(
            filename="main.py",
            status="modified",
            patch="@@ -10,3 +10,4 @@\n ctx\n+added_line_11\n+added_line_12\n",
            changed_lines=[11, 12],
        )

        findings = [
            # Line 11 is in diff, but already exists -> duplicate!
            Finding(file_path="main.py", line_number=11, rule_id="SEC1", severity=Severity.HIGH, message="Issue 1"),
            # Line 12 is in diff and new -> should be posted!
            Finding(file_path="main.py", line_number=12, rule_id="SEC2", severity=Severity.CRITICAL, message="Issue 2"),
            # Line 99 is outside diff -> must be skipped!
            Finding(file_path="main.py", line_number=99, rule_id="SEC3", severity=Severity.MEDIUM, message="Issue 3"),
        ]

        result = post_pr_review_comments(
            self.client,
            "owner",
            "repo",
            1,
            "commit_sha",
            findings,
            [file_change],
            user_confirmed=True,
        )

        self.assertEqual(result["posted_inline_count"], 1)
        self.assertEqual(result["skipped_duplicate"], 1)
        self.assertEqual(result["skipped_not_in_diff"], 1)


if __name__ == "__main__":
    unittest.main()
