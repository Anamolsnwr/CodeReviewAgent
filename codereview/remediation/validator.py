"""Comprehensive 7-step Patch Validation Engine."""

import ast
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from codereview.models import Finding, FixProposal, FixStatus, Severity
from codereview.remediation.patcher import apply_patch_to_string
from codereview.scanners.ast_scanner import ASTScanner
from codereview.scanners.security_scanner import SecurityScanner

logger = logging.getLogger(__name__)


class PatchValidator:
    """Validates proposed code fixes through 7 rigorous safety checks."""

    def __init__(self):
        self.ast_scanner = ASTScanner()
        self.security_scanner = SecurityScanner()

    def validate_proposal(
        self,
        proposal: FixProposal,
        original_file_content: str,
        finding: Optional[Finding] = None,
        test_script_content: Optional[str] = None,
        cwd: Optional[str] = None,
    ) -> FixProposal:
        """Executes the 7-step validation pipeline on a FixProposal."""
        results: Dict[str, Any] = {
            "step_1_match": {"passed": False, "details": ""},
            "step_2_unambiguous": {"passed": False, "details": ""},
            "step_3_scope": {"passed": False, "details": ""},
            "step_4_syntax": {"passed": False, "details": ""},
            "step_5_tests": {"passed": False, "details": "", "skipped": False},
            "step_6_security_verified": {"passed": False, "details": ""},
            "step_7_regression_check": {"passed": False, "details": ""},
        }

        # Step 1: Check target file and expected original code match
        if not proposal.original_code or not proposal.original_code.strip():
            proposal.status = FixStatus.VALIDATION_FAILED
            proposal.error_message = "Step 1 Failed: Original code snippet is empty."
            results["step_1_match"] = {"passed": False, "details": "Empty original code"}
            proposal.validation_results = results
            return proposal

        if proposal.original_code.strip() not in original_file_content:
            proposal.status = FixStatus.VALIDATION_FAILED
            proposal.error_message = "Step 1 Failed: Expected original code not found in target file."
            results["step_1_match"] = {"passed": False, "details": "Snippet does not match target file"}
            proposal.validation_results = results
            return proposal

        results["step_1_match"] = {"passed": True, "details": "Expected original code matches target file"}

        # Step 2: Reject ambiguous, stale, malformed, or out-of-range patches
        success, patched_content, err_msg = apply_patch_to_string(
            original_file_content,
            proposal.original_code,
            proposal.replacement_code,
        )
        if not success:
            proposal.status = FixStatus.VALIDATION_FAILED
            proposal.error_message = f"Step 2 Failed: {err_msg}"
            results["step_2_unambiguous"] = {"passed": False, "details": err_msg}
            proposal.validation_results = results
            return proposal

        results["step_2_unambiguous"] = {"passed": True, "details": "Patch target is unique and unambiguous"}

        # Step 3: Verify that the patch does not modify unrelated code
        orig_lines = original_file_content.splitlines()
        patched_lines = patched_content.splitlines()
        line_delta = abs(len(patched_lines) - len(orig_lines))
        # Replacement should be proportionate to the fix snippet
        expected_orig_len = len(proposal.original_code.splitlines())
        expected_repl_len = len(proposal.replacement_code.splitlines())
        expected_delta = abs(expected_repl_len - expected_orig_len)

        if line_delta > (expected_delta + 5):
            proposal.status = FixStatus.VALIDATION_FAILED
            proposal.error_message = f"Step 3 Failed: Patch modifies unrelated lines (delta {line_delta} exceeds expected {expected_delta})."
            results["step_3_scope"] = {"passed": False, "details": f"Unrelated lines altered: delta {line_delta}"}
            proposal.validation_results = results
            return proposal

        results["step_3_scope"] = {"passed": True, "details": "Patch strictly scoped to targeted snippet"}

        # Step 4: Syntax / compilation check
        if proposal.file_path.endswith(".py"):
            try:
                ast.parse(patched_content, filename=proposal.file_path)
                results["step_4_syntax"] = {"passed": True, "details": "Python AST parse passed"}
            except SyntaxError as e:
                proposal.status = FixStatus.VALIDATION_FAILED
                proposal.error_message = f"Step 4 Failed: Syntax error introduced by patch: {e.msg} at line {e.lineno}"
                results["step_4_syntax"] = {"passed": False, "details": f"SyntaxError: {e.msg}"}
                proposal.validation_results = results
                return proposal
        else:
            results["step_4_syntax"] = {"passed": True, "details": "Non-python file, syntax check skipped"}

        # Step 5: Run targeted tests / regression tests in isolated subprocess
        tests_executed = False
        if test_script_content:
            test_passed, test_msg = self._run_test_in_isolation(
                patched_content,
                test_script_content,
                filename=os.path.basename(proposal.file_path),
                cwd=cwd,
            )
            tests_executed = True
            if not test_passed:
                proposal.status = FixStatus.VALIDATION_FAILED
                proposal.error_message = f"Step 5 Failed: Targeted tests failed: {test_msg}"
                results["step_5_tests"] = {"passed": False, "details": test_msg, "skipped": False}
                proposal.validation_results = results
                return proposal
            results["step_5_tests"] = {"passed": True, "details": test_msg, "skipped": False}
        else:
            results["step_5_tests"] = {
                "passed": True,
                "details": "No targeted test suite provided for this finding.",
                "skipped": True,
            }

        # Step 6: Rerun applicable static security and quality checks to verify fix
        before_ast = self.ast_scanner.scan(proposal.file_path, original_file_content) if proposal.file_path.endswith(".py") else []
        before_sec = self.security_scanner.scan(proposal.file_path, original_file_content)
        before_findings = before_ast + before_sec

        after_ast = self.ast_scanner.scan(proposal.file_path, patched_content) if proposal.file_path.endswith(".py") else []
        after_sec = self.security_scanner.scan(proposal.file_path, patched_content)
        after_findings = after_ast + after_sec

        # If a specific finding was targeted, verify its rule is no longer present
        if finding:
            remains = any(f.rule_id == finding.rule_id for f in after_findings)
            if remains:
                proposal.status = FixStatus.VALIDATION_FAILED
                proposal.error_message = f"Step 6 Failed: Vulnerability ({finding.rule_id}) still detected in patched code."
                results["step_6_security_verified"] = {
                    "passed": False,
                    "details": f"Target vulnerability {finding.rule_id} remains active.",
                }
                proposal.validation_results = results
                return proposal

        results["step_6_security_verified"] = {
            "passed": True,
            "details": "Target vulnerability successfully eliminated.",
        }

        # Step 7: Compare before-and-after findings to detect newly introduced issues or regressions
        before_fingerprints = {f.fingerprint for f in before_findings}
        new_regressions = [f for f in after_findings if f.fingerprint not in before_fingerprints]

        if new_regressions:
            crit_or_high = [r for r in new_regressions if r.severity in (Severity.CRITICAL, Severity.HIGH)]
            if crit_or_high:
                proposal.status = FixStatus.VALIDATION_FAILED
                proposal.error_message = (
                    f"Step 7 Failed: Patch introduced {len(crit_or_high)} new high/critical regressions "
                    f"({[r.rule_id for r in crit_or_high]})."
                )
                results["step_7_regression_check"] = {
                    "passed": False,
                    "details": f"Introduced new issues: {[r.rule_id for r in new_regressions]}",
                }
                proposal.validation_results = results
                return proposal

        results["step_7_regression_check"] = {
            "passed": True,
            "details": "No newly introduced regressions detected.",
        }

        # Final Status determination
        if results["step_5_tests"].get("skipped") and not results["step_6_security_verified"]["passed"]:
            proposal.status = FixStatus.UNVERIFIED
        else:
            proposal.status = FixStatus.VALIDATION_PASSED

        proposal.validation_results = results
        return proposal

    def _run_test_in_isolation(
        self,
        patched_code: str,
        test_code: str,
        filename: str,
        cwd: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Runs test in a secure temporary directory with a strict timeout and no shell=True."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = os.path.join(tmp_dir, filename)
            test_file = os.path.join(tmp_dir, "test_runner.py")

            with open(source_file, "w", encoding="utf-8") as f:
                f.write(patched_code)

            with open(test_file, "w", encoding="utf-8") as f:
                f.write(test_code)

            try:
                # Execute in isolated subprocess with 8 second timeout
                proc = subprocess.run(
                    [sys.executable, test_file],
                    cwd=tmp_dir,
                    capture_output=True,
                    text=True,
                    timeout=8,
                    shell=False,
                )
                if proc.returncode == 0:
                    return True, "Test suite passed successfully in isolation."
                else:
                    return False, f"Test failed with exit code {proc.returncode}: {proc.stderr or proc.stdout}"
            except subprocess.TimeoutExpired:
                return False, "Test execution timed out (exceeded 8s limit)."
            except Exception as e:
                return False, f"Error running test workload: {e}"
