"""Unit and integration tests for AI fix validation, patch application, and rollback."""

import os
import tempfile
import unittest

from codereview.models import Finding, FixProposal, FixStatus, Severity, Category
from codereview.remediation.patcher import (
    apply_patch_to_string,
    apply_fix_to_file,
    rollback_fix,
    create_unified_diff,
)
from codereview.remediation.validator import PatchValidator


class TestRemediationAndValidation(unittest.TestCase):

    def setUp(self):
        self.validator = PatchValidator()

    def test_apply_patch_to_string_success(self):
        original = "def add(a, b):\n    return a - b\n"
        success, new_code, err = apply_patch_to_string(
            original,
            "return a - b",
            "return a + b",
        )
        self.assertTrue(success)
        self.assertEqual(err, "")
        self.assertIn("return a + b", new_code)

    def test_apply_patch_rejects_stale_target(self):
        original = "def multiply(a, b):\n    return a * b\n"
        success, new_code, err = apply_patch_to_string(
            original,
            "return a - b",  # does not exist
            "return a + b",
        )
        self.assertFalse(success)
        self.assertIn("stale", err.lower())

    def test_apply_patch_rejects_ambiguous_target(self):
        original = "x = 1\nx = 1\n"
        success, new_code, err = apply_patch_to_string(
            original,
            "x = 1",
            "x = 2",
        )
        self.assertFalse(success)
        self.assertIn("ambiguous", err.lower())

    def test_validation_passes_clean_fix(self):
        original = "import os\n\ndef calc(inp):\n    res = eval(inp)\n    return res\n"
        finding = Finding(
            file_path="calc.py",
            line_number=4,
            rule_id="SEC-AST-EVAL",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            code_snippet="res = eval(inp)",
        )

        proposal = FixProposal(
            finding_id=finding.id,
            file_path="calc.py",
            root_cause="eval() used on input",
            explanation="Use ast.literal_eval() instead of eval()",
            original_code="res = eval(inp)",
            replacement_code="res = ast.literal_eval(inp)",
            unified_diff="",
            status=FixStatus.SUGGESTED,
        )

        val_proposal = self.validator.validate_proposal(
            proposal=proposal,
            original_file_content=original,
            finding=finding,
        )

        self.assertEqual(val_proposal.status, FixStatus.VALIDATION_PASSED)
        self.assertTrue(val_proposal.validation_results["step_1_match"]["passed"])
        self.assertTrue(val_proposal.validation_results["step_2_unambiguous"]["passed"])
        self.assertTrue(val_proposal.validation_results["step_4_syntax"]["passed"])
        self.assertTrue(val_proposal.validation_results["step_6_security_verified"]["passed"])
        self.assertTrue(val_proposal.validation_results["step_7_regression_check"]["passed"])

    def test_validation_fails_on_syntax_error(self):
        original = "def compute():\n    return 42\n"
        proposal = FixProposal(
            file_path="test.py",
            original_code="return 42",
            replacement_code="return def 42 invalid_syntax:::",
        )
        val_proposal = self.validator.validate_proposal(
            proposal=proposal,
            original_file_content=original,
        )
        self.assertEqual(val_proposal.status, FixStatus.VALIDATION_FAILED)
        self.assertFalse(val_proposal.validation_results["step_4_syntax"]["passed"])

    def test_validation_fails_if_vulnerability_remains(self):
        original = "def run(x):\n    eval(x)\n"
        finding = Finding(file_path="test.py", line_number=2, rule_id="SEC-AST-EVAL")
        # Proposed fix still has eval()!
        proposal = FixProposal(
            file_path="test.py",
            original_code="eval(x)",
            replacement_code="eval(x)  # note",
        )
        val_proposal = self.validator.validate_proposal(
            proposal=proposal,
            original_file_content=original,
            finding=finding,
        )
        self.assertEqual(val_proposal.status, FixStatus.VALIDATION_FAILED)
        self.assertFalse(val_proposal.validation_results["step_6_security_verified"]["passed"])

    def test_apply_and_rollback_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = os.path.join(tmp_dir, "app.py")
            orig_text = "def greet():\n    return 'bad'\n"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(orig_text)

            proposal = FixProposal(
                file_path=file_path,
                original_code="return 'bad'",
                replacement_code="return 'good'",
            )

            # Applying without user confirmation must fail
            ok, msg = apply_fix_to_file(file_path, proposal, user_confirmed=False)
            self.assertFalse(ok)
            self.assertIn("explicit user confirmation", msg.lower())

            # Applying with user confirmation succeeds
            ok, msg = apply_fix_to_file(file_path, proposal, user_confirmed=True)
            self.assertTrue(ok)
            self.assertEqual(proposal.status, FixStatus.APPLIED)
            self.assertIsNotNone(proposal.backup_path)

            with open(file_path, "r", encoding="utf-8") as f:
                self.assertIn("return 'good'", f.read())

            # Rollback restores original text
            rb_ok, rb_msg = rollback_fix(proposal)
            self.assertTrue(rb_ok)
            self.assertEqual(proposal.status, FixStatus.ROLLED_BACK)

            with open(file_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), orig_text)


if __name__ == "__main__":
    unittest.main()
