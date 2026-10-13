"""Unit and integration tests for static scanners and ReviewEngine."""

import unittest

from codereview.models import Severity, Category
from codereview.providers.mock_provider import MockAIProvider
from codereview.scanners.ast_scanner import ASTScanner
from codereview.scanners.complexity_scanner import ComplexityScanner
from codereview.scanners.engine import ReviewEngine
from codereview.scanners.security_scanner import SecurityScanner
from codereview.scoring.calculator import calculate_risk_score


class TestScannersAndEngine(unittest.TestCase):

    def test_ast_scanner_eval_and_bare_except(self):
        scanner = ASTScanner()
        code = (
            "def test_func(param=[]):\n"
            "    try:\n"
            "        eval(param)\n"
            "    except:\n"
            "        pass\n"
        )
        findings = scanner.scan("test.py", code)
        rule_ids = [f.rule_id for f in findings]

        self.assertIn("SEC-AST-EVAL", rule_ids)
        self.assertIn("QUAL-AST-BARE-EXCEPT", rule_ids)
        self.assertIn("BUG-AST-MUTABLE-DEFAULT", rule_ids)

    def test_ast_scanner_syntax_error(self):
        scanner = ASTScanner()
        bad_code = "def broken(\n"
        findings = scanner.scan("broken.py", bad_code)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SYNTAX-ERROR")
        self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_security_scanner_patterns(self):
        scanner = SecurityScanner()
        code = (
            "api_key = 'sk-live-1234567890abcdef123'\n"
            "cursor.execute(f'SELECT * FROM accounts WHERE id = {user_id}')\n"
            "requests.get('https://example.com', verify=False)\n"
        )
        findings = scanner.scan("vuln.py", code)
        rule_ids = [f.rule_id for f in findings]

        self.assertIn("SEC-REGEX-HARDCODED-SECRET", rule_ids)
        self.assertIn("SEC-REGEX-SQLI", rule_ids)
        self.assertIn("SEC-REGEX-SSL-VERIFY-FALSE", rule_ids)

    def test_complexity_scanner(self):
        scanner = ComplexityScanner()
        # Function with high cyclomatic complexity (multiple branches)
        code = """
def complex_fn(a, b, c, d, e, f):
    if a:
        if b:
            return 1
        elif c:
            return 2
    if d:
        if e:
            return 3
        elif f:
            return 4
    if a and b and c:
        return 5
    if d and e and f:
        return 6
    return 7
"""
        findings = scanner.scan("complex.py", code)
        # Should flag high complexity if radon is installed
        if findings:
            self.assertTrue(any("COMPLEXITY" in f.rule_id for f in findings))

    def test_risk_scoring_calculator(self):
        mock_provider = MockAIProvider()
        engine = ReviewEngine(ai_provider=mock_provider)
        code = (
            "import os\n"
            "def query(uid):\n"
            "    eval(uid)\n"
        )
        scan = engine.review_file("app.py", code, use_ai=False)

        score, level, breakdown = calculate_risk_score(scan.findings)
        self.assertGreater(score, 20.0)
        self.assertIn(level, ["HIGH", "CRITICAL"])
        self.assertGreater(breakdown["total_findings"], 0)

    def test_engine_prioritizes_changed_lines(self):
        mock_provider = MockAIProvider()
        engine = ReviewEngine(ai_provider=mock_provider)
        code = (
            "line1 = 1\n"
            "eval('x')\n"       # Line 2 (changed)
            "except_line = 3\n" # Line 3
        )
        # Mark only line 2 as changed in PR
        scan = engine.review_file("pr.py", code, changed_lines=[2], use_ai=False)

        eval_findings = [f for f in scan.findings if "EVAL" in f.rule_id]
        self.assertTrue(len(eval_findings) > 0)
        self.assertTrue(eval_findings[0].newly_introduced)


if __name__ == "__main__":
    unittest.main()
