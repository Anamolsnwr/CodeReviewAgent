"""Unit tests for JSON and PDF report generation."""

import json
import unittest

from codereview.models import (
    Finding,
    FixProposal,
    FixStatus,
    ScanComparison,
    ScanMetadata,
    ScanResult,
    Severity,
    Category,
)
from codereview.reports.json_exporter import export_scan_json, export_comparison_json
from codereview.reports.pdf_exporter import export_scan_pdf, export_comparison_pdf


class TestReports(unittest.TestCase):

    def setUp(self):
        self.meta = ScanMetadata(
            target_type="local_file",
            target_identifier="payment_gateway.py",
            risk_score=75.0,
            risk_level="CRITICAL",
            duration_seconds=1.2,
        )
        self.findings = [
            Finding(
                file_path="payment_gateway.py",
                line_number=45,
                rule_id="SEC-PAYMENT-SECRET",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                message="Hardcoded Stripe API key in client script",
                explanation="Exposing private keys allows unauthorized transaction execution.",
                suggestion="Inject via secure environment secret.",
                code_snippet='stripe_key = "sk-live-1234567890abcdef12345678"',
            ),
            Finding(
                file_path="payment_gateway.py",
                line_number=88,
                rule_id="QUAL-BARE-EXCEPT",
                severity=Severity.LOW,
                category=Category.CODE_QUALITY,
                message="Bare except block catches SystemExit",
                code_snippet="except:",
            ),
        ]
        self.fixes = [
            FixProposal(
                file_path="payment_gateway.py",
                root_cause="Hardcoded key in source file",
                explanation="Replaced with os.environ.get('STRIPE_KEY')",
                original_code='stripe_key = "sk-live-1234567890abcdef12345678"',
                replacement_code='stripe_key = os.environ.get("STRIPE_KEY")',
                status=FixStatus.VALIDATION_PASSED,
                validation_results={"step_4_syntax": {"passed": True}},
            )
        ]
        self.scan_result = ScanResult(
            metadata=self.meta,
            findings=self.findings,
            fix_proposals=self.fixes,
            summary={"severity_counts": {"CRITICAL": 1, "LOW": 1}},
        )

    def test_export_scan_json(self):
        json_str = export_scan_json(self.scan_result)
        self.assertIsInstance(json_str, str)
        # Parse back to verify validity
        parsed = json.loads(json_str)
        self.assertEqual(parsed["metadata"]["target_identifier"], "payment_gateway.py")
        self.assertEqual(len(parsed["findings"]), 2)
        # Verify secret redaction
        self.assertNotIn("sk-live-1234567890abcdef12345678", json_str)
        self.assertIn("[REDACTED_API_KEY]", json_str)

    def test_export_scan_pdf(self):
        pdf_bytes = export_scan_pdf(self.scan_result)
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertTrue(len(pdf_bytes) > 500)
        # PDF magic header
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    def test_export_comparison_reports(self):
        comparison = ScanComparison(
            base_scan_id="scan-001",
            target_scan_id="scan-002",
            new_findings=[self.findings[0]],
            resolved_findings=[self.findings[1]],
            unchanged_findings=[],
            severity_changes=[],
            risk_score_diff=50.0,
        )

        # JSON
        cmp_json = export_comparison_json(comparison)
        parsed_cmp = json.loads(cmp_json)
        self.assertEqual(parsed_cmp["risk_score_diff"], 50.0)
        self.assertEqual(len(parsed_cmp["new_findings"]), 1)

        # PDF
        cmp_pdf = export_comparison_pdf(comparison, self.scan_result, self.scan_result)
        self.assertTrue(cmp_pdf.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
