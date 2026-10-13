"""Unit and integration tests for SQLite scan storage and comparison."""

import os
import tempfile
import unittest

from codereview.models import (
    Finding,
    FixProposal,
    FixStatus,
    ScanMetadata,
    ScanResult,
    Severity,
    Category,
)
from codereview.storage.db import ScanStorage


class TestScanStorage(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_scans.db")
        self.storage = ScanStorage(db_path=self.db_path)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_save_and_retrieve_scan(self):
        meta = ScanMetadata(
            target_type="local_file",
            target_identifier="server.py",
            risk_score=65.0,
            risk_level="HIGH",
            user_id="user_123",
        )
        finding = Finding(
            file_path="server.py",
            line_number=10,
            rule_id="SEC-SQLI",
            severity=Severity.CRITICAL,
            category=Category.SECURITY,
            message="SQL Injection",
            code_snippet="cursor.execute(f'...')",
        )
        proposal = FixProposal(
            finding_id=finding.id,
            file_path="server.py",
            original_code="bad",
            replacement_code="good",
            status=FixStatus.VALIDATION_PASSED,
        )

        scan = ScanResult(
            metadata=meta,
            findings=[finding],
            fix_proposals=[proposal],
            summary={"total_findings": 1},
        )

        scan_id = self.storage.save_scan(scan)
        self.assertEqual(scan_id, meta.scan_id)

        # Retrieve
        loaded = self.storage.get_scan(scan_id, user_id="user_123")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.metadata.target_identifier, "server.py")
        self.assertEqual(len(loaded.findings), 1)
        self.assertEqual(loaded.findings[0].rule_id, "SEC-SQLI")
        self.assertEqual(len(loaded.fix_proposals), 1)
        self.assertEqual(loaded.fix_proposals[0].status, FixStatus.VALIDATION_PASSED)

    def test_multi_user_access_control(self):
        meta1 = ScanMetadata(target_identifier="file1.py", user_id="user_alice")
        meta2 = ScanMetadata(target_identifier="file2.py", user_id="user_bob")

        self.storage.save_scan(ScanResult(metadata=meta1))
        self.storage.save_scan(ScanResult(metadata=meta2))

        # Alice cannot fetch Bob's scan
        alice_scans, _ = self.storage.list_scans(user_id="user_alice")
        self.assertEqual(len(alice_scans), 1)
        self.assertEqual(alice_scans[0].target_identifier, "file1.py")

        bob_scans, _ = self.storage.list_scans(user_id="user_bob")
        self.assertEqual(len(bob_scans), 1)
        self.assertEqual(bob_scans[0].target_identifier, "file2.py")

        self.assertIsNone(self.storage.get_scan(meta2.scan_id, user_id="user_alice"))

    def test_compare_scans_with_stable_fingerprints(self):
        # Scan 1: Base scan with finding A at line 10 and finding B at line 20
        finding_a1 = Finding(
            file_path="main.py",
            line_number=10,
            rule_id="RULE-A",
            severity=Severity.HIGH,
            code_snippet="eval(x)",
        )
        finding_b1 = Finding(
            file_path="main.py",
            line_number=20,
            rule_id="RULE-B",
            severity=Severity.MEDIUM,
            code_snippet="except:",
        )
        base_meta = ScanMetadata(target_identifier="main.py", risk_score=25.0)
        base_scan = ScanResult(metadata=base_meta, findings=[finding_a1, finding_b1])
        self.storage.save_scan(base_scan)

        # Scan 2: Target scan where:
        # - Finding A moved from line 10 to line 35 (line shifted, but same code & rule!) -> unchanged
        # - Finding B is fixed -> resolved
        # - Finding C is newly added -> new finding
        finding_a2 = Finding(
            file_path="main.py",
            line_number=35,  # line moved!
            rule_id="RULE-A",
            severity=Severity.HIGH,
            code_snippet="eval(x)",  # same snippet
        )
        finding_c2 = Finding(
            file_path="main.py",
            line_number=50,
            rule_id="RULE-C",
            severity=Severity.CRITICAL,
            code_snippet="cursor.execute(f'...)",
        )
        target_meta = ScanMetadata(target_identifier="main.py", risk_score=40.0)
        target_scan = ScanResult(metadata=target_meta, findings=[finding_a2, finding_c2])
        self.storage.save_scan(target_scan)

        comparison = self.storage.compare_scans(base_meta.scan_id, target_meta.scan_id)

        # Stable fingerprint correctly recognizes finding A as unchanged despite line shift!
        self.assertEqual(len(comparison.unchanged_findings), 1)
        self.assertEqual(comparison.unchanged_findings[0].rule_id, "RULE-A")

        # Finding B was resolved
        self.assertEqual(len(comparison.resolved_findings), 1)
        self.assertEqual(comparison.resolved_findings[0].rule_id, "RULE-B")

        # Finding C is newly introduced
        self.assertEqual(len(comparison.new_findings), 1)
        self.assertEqual(comparison.new_findings[0].rule_id, "RULE-C")

        # Risk delta
        self.assertEqual(comparison.risk_score_diff, 15.0)

    def test_delete_scan(self):
        meta = ScanMetadata(target_identifier="del.py")
        self.storage.save_scan(ScanResult(metadata=meta))

        self.assertTrue(self.storage.delete_scan(meta.scan_id))
        self.assertIsNone(self.storage.get_scan(meta.scan_id))


if __name__ == "__main__":
    unittest.main()
