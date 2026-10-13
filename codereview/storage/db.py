"""Persistent SQLite storage for scans, findings, fix proposals, and scan comparisons."""

from contextlib import contextmanager
import json
import logging
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

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

logger = logging.getLogger(__name__)

CURRENT_SCHEMA_VERSION = 1


class ScanStorage:
    """Manages SQLite database storage for review scans and comparisons."""

    def __init__(self, db_path: str = "scans.db"):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Initializes database tables and verifies schema migration version."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT
                )
            """)

            cursor = conn.execute("SELECT MAX(version) FROM schema_migrations")
            row = cursor.fetchone()
            current_ver = row[0] if row and row[0] is not None else 0

            if current_ver < 1:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        scan_date TEXT,
                        duration_seconds REAL,
                        target_type TEXT,
                        target_identifier TEXT,
                        ref_name TEXT,
                        commit_sha TEXT,
                        risk_score REAL,
                        risk_level TEXT,
                        scanner_versions TEXT,
                        status TEXT,
                        error_message TEXT,
                        user_id TEXT,
                        summary TEXT,
                        created_at REAL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date)")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        file_path TEXT,
                        line_number INTEGER,
                        end_line_number INTEGER,
                        rule_id TEXT,
                        severity TEXT,
                        category TEXT,
                        message TEXT,
                        explanation TEXT,
                        suggestion TEXT,
                        confidence REAL,
                        code_snippet TEXT,
                        fingerprint TEXT,
                        newly_introduced INTEGER,
                        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS fix_proposals (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        finding_id TEXT,
                        file_path TEXT,
                        root_cause TEXT,
                        explanation TEXT,
                        original_code TEXT,
                        replacement_code TEXT,
                        unified_diff TEXT,
                        compatibility_risks TEXT,
                        status TEXT,
                        validation_results TEXT,
                        backup_path TEXT,
                        error_message TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_fixes_scan ON fix_proposals(scan_id)")

                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (1, time.strftime("%Y-%m-%d %H:%M:%S")),
                )
                conn.commit()

    def save_scan(self, scan_result: ScanResult) -> str:
        """Saves a ScanResult including its findings and fix proposals."""
        meta = scan_result.metadata
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    scan_id, scan_date, duration_seconds, target_type, target_identifier,
                    ref_name, commit_sha, risk_score, risk_level, scanner_versions,
                    status, error_message, user_id, summary, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    meta.scan_id,
                    meta.scan_date,
                    meta.duration_seconds,
                    meta.target_type,
                    meta.target_identifier,
                    meta.ref_name,
                    meta.commit_sha,
                    meta.risk_score,
                    meta.risk_level,
                    json.dumps(meta.scanner_versions),
                    meta.status,
                    meta.error_message,
                    meta.user_id,
                    json.dumps(scan_result.summary),
                    time.time(),
                ),
            )

            # Insert findings
            for f in scan_result.findings:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        id, scan_id, file_path, line_number, end_line_number,
                        rule_id, severity, category, message, explanation,
                        suggestion, confidence, code_snippet, fingerprint, newly_introduced
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id,
                        meta.scan_id,
                        f.file_path,
                        f.line_number,
                        f.end_line_number,
                        f.rule_id,
                        f.severity.value,
                        f.category.value,
                        f.message,
                        f.explanation,
                        f.suggestion,
                        f.confidence,
                        f.code_snippet,
                        f.fingerprint,
                        1 if f.newly_introduced else 0,
                    ),
                )

            # Insert fix proposals
            for p in scan_result.fix_proposals:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO fix_proposals (
                        id, scan_id, finding_id, file_path, root_cause,
                        explanation, original_code, replacement_code, unified_diff,
                        compatibility_risks, status, validation_results, backup_path, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        p.id,
                        meta.scan_id,
                        p.finding_id,
                        p.file_path,
                        p.root_cause,
                        p.explanation,
                        p.original_code,
                        p.replacement_code,
                        p.unified_diff,
                        p.compatibility_risks,
                        p.status.value,
                        json.dumps(p.validation_results),
                        p.backup_path,
                        p.error_message,
                    ),
                )

            conn.commit()
        return meta.scan_id

    def get_scan(self, scan_id: str, user_id: Optional[str] = None) -> Optional[ScanResult]:
        """Loads a complete ScanResult by ID, checking user_id access control if provided."""
        with self._get_connection() as conn:
            query = "SELECT * FROM scans WHERE scan_id = ?"
            params: List[Any] = [scan_id]
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            row = conn.execute(query, params).fetchone()
            if not row:
                return None

            meta = ScanMetadata(
                scan_id=row["scan_id"],
                scan_date=row["scan_date"],
                duration_seconds=row["duration_seconds"],
                target_type=row["target_type"],
                target_identifier=row["target_identifier"],
                ref_name=row["ref_name"],
                commit_sha=row["commit_sha"],
                risk_score=row["risk_score"],
                risk_level=row["risk_level"],
                scanner_versions=json.loads(row["scanner_versions"] or "{}"),
                status=row["status"],
                error_message=row["error_message"],
                user_id=row["user_id"],
            )

            # Fetch findings
            f_rows = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY line_number", (scan_id,)).fetchall()
            findings = [
                Finding(
                    id=fr["id"],
                    file_path=fr["file_path"],
                    line_number=fr["line_number"],
                    end_line_number=fr["end_line_number"],
                    rule_id=fr["rule_id"],
                    severity=Severity(fr["severity"]),
                    category=Category(fr["category"]),
                    message=fr["message"],
                    explanation=fr["explanation"],
                    suggestion=fr["suggestion"],
                    confidence=fr["confidence"],
                    code_snippet=fr["code_snippet"],
                    fingerprint=fr["fingerprint"],
                    newly_introduced=bool(fr["newly_introduced"]),
                )
                for fr in f_rows
            ]

            # Fetch fix proposals
            p_rows = conn.execute("SELECT * FROM fix_proposals WHERE scan_id = ?", (scan_id,)).fetchall()
            fixes = [
                FixProposal(
                    id=pr["id"],
                    finding_id=pr["finding_id"],
                    file_path=pr["file_path"],
                    root_cause=pr["root_cause"],
                    explanation=pr["explanation"],
                    original_code=pr["original_code"],
                    replacement_code=pr["replacement_code"],
                    unified_diff=pr["unified_diff"],
                    compatibility_risks=pr["compatibility_risks"],
                    status=FixStatus(pr["status"]),
                    validation_results=json.loads(pr["validation_results"] or "{}"),
                    backup_path=pr["backup_path"],
                    error_message=pr["error_message"],
                )
                for pr in p_rows
            ]

            summary = json.loads(row["summary"] or "{}")
            return ScanResult(metadata=meta, findings=findings, fix_proposals=fixes, summary=summary)

    def list_scans(
        self,
        search: Optional[str] = None,
        target_type: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
        user_id: Optional[str] = None,
    ) -> Tuple[List[ScanMetadata], int]:
        """Lists scan metadata with search, filtering, and pagination."""
        offset = max(0, (page - 1) * per_page)
        conditions = []
        params: List[Any] = []

        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)

        if target_type:
            conditions.append("target_type = ?")
            params.append(target_type)

        if search:
            conditions.append("(target_identifier LIKE ? OR scan_id LIKE ?)")
            term = f"%{search}%"
            params.extend([term, term])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self._get_connection() as conn:
            count_query = f"SELECT COUNT(*) FROM scans {where_clause}"
            total = conn.execute(count_query, params).fetchone()[0]

            data_query = f"""
                SELECT * FROM scans
                {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """
            rows = conn.execute(data_query, params + [per_page, offset]).fetchall()

            scans = [
                ScanMetadata(
                    scan_id=r["scan_id"],
                    scan_date=r["scan_date"],
                    duration_seconds=r["duration_seconds"],
                    target_type=r["target_type"],
                    target_identifier=r["target_identifier"],
                    ref_name=r["ref_name"],
                    commit_sha=r["commit_sha"],
                    risk_score=r["risk_score"],
                    risk_level=r["risk_level"],
                    scanner_versions=json.loads(r["scanner_versions"] or "{}"),
                    status=r["status"],
                    error_message=r["error_message"],
                    user_id=r["user_id"],
                )
                for r in rows
            ]

            return scans, total

    def delete_scan(self, scan_id: str, user_id: Optional[str] = None) -> bool:
        """Deletes a scan and cascades deletion of its findings and proposals."""
        with self._get_connection() as conn:
            query = "DELETE FROM scans WHERE scan_id = ?"
            params: List[Any] = [scan_id]
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            cursor = conn.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0

    def delete_old_scans(self, days: int = 30, user_id: Optional[str] = None) -> int:
        """Retention cleanup: deletes scans older than specified days."""
        cutoff_time = time.time() - (days * 86400)
        with self._get_connection() as conn:
            query = "DELETE FROM scans WHERE created_at < ?"
            params: List[Any] = [cutoff_time]
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)

            cursor = conn.execute(query, params)
            conn.commit()
            return cursor.rowcount

    def compare_scans(
        self,
        base_scan_id: str,
        target_scan_id: str,
        user_id: Optional[str] = None,
    ) -> ScanComparison:
        """Compares two scans using stable finding fingerprints rather than line numbers."""
        base_scan = self.get_scan(base_scan_id, user_id=user_id)
        if not base_scan:
            raise ValueError(f"Base scan '{base_scan_id}' not found.")

        target_scan = self.get_scan(target_scan_id, user_id=user_id)
        if not target_scan:
            raise ValueError(f"Target scan '{target_scan_id}' not found.")

        base_map = {f.fingerprint: f for f in base_scan.findings}
        target_map = {f.fingerprint: f for f in target_scan.findings}

        new_findings: List[Finding] = []
        resolved_findings: List[Finding] = []
        unchanged_findings: List[Finding] = []
        severity_changes: List[Dict[str, Any]] = []

        # Check target findings against base
        for fp, tf in target_map.items():
            if fp not in base_map:
                new_findings.append(tf)
            else:
                bf = base_map[fp]
                if bf.severity != tf.severity:
                    severity_changes.append({
                        "finding_fingerprint": fp,
                        "rule_id": tf.rule_id,
                        "file_path": tf.file_path,
                        "old_severity": bf.severity.value,
                        "new_severity": tf.severity.value,
                    })
                unchanged_findings.append(tf)

        # Check resolved findings (present in base, gone from target)
        for fp, bf in base_map.items():
            if fp not in target_map:
                resolved_findings.append(bf)

        risk_diff = round(target_scan.metadata.risk_score - base_scan.metadata.risk_score, 1)

        return ScanComparison(
            base_scan_id=base_scan_id,
            target_scan_id=target_scan_id,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            unchanged_findings=unchanged_findings,
            severity_changes=severity_changes,
            risk_score_diff=risk_diff,
        )
