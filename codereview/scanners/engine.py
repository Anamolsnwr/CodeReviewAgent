"""Unified Review Engine coordinating static scanners and AI providers."""

import time
from typing import Dict, List, Optional
from codereview.models import Finding, Severity, ScanMetadata, ScanResult
from codereview.providers.base import BaseAIProvider
from codereview.scanners.ast_scanner import ASTScanner
from codereview.scanners.security_scanner import SecurityScanner
from codereview.scanners.complexity_scanner import ComplexityScanner
from codereview.scoring.calculator import calculate_risk_score


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ReviewEngine:
    """Orchestrates AST, Security, Complexity, and AI scanners to produce structured scan results."""

    def __init__(self, ai_provider: Optional[BaseAIProvider] = None):
        self.ai_provider = ai_provider
        self.ast_scanner = ASTScanner()
        self.security_scanner = SecurityScanner()
        self.complexity_scanner = ComplexityScanner()

    def review_file(
        self,
        filename: str,
        code: str,
        changed_lines: Optional[List[int]] = None,
        use_ai: bool = True,
        target_type: str = "local_file",
        target_identifier: str = "",
        user_id: str = "default_user",
    ) -> ScanResult:
        """Runs full static and AI review on a single file."""
        return self.review_files(
            files_dict={filename: code},
            changed_lines_dict={filename: changed_lines} if changed_lines else None,
            use_ai=use_ai,
            target_type=target_type,
            target_identifier=target_identifier or filename,
            user_id=user_id,
        )

    def review_files(
        self,
        files_dict: Dict[str, str],
        changed_lines_dict: Optional[Dict[str, List[int]]] = None,
        use_ai: bool = True,
        target_type: str = "local_directory",
        target_identifier: str = "",
        commit_sha: Optional[str] = None,
        ref_name: Optional[str] = None,
        user_id: str = "default_user",
    ) -> ScanResult:
        """Runs full review across multiple files."""
        start_time = time.time()
        all_findings: List[Finding] = []
        scanner_versions = {
            "ast_scanner": "python-ast",
            "security_scanner": "pattern-v2",
            "complexity_scanner": "radon-6.0",
        }
        if self.ai_provider:
            scanner_versions["ai_provider"] = self.ai_provider.__class__.__name__

        for filename, code in files_dict.items():
            if not code or not code.strip():
                continue

            changed = changed_lines_dict.get(filename) if changed_lines_dict else None

            # 1. AST Scanner (Python files)
            if filename.endswith(".py"):
                ast_findings = self.ast_scanner.scan(filename, code, changed_lines=changed)
                all_findings.extend(ast_findings)

            # 2. Security Regex Scanner
            sec_findings = self.security_scanner.scan(filename, code, changed_lines=changed)
            all_findings.extend(sec_findings)

            # 3. Complexity Scanner (Python files)
            if filename.endswith(".py"):
                comp_findings = self.complexity_scanner.scan(filename, code, changed_lines=changed)
                all_findings.extend(comp_findings)

            # 4. AI Provider Review
            if use_ai and self.ai_provider:
                try:
                    ai_findings = self.ai_provider.review_code(
                        filename=filename,
                        code=code,
                        changed_lines=changed,
                    )
                    all_findings.extend(ai_findings)
                except Exception as e:
                    # AI failure should not invalidate static scan findings
                    all_findings.append(Finding(
                        file_path=filename,
                        line_number=1,
                        rule_id="AI-REVIEW-WARNING",
                        severity=Severity.INFO,
                        message="AI review completed with warnings",
                        explanation=f"AI model was unable to complete full analysis: {e}",
                        confidence=0.5,
                        newly_introduced=False,
                    ))

        # Deduplicate findings by fingerprint
        unique_findings: List[Finding] = []
        seen_fingerprints = set()

        for f in all_findings:
            if f.fingerprint not in seen_fingerprints:
                seen_fingerprints.add(f.fingerprint)
                unique_findings.append(f)

        # Sort findings: newly introduced first, then by severity priority, then by line number
        unique_findings.sort(
            key=lambda item: (
                0 if item.newly_introduced else 1,
                SEVERITY_ORDER.get(item.severity, 99),
                item.file_path,
                item.line_number,
            )
        )

        duration = round(time.time() - start_time, 2)
        score, risk_lvl, breakdown = calculate_risk_score(unique_findings)

        metadata = ScanMetadata(
            scan_date=time.strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds=duration,
            target_type=target_type,
            target_identifier=target_identifier or (list(files_dict.keys())[0] if len(files_dict) == 1 else "multi-file"),
            ref_name=ref_name,
            commit_sha=commit_sha,
            risk_score=score,
            risk_level=risk_lvl,
            scanner_versions=scanner_versions,
            status="COMPLETED",
            user_id=user_id,
        )

        return ScanResult(
            metadata=metadata,
            findings=unique_findings,
            fix_proposals=[],
            summary=breakdown,
        )
