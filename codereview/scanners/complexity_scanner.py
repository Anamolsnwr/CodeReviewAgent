"""Code complexity and maintainability analyzer using Radon."""

import logging
from typing import List, Optional
from codereview.models import Finding, Severity, Category

logger = logging.getLogger(__name__)

try:
    from radon.complexity import cc_visit
    from radon.metrics import mi_visit
    RADON_AVAILABLE = True
except ImportError:
    RADON_AVAILABLE = False


class ComplexityScanner:
    """Calculates Cyclomatic Complexity (CC) and Maintainability Index (MI)."""

    def scan(
        self,
        filename: str,
        code: str,
        changed_lines: Optional[List[int]] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        if not RADON_AVAILABLE:
            return findings

        # 1. Cyclomatic Complexity
        try:
            blocks = cc_visit(code)
            for block in blocks:
                # Flag functions with CC > 10 (moderate risk) and CC > 15 (high risk)
                if block.complexity > 10:
                    is_new = changed_lines is None or (block.lineno in changed_lines)
                    sev = Severity.HIGH if block.complexity >= 15 else Severity.MEDIUM
                    findings.append(Finding(
                        file_path=filename,
                        line_number=block.lineno,
                        end_line_number=block.endline,
                        rule_id="QUAL-RADON-HIGH-COMPLEXITY",
                        severity=sev,
                        category=Category.CODE_QUALITY,
                        message=f"High Cyclomatic Complexity ({block.complexity}) in {block.name}",
                        explanation=(
                            f"Function or method '{block.name}' has a cyclomatic complexity score of {block.complexity}. "
                            f"Scores above 10 indicate difficult-to-test and error-prone control flow."
                        ),
                        suggestion="Refactor complex logic into smaller, single-responsibility helper functions.",
                        confidence=1.0,
                        code_snippet=f"def {block.name}(...): # CC = {block.complexity}",
                        newly_introduced=is_new,
                    ))
        except Exception as e:
            logger.debug(f"Complexity scan skipped for {filename}: {e}")

        # 2. Maintainability Index
        try:
            mi_score = mi_visit(code, multi=True)
            if mi_score < 40:  # Radon rank C (very low maintainability)
                findings.append(Finding(
                    file_path=filename,
                    line_number=1,
                    rule_id="QUAL-RADON-LOW-MAINTAINABILITY",
                    severity=Severity.MEDIUM,
                    category=Category.CODE_QUALITY,
                    message=f"Low Maintainability Index ({mi_score:.1f}/100)",
                    explanation="The overall maintainability index of this file is critically low.",
                    suggestion="Decompose large functions, reduce duplicate logic, and add clean modular abstraction.",
                    confidence=0.9,
                    code_snippet=f"# File Maintainability Index: {mi_score:.1f}",
                    newly_introduced=(changed_lines is None or 1 in changed_lines),
                ))
        except Exception as e:
            logger.debug(f"Maintainability scan skipped for {filename}: {e}")

        return findings
