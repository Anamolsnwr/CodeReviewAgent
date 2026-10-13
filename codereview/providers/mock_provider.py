"""Mock AI Provider for deterministic offline testing and fallback."""

import difflib
from typing import List, Optional
from codereview.models import Finding, FixProposal, Severity, Category, FixStatus, PRMetadata
from codereview.providers.base import BaseAIProvider


class MockAIProvider(BaseAIProvider):
    """Mock implementation of BaseAIProvider returning predefined or synthesized responses."""

    def __init__(self, canned_findings: Optional[List[Finding]] = None):
        self.canned_findings = canned_findings or []
        self.calls: List[dict] = []

    def review_code(
        self,
        filename: str,
        code: str,
        context: Optional[str] = None,
        changed_lines: Optional[List[int]] = None,
    ) -> List[Finding]:
        self.calls.append({
            "action": "review_code",
            "filename": filename,
            "code_len": len(code),
            "changed_lines": changed_lines,
        })
        if self.canned_findings:
            return self.canned_findings

        findings = []
        # Basic heuristic findings for mock demonstrations
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            if changed_lines is not None and idx not in changed_lines:
                continue

            if "eval(" in line:
                findings.append(Finding(
                    file_path=filename,
                    line_number=idx,
                    rule_id="SEC001-EVAL-INJECTION",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    message="Use of dangerous eval() detected.",
                    explanation="eval() executes arbitrary code and opens severe remote code execution vulnerabilities.",
                    suggestion="Replace eval() with safe alternatives like ast.literal_eval() or explicit parsers.",
                    confidence=0.98,
                    code_snippet=line.strip(),
                    newly_introduced=(changed_lines is not None and idx in changed_lines),
                ))
            elif "password" in line.lower() and "=" in line and ("123" in line or "secret" in line):
                findings.append(Finding(
                    file_path=filename,
                    line_number=idx,
                    rule_id="SEC002-HARDCODED-SECRET",
                    severity=Severity.HIGH,
                    category=Category.SECURITY,
                    message="Potential hardcoded secret or password.",
                    explanation="Hardcoding secrets in source files allows unauthorized access if committed.",
                    suggestion="Use environment variables or a secrets manager.",
                    confidence=0.92,
                    code_snippet=line.strip(),
                    newly_introduced=(changed_lines is not None and idx in changed_lines),
                ))
            elif "except:" in line.replace(" ", ""):
                findings.append(Finding(
                    file_path=filename,
                    line_number=idx,
                    rule_id="QUAL001-BARE-EXCEPT",
                    severity=Severity.LOW,
                    category=Category.CODE_QUALITY,
                    message="Bare except clause catches all exceptions including system exits.",
                    explanation="Catches KeyboardInterrupt and SystemExit, making graceful termination difficult.",
                    suggestion="Specify explicit exception types e.g. except Exception:.",
                    confidence=0.95,
                    code_snippet=line.strip(),
                    newly_introduced=(changed_lines is not None and idx in changed_lines),
                ))

        return findings

    def generate_fix(
        self,
        finding: Finding,
        file_content: str,
        context: Optional[str] = None,
    ) -> FixProposal:
        self.calls.append({
            "action": "generate_fix",
            "finding_id": finding.id,
            "rule_id": finding.rule_id,
        })

        lines = file_content.splitlines(keepends=True)
        orig_line = lines[finding.line_number - 1] if 0 < finding.line_number <= len(lines) else ""
        
        # Synthesize a safe replacement based on rule
        if "eval" in finding.rule_id.lower() or "eval" in finding.message.lower():
            replacement_line = orig_line.replace("eval(", "ast.literal_eval(")
            root_cause = "Direct invocation of eval() on unvalidated input."
            explanation = "Replaced eval() with safe ast.literal_eval() to eliminate remote code execution."
        elif "bare-except" in finding.rule_id.lower() or "except:" in orig_line:
            replacement_line = orig_line.replace("except:", "except Exception:")
            root_cause = "Bare except clause."
            explanation = "Changed bare except to except Exception to avoid suppressing system interrupts."
        else:
            replacement_line = f"# [FIXED: {finding.rule_id}]\n" + orig_line
            root_cause = finding.explanation or "Identified issue."
            explanation = finding.suggestion or "Applied recommended remediation."

        # Construct new content and unified diff
        new_lines = list(lines)
        if 0 < finding.line_number <= len(new_lines):
            new_lines[finding.line_number - 1] = replacement_line

        diff = "".join(difflib.unified_diff(
            lines,
            new_lines,
            fromfile=finding.file_path,
            tofile=finding.file_path,
        ))

        return FixProposal(
            finding_id=finding.id,
            file_path=finding.file_path,
            root_cause=root_cause,
            explanation=explanation,
            original_code=orig_line.strip(),
            replacement_code=replacement_line.strip(),
            unified_diff=diff,
            compatibility_risks="Ensure callers handle standard syntax exceptions.",
            status=FixStatus.SUGGESTED,
        )

    def generate_pr_summary(
        self,
        pr_metadata: PRMetadata,
        findings: List[Finding],
    ) -> str:
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        status = "CHANGES REQUESTED" if (crit_count + high_count > 0) else "APPROVED"

        return (
            f"### Automated Pull Request Review Summary\n\n"
            f"- **Repository**: {pr_metadata.owner}/{pr_metadata.repo} (PR #{pr_metadata.pull_number})\n"
            f"- **Status**: **{status}**\n"
            f"- **Total Findings**: {len(findings)} ({crit_count} Critical, {high_count} High)\n"
            f"- **Summary**: {'Potential security regressions detected. Please address critical issues.' if crit_count > 0 else 'No blocking security issues found.'}\n"
        )
