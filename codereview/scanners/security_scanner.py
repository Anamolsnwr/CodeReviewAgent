"""Static security analyzer using pattern recognition and optional Bandit integration."""

import re
from typing import List, Optional
from codereview.models import Finding, Severity, Category


SECURITY_PATTERNS = [
    # Hardcoded credentials
    (
        re.compile(r"""(?i)(?:api_key|apikey|secret|password|passwd|token|auth_token)\s*=\s*['"][a-zA-Z0-9_\-]{8,}['"]"""),
        "SEC-REGEX-HARDCODED-SECRET",
        Severity.HIGH,
        "Hardcoded secret or credential detected in source code.",
        "Committing secrets to source control risks credential compromise.",
        "Store secrets in environment variables or a vault.",
    ),
    # SQL Injection via formatted string
    (
        re.compile(r"""(?i)(?:cursor\.execute|execute)\s*\(\s*(?:f['"]|['"].*?%|['"].*?\.format).*?(?:SELECT|INSERT|UPDATE|DELETE)"""),
        "SEC-REGEX-SQLI",
        Severity.CRITICAL,
        "Potential SQL Injection via dynamic string formatting.",
        "Interpolating variables directly into SQL queries allows attackers to alter query logic.",
        "Use parameterized queries (e.g. cursor.execute('SELECT * FROM tbl WHERE id = ?', (user_id,)))",
    ),
    # Disabled SSL certificate verification
    (
        re.compile(r"""verify\s*=\s*False"""),
        "SEC-REGEX-SSL-VERIFY-FALSE",
        Severity.HIGH,
        "SSL certificate verification explicitly disabled (verify=False).",
        "Disabling SSL verification exposes HTTP requests to man-in-the-middle (MITM) attacks.",
        "Enable SSL verification (verify=True or provide a trusted CA bundle).",
    ),
    # Weak cryptography (MD5 / SHA1)
    (
        re.compile(r"""hashlib\.(?:md5|sha1)\s*\("""),
        "SEC-REGEX-WEAK-HASH",
        Severity.MEDIUM,
        "Use of weak hash algorithm (MD5 / SHA1).",
        "MD5 and SHA1 are cryptographically broken and vulnerable to collision attacks.",
        "Use SHA-256 (hashlib.sha256) or bcrypt/argon2 for password hashing.",
    ),
    # Insecure temporary file
    (
        re.compile(r"""(?:mktemp|tempfile\.mktemp)\s*\("""),
        "SEC-REGEX-INSECURE-MKTEMP",
        Severity.MEDIUM,
        "Insecure temporary file creation via mktemp.",
        "mktemp is susceptible to race condition symlink attacks.",
        "Use tempfile.NamedTemporaryFile or tempfile.TemporaryDirectory.",
    ),
    # Debug mode in production frameworks
    (
        re.compile(r"""(?i)(?:app\.run|DEBUG)\s*(?:=|\()\s*True"""),
        "SEC-REGEX-DEBUG-ENABLED",
        Severity.MEDIUM,
        "Debug mode enabled.",
        "Debug mode exposes interactive debuggers, stack traces, and sensitive internal paths.",
        "Ensure debug mode is disabled in production.",
    ),
]


class SecurityScanner:
    """Scans code for security vulnerabilities using regex patterns and heuristics."""

    def scan(
        self,
        filename: str,
        code: str,
        changed_lines: Optional[List[int]] = None,
    ) -> List[Finding]:
        findings: List[Finding] = []
        lines = code.splitlines()

        for idx, line in enumerate(lines, 1):
            is_new = changed_lines is None or (idx in changed_lines)
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for pattern, rule_id, severity, msg, expl, sugg in SECURITY_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        file_path=filename,
                        line_number=idx,
                        rule_id=rule_id,
                        severity=severity,
                        category=Category.SECURITY,
                        message=msg,
                        explanation=expl,
                        suggestion=sugg,
                        confidence=0.90,
                        code_snippet=stripped,
                        newly_introduced=is_new,
                    ))

        return findings
