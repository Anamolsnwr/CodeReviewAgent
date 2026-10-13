"""Data models for CodeReviewAgent.

Includes enums, finding structures, fix proposals, PR metadata, and scan results.
"""

from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    SECURITY = "SECURITY"
    BUG = "BUG"
    CODE_QUALITY = "CODE_QUALITY"
    PERFORMANCE = "PERFORMANCE"
    COMPATIBILITY = "COMPATIBILITY"


class FixStatus(str, Enum):
    SUGGESTED = "Suggested"
    AWAITING_APPROVAL = "Awaiting Approval"
    APPLIED = "Applied"
    VALIDATION_PASSED = "Validation Passed"
    VALIDATION_FAILED = "Validation Failed"
    UNVERIFIED = "Unverified"
    ROLLED_BACK = "Rolled Back"


def compute_finding_fingerprint(rule_id: str, file_path: str, code_snippet: str) -> str:
    """Compute a stable fingerprint for a finding independent of line number drift.

    Normalizes whitespace and relative file paths to allow robust tracking
    across subsequent code commits and refactorings.
    """
    clean_path = file_path.replace("\\", "/").strip().lower()
    # Normalize snippet: strip leading/trailing whitespace per line, collapse spaces
    normalized_lines = [re.sub(r"\s+", " ", line.strip()) for line in code_snippet.splitlines() if line.strip()]
    normalized_snippet = "\n".join(normalized_lines)
    raw_key = f"{rule_id}:{clean_path}:{normalized_snippet}"
    return hashlib.sha256(raw_key.encode("utf-8", errors="ignore")).hexdigest()[:16]


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str = ""
    line_number: int = 1
    end_line_number: Optional[int] = None
    rule_id: str = "GENERAL"
    severity: Severity = Severity.MEDIUM
    category: Category = Category.CODE_QUALITY
    message: str = ""
    explanation: str = ""
    suggestion: str = ""
    confidence: float = 1.0  # 0.0 to 1.0
    code_snippet: str = ""
    fingerprint: str = ""
    newly_introduced: bool = False

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = compute_finding_fingerprint(
                self.rule_id, self.file_path, self.code_snippet or self.message
            )
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.category, str):
            self.category = Category(self.category)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        item = dict(data)
        if "severity" in item and isinstance(item["severity"], str):
            item["severity"] = Severity(item["severity"])
        if "category" in item and isinstance(item["category"], str):
            item["category"] = Category(item["category"])
        return cls(**item)


@dataclass
class FixProposal:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str = ""
    file_path: str = ""
    root_cause: str = ""
    explanation: str = ""
    original_code: str = ""
    replacement_code: str = ""
    unified_diff: str = ""
    compatibility_risks: str = ""
    status: FixStatus = FixStatus.SUGGESTED
    validation_results: Dict[str, Any] = field(default_factory=dict)
    backup_path: Optional[str] = None
    error_message: Optional[str] = None

    def __post_init__(self):
        if isinstance(self.status, str):
            self.status = FixStatus(self.status)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FixProposal:
        item = dict(data)
        if "status" in item and isinstance(item["status"], str):
            item["status"] = FixStatus(item["status"])
        return cls(**item)


@dataclass
class PRMetadata:
    owner: str
    repo: str
    pull_number: int
    title: str = ""
    author: str = ""
    base_branch: str = "main"
    head_branch: str = ""
    head_sha: str = ""
    state: str = "open"
    changed_files_count: int = 0
    html_url: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PRMetadata:
        return cls(**data)


@dataclass
class PRFileChange:
    filename: str
    status: str  # 'modified', 'added', 'removed', 'renamed'
    additions: int = 0
    deletions: int = 0
    patch: Optional[str] = None
    changed_lines: List[int] = field(default_factory=list)
    old_filename: Optional[str] = None
    is_binary: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PRFileChange:
        return cls(**data)


@dataclass
class ScanMetadata:
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_date: str = ""
    duration_seconds: float = 0.0
    target_type: str = "local_file"  # 'local_file', 'local_directory', 'github_pr'
    target_identifier: str = ""  # filename, path, or owner/repo#123
    ref_name: Optional[str] = None
    commit_sha: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "LOW"
    scanner_versions: Dict[str, str] = field(default_factory=dict)
    status: str = "COMPLETED"  # 'COMPLETED', 'FAILED', 'IN_PROGRESS'
    error_message: Optional[str] = None
    user_id: str = "default_user"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanMetadata:
        return cls(**data)


@dataclass
class ScanResult:
    metadata: ScanMetadata
    findings: List[Finding] = field(default_factory=list)
    fix_proposals: List[FixProposal] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "fix_proposals": [p.to_dict() for p in self.fix_proposals],
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanResult:
        meta = ScanMetadata.from_dict(data.get("metadata", {}))
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        fixes = [FixProposal.from_dict(p) for p in data.get("fix_proposals", [])]
        summary = data.get("summary", {})
        return cls(metadata=meta, findings=findings, fix_proposals=fixes, summary=summary)


@dataclass
class ScanComparison:
    base_scan_id: str
    target_scan_id: str
    new_findings: List[Finding] = field(default_factory=list)
    resolved_findings: List[Finding] = field(default_factory=list)
    unchanged_findings: List[Finding] = field(default_factory=list)
    severity_changes: List[Dict[str, Any]] = field(default_factory=list)
    risk_score_diff: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_scan_id": self.base_scan_id,
            "target_scan_id": self.target_scan_id,
            "new_findings": [f.to_dict() for f in self.new_findings],
            "resolved_findings": [f.to_dict() for f in self.resolved_findings],
            "unchanged_findings": [f.to_dict() for f in self.unchanged_findings],
            "severity_changes": self.severity_changes,
            "risk_score_diff": self.risk_score_diff,
        }
