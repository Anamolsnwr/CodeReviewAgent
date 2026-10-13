"""Base interface for AI providers."""

from abc import ABC, abstractmethod
from typing import List, Optional
from codereview.models import Finding, FixProposal, PRMetadata


class BaseAIProvider(ABC):
    """Abstract interface for AI code review and fix generation providers."""

    @abstractmethod
    def review_code(
        self,
        filename: str,
        code: str,
        context: Optional[str] = None,
        changed_lines: Optional[List[int]] = None,
    ) -> List[Finding]:
        """Reviews code and returns a list of Findings."""
        pass

    @abstractmethod
    def generate_fix(
        self,
        finding: Finding,
        file_content: str,
        context: Optional[str] = None,
    ) -> FixProposal:
        """Generates a structured fix proposal for a finding."""
        pass

    @abstractmethod
    def generate_pr_summary(
        self,
        pr_metadata: PRMetadata,
        findings: List[Finding],
    ) -> str:
        """Generates an executive pull request summary based on review findings."""
        pass
