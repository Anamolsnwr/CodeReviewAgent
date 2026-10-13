"""Structured JSON report exporter with sensitive data redaction."""

import json
from typing import Optional
from codereview.models import ScanResult, ScanComparison
from codereview.utils.security import redact_sensitive_text


def export_scan_json(scan_result: ScanResult, indent: int = 2) -> str:
    """Exports a ScanResult as clean, redacted, structured JSON."""
    data = scan_result.to_dict()
    raw_json = json.dumps(data, indent=indent)
    return redact_sensitive_text(raw_json)


def export_comparison_json(comparison: ScanComparison, indent: int = 2) -> str:
    """Exports a ScanComparison as clean, redacted, structured JSON."""
    data = comparison.to_dict()
    raw_json = json.dumps(data, indent=indent)
    return redact_sensitive_text(raw_json)
