"""Scoring calculation module."""
from codereview.models import Finding, Severity, Category
from typing import List, Dict, Any, Tuple


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 7.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.5,
}


def calculate_risk_score(findings: List[Finding]) -> Tuple[float, str, Dict[str, Any]]:
    """Calculates an overall risk score from 0.0 to 100.0 based on findings.

    Returns:
        (score, risk_level, breakdown_dict)
    """
    if not findings:
        return 0.0, "CLEAN", {
            "total_findings": 0,
            "severity_counts": {s.value: 0 for s in Severity},
            "category_counts": {c.value: 0 for c in Category},
            "raw_points": 0.0,
            "explanation": "No issues detected. Code appears clean.",
        }

    severity_counts = {s.value: 0 for s in Severity}
    category_counts = {c.value: 0 for c in Category}
    raw_points = 0.0

    for f in findings:
        sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
        cat = f.category if isinstance(f.category, Category) else Category(f.category)
        severity_counts[sev.value] += 1
        category_counts[cat.value] += 1

        weight = SEVERITY_WEIGHTS.get(sev, 5.0)
        conf = max(0.2, min(1.0, f.confidence))
        mult = 1.25 if f.newly_introduced else 1.0
        raw_points += weight * conf * mult

    # Scale non-linearly to 100 max
    score = round(min(100.0, raw_points), 1)

    if score >= 75.0 or severity_counts[Severity.CRITICAL.value] > 0:
        risk_level = "CRITICAL"
        explanation = f"Critical risk detected! Contains {severity_counts[Severity.CRITICAL.value]} critical and {severity_counts[Severity.HIGH.value]} high severity issues requiring immediate remediation."
    elif score >= 45.0 or severity_counts[Severity.HIGH.value] > 0:
        risk_level = "HIGH"
        explanation = f"High risk detected with {severity_counts[Severity.HIGH.value]} high severity issues present."
    elif score >= 20.0:
        risk_level = "MEDIUM"
        explanation = f"Medium risk: found several medium/low priority improvements and bug fixes."
    elif score > 0.0:
        risk_level = "LOW"
        explanation = "Low risk: minor code quality suggestions or informational notices."
    else:
        risk_level = "CLEAN"
        explanation = "Code is clean with no flagged issues."

    breakdown = {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "raw_points": round(raw_points, 1),
        "explanation": explanation,
    }

    return score, risk_level, breakdown
