"""PDF Report Generator using fpdf2 with safe typography and structured styling."""

import os
from typing import Optional
from fpdf import FPDF
from codereview.models import ScanResult, ScanComparison, Severity
from codereview.utils.security import redact_sensitive_text


def _clean_text(text: str) -> str:
    """Sanitizes text for safe rendering in core PDF fonts."""
    if not text:
        return ""
    redacted = redact_sensitive_text(str(text))
    # Replace unsupported unicode quotes or dashes
    cleaned = (
        redacted.replace("“", '"')
        .replace("”", '"')
        .replace("‘", "'")
        .replace("’", "'")
        .replace("—", "-")
        .replace("–", "-")
        .replace("…", "...")
    )
    # Ensure latin-1 encodeable for standard PDF Helvetica font
    return cleaned.encode("latin-1", "replace").decode("latin-1")


class CodeReviewPDF(FPDF):
    """Custom styled PDF document for CodeReviewAgent reports."""

    def __init__(self, title_text: str = "CodeReviewAgent Security & Quality Report"):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.title_text = title_text
        self.set_auto_page_break(auto=True, margin=15)
        self.set_margins(15, 15, 15)

    def header(self):
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 110, 120)
        self.cell(100, 8, _clean_text(self.title_text), border=0)
        self.set_font("Helvetica", "", 9)
        self.cell(self.epw - 100, 8, "Automated Security Audit", border=0, align="R")
        self.ln(9)
        self.set_draw_color(220, 224, 230)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_draw_color(220, 224, 230)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(self.epw, 10, f"Page {self.page_no()}", border=0, align="C")


def export_scan_pdf(scan_result: ScanResult, output_path: Optional[str] = None) -> bytes:
    """Renders a complete, professional PDF report from a ScanResult."""
    meta = scan_result.metadata
    pdf = CodeReviewPDF(title_text=f"CodeReviewAgent Report - {meta.target_identifier}")
    pdf.add_page()

    # Title Banner
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(pdf.epw, 10, "Code Review & Security Audit Report")
    pdf.ln(11)

    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 90, 100)
    pdf.cell(pdf.epw, 6, f"Generated: {meta.scan_date} | Scan ID: {meta.scan_id}")
    pdf.ln(8)

    # Executive Summary Card
    top_y = pdf.get_y()
    pdf.set_fill_color(245, 247, 250)
    pdf.rect(pdf.l_margin, top_y, pdf.epw, 26, "F")

    pdf.set_xy(pdf.l_margin + 5, top_y + 3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(30, 41, 59)
    col_w = (pdf.epw - 10) / 3
    pdf.cell(col_w, 5, "Risk Score")
    pdf.cell(col_w, 5, "Target Type")
    pdf.cell(col_w, 5, "Duration")
    pdf.ln(6)

    pdf.set_x(pdf.l_margin + 5)
    pdf.set_font("Helvetica", "B", 13)
    # Risk color
    if meta.risk_score >= 50:
        pdf.set_text_color(220, 38, 38)
    elif meta.risk_score >= 20:
        pdf.set_text_color(217, 119, 6)
    else:
        pdf.set_text_color(16, 185, 129)

    pdf.cell(col_w, 8, f"{meta.risk_score}/100 ({meta.risk_level})")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(col_w, 8, _clean_text(meta.target_type))
    pdf.cell(col_w, 8, f"{meta.duration_seconds}s")
    pdf.set_y(top_y + 32)

    # Severity Summary
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(pdf.epw, 8, "Findings Summary by Severity")
    pdf.ln(9)

    sev_counts = scan_result.summary.get("severity_counts", {})
    pdf.set_font("Helvetica", "B", 10)

    # Render summary table
    cell_w = pdf.epw / 5
    pdf.set_x(pdf.l_margin)
    pdf.set_fill_color(220, 38, 38)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(cell_w, 7, "Critical", 1, align="C", fill=True)

    pdf.set_fill_color(234, 88, 12)
    pdf.cell(cell_w, 7, "High", 1, align="C", fill=True)

    pdf.set_fill_color(202, 138, 4)
    pdf.cell(cell_w, 7, "Medium", 1, align="C", fill=True)

    pdf.set_fill_color(59, 130, 246)
    pdf.cell(cell_w, 7, "Low", 1, align="C", fill=True)

    pdf.set_fill_color(107, 114, 128)
    pdf.cell(cell_w, 7, "Info", 1, align="C", fill=True)
    pdf.ln(7)

    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(cell_w, 8, str(sev_counts.get("CRITICAL", 0)), 1, align="C")
    pdf.cell(cell_w, 8, str(sev_counts.get("HIGH", 0)), 1, align="C")
    pdf.cell(cell_w, 8, str(sev_counts.get("MEDIUM", 0)), 1, align="C")
    pdf.cell(cell_w, 8, str(sev_counts.get("LOW", 0)), 1, align="C")
    pdf.cell(cell_w, 8, str(sev_counts.get("INFO", 0)), 1, align="C")
    pdf.ln(12)

    # Detailed Findings Section
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(pdf.epw, 8, f"Detailed Findings ({len(scan_result.findings)})")
    pdf.ln(9)

    if not scan_result.findings:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "I", 10)
        pdf.set_text_color(75, 85, 99)
        pdf.cell(pdf.epw, 8, "No security vulnerabilities or code quality issues detected.")
        pdf.ln(8)
    else:
        for idx, f in enumerate(scan_result.findings, 1):
            if pdf.get_y() > 240:
                pdf.add_page()

            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 10)
            if f.severity == Severity.CRITICAL:
                pdf.set_text_color(220, 38, 38)
            elif f.severity == Severity.HIGH:
                pdf.set_text_color(234, 88, 12)
            elif f.severity == Severity.MEDIUM:
                pdf.set_text_color(180, 83, 9)
            else:
                pdf.set_text_color(59, 130, 246)

            new_badge = " [NEW REGRESSION]" if f.newly_introduced else ""
            pdf.cell(pdf.epw, 6, f"{idx}. [{f.severity.value}] {f.rule_id}{new_badge}")
            pdf.ln(6)

            # Location
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(55, 65, 81)
            pdf.cell(pdf.epw, 5, _clean_text(f"File: {f.file_path} (Line {f.line_number})"))
            pdf.ln(5)

            # Issue
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(31, 41, 55)
            pdf.multi_cell(pdf.epw, 4.5, _clean_text(f"Issue: {f.message}"))

            if f.explanation:
                pdf.set_x(pdf.l_margin)
                pdf.set_font("Helvetica", "I", 9)
                pdf.set_text_color(75, 85, 99)
                pdf.multi_cell(pdf.epw, 4.5, _clean_text(f"Root Cause: {f.explanation}"))

            if f.suggestion:
                pdf.set_x(pdf.l_margin)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(16, 120, 80)
                pdf.multi_cell(pdf.epw, 4.5, _clean_text(f"Remediation: {f.suggestion}"))

            pdf.ln(2)
            pdf.set_draw_color(240, 242, 245)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(3)

    # Fix Proposals Section (if any)
    if scan_result.fix_proposals:
        pdf.add_page()
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(24, 43, 73)
        pdf.cell(pdf.epw, 8, f"AI Remediation & Fix Proposals ({len(scan_result.fix_proposals)})")
        pdf.ln(9)

        for p_idx, p in enumerate(scan_result.fix_proposals, 1):
            if pdf.get_y() > 230:
                pdf.add_page()

            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(30, 41, 59)
            pdf.cell(pdf.epw, 6, f"Proposal #{p_idx}: File {p.file_path} - Status: {p.status.value}")
            pdf.ln(6)

            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(75, 85, 99)
            pdf.multi_cell(pdf.epw, 4.5, _clean_text(f"Explanation: {p.explanation}"))

            if p.validation_results:
                pdf.set_x(pdf.l_margin)
                pdf.set_font("Helvetica", "B", 8)
                val_summary = ", ".join([f"{k}: {'PASS' if v.get('passed') else 'FAIL'}" for k, v in p.validation_results.items()])
                pdf.cell(pdf.epw, 5, _clean_text(f"Validation Pipeline: {val_summary}"))
                pdf.ln(5)

            pdf.ln(4)

    pdf_bytes = bytes(pdf.output())
    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes


def export_comparison_pdf(
    comparison: ScanComparison,
    base_scan: ScanResult,
    target_scan: ScanResult,
    output_path: Optional[str] = None,
) -> bytes:
    """Renders a PDF comparison report between two scans."""
    pdf = CodeReviewPDF(title_text="Scan Comparison Audit Report")
    pdf.add_page()

    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(24, 43, 73)
    pdf.cell(pdf.epw, 10, "Code Review Scan Comparison")
    pdf.ln(11)

    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(75, 85, 99)
    pdf.cell(pdf.epw, 5, f"Base Scan: {base_scan.metadata.scan_id} ({base_scan.metadata.scan_date})")
    pdf.ln(6)
    pdf.set_x(pdf.l_margin)
    pdf.cell(pdf.epw, 5, f"Target Scan: {target_scan.metadata.scan_id} ({target_scan.metadata.scan_date})")
    pdf.ln(8)

    # Delta Summary Card
    top_y = pdf.get_y()
    pdf.set_fill_color(245, 247, 250)
    pdf.rect(pdf.l_margin, top_y, pdf.epw, 22, "F")

    pdf.set_xy(pdf.l_margin + 5, top_y + 3)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(30, 41, 59)
    col_w = (pdf.epw - 10) / 4
    pdf.cell(col_w, 5, "New Issues")
    pdf.cell(col_w, 5, "Resolved Issues")
    pdf.cell(col_w, 5, "Unchanged")
    pdf.cell(col_w, 5, "Risk Delta")
    pdf.ln(6)

    pdf.set_x(pdf.l_margin + 5)
    pdf.set_font("Helvetica", "B", 12)
    # New issues (red if >0)
    pdf.set_text_color(220, 38, 38 if len(comparison.new_findings) > 0 else 55)
    pdf.cell(col_w, 7, str(len(comparison.new_findings)))

    # Resolved (green if >0)
    pdf.set_text_color(16, 185, 129 if len(comparison.resolved_findings) > 0 else 55)
    pdf.cell(col_w, 7, str(len(comparison.resolved_findings)))

    pdf.set_text_color(55, 65, 81)
    pdf.cell(col_w, 7, str(len(comparison.unchanged_findings)))

    # Risk diff
    delta_color = (220, 38, 38) if comparison.risk_score_diff > 0 else (16, 185, 129)
    pdf.set_text_color(*delta_color)
    delta_sign = "+" if comparison.risk_score_diff > 0 else ""
    pdf.cell(col_w, 7, f"{delta_sign}{comparison.risk_score_diff}")
    pdf.set_y(top_y + 28)

    # New Findings list
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(220, 38, 38)
    pdf.cell(pdf.epw, 8, f"Newly Introduced Findings ({len(comparison.new_findings)})")
    pdf.ln(9)

    for nf in comparison.new_findings:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(pdf.epw, 5, _clean_text(f"- [{nf.severity.value}] {nf.rule_id} in {nf.file_path}:{nf.line_number}"))
        pdf.ln(5)
        pdf.set_x(pdf.l_margin + 5)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(75, 85, 99)
        pdf.multi_cell(pdf.epw - 5, 4.5, _clean_text(f"{nf.message}"))
    pdf.ln(4)

    # Resolved Findings list
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(16, 185, 129)
    pdf.cell(pdf.epw, 8, f"Resolved Findings ({len(comparison.resolved_findings)})")
    pdf.ln(9)

    for rf in comparison.resolved_findings:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(pdf.epw, 5, _clean_text(f"- [RESOLVED] {rf.rule_id} in {rf.file_path}:{rf.line_number}"))
        pdf.ln(5)
        pdf.set_x(pdf.l_margin + 5)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(75, 85, 99)
        pdf.multi_cell(pdf.epw - 5, 4.5, _clean_text(f"{rf.message}"))

    pdf_bytes = bytes(pdf.output())
    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes
