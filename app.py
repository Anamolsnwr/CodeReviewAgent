"""CodeReviewAgent - Streamlit Web Dashboard.

Provides production-ready interfaces for:
1. Local File Review
2. GitHub Pull Request Reviews with inline diff analysis and authorized publishing
3. AI Fix Proposals with 7-step safety validation and rollback controls
4. Persistent Scan History and Deep Scan Comparisons
5. Professional PDF and JSON Report Exports
"""

import json
import os
import streamlit as st
from dotenv import load_dotenv

# Load env variables
load_dotenv()

from codereview.models import (
    Category,
    Finding,
    FixProposal,
    FixStatus,
    PRFileChange,
    PRMetadata,
    ScanMetadata,
    ScanResult,
    Severity,
)
from codereview.github.client import GitHubClient
from codereview.github.review_poster import post_pr_review_comments, post_pr_summary_comment
from codereview.providers.groq_provider import GroqAIProvider
from codereview.providers.mock_provider import MockAIProvider
from codereview.remediation.patcher import apply_fix_to_file, rollback_fix
from codereview.remediation.validator import PatchValidator
from codereview.reports.json_exporter import export_comparison_json, export_scan_json
from codereview.reports.pdf_exporter import export_comparison_pdf, export_scan_pdf
from codereview.scanners.engine import ReviewEngine
from codereview.storage.db import ScanStorage

# Page configuration
st.set_page_config(
    page_title="CodeReviewAgent - Production Code Review Platform",
    page_icon="🛡️",
    layout="wide",
)

# Initialize Storage & Session State
storage = ScanStorage()

if "current_scan" not in st.session_state:
    st.session_state.current_scan = None
if "current_proposal" not in st.session_state:
    st.session_state.current_proposal = None
if "pr_files" not in st.session_state:
    st.session_state.pr_files = []
if "pr_metadata" not in st.session_state:
    st.session_state.pr_metadata = None


def get_ai_provider(api_key: str, model_name: str):
    """Initializes Groq provider if key is available, else returns Mock provider for fallback."""
    if api_key:
        try:
            return GroqAIProvider(api_key=api_key, model=model_name)
        except Exception as e:
            st.sidebar.warning(f"Groq API error ({e}). Using mock provider.")
            return MockAIProvider()
    return MockAIProvider()


# Sidebar Configuration
st.sidebar.title("🛡️ CodeReviewAgent")
st.sidebar.markdown("**AI-Powered Code Review & Automated Remediation**")
st.sidebar.divider()

groq_key_env = os.environ.get("GROQ_API_KEY", "")
github_token_env = os.environ.get("GITHUB_TOKEN", "")

with st.sidebar.expander("🔑 API Credentials & Settings", expanded=False):
    groq_key = st.text_input(
        "Groq API Key",
        value=groq_key_env,
        type="password",
        help="Used for LLM-powered review and fix generation.",
    )
    model_choice = st.selectbox(
        "AI Model",
        options=["openai/gpt-oss-120b", "llama-3.3-70b-versatile"],
        index=0,
    )
    github_token = st.text_input(
        "GitHub Token (PAT)",
        value=github_token_env,
        type="password",
        help="Required for private repositories or posting review comments.",
    )

ai_provider = get_ai_provider(groq_key, model_choice)
review_engine = ReviewEngine(ai_provider=ai_provider)

# Sidebar Quick Metrics
scans_list, total_scans_count = storage.list_scans(page=1, per_page=100)
st.sidebar.metric("Saved Scans in History", total_scans_count)
if st.sidebar.button("🧹 Run Data Retention Cleanup (30 days)"):
    deleted_count = storage.delete_old_scans(days=30)
    st.sidebar.success(f"Purged {deleted_count} scans older than 30 days.")
    st.rerun()

# Main Header
st.title("🛡️ Production Code Review & Remediation Platform")

# Tabs
tab_local, tab_github, tab_fix, tab_history, tab_reports = st.tabs([
    "📁 Local Review",
    "🐙 GitHub PR Reviews",
    "🛠️ AI Fix & Validation Studio",
    "📜 Scan History & Comparisons",
    "📥 Reports & Exports",
])


# ==============================================================================
# TAB 1: LOCAL REVIEW
# ==============================================================================
with tab_local:
    st.header("Analyze Local Source Code")
    st.markdown("Run static security analyzers (AST, regex rules, complexity) combined with AI code review.")

    local_mode = st.radio("Choose Input Mode", ["Upload Python File", "Paste Code Snippet"], horizontal=True)

    file_name = "sample.py"
    file_content = ""

    if local_mode == "Upload Python File":
        uploaded_file = st.file_uploader("Upload a Python file", type=["py", "txt"])
        if uploaded_file is not None:
            file_name = uploaded_file.name
            file_content = uploaded_file.getvalue().decode("utf-8", errors="replace")
    else:
        file_name = st.text_input("Filename", value="snippet.py")
        file_content = st.text_area(
            "Source Code",
            height=250,
            value="""import os\n\ndef run_query(user_id):\n    # Potential SQLi & bare except\n    try:\n        query = f"SELECT * FROM users WHERE id = '{user_id}'"\n        print(query)\n    except:\n        pass\n""",
        )

    col_btn1, col_btn2 = st.columns([1, 4])
    with col_btn1:
        start_local_scan = st.button("🚀 Start Code Review", type="primary", use_container_width=True)

    if start_local_scan:
        if not file_content.strip():
            st.error("Please provide non-empty source code to review.")
        else:
            with st.spinner("Analyzing code with static analyzers and AI..."):
                scan_res = review_engine.review_file(
                    filename=file_name,
                    code=file_content,
                    use_ai=True,
                    target_type="local_file",
                    target_identifier=file_name,
                )
                storage.save_scan(scan_res)
                st.session_state.current_scan = scan_res
                st.session_state.local_code_cache = file_content
                st.success(f"Review completed! Scan ID: `{scan_res.metadata.scan_id}`")

    # Render Current Scan Results if available
    if st.session_state.current_scan and st.session_state.current_scan.metadata.target_type == "local_file":
        scan = st.session_state.current_scan
        st.divider()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk Score", f"{scan.metadata.risk_score}/100", scan.metadata.risk_level)
        c2.metric("Total Findings", len(scan.findings))
        crit_count = sum(1 for f in scan.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in scan.findings if f.severity == Severity.HIGH)
        c3.metric("Critical / High", f"{crit_count} / {high_count}")
        c4.metric("Scan Duration", f"{scan.metadata.duration_seconds}s")

        st.info(scan.summary.get("explanation", ""))

        st.subheader("Findings List")
        if not scan.findings:
            st.success("🎉 No issues detected! Your code passed all checks.")
        else:
            for idx, finding in enumerate(scan.findings, 1):
                sev_color = {
                    Severity.CRITICAL: "red",
                    Severity.HIGH: "orange",
                    Severity.MEDIUM: "blue",
                    Severity.LOW: "gray",
                    Severity.INFO: "gray",
                }.get(finding.severity, "gray")

                with st.expander(f"{idx}. [{finding.severity.value}] {finding.rule_id} (Line {finding.line_number}) - {finding.message}"):
                    st.markdown(f"**Category**: `{finding.category.value}` | **Confidence**: `{finding.confidence * 100:.0f}%`")
                    st.markdown(f"**Explanation**: {finding.explanation}")
                    if finding.code_snippet:
                        st.code(finding.code_snippet, language="python")
                    st.markdown(f"💡 **Suggested Fix**: {finding.suggestion}")

                    if st.button(f"Generate Fix Proposal for #{idx}", key=f"fix_btn_{finding.id}"):
                        with st.spinner("Generating fix proposal with AI..."):
                            code_source = st.session_state.get("local_code_cache", "")
                            proposal = ai_provider.generate_fix(finding, code_source)
                            st.session_state.current_proposal = proposal
                            st.session_state.proposal_finding = finding
                            st.session_state.proposal_source = code_source
                            st.success("Fix proposal generated! Switch to the 'AI Fix & Validation Studio' tab to inspect and validate.")


# ==============================================================================
# TAB 2: GITHUB PULL REQUEST REVIEWS
# ==============================================================================
with tab_github:
    st.header("GitHub Pull Request Code Review")
    st.markdown("Inspect changed files, map diffs to head lines, prioritize newly introduced vulnerabilities, and publish reviews.")

    col_gh1, col_gh2, col_gh3 = st.columns([2, 2, 1])
    with col_gh1:
        gh_owner = st.text_input("Repository Owner", placeholder="e.g. octocat")
    with col_gh2:
        gh_repo = st.text_input("Repository Name", placeholder="e.g. Hello-World")
    with col_gh3:
        gh_pr_num = st.number_input("PR #", min_value=1, step=1, value=1)

    btn_fetch_pr = st.button("🔍 Fetch & Review Pull Request", type="primary")

    if btn_fetch_pr:
        if not gh_owner.strip() or not gh_repo.strip():
            st.error("Please specify repository owner and repository name.")
        else:
            try:
                gh_client = GitHubClient(token=github_token)
                with st.spinner("Fetching pull request metadata and changed files..."):
                    pr_meta = gh_client.get_pull_request(gh_owner, gh_repo, gh_pr_num)
                    pr_files = gh_client.get_pull_request_files(gh_owner, gh_repo, gh_pr_num)

                st.session_state.pr_metadata = pr_meta
                st.session_state.pr_files = pr_files

                # Analyze files
                with st.spinner(f"Reviewing {len(pr_files)} changed files..."):
                    files_dict = {}
                    changed_lines_dict = {}

                    for pf in pr_files:
                        if pf.is_binary or pf.status == "removed":
                            continue
                        try:
                            content = gh_client.get_file_content(gh_owner, gh_repo, pf.filename, pr_meta.head_sha)
                            files_dict[pf.filename] = content
                            changed_lines_dict[pf.filename] = pf.changed_lines
                        except Exception as fetch_err:
                            st.warning(f"Could not load full content for {pf.filename}: {fetch_err}")

                    scan_res = review_engine.review_files(
                        files_dict=files_dict,
                        changed_lines_dict=changed_lines_dict,
                        use_ai=True,
                        target_type="github_pr",
                        target_identifier=f"{gh_owner}/{gh_repo}#{gh_pr_num}",
                        commit_sha=pr_meta.head_sha,
                        ref_name=pr_meta.head_branch,
                    )

                    # Save scan in history
                    storage.save_scan(scan_res)
                    st.session_state.current_scan = scan_res
                    st.session_state.pr_summary_text = ai_provider.generate_pr_summary(pr_meta, scan_res.findings)
                    st.success(f"PR #{gh_pr_num} review complete! Stored under Scan ID `{scan_res.metadata.scan_id}`")

            except Exception as e:
                st.error(f"Failed to review PR: {e}")

    # Display PR Review Dashboard
    if st.session_state.pr_metadata and st.session_state.current_scan and st.session_state.current_scan.metadata.target_type == "github_pr":
        pr_meta = st.session_state.pr_metadata
        scan = st.session_state.current_scan

        st.divider()
        st.subheader(f"Pull Request #{pr_meta.pull_number}: {pr_meta.title}")
        st.markdown(f"**Author**: `{pr_meta.author}` | **Branches**: `{pr_meta.base_branch}` ⬅️ `{pr_meta.head_branch}` (`{pr_meta.head_sha[:7]}`)")

        col_pr1, col_pr2, col_pr3, col_pr4 = st.columns(4)
        col_pr1.metric("Risk Score", f"{scan.metadata.risk_score}/100", scan.metadata.risk_level)
        newly_intro_count = sum(1 for f in scan.findings if f.newly_introduced)
        col_pr2.metric("New Issues in Diff", newly_intro_count)
        col_pr3.metric("Total Findings", len(scan.findings))
        col_pr4.metric("Files Changed", len(st.session_state.pr_files))

        # Executive Summary
        if "pr_summary_text" in st.session_state:
            with st.expander("📋 Executive PR Review Summary", expanded=True):
                st.markdown(st.session_state.pr_summary_text)

        # Filters
        st.subheader("Filter Findings")
        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            selected_sev = st.multiselect("Severity", options=[s.value for s in Severity], default=[s.value for s in Severity])
        with fcol2:
            selected_cat = st.multiselect("Category", options=[c.value for c in Category], default=[c.value for c in Category])
        with fcol3:
            avail_files = sorted(list({f.file_path for f in scan.findings}))
            selected_files = st.multiselect("Files", options=avail_files, default=avail_files)

        filtered_findings = [
            f for f in scan.findings
            if f.severity.value in selected_sev and f.category.value in selected_cat and (not selected_files or f.file_path in selected_files)
        ]

        st.markdown(f"Showing **{len(filtered_findings)}** of {len(scan.findings)} findings:")

        for idx, f in enumerate(filtered_findings, 1):
            badge = "🔥 [NEW REGRESSION IN DIFF]" if f.newly_introduced else "ℹ️ [EXISTING IN FILE]"
            with st.expander(f"{idx}. [{f.severity.value}] {badge} {f.file_path}:{f.line_number} - {f.rule_id}"):
                st.markdown(f"**Message**: {f.message}")
                st.markdown(f"**Root Cause**: {f.explanation}")
                if f.code_snippet:
                    st.code(f.code_snippet, language="python")
                st.markdown(f"💡 **Remediation**: {f.suggestion}")

        # Publish Review to GitHub (Explicit User Confirmation Required)
        st.divider()
        st.subheader("📤 Publish Review to GitHub")
        st.markdown("Submit findings as inline diff comments or as an executive review summary.")

        confirm_publish = st.checkbox(
            "I explicitly confirm and authorize posting these review comments to GitHub.",
            value=False,
            help="Safety control: comments will never be posted without explicit user consent.",
        )

        col_pub1, col_pub2 = st.columns(2)
        with col_pub1:
            if st.button("Post Executive Summary Comment", type="primary", disabled=not confirm_publish):
                try:
                    gh_client = GitHubClient(token=github_token)
                    res = post_pr_summary_comment(
                        client=gh_client,
                        owner=pr_meta.owner,
                        repo=pr_meta.repo,
                        pull_number=pr_meta.pull_number,
                        summary_markdown=st.session_state.get("pr_summary_text", "Review completed."),
                        user_confirmed=confirm_publish,
                    )
                    st.success(f"Review summary comment published successfully! Result: {res.get('status', 'created')}")
                except Exception as post_err:
                    st.error(f"Failed to post summary: {post_err}")

        with col_pub2:
            if st.button("Post Inline Diff Review Comments", disabled=not confirm_publish):
                try:
                    gh_client = GitHubClient(token=github_token)
                    res = post_pr_review_comments(
                        client=gh_client,
                        owner=pr_meta.owner,
                        repo=pr_meta.repo,
                        pull_number=pr_meta.pull_number,
                        commit_sha=pr_meta.head_sha,
                        findings=scan.findings,
                        file_changes=st.session_state.pr_files,
                        summary_text=st.session_state.get("pr_summary_text", "Review findings"),
                        user_confirmed=confirm_publish,
                    )
                    st.success(f"Inline comments published! Posted: {res.get('posted_inline_count', 0)}, Skipped: {res.get('skipped_not_in_diff', 0)} outside diff, {res.get('skipped_duplicate', 0)} duplicates.")
                except Exception as post_err:
                    st.error(f"Failed to post review comments: {post_err}")


# ==============================================================================
# TAB 3: AI FIX & VALIDATION STUDIO
# ==============================================================================
with tab_fix:
    st.header("AI-Powered Fixes & 7-Step Validation Studio")
    st.markdown("Inspect proposed fixes, execute rigorous multi-step safety validation, and apply or rollback changes safely.")

    if not st.session_state.current_proposal:
        st.info("No fix proposal selected. Run a code review in Tab 1 or Tab 2 and click 'Generate Fix Proposal'.")
    else:
        proposal: FixProposal = st.session_state.current_proposal
        st.subheader(f"Fix Proposal for `{proposal.file_path}`")
        st.markdown(f"**Status**: `{proposal.status.value}`")

        c_info1, c_info2 = st.columns(2)
        c_info1.markdown(f"**Root Cause**: {proposal.root_cause}")
        c_info2.markdown(f"**Compatibility Risks**: {proposal.compatibility_risks or 'None identified'}")
        st.markdown(f"**Explanation**: {proposal.explanation}")

        # Unified Diff
        st.markdown("#### Proposed Patch (Unified Diff)")
        if proposal.unified_diff:
            st.code(proposal.unified_diff, language="diff")
        else:
            col_orig, col_repl = st.columns(2)
            with col_orig:
                st.markdown("**Original Code**")
                st.code(proposal.original_code, language="python")
            with col_repl:
                st.markdown("**Replacement Code**")
                st.code(proposal.replacement_code, language="python")

        # Validation Section
        st.divider()
        st.subheader("7-Step Patch Safety Validation")

        if st.button("🧪 Execute 7-Step Validation Pipeline", type="primary"):
            validator = PatchValidator()
            source = st.session_state.get("proposal_source", "")
            target_finding = st.session_state.get("proposal_finding", None)

            with st.spinner("Running 7-step validation pipeline..."):
                validated_proposal = validator.validate_proposal(
                    proposal=proposal,
                    original_file_content=source,
                    finding=target_finding,
                )
                st.session_state.current_proposal = validated_proposal

            if validated_proposal.status == FixStatus.VALIDATION_PASSED:
                st.success("✅ All validation checks PASSED! Patch is verified and safe.")
            elif validated_proposal.status == FixStatus.VALIDATION_FAILED:
                st.error(f"❌ Validation FAILED: {validated_proposal.error_message}")
            else:
                st.warning("⚠️ Fix marked as UNVERIFIED (test suite omitted or incomplete).")

        # Show Validation Steps breakdown
        if proposal.validation_results:
            st.markdown("#### Validation Checks Results")
            for step_key, step_data in proposal.validation_results.items():
                step_name = step_key.replace("_", " ").title()
                passed = step_data.get("passed", False)
                details = step_data.get("details", "")
                skipped = step_data.get("skipped", False)

                if skipped:
                    st.info(f"⚪ **{step_name}**: Skipped - {details}")
                elif passed:
                    st.success(f"🟢 **{step_name}**: PASSED - {details}")
                else:
                    st.error(f"🔴 **{step_name}**: FAILED - {details}")

        # Application and Rollback Controls
        st.divider()
        st.subheader("Apply / Rollback Fix")

        confirm_apply = st.checkbox("I authorize modifying the target source file on disk.", value=False)
        col_app1, col_app2 = st.columns(2)

        with col_app1:
            if st.button("💾 Apply Fix (with automatic backup)", disabled=not confirm_apply or proposal.status == FixStatus.VALIDATION_FAILED):
                ok, msg = apply_fix_to_file(
                    proposal.file_path,
                    proposal,
                    user_confirmed=confirm_apply,
                )
                if ok:
                    st.success(f"{msg} Backup saved to `{proposal.backup_path}`")
                    st.rerun()
                else:
                    st.error(f"Apply failed: {msg}")

        with col_app2:
            if st.button("⏪ Rollback Fix", disabled=not (proposal.status == FixStatus.APPLIED and proposal.backup_path)):
                ok, msg = rollback_fix(proposal)
                if ok:
                    st.success(f"{msg} File restored from backup.")
                    st.rerun()
                else:
                    st.error(f"Rollback failed: {msg}")


# ==============================================================================
# TAB 4: SCAN HISTORY & COMPARISONS
# ==============================================================================
with tab_history:
    st.header("Persistent Scan History & Comparisons")
    st.markdown("Revisit previous scan results, inspect past findings, and compare scans to detect new or resolved issues.")

    search_query = st.text_input("🔍 Search Scans (by target or ID)", placeholder="e.g. sample.py, repo#12")
    scans, total_count = storage.list_scans(search=search_query.strip() or None, page=1, per_page=50)

    if not scans:
        st.info("No scans found in history.")
    else:
        scan_table_data = [
            {
                "Scan ID": s.scan_id[:8] + "...",
                "Target": s.target_identifier,
                "Type": s.target_type,
                "Date": s.scan_date,
                "Risk Score": f"{s.risk_score} ({s.risk_level})",
                "Duration": f"{s.duration_seconds}s",
                "Full ID": s.scan_id,
            }
            for s in scans
        ]
        st.dataframe(scan_table_data, use_container_width=True)

        col_sel, col_del = st.columns([3, 1])
        with col_sel:
            selected_scan_id = st.selectbox("Select Scan to Inspect", options=[s.scan_id for s in scans], format_func=lambda sid: f"{sid} ({next((s.target_identifier for s in scans if s.scan_id == sid), '')})")
        with col_del:
            st.write("")
            st.write("")
            if st.button("🗑️ Delete Selected Scan"):
                storage.delete_scan(selected_scan_id)
                st.success("Scan deleted.")
                st.rerun()

        if st.button("📂 Load Selected Scan"):
            loaded = storage.get_scan(selected_scan_id)
            if loaded:
                st.session_state.current_scan = loaded
                st.success(f"Loaded scan `{selected_scan_id}` with {len(loaded.findings)} findings.")

        # Scan Comparison Studio
        st.divider()
        st.subheader("⚖️ Compare Two Scans")
        st.markdown("Detect new regressions, resolved findings, and risk score differences using stable finding fingerprints.")

        col_cmp1, col_cmp2 = st.columns(2)
        with col_cmp1:
            base_id = st.selectbox("Base Scan (Earlier / Baseline)", options=[s.scan_id for s in scans], key="cmp_base")
        with col_cmp2:
            target_id = st.selectbox("Target Scan (Newer / PR)", options=[s.scan_id for s in scans], key="cmp_target")

        if st.button("🔍 Run Deep Comparison"):
            if base_id == target_id:
                st.warning("Please choose two different scans to compare.")
            else:
                try:
                    comparison = storage.compare_scans(base_id, target_id)
                    st.session_state.current_comparison = comparison
                    base_scan = storage.get_scan(base_id)
                    target_scan = storage.get_scan(target_id)
                    st.session_state.comparison_base_scan = base_scan
                    st.session_state.comparison_target_scan = target_scan

                    st.markdown("#### Comparison Summary")
                    mc1, mc2, mc3, mc4 = st.columns(4)
                    mc1.metric("New Findings", len(comparison.new_findings), delta=len(comparison.new_findings), delta_color="inverse")
                    mc2.metric("Resolved Findings", len(comparison.resolved_findings), delta=len(comparison.resolved_findings))
                    mc3.metric("Unchanged Findings", len(comparison.unchanged_findings))
                    mc4.metric("Risk Score Delta", f"{comparison.risk_score_diff:+0.1f}")

                    if comparison.new_findings:
                        st.error(f"🚨 **{len(comparison.new_findings)} Newly Introduced Findings**:")
                        for nf in comparison.new_findings:
                            st.markdown(f"- **[{nf.severity.value}]** `{nf.file_path}:{nf.line_number}` - {nf.rule_id}: {nf.message}")

                    if comparison.resolved_findings:
                        st.success(f"✅ **{len(comparison.resolved_findings)} Resolved Findings**:")
                        for rf in comparison.resolved_findings:
                            st.markdown(f"- **[RESOLVED]** `{rf.file_path}:{rf.line_number}` - {rf.rule_id}: {rf.message}")

                except Exception as cmp_err:
                    st.error(f"Comparison error: {cmp_err}")


# ==============================================================================
# TAB 5: REPORTS & EXPORTS
# ==============================================================================
with tab_reports:
    st.header("Download & Export Reports")
    st.markdown("Generate executive PDF reports or structured JSON exports for audit compliance, integration, and CI/CD pipelines.")

    report_source = st.radio("Choose Report Target", ["Current Active Scan", "Scan Comparison"], horizontal=True)

    if report_source == "Current Active Scan":
        if not st.session_state.current_scan:
            st.info("No active scan loaded. Select or run a scan first.")
        else:
            scan = st.session_state.current_scan
            st.markdown(f"**Selected Scan**: `{scan.metadata.scan_id}` ({scan.metadata.target_identifier})")

            col_rep1, col_rep2 = st.columns(2)
            with col_rep1:
                pdf_data = export_scan_pdf(scan)
                st.download_button(
                    label="📄 Download PDF Report",
                    data=pdf_data,
                    file_name=f"codereview_report_{scan.metadata.scan_id[:8]}.pdf",
                    mime="application/pdf",
                    type="primary",
                )

            with col_rep2:
                json_data = export_scan_json(scan)
                st.download_button(
                    label="💾 Download JSON Report",
                    data=json_data,
                    file_name=f"codereview_report_{scan.metadata.scan_id[:8]}.json",
                    mime="application/json",
                )

    else:
        if "current_comparison" not in st.session_state:
            st.info("No comparison generated yet. Perform a scan comparison in Tab 4 first.")
        else:
            cmp_res = st.session_state.current_comparison
            b_scan = st.session_state.comparison_base_scan
            t_scan = st.session_state.comparison_target_scan

            st.markdown(f"**Comparison**: Base `{cmp_res.base_scan_id[:8]}` vs Target `{cmp_res.target_scan_id[:8]}`")

            col_rep1, col_rep2 = st.columns(2)
            with col_rep1:
                cmp_pdf_data = export_comparison_pdf(cmp_res, b_scan, t_scan)
                st.download_button(
                    label="📄 Download Comparison PDF Report",
                    data=cmp_pdf_data,
                    file_name=f"comparison_report_{cmp_res.target_scan_id[:8]}.pdf",
                    mime="application/pdf",
                    type="primary",
                )

            with col_rep2:
                cmp_json_data = export_comparison_json(cmp_res)
                st.download_button(
                    label="💾 Download Comparison JSON Report",
                    data=cmp_json_data,
                    file_name=f"comparison_report_{cmp_res.target_scan_id[:8]}.json",
                    mime="application/json",
                )
