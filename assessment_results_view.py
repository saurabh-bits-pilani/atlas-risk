"""
Standardized Assessment Results View for ATLAS-Risk.
Used both immediately after an assessment completes and when opening a saved report from the Reports section.
Guarantees:
- Clear honest count metrics (no arbitrary overall scores, no false '100% secure' claims).
- Actionable findings with What was observed, Why it matters, Evidence, Practical action, and Verification steps.
- Clear distinction between positive observations and unassessed / protected areas.
- 1-click downloads for verified PDF and standalone HTML reports.
"""

import streamlit as st
import json
import os
from engines.report_exporter import export_assessment_pdf_and_html


def render_assessment_results(record: dict, show_back_button: bool = False):
    rec_id = record.get("id", "ASM-VIEW")
    target = record.get("target_input", record.get("target_url", "Target"))
    status = record.get("status", "COMPLETE")
    summary = record.get("summary", "Assessment completed.")
    counts = record.get("counts", {})

    if show_back_button:
        if st.button("← Back to Reports List"):
            if "opened_report_id" in st.session_state:
                del st.session_state["opened_report_id"]
            st.rerun()

    # Top Header & Action Row
    col_hdr, col_pdf, col_html = st.columns([3, 1.2, 1.2])
    with col_hdr:
        st.subheader(f"📊 Assessment Results: `{target}`")
        status_color = "🟢" if status == "COMPLETE" else ("🟡" if status == "PARTIAL" else "🔴")
        st.caption(f"Status: **{status_color} {status}** | ID: `{rec_id}` | Date: {record.get('created_at', '')[:19].replace('T', ' ')} UTC")

    # Generate or retrieve PDF & HTML exports
    pdf_path, html_path = None, None
    try:
        pdf_path, html_path = export_assessment_pdf_and_html(record)
    except Exception as e:
        st.warning(f"Note: PDF generation background warning: {e}")

    with col_pdf:
        if pdf_path and os.path.exists(pdf_path):
            with open(pdf_path, "rb") as f_pdf:
                st.download_button(
                    "📕 Download PDF",
                    data=f_pdf.read(),
                    file_name=f"{rec_id}.pdf",
                    mime="application/pdf",
                    type="primary",
                    key=f"dl_pdf_{rec_id}"
                )
    with col_html:
        if html_path and os.path.exists(html_path):
            with open(html_path, "rb") as f_html:
                st.download_button(
                    "🌐 Download HTML",
                    data=f_html.read(),
                    file_name=f"{rec_id}.html",
                    mime="text/html",
                    key=f"dl_html_{rec_id}"
                )

    # 4 Standardized Counts Metrics Row (NO arbitrary 100% or /100 score)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Issues Observed", counts.get("issues", 0), delta="Action Recommended" if counts.get("issues", 0) > 0 else "None", delta_color="inverse")
    with c2:
        st.metric("No Issues Observed", counts.get("no_issue", 0), delta="Verified Passing", delta_color="normal")
    with c3:
        st.metric("Unassessed / Blocked", counts.get("not_completed", 0), delta="Requires Access" if counts.get("not_completed", 0) > 0 else "None", delta_color="off")
    with c4:
        st.metric("Not Applicable", counts.get("not_applicable", 0))

    # Executive Summary Box
    st.info(f"**Executive Summary:** {summary}")

    # Tabs: Overview | Findings | Evidence & Coverage | Technical Details
    tab_overview, tab_findings, tab_evidence, tab_tech = st.tabs([
        "📋 Overview",
        "🚨 Findings & Actions",
        "🔍 Evidence & Coverage",
        "⚙️ Technical Details"
    ])

    with tab_overview:
        st.markdown("### Assessment Overview")
        st.write(f"- **Target Evaluated:** `{target}`")
        st.write(f"- **Assessment Mode:** {record.get('target_type', 'Public Review').title()}")
        st.write(f"- **Evaluation Scope:** Bounded public-first inspection.")
        st.write(f"- **Completion State:** `{status}`")
        st.markdown("---")
        st.markdown("#### Recommended Next Steps")
        next_steps = record.get("next_steps", record.get("next_steps_required_access", []))
        for step in next_steps:
            st.markdown(f"• {step}")

    with tab_findings:
        st.markdown("### Observed Issues & Practical Code Fixes")
        findings = record.get("findings", [])
        if not findings:
            st.success("🎉 Zero issues observed within the tested scope!")
        else:
            for idx, f in enumerate(findings, 1):
                sev = f.get("severity", "MEDIUM").upper()
                sev_icon = "🔴" if "HIGH" in sev or "CRIT" in sev else ("🟡" if "MED" in sev else "🔵")
                with st.expander(f"{sev_icon} #{idx}: {f.get('title', f.get('issue', 'Issue'))} ({sev})", expanded=True):
                    st.markdown(f"**What we observed:** {f.get('observed', f.get('evidence', ''))}")
                    st.markdown(f"**Why it matters:** {f.get('why_it_matters', 'Affects application reliability or security.')}")
                    st.markdown(f"**Traceable Evidence:** `{f.get('evidence', '')}`")
                    st.markdown(f"**Recommended Action / Practical Fix:**")
                    st.code(f.get("action", f.get("fix", "")), language="javascript" if "header" in str(f.get("action")).lower() else "html")
                    if f.get("how_to_verify"):
                        st.caption(f"**How to verify:** {f.get('how_to_verify')}")

    with tab_evidence:
        st.markdown("### Verified Positive Observations")
        positives = record.get("positive_observations", [])
        if positives:
            for p in positives:
                st.markdown(f"• **[{p.get('area', 'Verified')}]** {p.get('observation', '')}\n  - *Evidence:* `{p.get('evidence', '')}`")
        else:
            st.caption("No positive observations recorded.")

        st.markdown("---")
        st.markdown("### What We Could Not Assess & Required Access")
        st.caption("Protected barriers and private databases are not vulnerabilities. They indicate boundaries requiring credentials:")
        unassessed = record.get("unassessed_areas", [])
        if unassessed:
            for u in unassessed:
                st.warning(f"• **Area:** `{u.get('area', 'Protected Section')}`\n\n  - *Reason:* {u.get('reason', '')}\n\n  - *Required Access:* **{u.get('required_access', '')}**")
        else:
            st.caption("No unassessed areas reported.")

    with tab_tech:
        st.markdown("### Technical Metadata & Raw Logs")
        st.caption("Detailed taxonomy mappings, raw response headers, and completion metadata:")
        st.json(record)
