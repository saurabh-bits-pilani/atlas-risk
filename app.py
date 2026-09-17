"""
ATLAS-Risk: Professional Guided Security & Posture Assessment Platform.
Main Application Entry Point.
Navigation:
- Home (Clean plain-language dashboard with Start Assessment CTA & Recent Runs)
- New Assessment (Guided 4-Step Wizard: What to check → App details → Checks & permission → Results)
- Reports (Persistent, searchable archive of past assessments with real PDF/HTML downloads)
- Research & Benchmarks (Preserved historical v0.2/v0.3 experiment platform and ground-truth datasets)
- Settings (Connection preferences, gateway endpoints, and historical archives)
"""

import streamlit as st
import os
import json
from datetime import datetime, timezone

from guided_assessment_ui import render_guided_assessment_wizard
from assessment_results_view import render_assessment_results
from engines.assessment_store import AssessmentStore
from engines.report_exporter import export_assessment_pdf_and_html

# Preserved historical modules
from app_v01 import render_v01_app
from questionnaire_ui import render_interactive_questionnaire_app
from local_ai_testing_ui import render_local_ai_testing_tab


st.set_page_config(
    page_title="ATLAS-Risk Security Platform",
    page_icon="🛡️",
    layout="wide"
)


def render_home_page():
    st.title("Understand your app's risks.")
    st.write("Check what we can access. See what needs attention and what remains untested.")

    col_cta1, col_cta2, col_space = st.columns([1.6, 1.6, 3])
    with col_cta1:
        if st.button("🚀 Start an assessment", type="primary", use_container_width=True):
            st.session_state.app_nav = "➕ New Assessment"
            st.session_state.wizard_step = 1
            st.session_state.current_completed_record = None
            st.rerun()
    with col_cta2:
        if st.button("📄 View sample report", use_container_width=True):
            store = AssessmentStore()
            sample = store.get_sample_report()
            st.session_state.opened_report_id = sample["id"]
            st.session_state.app_nav = "📑 Reports"
            st.rerun()

    st.markdown("---")

    # Recent Assessments History
    st.subheader("Recent Assessments")
    store = AssessmentStore()
    assessments = store.list_assessments()

    # Filter out sample unless requested
    user_assessments = [a for a in assessments if a["id"] != "SAMPLE-HYBRID-001"]

    if not user_assessments:
        st.info("ℹ️ No assessments recorded yet. Click **Start an assessment** above to begin your first review.")
    else:
        for rec in user_assessments[:5]:
            with st.container():
                c_info, c_status, c_act = st.columns([3, 1.2, 1.5])
                with c_info:
                    st.markdown(f"**{rec['name']}** (`{rec['target_input']}`)")
                    st.caption(f"Date: {rec['created_at'][:19].replace('T', ' ')} UTC | ID: `{rec['id']}`")
                with c_status:
                    stat = rec.get("status", "COMPLETE")
                    stat_icon = "🟢" if stat == "COMPLETE" else ("🟡" if stat == "PARTIAL" else "🔴")
                    st.markdown(f"**{stat_icon} {stat}**")
                    issues_cnt = rec.get("counts", {}).get("issues", 0)
                    st.caption(f"{issues_cnt} issue(s) observed")
                with c_act:
                    if st.button("Open Report", key=f"open_home_{rec['id']}"):
                        st.session_state.opened_report_id = rec["id"]
                        st.session_state.app_nav = "📑 Reports"
                        st.rerun()
                st.markdown("---")


def render_reports_page():
    store = AssessmentStore()

    # If a specific report is currently open, render its full results view
    if "opened_report_id" in st.session_state and st.session_state.opened_report_id:
        record = store.get_assessment(st.session_state.opened_report_id)
        if record:
            render_assessment_results(record, show_back_button=True)
            return
        else:
            st.error("Report not found.")
            if st.button("Back to Reports"):
                del st.session_state.opened_report_id
                st.rerun()
            return

    st.title("📑 Assessment Reports")
    st.caption("Permanent, immutable archive of completed and partial assessment runs.")

    all_recs = store.list_assessments()

    if not all_recs:
        st.info("No saved reports available yet. Launch an assessment to generate your first report.")
        return

    # Search and filter controls
    col_search, col_filter = st.columns([3, 1.5])
    with col_search:
        search_query = st.text_input("🔍 Search reports by name or target URL", value="").lower()
    with col_filter:
        status_filter = st.selectbox("Filter by Status", ["All", "COMPLETE", "PARTIAL", "STOPPED"])

    filtered = []
    for r in all_recs:
        if status_filter != "All" and r.get("status") != status_filter:
            continue
        if search_query:
            match_str = f"{r.get('name', '')} {r.get('target_input', '')} {r.get('id', '')}".lower()
            if search_query not in match_str:
                continue
        filtered.append(r)

    st.write(f"Showing {len(filtered)} of {len(all_recs)} report(s):")

    for rec in filtered:
        with st.container():
            c1, c2, c3, c4 = st.columns([3, 1.2, 1.2, 1.2])
            with c1:
                st.markdown(f"**{rec['name']}**")
                st.caption(f"Target: `{rec['target_input']}` | Date: {rec['created_at'][:19].replace('T', ' ')} UTC")
            with c2:
                stat = rec.get("status", "COMPLETE")
                stat_icon = "🟢" if stat == "COMPLETE" else ("🟡" if stat == "PARTIAL" else "🔴")
                st.markdown(f"**{stat_icon} {stat}**")
                st.caption(f"ID: `{rec['id']}`")
            with c3:
                if st.button("Open Report", key=f"rep_open_{rec['id']}"):
                    st.session_state.opened_report_id = rec["id"]
                    st.rerun()
            with c4:
                # Fast direct download
                full_rec = store.get_assessment(rec["id"])
                if full_rec:
                    try:
                        pdf_path, _ = export_assessment_pdf_and_html(full_rec)
                        if pdf_path and os.path.exists(pdf_path):
                            with open(pdf_path, "rb") as f_pdf:
                                st.download_button(
                                    "📕 PDF",
                                    data=f_pdf.read(),
                                    file_name=f"{rec['id']}.pdf",
                                    mime="application/pdf",
                                    key=f"rep_dl_{rec['id']}"
                                )
                    except Exception:
                        st.caption("PDF pending")
            st.markdown("---")


def render_settings_page():
    st.title("⚙️ System Settings & Preferences")
    st.caption("Manage connection endpoints, scan limits, and archived platform interfaces.")

    st.subheader("Connection & Gateway Endpoints")
    col1, col2 = st.columns(2)
    with col1:
        st.text_input("Local Ollama Gateway URL", value="http://127.0.0.1:8080")
        st.caption("Routes to local Ollama daemon for LLM red-teaming.")
    with col2:
        st.number_input("Default Public Web Crawl Depth", min_value=1, max_value=5, value=3)
        st.caption("Maximum internal same-origin pages inspected during public review.")

    st.markdown("---")
    st.subheader("Historical Platform Archives (Auditing & Regression)")
    st.caption("Frozen historical modules are preserved here for academic and verification review:")

    col_a1, col_a2 = st.columns(2)
    with col_a1:
        with st.expander("🔬 Open Historical v0.4 Architecture Questionnaire"):
            st.info("Launches the preserved 24-question system profiling form.")
            if st.button("Launch v0.4 Questionnaire Mode"):
                st.session_state["show_archive_v04"] = True
    with col_a2:
        with st.expander("📜 Open Historical v0.1 POC Baseline"):
            st.info("Launches the preserved v0.1 proof-of-concept interface.")
            if st.button("Launch v0.1 Baseline Mode"):
                st.session_state["show_archive_v01"] = True

    if st.session_state.get("show_archive_v04"):
        st.markdown("---")
        render_interactive_questionnaire_app()
    elif st.session_state.get("show_archive_v01"):
        st.markdown("---")
        render_v01_app()


def main():
    # Primary Main Navigation
    if "app_nav" not in st.session_state:
        st.session_state.app_nav = "🏠 Home"

    nav_options = [
        "🏠 Home",
        "➕ New Assessment",
        "📑 Reports",
        "🔬 Research & Benchmarks",
        "⚙️ Settings"
    ]

    selected_nav = st.sidebar.radio(
        "Navigation",
        nav_options,
        index=nav_options.index(st.session_state.app_nav) if st.session_state.app_nav in nav_options else 0
    )
    st.session_state.app_nav = selected_nav

    st.sidebar.markdown("---")
    st.sidebar.caption("ATLAS-Risk Platform • Build `64b7438` (Verified)")

    # Route according to selection
    if selected_nav == "🏠 Home":
        render_home_page()
    elif selected_nav == "➕ New Assessment":
        render_guided_assessment_wizard()
    elif selected_nav == "📑 Reports":
        render_reports_page()
    elif selected_nav == "🔬 Research & Benchmarks":
        # Render preserved v0.2/v0.3 research platform
        from app_v01 import render_v01_app
        from reports.report_v02 import ExperimentReportGenerator
        st.title("🔬 Research & Benchmark Platform (v0.3.0 Freeze)")
        st.caption("Preserved empirical datasets, ground-truth benchmarks, and ASR experimental platform.")
        st.info("All frozen experiment runs and benchmark catalogues remain preserved in `data/runs/`.")
        # Load targets and benchmark data
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path_cat = os.path.join(base_dir, "data", "benchmark_catalogue.json")
        if os.path.exists(path_cat):
            with open(path_cat, "r") as f:
                cat_data = json.load(f)
                st.write(f"• **Benchmark Test Cases:** {len(cat_data.get('test_cases', []))}")
                st.write(f"• **Framework Alignment:** OWASP Top 10 for LLM (2025) & MITRE ATLAS v4.0")
    elif selected_nav == "⚙️ Settings":
        render_settings_page()


if __name__ == "__main__":
    main()
