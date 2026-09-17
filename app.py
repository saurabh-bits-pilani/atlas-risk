"""
ATLAS-Risk: Professional Guided Security & Posture Assessment Platform.
Main Application Entry Point.
Implements modern, human-centered UI/UX with smooth sidebar navigation:
- 🏠 Home (Matching user specification with Hero, 3-Step Process Flow, What can you assess, and Recent reports)
- ➕ New assessment (Guided 4-Step Wizard: What to check → App details → Checks & permission → Results)
- 📄 Reports (Persistent, searchable archive of past assessments with real PDF/HTML downloads)
- 📊 Research & benchmarks (Preserved historical v0.2/v0.3 experiment platform and ground-truth datasets)
- ⚙️ Settings (Connection preferences, gateway endpoints, and historical archives)
- ❓ Help (Practical guidance and scope overview)
"""

import streamlit as st
import os
import json
from datetime import datetime, timezone

import importlib
import guided_assessment_ui
import home_view
importlib.reload(guided_assessment_ui)
importlib.reload(home_view)

from guided_assessment_ui import render_guided_assessment_wizard
from assessment_results_view import render_assessment_results
from home_view import render_home_page
from engines.assessment_store import AssessmentStore
from engines.report_exporter import export_assessment_pdf_and_html

# Preserved historical modules
from app_v01 import render_v01_app
from questionnaire_ui import render_interactive_questionnaire_app
from local_ai_testing_ui import render_local_ai_testing_tab


st.set_page_config(
    page_title="ATLAS-Risk Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Sleek Modern Sidebar & Global Styling
st.markdown("""
<style>
    /* Font family */
    html, body, [class*="css"] {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Clean header */
    header[data-testid="stHeader"] {
        background-color: transparent !important;
    }

    /* Generous top and side padding for main content area */
    .stMainBlockContainer,
    div[data-testid="stMain"] > div:first-child,
    .main .block-container {
        padding-top: 2.2rem !important;
        padding-bottom: 3rem !important;
        max-width: 1160px !important;
    }

    /* Sidebar Background */
    [data-testid="stSidebar"] {
        background-color: #f8fafc !important;
        border-right: 1px solid #e2e8f0 !important;
    }
    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.25rem !important;
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }

    /* Sleek Navigation Button Styling in Sidebar */
    [data-testid="stSidebar"] button {
        text-align: left !important;
        justify-content: flex-start !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 9px 14px !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        margin-bottom: 3px !important;
        width: 100% !important;
        transition: all 0.15s ease-in-out !important;
        box-shadow: none !important;
    }

    /* Inactive Nav Button */
    [data-testid="stSidebar"] button[kind="secondary"] {
        background-color: transparent !important;
        color: #475569 !important;
    }
    [data-testid="stSidebar"] button[kind="secondary"]:hover {
        background-color: #f1f5f9 !important;
        color: #0f172a !important;
    }

    /* Active Nav Button (Lavender pill matching Image 2) */
    [data-testid="stSidebar"] button[kind="primary"] {
        background-color: #eef2ff !important;
        color: #4f46e5 !important;
        font-weight: 600 !important;
        border: 1px solid #e0e7ff !important;
    }
    [data-testid="stSidebar"] button[kind="primary"]:hover {
        background-color: #e0e7ff !important;
        color: #4338ca !important;
    }

    /* Content Area Primary CTA Buttons */
    .stMainBlockContainer button[kind="primary"],
    div[data-testid="stMain"] button[kind="primary"],
    div[data-testid="stMain"] button[data-testid="baseButton-primary"],
    div.stButton > button[kind="primary"],
    div.stButton > button[data-testid="baseButton-primary"] {
        background-color: #2563eb !important;
        border-color: #2563eb !important;
        color: #ffffff !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05) !important;
    }
    .stMainBlockContainer button[kind="primary"]:hover,
    div[data-testid="stMain"] button[kind="primary"]:hover,
    div[data-testid="stMain"] button[data-testid="baseButton-primary"]:hover {
        background-color: #1d4ed8 !important;
        border-color: #1d4ed8 !important;
        color: #ffffff !important;
    }

    /* Content Area Secondary Buttons */
    .stMainBlockContainer button[kind="secondary"],
    div[data-testid="stMain"] button[kind="secondary"],
    div[data-testid="stMain"] button[data-testid="baseButton-secondary"],
    div.stButton > button[kind="secondary"],
    div.stButton > button[data-testid="baseButton-secondary"] {
        border-radius: 8px !important;
        font-weight: 500 !important;
        border: 1px solid #cbd5e1 !important;
        background-color: #ffffff !important;
        color: #334155 !important;
    }
    .stMainBlockContainer button[kind="secondary"]:hover,
    div[data-testid="stMain"] button[kind="secondary"]:hover,
    div[data-testid="stMain"] button[data-testid="baseButton-secondary"]:hover {
        border-color: #94a3b8 !important;
        background-color: #f8fafc !important;
    }

    /* Step 1: Card Overlay for Direct Card Clicking */
    div[data-testid="column"]:has(.guided-card-wrapper) {
        position: relative !important;
    }
    div[data-testid="column"]:has(.guided-card-wrapper) div.stButton {
        position: absolute !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        height: 100% !important;
        z-index: 20 !important;
    }
    div[data-testid="column"]:has(.guided-card-wrapper) div.stButton button {
        width: 100% !important;
        height: 100% !important;
        opacity: 0 !important;
        cursor: pointer !important;
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
    }

    /* Step 2: Change button styled as clean hyperlink */
    div[data-testid="stButton"]:has(button[key="btn_change_target"]) button,
    button[key="btn_change_target"] {
        background: transparent !important;
        border: none !important;
        color: #2563eb !important;
        font-weight: 600 !important;
        font-size: 14px !important;
        text-decoration: none !important;
        box-shadow: none !important;
        padding: 6px 10px !important;
        cursor: pointer !important;
        min-height: unset !important;
        height: auto !important;
    }
    button[key="btn_change_target"]:hover {
        text-decoration: underline !important;
        color: #1d4ed8 !important;
        background: transparent !important;
    }

    /* Step 2: Segmented AI feature toggle buttons */
    div[data-testid="column"]:has(.ai-btn-active) button,
    div[data-testid="column"]:has(.ai-btn-active) div.stButton button {
        background-color: #eff6ff !important;
        border: 2px solid #2563eb !important;
        color: #2563eb !important;
        font-weight: 600 !important;
    }
    div[data-testid="column"]:has(.ai-btn-inactive) button,
    div[data-testid="column"]:has(.ai-btn-inactive) div.stButton button {
        background-color: #ffffff !important;
        border: 1px solid #cbd5e1 !important;
        color: #334155 !important;
        font-weight: 500 !important;
    }
</style>
""", unsafe_allow_html=True)


def navigate_to(tab_name: str, extra_state: dict = None):
    """Smooth navigation helper ensuring instant state synchronization."""
    if extra_state:
        for k, v in extra_state.items():
            if k == "wizard_step":
                st.session_state["wizard_step"] = v
            elif k == "target_type":
                if "wizard_inputs" not in st.session_state:
                    st.session_state["wizard_inputs"] = {}
                st.session_state["wizard_inputs"]["target_type"] = v
            else:
                st.session_state[k] = v
    st.session_state["app_nav"] = tab_name
    st.rerun()


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

    st.title("📄 Assessment Reports")
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
                # Direct download button
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
    st.subheader("Local AI Security Testing (Ollama)")
    st.caption("Direct interactive console for deep prompt injection probing, token telemetry, and preflight testing.")
    if st.button("🚀 Launch Interactive Ollama Testing Console", type="primary", key="btn_open_ollama_console"):
        st.session_state["show_local_ai_console"] = True
        st.session_state["show_archive_v04"] = False
        st.session_state["show_archive_v01"] = False
        st.rerun()

    if st.session_state.get("show_local_ai_console") or st.session_state.get("open_local_ai_console"):
        st.markdown("---")
        render_local_ai_testing_tab()
        return

    st.markdown("---")
    st.subheader("Historical Platform Archives (Auditing & Regression)")
    st.caption("Frozen historical modules are preserved here for academic and verification review:")

    col_a1, col_a2 = st.columns(2)
    with col_a1:
        with st.expander("🔬 Open Historical v0.4 Architecture Questionnaire"):
            st.info("Launches the preserved 24-question system profiling form.")
            if st.button("Launch v0.4 Questionnaire Mode"):
                st.session_state["show_archive_v04"] = True
                st.session_state["show_local_ai_console"] = False
    with col_a2:
        with st.expander("📜 Open Historical v0.1 POC Baseline"):
            st.info("Launches the preserved v0.1 proof-of-concept interface.")
            if st.button("Launch v0.1 Baseline Mode"):
                st.session_state["show_archive_v01"] = True
                st.session_state["show_local_ai_console"] = False

    if st.session_state.get("show_archive_v04"):
        st.markdown("---")
        render_interactive_questionnaire_app()
    elif st.session_state.get("show_archive_v01"):
        st.markdown("---")
        render_v01_app()


def render_help_page():
    st.title("❓ Help & Assessment Guide")
    st.caption("Everything you need to know about how ATLAS-Risk evaluates applications.")

    st.markdown("""
    ### 🛡️ How ATLAS-Risk Works
    ATLAS-Risk provides honest, evidence-based security and quality assessments designed specifically for applications built through vibe coding, AI prototypes, and public web services.

    #### The Assessment Process
    1. **Choose your app**: Select whether you are reviewing a public website, GitHub code repository, AI chatbot endpoint, or answering architecture questions.
    2. **Review the checks**: We present what will be checked, what cannot be assessed without deeper credentials, and required permissions.
    3. **Get your report**: Receive a publication-grade report with verified findings, practical code fixes, and download options in PDF and HTML.

    #### Our Product Principles
    - **Assess what is publicly observable**: We do not fail an assessment simply because some protected areas require credentials.
    - **No arbitrary scores**: We report honest counts (*Issues Observed*, *No Issue Observed*, *Unassessed / Blocked*, *Not Applicable*) instead of made-up percentage scores.
    - **Non-intrusive by default**: No invasive probes are ever dispatched against unauthorized targets.
    """)

    st.markdown("---")
    if st.button("🚀 Start an assessment now", type="primary"):
        navigate_to("➕ New assessment", {"wizard_step": 1})


def main():
    # Sidebar Brand Header matching user mock (Shield logo + ATLAS-Risk)
    st.sidebar.markdown("""
    <div style="display: flex; align-items: center; gap: 10px; padding: 4px 6px 14px 6px; margin-bottom: 12px; border-bottom: 1px solid #e2e8f0;">
        <span style="font-size: 24px;">🛡️</span>
        <span style="font-size: 19px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em;">ATLAS-Risk</span>
    </div>
    """, unsafe_allow_html=True)

    # Initialize navigation state
    if "app_nav" not in st.session_state:
        st.session_state["app_nav"] = "🏠 Home"

    current_nav = st.session_state["app_nav"]

    # Main Navigation Items
    primary_nav_items = [
        ("🏠 Home", "🏠 Home"),
        ("➕ New assessment", "➕ New assessment"),
        ("📄 Reports", "📄 Reports"),
        ("📊 Research & benchmarks", "📊 Research & benchmarks"),
    ]

    for label, target_key in primary_nav_items:
        is_active = (current_nav == target_key or (target_key == "➕ New assessment" and current_nav == "➕ New Assessment"))
        btn_type = "primary" if is_active else "secondary"
        if st.sidebar.button(label, key=f"nav_btn_{target_key}", type=btn_type, use_container_width=True):
            if current_nav != target_key:
                st.session_state["app_nav"] = target_key
                st.rerun()

    # Vertical spacer to push settings and help to bottom
    st.sidebar.markdown("<div style='height: 180px;'></div>", unsafe_allow_html=True)

    # Bottom Navigation Items
    bottom_nav_items = [
        ("⚙️ Settings", "⚙️ Settings"),
        ("❓ Help", "❓ Help"),
    ]

    for label, target_key in bottom_nav_items:
        is_active = (current_nav == target_key)
        btn_type = "primary" if is_active else "secondary"
        if st.sidebar.button(label, key=f"nav_btn_{target_key}", type=btn_type, use_container_width=True):
            if current_nav != target_key:
                st.session_state["app_nav"] = target_key
                st.rerun()

    st.sidebar.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
    st.sidebar.caption("ATLAS-Risk Platform • Build `64b7438`")

    # Route view according to selection
    if current_nav == "🏠 Home":
        render_home_page(on_navigate=navigate_to)
    elif current_nav in ("➕ New assessment", "➕ New Assessment"):
        render_guided_assessment_wizard(on_navigate=navigate_to)
    elif current_nav in ("📄 Reports", "📑 Reports"):
        render_reports_page()
    elif current_nav in ("📊 Research & benchmarks", "🔬 Research & Benchmarks"):
        from app_v01 import render_v01_app
        from reports.report_v02 import ExperimentReportGenerator
        st.title("📊 Research & Benchmark Platform (v0.3.0 Freeze)")
        st.caption("Preserved empirical datasets, ground-truth benchmarks, and ASR experimental platform.")
        st.info("All frozen experiment runs and benchmark catalogues remain preserved in `data/runs/`.")
        base_dir = os.path.dirname(os.path.abspath(__file__))
        path_cat = os.path.join(base_dir, "data", "benchmark_catalogue.json")
        if os.path.exists(path_cat):
            with open(path_cat, "r") as f:
                cat_data = json.load(f)
                st.write(f"• **Benchmark Test Cases:** {len(cat_data.get('test_cases', []))}")
                st.write(f"• **Framework Alignment:** OWASP Top 10 for LLM (2025) & MITRE ATLAS v4.0")
    elif current_nav == "⚙️ Settings":
        render_settings_page()
    elif current_nav == "❓ Help":
        render_help_page()


if __name__ == "__main__":
    main()
