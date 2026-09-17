"""
Preserved v0.1 Streamlit POC UI Module.
Maintains the original 5-test demonstration pipeline intact.
"""

import streamlit as st
import json
import os
from questionnaire import QUESTIONNAIRE_QUESTIONS, get_default_answers
from engines.threat_mapper import ThreatMapper
from engines.test_runner import TestRunner
from report import ReportGenerator


def render_v01_app():
    st.title("🛡️ ATLAS-Risk POC v0.1: Preserved Baseline Demo")
    st.caption("Preserved 5-Test Demonstration Pipeline | OWASP LLM Top 10 (2025) & MITRE ATLAS (v4.0)")

    st.sidebar.header("🎯 Target Configuration (v0.1)")
    target_name = st.sidebar.text_input("Target Name (v0.1)", value="OWASP DonkAI Challenge Harness")

    mapper = ThreatMapper()

    if "answers_v01" not in st.session_state:
        st.session_state.answers_v01 = get_default_answers()
    if "session_log_v01" not in st.session_state:
        st.session_state.session_log_v01 = None

    tabs = st.tabs([
        "📋 1. Questionnaire",
        "🎯 2. Threat Applicability",
        "🧪 3. Test Execution",
        "🧮 4. Risk & Metrics",
        "📄 5. Final Report"
    ])

    with tabs[0]:
        st.subheader("System Security Profile Survey (v0.1)")
        col1, col2 = st.columns(2)
        for i, q in enumerate(QUESTIONNAIRE_QUESTIONS):
            target_col = col1 if i % 2 == 0 else col2
            with target_col:
                val = st.selectbox(
                    q["question"],
                    options=q["options"],
                    index=q["options"].index(st.session_state.answers_v01.get(q["id"], q["default"])),
                    key=f"v01_input_{q['id']}"
                )
                st.session_state.answers_v01[q["id"]] = val

        if st.button("🚀 Evaluate Threat Applicability & Run v0.1 Baseline", type="primary"):
            st.success("v0.1 Profile captured!")

    with tabs[1]:
        st.subheader("Stage 1: Threat Applicability Engine (v0.1)")
        app_list = mapper.evaluate_applicability(st.session_state.answers_v01)
        for app in app_list:
            symbol = "✅ APPLICABLE" if app["is_applicable"] else "❌ NOT APPLICABLE"
            with st.expander(f"{symbol} - {app['threat_family']}", expanded=True):
                st.write(f"**OWASP:** `{app['owasp']['id']}` | **ATLAS:** `{app['atlas']['id']}`")
                st.write(app["rationale"])

    with tabs[2]:
        st.subheader("Stage 2: Predefined 5-Test Runner (v0.1)")
        if st.button("▶️ Execute 5-Test Benchmark Suite", type="primary"):
            runner = TestRunner()
            # Run using preserved legacy method
            app_list = mapper.evaluate_applicability(st.session_state.answers_v01)
            exp = runner.run_experiment(
                experiment_id="EXP-V01-DEMO",
                target_id="DONKAI-V01",
                target_name=target_name,
                target_type="deterministic_benchmark",
                configuration_variant="v0.1 POC Baseline",
                questionnaire_answers=st.session_state.answers_v01,
                applicability_list=app_list,
                framework_versions=mapper.framework_versions,
                repeats_per_test=1
            )
            st.session_state.session_log_v01 = exp
            st.success("v0.1 Benchmark run complete!")

        if st.session_state.session_log_v01:
            for er in st.session_state.session_log_v01.execution_records[:5]:
                st.write(f"**{er.test_id}:** {er.test_name} - Result: `{er.severity_rating}`")

    with tabs[3]:
        st.subheader("Stage 3: Risk Engine & Metrics (v0.1)")
        if st.session_state.session_log_v01:
            st.success("v0.1 Risk Engine computed successfully.")

    with tabs[4]:
        st.subheader("Stage 4: Executive Report (v0.1)")
        if st.session_state.session_log_v01:
            st.info("v0.1 Report view available.")
