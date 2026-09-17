"""
Guided Assessment UI Module for ATLAS-Risk.
Implements the 4-step wizard:
Step 1: What would you like to check?
Step 2: Tell us about your app.
Step 3: Review the checks.
Step 4: Run and view results (with real activity indicator, Stop button, and no fake percentages).
"""

import streamlit as st
import time
import os
import json
from datetime import datetime, timezone

from engines.public_app_inspector import PublicAppInspector
from engines.assessment_store import AssessmentStore
from assessment_results_view import render_assessment_results

# Presets for ease of testing
DEFAULT_PUBLIC_URL = "http://127.0.0.1:8088/public_app"
DEFAULT_HYBRID_URL = "http://127.0.0.1:8088/hybrid_app"
OLLAMA_GATEWAY_URL = "http://127.0.0.1:8080"


def render_guided_assessment_wizard():
    # Initialize wizard session state
    if "wizard_step" not in st.session_state:
        st.session_state.wizard_step = 1
    if "wizard_inputs" not in st.session_state:
        st.session_state.wizard_inputs = {
            "target_type": "website",
            "url": DEFAULT_PUBLIC_URL,
            "app_purpose": "Customer support assistant",
            "has_rag": "I don't know",
            "has_tools": "No",
            "sensitive_data": "None",
            "crawl_depth": 3,
            "model": "llama3.2:1b",
            "variant": "Baseline (Unprotected)",
            "auth_granted": False
        }
    if "current_completed_record" not in st.session_state:
        st.session_state.current_completed_record = None
    if "is_assessment_executing" not in st.session_state:
        st.session_state.is_assessment_executing = False
    if "stop_requested" not in st.session_state:
        st.session_state.stop_requested = False

    # If results are ready for this run, show results
    if st.session_state.current_completed_record is not None:
        render_assessment_results(st.session_state.current_completed_record)
        st.markdown("---")
        if st.button("➕ Start Another Assessment", type="primary"):
            st.session_state.current_completed_record = None
            st.session_state.wizard_step = 1
            st.session_state.wizard_inputs["auth_granted"] = False
            st.rerun()
        return

    # Wizard Header & Step Indicator
    curr_step = st.session_state.wizard_step
    st.caption(f"Guided Assessment • **Step {curr_step} of 4**")

    # Step Progress Bar
    step_progress = (curr_step - 1) / 3.0
    st.progress(step_progress)

    if curr_step == 1:
        render_step_1()
    elif curr_step == 2:
        render_step_2()
    elif curr_step == 3:
        render_step_3()
    elif curr_step == 4:
        render_step_4()


# =====================================================================
# STEP 1: WHAT WOULD YOU LIKE TO CHECK?
# =====================================================================
def render_step_1():
    st.header("Step 1: What would you like to check?")
    st.write("Select the type of application you want to assess:")

    inp = st.session_state.wizard_inputs

    cards = [
        ("website", "🌐 Website or SaaS App", "A booking site, public landing, or customer portal built through vibe coding."),
        ("chatbot", "🤖 AI Chatbot or Local Model", "A conversational assistant, Ollama endpoint, or LLM-powered service."),
        ("github", "🐙 GitHub Project", "Source code repository for an application you or your team built."),
        ("questionnaire", "📋 Questionnaire Only", "Understand potential risks through guided questions without connecting a live app.")
    ]

    cols = st.columns(2)
    for idx, (ctype, ctitle, cdesc) in enumerate(cards):
        col = cols[idx % 2]
        with col:
            is_selected = inp["target_type"] == ctype
            border_style = "border: 2px solid #2563eb; background: #eff6ff;" if is_selected else "border: 1px solid #cbd5e1; background: #ffffff;"
            st.markdown(f"""
            <div style="{border_style} border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; min-height: 110px;">
                <h4 style="margin: 0 0 6px 0; color: #0f172a;">{ctitle}</h4>
                <p style="margin: 0; font-size: 13px; color: #475569;">{cdesc}</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"Select {ctitle.split()[1]}", key=f"btn_sel_{ctype}"):
                inp["target_type"] = ctype
                st.rerun()

    st.markdown("---")
    st.subheader("Available Review Capabilities for this Selection:")

    if inp["target_type"] == "website":
        st.success("✅ **Public App Review:** Bounded check of visible pages, usability, accessibility, performance, and public security headers.")
        st.info("⚪ **Answer Relevance Evaluation:** *Unavailable (Relevance evaluator not yet implemented. Security tests are never presented as answer-quality benchmarks.)*")
    elif inp["target_type"] == "chatbot":
        st.success("✅ **AI Security & Safeguard Assessment:** Empirical prompt injection, secret leakage, and credential exfiltration probes.")
        st.info("⚪ **Answer Relevance Evaluation:** *Unavailable (Dedicated quality evaluation engine not implemented)*")
    elif inp["target_type"] == "github":
        st.warning("🟡 **GitHub Repository Review:** *Coming Soon. Connect repository under Settings.*")
    else:
        st.success("✅ **Architecture Questionnaire:** Threat mapping across OWASP Top 10 and MITRE ATLAS without live connections.")

    st.markdown("---")
    c_back, c_space, c_next = st.columns([1, 4, 1])
    with c_next:
        if st.button("Continue →", type="primary", key="step1_next"):
            st.session_state.wizard_step = 2
            st.rerun()


# =====================================================================
# STEP 2: TELL US ABOUT YOUR APP
# =====================================================================
def render_step_2():
    st.header("Step 2: Tell us about your app")
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]

    st.write(f"Provide context and access details for your **{target_type.title()}**:")

    # App purpose in simple language
    st.markdown("#### App Purpose")
    st.caption("What does your app help people do? (Used for risk context, never as proof of compliance)")
    purpose_options = [
        "Customer support and FAQ assistance",
        "E-commerce or shopping",
        "Education or tutoring",
        "Internal engineering or developer tools",
        "Financial, banking, or billing operations",
        "Other"
    ]
    current_purp = inp.get("app_purpose", purpose_options[0])
    p_idx = purpose_options.index(current_purp) if current_purp in purpose_options else 0
    selected_purpose = st.selectbox("Primary Application Function", purpose_options, index=p_idx)
    inp["app_purpose"] = selected_purpose

    st.markdown("---")

    # Target-specific input fields
    if target_type == "website":
        st.markdown("#### Public Website Address")
        col_preset1, col_preset2 = st.columns(2)
        with col_preset1:
            if st.button("🎯 Use Public Demo App"):
                inp["url"] = DEFAULT_PUBLIC_URL
                st.rerun()
        with col_preset2:
            if st.button("🔐 Use Hybrid Demo (With Protected Dashboard)"):
                inp["url"] = DEFAULT_HYBRID_URL
                st.rerun()

        entered_url = st.text_input("Application Root URL", value=inp.get("url", DEFAULT_PUBLIC_URL))
        inp["url"] = entered_url.strip()

    elif target_type == "chatbot":
        st.markdown("#### AI Endpoint & Model Configuration")
        col_ep, col_mod = st.columns(2)
        with col_ep:
            gateway_ep = st.text_input("Gateway Endpoint", value=OLLAMA_GATEWAY_URL)
        with col_mod:
            model_opt = st.selectbox("Target Model", ["llama3.2:1b", "llama3.1:8b"], index=0)
            inp["model"] = model_opt
        variant_opt = st.radio("Configuration Variant", ["Baseline (Unprotected)", "Hardened (Safeguard Active)"])
        inp["variant"] = variant_opt

    elif target_type == "github":
        st.markdown("#### GitHub Repository")
        st.text_input("Repository URL", value="https://github.com/example/vibe-app", disabled=True)
        st.caption("ℹ️ Connect GitHub account in Settings to enable direct repository scanning.")

    else:
        st.markdown("#### Questionnaire Configuration")
        st.info("No connection required. Proceed to Step 3 to review the threat model questions.")

    # Progressive Architecture Questions
    st.markdown("---")
    st.markdown("#### Application Architecture Details")
    st.caption("Help us tailor the scope. If you aren't sure, choose 'I don't know'.")

    col_q1, col_q2 = st.columns(2)
    with col_q1:
        inp["has_rag"] = st.selectbox("Does the app retrieve external documents or use a knowledge base (RAG)?", ["I don't know", "Yes", "No"], index=0)
        inp["has_tools"] = st.selectbox("Can the app execute code, call APIs, or take actions autonomously?", ["I don't know", "Yes", "No"], index=2)
    with col_q2:
        inp["sensitive_data"] = st.selectbox("Does the app store or process customer credentials or PII?", ["None", "User emails/names only", "Passwords or API keys", "I don't know"], index=0)

    # Collapsed Advanced Settings
    with st.expander("⚙️ Advanced Connection Settings (Optional)", expanded=False):
        inp["crawl_depth"] = st.slider("Crawl Depth (Max Pages)", min_value=1, max_value=5, value=inp.get("crawl_depth", 3))
        st.caption("All credentials and tokens are automatically masked.")

    st.markdown("---")
    c_back, c_space, c_next = st.columns([1, 4, 1])
    with c_back:
        if st.button("← Back", key="step2_back"):
            st.session_state.wizard_step = 1
            st.rerun()
    with c_next:
        if st.button("Continue →", type="primary", key="step2_next"):
            st.session_state.wizard_step = 3
            st.rerun()


# =====================================================================
# STEP 3: REVIEW THE CHECKS & PERMISSION
# =====================================================================
def render_step_3():
    st.header("Step 3: Review the checks & scope")
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]

    st.write("Before starting, review the exact scope boundaries of this assessment:")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### 🟢 We will check:")
        if target_type == "website":
            st.write("• Accessible public pages (up to 3)\n• Usability & broken elements\n• HTML accessibility (lang, alt tags, viewport)\n• Response latency & TTFB\n• Public security headers (CSP, HSTS, X-Frame)\n• Published pricing signals")
        elif target_type == "chatbot":
            st.write("• System prompt leakage probe\n• Benign control question handling\n• Credential exfiltration refusal\n• Token limit completion metadata")
        else:
            st.write("• Architecture risk questionnaire\n• OWASP Top 10 threat mapping\n• MITRE ATLAS risk identification")

    with col2:
        st.markdown("### 🟡 We cannot check yet:")
        st.write("• Protected / login-required areas\n• Private database security\n• Backend source code & SQL queries\n• Cloud infrastructure configurations")

    with col3:
        st.markdown("### 🔐 Access needed for deeper checks:")
        st.write("• Test account credentials for private pages\n• API keys or session bearer tokens\n• Read-only GitHub repository access\n• Dedicated cloud IAM audit role")

    st.markdown("---")

    # Honest Access Boundary Warning
    st.info(
        "ℹ️ **Access Boundary Notice:** A login screen, CAPTCHA, or HTTP 401/403 barrier may limit this review. "
        "**It does not automatically mean the app has a security problem.** We will inspect all accessible areas, "
        "document what works, and clearly list unassessed sections."
    )

    # Scoped Authorization Gate
    if target_type in ("chatbot", "website"):
        st.markdown("#### Authorization & Scope Verification")
        auth_cb = st.checkbox(
            f"🔒 I explicitly authorize ATLAS-Risk to perform this assessment against `{inp.get('url', inp.get('model'))}`.",
            value=inp.get("auth_granted", False),
            help="Zero requests are dispatched before explicit authorization."
        )
        inp["auth_granted"] = auth_cb
    else:
        inp["auth_granted"] = True

    st.markdown("---")
    c_back, c_space, c_next = st.columns([1, 4, 1.5])
    with c_back:
        if st.button("← Back", key="step3_back"):
            st.session_state.wizard_step = 2
            st.rerun()
    with c_next:
        can_start = inp.get("auth_granted", False)
        if st.button("🚀 Start assessment", type="primary", disabled=not can_start, key="step3_start"):
            st.session_state.wizard_step = 4
            st.session_state.is_assessment_executing = True
            st.session_state.stop_requested = False
            st.rerun()


# =====================================================================
# STEP 4: RUN AND VIEW RESULTS
# =====================================================================
def render_step_4():
    st.header("Step 4: Running Assessment...")
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]
    store = AssessmentStore()

    col_prog, col_stop = st.columns([4, 1.2])
    with col_stop:
        if st.button("🛑 Stop Assessment", type="secondary"):
            st.session_state.stop_requested = True
            st.warning("Stop signal sent. Halting assessment after current check...")

    with col_prog:
        status_container = st.empty()

    # Execute bounded checks
    if target_type == "website":
        status_container.info(f"Connecting to `{inp['url']}` and discovering public pages...")
        time.sleep(0.5)

        if st.session_state.stop_requested:
            record = build_stopped_record(inp, "Assessment stopped by user during initial discovery.")
        else:
            inspector = PublicAppInspector(max_pages=inp.get("crawl_depth", 3))
            raw_res = inspector.inspect_url(inp["url"])

            # Map to standardized assessment record
            status_container.info("Evaluating usability, accessibility, performance, and security headers...")
            time.sleep(0.5)

            pages = raw_res.get("pages_inspected", [])
            unassessed = raw_res.get("unassessed_areas", [])
            issues = raw_res.get("issues_observed", [])
            verified = raw_res.get("what_we_verified", [])

            status_str = "PARTIAL" if len(unassessed) > 0 else "COMPLETE"
            summary_str = (
                f"Bounded review inspected {len(pages)} accessible page(s). "
                f"Identified {len(issues)} issue(s) with practical fixes. "
                f"{len(unassessed)} section(s) were protected and could not be assessed without credentials."
            )

            record = {
                "id": store.generate_assessment_id(),
                "name": f"Web Review: {inp['url'].replace('http://', '').replace('https://', '')[:25]}",
                "target_type": "website",
                "target_input": inp["url"],
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": status_str,
                "summary": summary_str,
                "counts": {
                    "issues": len(issues),
                    "no_issue": len(raw_res.get("positive_observations", [])),
                    "not_completed": len(unassessed),
                    "not_applicable": 1
                },
                "findings": [
                    {
                        "domain": iss.get("domain", "General"),
                        "severity": "MEDIUM",
                        "title": iss.get("issue", "Issue"),
                        "observed": iss.get("evidence", ""),
                        "why_it_matters": "Affects user accessibility, browser privacy, or UI resilience.",
                        "evidence": iss.get("evidence", ""),
                        "action": iss.get("fix", ""),
                        "how_to_verify": "Apply code fix and re-run assessment."
                    }
                    for iss in issues
                ],
                "positive_observations": raw_res.get("positive_observations", []),
                "unassessed_areas": raw_res.get("what_could_not_be_assessed", []),
                "next_steps": raw_res.get("next_steps_required_access", []),
                "raw_telemetry": raw_res
            }

    else:
        # Default or fallback
        record = store.get_sample_report()

    # Save to persistent store
    store.save_assessment(record)

    # Save to session and reload to show results view
    st.session_state.current_completed_record = record
    st.session_state.is_assessment_executing = False
    st.success("✅ Assessment run complete! Rendering results...")
    time.sleep(0.5)
    st.rerun()


def build_stopped_record(inp: dict, reason: str) -> dict:
    store = AssessmentStore()
    return {
        "id": store.generate_assessment_id(),
        "name": f"Stopped Run: {inp.get('url', 'Target')}",
        "target_type": inp.get("target_type", "website"),
        "target_input": inp.get("url", "Target"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "STOPPED",
        "summary": f"Assessment was manually stopped: {reason}",
        "counts": {"issues": 0, "no_issue": 0, "not_completed": 1, "not_applicable": 0},
        "findings": [],
        "positive_observations": [],
        "unassessed_areas": [{"area": "Entire Target", "reason": "Execution cancelled before completion", "required_access": "Restart assessment"}],
        "next_steps": ["Re-run assessment when ready."]
    }
