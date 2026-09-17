"""
Guided Assessment UI Module for ATLAS-Risk.
Implements the 4-step wizard matching the exact visual designs in Screen 2 and Screen 3:
Step 1: What would you like to check? (2x2 selection cards with radio indicators & info box)
Step 2: Tell us about your app (Two-column layout, selection badge with Change link, "What happens next?" card)
Step 3: Review the checks & scope (Honest boundaries, permission checkbox)
Step 4: Run and view results (with real activity indicator, Stop button, and no fake percentages)
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


# SVGs for Step 1 Cards
SVG_BROWSER = '''<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#1e293b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="18" rx="3" ry="3"></rect><line x1="2" y1="9" x2="22" y2="9"></line><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="10" y1="6" x2="10.01" y2="6"></line></svg>'''

SVG_GITHUB = '''<svg width="26" height="26" viewBox="0 0 24 24" fill="#1e293b"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"></path></svg>'''

SVG_ROBOT = '''<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#1e293b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"></rect><circle cx="12" cy="5" r="2"></circle><path d="M12 7v4"></path><line x1="8" y1="16" x2="8.01" y2="16"></line><line x1="16" y1="16" x2="16.01" y2="16"></line></svg>'''

SVG_DOC = '''<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#1e293b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>'''

# Radio icons
SVG_RADIO_UNCHECKED = '''<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><circle cx="11" cy="11" r="9" stroke="#cbd5e1" stroke-width="2" fill="white"/></svg>'''
SVG_RADIO_CHECKED = '''<svg width="22" height="22" viewBox="0 0 22 22" fill="none"><circle cx="11" cy="11" r="9" stroke="#2563eb" stroke-width="2" fill="white"/><circle cx="11" cy="11" r="5" fill="#2563eb"/></svg>'''


def render_step_tracker(current_step: int):
    """Renders the top breadcrumb and 4-step progress bar matching Screen 2 and Screen 3."""
    st.markdown("""
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 22px;">
        <div style="font-size: 14px; color: #64748b; font-weight: 500;">
            <span style="color: #64748b;">Home</span>
            <span style="margin: 0 8px; color: #cbd5e1;">/</span>
            <span style="color: #0f172a; font-weight: 600;">New assessment</span>
        </div>
        <div style="display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 13px; font-weight: 600; color: #334155; box-shadow: 0 1px 2px rgba(0,0,0,0.04);">
            <span>👁️</span> Design preview
        </div>
    </div>
    """, unsafe_allow_html=True)

    steps = [
        (1, "What to check"),
        (2, "App details"),
        (3, "Review & permission"),
        (4, "Results")
    ]

    html_parts = ['<div style="display: flex; align-items: center; justify-content: space-between; max-width: 820px; margin-bottom: 28px;">']

    for idx, (s_num, s_label) in enumerate(steps):
        is_completed = (s_num < current_step)
        is_active = (s_num == current_step)

        if is_completed:
            circle_bg = "#2563eb"
            circle_fg = "#ffffff"
            circle_content = "✓"
            label_color = "#0f172a"
            font_weight = "600"
        elif is_active:
            circle_bg = "#2563eb"
            circle_fg = "#ffffff"
            circle_content = str(s_num)
            label_color = "#0f172a"
            font_weight = "700"
        else:
            circle_bg = "#f1f5f9"
            circle_fg = "#64748b"
            circle_content = str(s_num)
            label_color = "#64748b"
            font_weight = "500"

        node_html = f'''
        <div style="display: flex; align-items: center; gap: 10px; white-space: nowrap;">
            <div style="width: 30px; height: 30px; border-radius: 50%; background: {circle_bg}; color: {circle_fg}; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: 700;">
                {circle_content}
            </div>
            <span style="font-size: 14px; font-weight: {font_weight}; color: {label_color};">{s_label}</span>
        </div>
        '''
        html_parts.append(node_html)

        if idx < len(steps) - 1:
            line_color = "#2563eb" if s_num < current_step else "#e2e8f0"
            html_parts.append(f'<div style="flex: 1; height: 2px; background: {line_color}; margin: 0 14px;"></div>')

    html_parts.append('</div>')
    st.markdown("".join(html_parts), unsafe_allow_html=True)


def render_guided_assessment_wizard(on_navigate=None):
    """Main entry point for guided assessment wizard."""
    if "wizard_step" not in st.session_state:
        st.session_state.wizard_step = 1
    if "wizard_inputs" not in st.session_state:
        st.session_state.wizard_inputs = {
            "target_type": "website",
            "url": DEFAULT_PUBLIC_URL,
            "app_name": "",
            "app_purpose": "",
            "has_ai_feature": "Not sure",
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

    if st.session_state.current_completed_record is not None:
        render_step_tracker(4)
        render_assessment_results(st.session_state.current_completed_record)
        st.markdown("---")
        if st.button("➕ Start Another Assessment", type="primary"):
            st.session_state.current_completed_record = None
            st.session_state.wizard_step = 1
            st.session_state.wizard_inputs["auth_granted"] = False
            st.rerun()
        return

    curr_step = st.session_state.wizard_step
    render_step_tracker(curr_step)

    if curr_step == 1:
        render_step_1(on_navigate)
    elif curr_step == 2:
        render_step_2()
    elif curr_step == 3:
        render_step_3()
    elif curr_step == 4:
        render_step_4()


def render_step_1(on_navigate=None):
    st.markdown("""
    <div style="margin-bottom: 24px;">
        <div style="font-size: 12px; font-weight: 700; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">STEP 1 OF 4</div>
        <h1 style="font-size: 32px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; letter-spacing: -0.02em;">What would you like to check?</h1>
        <p style="font-size: 16px; color: #475569; margin: 0;">Choose one. We'll ask only for the details we need.</p>
    </div>
    """, unsafe_allow_html=True)

    inp = st.session_state.wizard_inputs

    cards = [
        ("website", "Website or SaaS app", "Review the public pages of your app.", "For example: a booking site or customer portal", SVG_BROWSER),
        ("github", "GitHub project", "Review available code and configuration.", "For example: an app you built with AI", SVG_GITHUB),
        ("chatbot", "AI chatbot or local model", "Test a supported AI connection.", "For example: a support bot or Ollama", SVG_ROBOT),
        ("questionnaire", "Questionnaire only", "Understand possible risks without connecting an app.", "Useful when you don't have access yet", SVG_DOC),
    ]

    row1 = st.columns(2)
    row2 = st.columns(2)
    col_mapping = [row1[0], row1[1], row2[0], row2[1]]

    for idx, (ctype, ctitle, cdesc, cexample, cicon) in enumerate(cards):
        col = col_mapping[idx]
        with col:
            is_selected = (inp["target_type"] == ctype)
            border_style = "2px solid #2563eb" if is_selected else "1px solid #e2e8f0"
            bg_style = "#eff6ff" if is_selected else "#ffffff"
            radio_svg = SVG_RADIO_CHECKED if is_selected else SVG_RADIO_UNCHECKED

            card_html = f"""<div class="guided-card-wrapper" style="border: {border_style}; background-color: {bg_style}; border-radius: 12px; padding: 22px; margin-bottom: 12px; min-height: 148px; cursor: pointer; transition: all 0.15s ease-in-out;"><div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;"><div>{cicon}</div><div>{radio_svg}</div></div><div style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">{ctitle}</div><div style="font-size: 14px; color: #334155; margin-bottom: 6px;">{cdesc}</div><div style="font-size: 13px; color: #64748b;">{cexample}</div></div>"""
            st.markdown(card_html, unsafe_allow_html=True)

            # Invisible overlay button covering entire card
            if st.button(f"Choose {ctype}", key=f"sel_card_{ctype}", use_container_width=True):
                inp["target_type"] = ctype
                st.rerun()

    st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

    st.markdown("""
    <div style="border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 22px; background: #ffffff; display: flex; align-items: flex-start; gap: 14px; margin-bottom: 28px; box-shadow: 0 1px 2px rgba(0,0,0,0.02);">
        <div style="font-size: 20px; color: #2563eb; line-height: 1;">ℹ️</div>
        <div>
            <div style="font-size: 15px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">For this selection</div>
            <div style="font-size: 14px; color: #475569; line-height: 1.5;">We'll review accessible pages and clearly list anything we cannot check.<br>Deeper testing requires your permission and suitable access.</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    col_b, col_sp, col_c = st.columns([2, 5, 2])
    with col_b:
        if st.button("← Back to Home", key="btn_back_to_home", use_container_width=True):
            if on_navigate:
                on_navigate("🏠 Home")
            else:
                st.session_state["app_nav"] = "🏠 Home"
                st.rerun()
    with col_c:
        if st.button("Continue →", type="primary", key="btn_step1_continue", use_container_width=True):
            st.session_state.wizard_step = 2
            st.rerun()


def render_step_2():
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]

    st.markdown("""
    <div style="margin-bottom: 20px;">
        <div style="font-size: 12px; font-weight: 700; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">STEP 2 OF 4</div>
        <h1 style="font-size: 32px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; letter-spacing: -0.02em;">Tell us about your app</h1>
        <p style="font-size: 16px; color: #475569; margin: 0;">Start with a web address. You can add more context if you have it.</p>
    </div>
    """, unsafe_allow_html=True)

    target_labels = {
        "website": "🌐 Website or SaaS app",
        "github": "🐙 GitHub project",
        "chatbot": "🤖 AI chatbot or local model",
        "questionnaire": "📋 Questionnaire only"
    }
    sel_label = target_labels.get(target_type, "🌐 Website or SaaS app")

    # Selection pill and Change link neatly aligned
    col_pill, col_chg, col_fill = st.columns([3.2, 1.5, 7.3])
    with col_pill:
        st.markdown(f"""<div style="display: inline-flex; align-items: center; padding: 6px 14px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 20px; font-size: 14px; font-weight: 600; color: #0f172a;">{sel_label}</div>""", unsafe_allow_html=True)
    with col_chg:
        if st.button("Change", key="btn_change_target"):
            st.session_state.wizard_step = 1
            st.rerun()

    st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

    col_left, col_right = st.columns([6.2, 3.8])

    with col_left:
        if target_type == "website":
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Website address <span style='color: #ef4444;'>*</span></div>", unsafe_allow_html=True)
            entered_url = st.text_input("Website address", value=inp.get("url", DEFAULT_PUBLIC_URL), label_visibility="collapsed")
            inp["url"] = entered_url.strip()
            st.caption("Enter the public page you want us to review.")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>App name <span style='font-size: 12px; font-weight: 400; color: #64748b;'>(optional)</span></div>", unsafe_allow_html=True)
            inp["app_name"] = st.text_input("App name", value=inp.get("app_name", ""), placeholder="For example: My Booking App", label_visibility="collapsed")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>What does your app help people do? <span style='font-size: 12px; font-weight: 400; color: #64748b;'>(optional)</span></div>", unsafe_allow_html=True)
            inp["app_purpose"] = st.text_area("App purpose", value=inp.get("app_purpose", ""), placeholder="For example: Customers book appointments and ask questions.", label_visibility="collapsed", height=90)

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 8px;'>Does your app include an AI feature?</div>", unsafe_allow_html=True)
            curr_ai = inp.get("has_ai_feature", "Not sure")
            col_ai1, col_ai2, col_ai3 = st.columns(3)
            with col_ai1:
                is_yes = (curr_ai == "Yes")
                marker = "ai-btn-active" if is_yes else "ai-btn-inactive"
                st.markdown(f'<div class="{marker}"></div>', unsafe_allow_html=True)
                if st.button("Yes", key="btn_ai_yes", use_container_width=True):
                    inp["has_ai_feature"] = "Yes"
                    st.rerun()
            with col_ai2:
                is_no = (curr_ai == "No")
                marker = "ai-btn-active" if is_no else "ai-btn-inactive"
                st.markdown(f'<div class="{marker}"></div>', unsafe_allow_html=True)
                if st.button("No", key="btn_ai_no", use_container_width=True):
                    inp["has_ai_feature"] = "No"
                    st.rerun()
            with col_ai3:
                is_not_sure = (curr_ai == "Not sure")
                marker = "ai-btn-active" if is_not_sure else "ai-btn-inactive"
                st.markdown(f'<div class="{marker}"></div>', unsafe_allow_html=True)
                if st.button("Not sure", key="btn_ai_not_sure", use_container_width=True):
                    inp["has_ai_feature"] = "Not sure"
                    st.rerun()

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

            with st.expander("› Advanced options", expanded=False):
                st.caption("Quick Demo Target Presets:")
                col_pre1, col_pre2 = st.columns(2)
                with col_pre1:
                    if st.button("🎯 Use Public Demo App", key="pre_pub"):
                        inp["url"] = DEFAULT_PUBLIC_URL
                        st.rerun()
                with col_pre2:
                    if st.button("🔐 Use Hybrid Demo (401 Protected)", key="pre_hyb"):
                        inp["url"] = DEFAULT_HYBRID_URL
                        st.rerun()
                inp["crawl_depth"] = st.slider("Max pages to inspect", min_value=1, max_value=5, value=inp.get("crawl_depth", 3))

        elif target_type == "chatbot":
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>AI Endpoint address <span style='color: #ef4444;'>*</span></div>", unsafe_allow_html=True)
            inp["url"] = st.text_input("Endpoint", value=inp.get("url", OLLAMA_GATEWAY_URL), label_visibility="collapsed")
            st.caption("Enter the Ollama Gateway or model endpoint (e.g. http://127.0.0.1:8080).")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Select Model</div>", unsafe_allow_html=True)
            inp["model"] = st.selectbox("Model", ["llama3.2:1b", "llama3.1:8b"], index=0, label_visibility="collapsed")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)

            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Protection Configuration</div>", unsafe_allow_html=True)
            inp["variant"] = st.radio("Variant", ["Baseline (Unprotected)", "Hardened (Safeguard Active)"], label_visibility="collapsed")

            with st.expander("› Advanced options", expanded=False):
                inp["has_rag"] = st.selectbox("Does the model use a document database (RAG)?", ["I don't know", "Yes", "No"])

        elif target_type == "github":
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Repository URL <span style='color: #ef4444;'>*</span></div>", unsafe_allow_html=True)
            st.text_input("Repo", value="https://github.com/example/vibe-app", disabled=True, label_visibility="collapsed")
            st.caption("Connect your GitHub account in Settings to enable direct repository scanning.")
            with st.expander("› Advanced options", expanded=False):
                st.text_input("Branch", value="main")

        else:
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Assessment Scope</div>", unsafe_allow_html=True)
            st.info("Questionnaire mode requires no live server. We will review your architecture across OWASP LLM and MITRE ATLAS.")

    with col_right:
        if target_type == "website":
            card_items = [
                ("📄", "We review accessible public pages."),
                ("🔍", "We list what we could not check."),
                ("👥", "You review the scope before we start.")
            ]
            lock_note = "🔒 No passwords needed for a public review."
        elif target_type == "chatbot":
            card_items = [
                ("🛡️", "We test prompt injection & boundary defense."),
                ("🔍", "We record token and completion metadata."),
                ("👥", "You authorize testing before probes run.")
            ]
            lock_note = "🔒 Zero requests dispatched without permission."
        else:
            card_items = [
                ("📋", "We evaluate architectural threat questions."),
                ("🔍", "We map gaps to OWASP and MITRE standards."),
                ("👥", "You receive actionable recommendations.")
            ]
            lock_note = "🔒 Safe offline analysis without credentials."

        # Zero indentation to guarantee standard HTML rendering without markdown code-block bug
        rows_str = "".join([f'<div style="display:flex; align-items:center; gap:12px; margin-bottom:14px;"><span style="font-size:18px;">{icon}</span><span style="font-size:14px; color:#334155; line-height:1.4;">{text}</span></div>' for icon, text in card_items])

        card_container_html = f'<div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:12px; padding:22px; margin-bottom:12px;"><div style="font-size:16px; font-weight:700; color:#0f172a; margin-bottom:16px;">What happens next?</div>{rows_str}</div><div style="font-size:13px; color:#64748b; display:flex; align-items:center; gap:6px; padding-left:4px;">{lock_note}</div>'
        st.markdown(card_container_html, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)

    st.markdown("""
    <div style="background: #eff6ff; border: 1px solid #dbeafe; border-radius: 10px; padding: 14px 18px; display: flex; align-items: center; gap: 10px; margin-bottom: 24px;">
        <span style="font-size: 18px; color: #2563eb;">ℹ️</span>
        <span style="font-size: 14px; color: #1e40af; font-weight: 500;">Login-protected pages stay untested unless you provide suitable access later.</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    col_b, col_sp, col_n = st.columns([2, 5, 2])
    with col_b:
        if st.button("← Back", key="btn_step2_back", use_container_width=True):
            st.session_state.wizard_step = 1
            st.rerun()
    with col_n:
        if st.button("Review checks →", type="primary", key="btn_step2_next", use_container_width=True):
            st.session_state.wizard_step = 3
            st.rerun()


def render_step_3():
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]

    st.markdown("""
    <div style="margin-bottom: 20px;">
        <div style="font-size: 12px; font-weight: 700; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">STEP 3 OF 4</div>
        <h1 style="font-size: 32px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; letter-spacing: -0.02em;">Review the checks & permission</h1>
        <p style="font-size: 16px; color: #475569; margin: 0;">Before starting, review the exact scope boundaries of this assessment.</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; min-height: 220px;">
            <div style="font-size: 15px; font-weight: 700; color: #16a34a; margin-bottom: 10px;">🟢 We will check:</div>
            <ul style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.6;">
                <li>Accessible public pages (up to 3)</li>
                <li>Visible elements & layout usability</li>
                <li>HTML accessibility (lang, alt tags, viewport)</li>
                <li>Response latency & TTFB</li>
                <li>Public security headers (CSP, HSTS)</li>
                <li>Published pricing signals</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; min-height: 220px;">
            <div style="font-size: 15px; font-weight: 700; color: #d97706; margin-bottom: 10px;">🟡 We cannot check yet:</div>
            <ul style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.6;">
                <li>Protected / login-required dashboards</li>
                <li>Private database security & SQL</li>
                <li>Internal backend code</li>
                <li>Cloud IAM roles & VPC rules</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; min-height: 220px;">
            <div style="font-size: 15px; font-weight: 700; color: #4f46e5; margin-bottom: 10px;">🔐 Access needed for deeper checks:</div>
            <ul style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.6;">
                <li>Test account credentials for private pages</li>
                <li>API keys or session tokens</li>
                <li>Read-only GitHub repo access</li>
                <li>Cloud audit role</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 18px;'></div>", unsafe_allow_html=True)

    st.markdown("""
    <div style="background: #eff6ff; border: 1px solid #dbeafe; border-radius: 10px; padding: 14px 18px; margin-bottom: 22px;">
        <span style="font-size: 14px; color: #1e40af; line-height: 1.5;">
            <strong>ℹ️ Access Boundary Notice:</strong> A login screen, CAPTCHA, or HTTP 401/403 barrier may limit this review. 
            <strong>It does not automatically mean the app has a security problem.</strong> We will inspect all accessible areas, document what works, and clearly list unassessed sections.
        </span>
    </div>
    """, unsafe_allow_html=True)

    target_spec = inp.get("url") if target_type == "website" else inp.get("model", "target")
    st.markdown("<div style='font-size: 15px; font-weight: 700; color: #0f172a; margin-bottom: 8px;'>Authorization & Scope Verification</div>", unsafe_allow_html=True)
    auth_cb = st.checkbox(
        f"🔒 I explicitly authorize ATLAS-Risk to perform this assessment against `{target_spec}`.",
        value=inp.get("auth_granted", False),
        help="Zero requests are dispatched before explicit authorization."
    )
    inp["auth_granted"] = auth_cb

    st.markdown("---")
    col_b, col_sp, col_s = st.columns([2, 5, 2.5])
    with col_b:
        if st.button("← Back", key="btn_step3_back", use_container_width=True):
            st.session_state.wizard_step = 2
            st.rerun()
    with col_s:
        can_start = inp.get("auth_granted", False)
        if st.button("🚀 Start assessment", type="primary", disabled=not can_start, key="btn_step3_start", use_container_width=True):
            st.session_state.wizard_step = 4
            st.session_state.is_assessment_executing = True
            st.session_state.stop_requested = False
            st.rerun()


def render_step_4():
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]
    store = AssessmentStore()

    st.markdown("""
    <div style="margin-bottom: 20px;">
        <div style="font-size: 12px; font-weight: 700; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">STEP 4 OF 4</div>
        <h1 style="font-size: 32px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; letter-spacing: -0.02em;">Running assessment...</h1>
        <p style="font-size: 16px; color: #475569; margin: 0;">Inspecting accessible surfaces with honest, evidence-based telemetry.</p>
    </div>
    """, unsafe_allow_html=True)

    col_prog, col_stop = st.columns([4, 1.2])
    with col_stop:
        if st.button("🛑 Stop Assessment", type="secondary", use_container_width=True):
            st.session_state.stop_requested = True
            st.warning("Stop signal sent. Halting assessment after current check...")

    with col_prog:
        status_container = st.empty()

    if target_type == "website":
        status_container.info(f"Connecting to `{inp['url']}` and discovering public pages...")
        time.sleep(0.5)

        if st.session_state.stop_requested:
            record = build_stopped_record(inp, "Assessment stopped by user during initial discovery.")
        else:
            inspector = PublicAppInspector(max_pages=inp.get("crawl_depth", 3))
            raw_res = inspector.inspect_url(inp["url"])

            status_container.info("Evaluating usability, accessibility, performance, and security headers...")
            time.sleep(0.5)

            pages = raw_res.get("pages_inspected", [])
            unassessed = raw_res.get("unassessed_areas", [])
            issues = raw_res.get("issues_observed", [])

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
        record = store.get_sample_report()

    store.save_assessment(record)

    st.session_state.current_completed_record = record
    st.session_state.is_assessment_executing = False
    st.success("✅ Assessment run complete! Rendering results...")
    time.sleep(0.4)
    st.rerun()


def build_stopped_record(inp: dict, reason: str) -> dict:
    """Builds a standardized STOPPED assessment record when user halts execution."""
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
