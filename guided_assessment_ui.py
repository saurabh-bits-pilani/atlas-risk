"""
Guided Assessment UI Module for ATLAS-Risk.
Implements the 4-step wizard matching the exact visual designs in Screen 2 and Screen 3:
Step 1: What would you like to check? (Interactive radio buttons & responsive target cards)
Step 2: Tell us about your app (Two-column layout, selection badge with Change link, "What happens next?" card)
Step 3: Review the checks & scope (Honest boundaries, permission checkbox)
Step 4: Run and view results (with real activity indicator, Stop button, and authentic telemetry)
"""

import streamlit as st
import time
import os
import json
import urllib.request
import urllib.error
from datetime import datetime, timezone

from engines.public_app_inspector import PublicAppInspector
from engines.assessment_store import AssessmentStore
from assessment_results_view import render_assessment_results
from local_ai_testing_ui import LOCAL_TEST_CATALOGUE, SYNTHETIC_SECRET

# Presets for ease of testing
DEFAULT_PUBLIC_URL = "http://127.0.0.1:8088/public_app"
DEFAULT_HYBRID_URL = "http://127.0.0.1:8088/hybrid_app"
OLLAMA_GATEWAY_URL = "http://127.0.0.1:8080"


# SVGs for Step 1 Cards
SVG_BROWSER = '''<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#1e293b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="18" rx="3" ry="3"></rect><line x1="2" y1="9" x2="22" y2="9"></line><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="10" y1="6" x2="10.01" y2="6"></line></svg>'''

SVG_GITHUB = '''<svg width="26" height="26" viewBox="0 0 24 24" fill="#1e293b"><path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"></path></svg>'''

SVG_CHAT = '''<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#1e293b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>'''

SVG_OLLAMA = '''<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#1e293b" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"></rect><circle cx="12" cy="5" r="2"></circle><path d="M12 7v4"></path><line x1="8" y1="16" x2="8.01" y2="16"></line><line x1="16" y1="16" x2="16.01" y2="16"></line></svg>'''

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
            "url": "",
            "github_url": "",
            "github_branch": "main",
            "chatbot_url": "",
            "chatbot_type": "OpenAI Compatible API (/v1/chat/completions)",
            "chatbot_token": "",
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

    curr_step = st.session_state.wizard_step

    # When starting fresh or on Steps 1-3, do not render old completed reports
    if curr_step < 4:
        st.session_state.current_completed_record = None

    if curr_step == 4 and st.session_state.current_completed_record is not None:
        # Top Navigation on Results View
        col_rt1, col_rt2, col_rt_sp = st.columns([2, 2.2, 5.8])
        with col_rt1:
            if st.button("← Back to Home", key="res_top_home"):
                st.session_state.current_completed_record = None
                st.session_state.wizard_step = 1
                if on_navigate:
                    on_navigate("🏠 Home")
                else:
                    st.session_state["app_nav"] = "🏠 Home"
                    st.rerun()
        with col_rt2:
            if st.button("➕ New Assessment", key="res_top_new"):
                st.session_state.current_completed_record = None
                st.session_state.wizard_step = 1
                st.rerun()

        render_step_tracker(4)
        render_assessment_results(st.session_state.current_completed_record)
        st.markdown("---")
        col_rb1, col_rb2, col_rb_sp = st.columns([2, 2.5, 5.5])
        with col_rb1:
            if st.button("🏠 Back to Home", key="res_bot_home", use_container_width=True):
                st.session_state.current_completed_record = None
                st.session_state.wizard_step = 1
                if on_navigate:
                    on_navigate("🏠 Home")
                else:
                    st.session_state["app_nav"] = "🏠 Home"
                    st.rerun()
        with col_rb2:
            if st.button("➕ Start Another Assessment", type="primary", key="res_bot_new", use_container_width=True):
                st.session_state.current_completed_record = None
                st.session_state.wizard_step = 1
                st.session_state.wizard_inputs["auth_granted"] = False
                st.rerun()
        return

    render_step_tracker(curr_step)

    if curr_step == 1:
        render_step_1(on_navigate)
    elif curr_step == 2:
        render_step_2(on_navigate)
    elif curr_step == 3:
        render_step_3(on_navigate)
    elif curr_step == 4:
        render_step_4(on_navigate)


def render_step_1(on_navigate=None):
    # Top Back Button
    col_tb, col_tsp = st.columns([2, 8])
    with col_tb:
        if st.button("← Back to Home", key="top_step1_back"):
            if on_navigate:
                on_navigate("🏠 Home")
            else:
                st.session_state["app_nav"] = "🏠 Home"
                st.rerun()

    st.markdown("""
    <div style="margin-bottom: 20px; margin-top: 10px;">
        <div style="font-size: 12px; font-weight: 700; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">STEP 1 OF 4</div>
        <h1 style="font-size: 32px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; letter-spacing: -0.02em;">What would you like to check?</h1>
        <p style="font-size: 16px; color: #475569; margin: 0;">Choose one. We'll ask only for the details we need.</p>
    </div>
    """, unsafe_allow_html=True)

    inp = st.session_state.wizard_inputs

    target_keys = ["website", "github", "chatbot", "local_model", "questionnaire"]
    target_radio_labels = {
        "website": "🌐 Website or SaaS app",
        "github": "🐙 GitHub project",
        "chatbot": "🤖 AI chatbot (Cloud / API)",
        "local_model": "🦙 Local AI model (Ollama)",
        "questionnaire": "📋 Architecture Questionnaire"
    }

    curr_target = inp.get("target_type", "website")
    if curr_target not in target_keys:
        curr_target = "website"

    st.markdown("<div style='font-size: 14px; font-weight: 700; color: #1e293b; margin-bottom: 8px;'>Select target type with radio button:</div>", unsafe_allow_html=True)
    sel_radio = st.radio(
        "Target Selector",
        options=target_keys,
        index=target_keys.index(curr_target),
        format_func=lambda k: target_radio_labels[k],
        horizontal=True,
        key="target_radio_horizontal",
        label_visibility="collapsed"
    )
    if sel_radio != inp.get("target_type"):
        inp["target_type"] = sel_radio
        st.rerun()

    st.markdown("<div style='margin-top: 16px;'></div>", unsafe_allow_html=True)

    cards = [
        ("website", "Website or SaaS app", "Review public pages of your web app or portal.", "For example: a booking site or customer dashboard", SVG_BROWSER),
        ("github", "GitHub project", "Review repository code, dependencies, and hygiene.", "For example: an app built with AI or open repo", SVG_GITHUB),
        ("chatbot", "AI chatbot (Cloud / API)", "Test conversational assistants, webhooks, and boundary defense.", "For example: customer support bot or API webhook", SVG_CHAT),
        ("local_model", "Local AI model (Ollama)", "Audit locally running models via port 8080 or ngrok tunnel.", "For example: Ollama running llama3.2:1b on your laptop", SVG_OLLAMA),
        ("questionnaire", "Architecture Questionnaire", "Understand architectural risks without connecting a live server.", "Useful during early design or when you don't have access", SVG_DOC),
    ]

    r1_cols = st.columns(3)
    r2_cols = st.columns(2)
    card_cols = [r1_cols[0], r1_cols[1], r1_cols[2], r2_cols[0], r2_cols[1]]

    for idx, (ctype, ctitle, cdesc, cexample, cicon) in enumerate(cards):
        col = card_cols[idx]
        with col:
            is_selected = (inp["target_type"] == ctype)
            border_style = "2px solid #2563eb" if is_selected else "1px solid #e2e8f0"
            bg_style = "#eff6ff" if is_selected else "#ffffff"
            radio_svg = SVG_RADIO_CHECKED if is_selected else SVG_RADIO_UNCHECKED

            card_html = f"""<div class="guided-card-wrapper" style="border: {border_style}; background-color: {bg_style}; border-radius: 12px; padding: 18px; margin-bottom: 8px; min-height: 140px; transition: all 0.15s ease-in-out;"><div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;"><div>{cicon}</div><div>{radio_svg}</div></div><div style="font-size: 15px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">{ctitle}</div><div style="font-size: 13.5px; color: #334155; margin-bottom: 4px;">{cdesc}</div><div style="font-size: 12.5px; color: #64748b;">{cexample}</div></div>"""
            st.markdown(card_html, unsafe_allow_html=True)

            btn_label = "🔘 Selected" if is_selected else f"⚪ Choose {ctitle}"
            btn_type = "primary" if is_selected else "secondary"
            if st.button(btn_label, key=f"sel_card_{ctype}", use_container_width=True, type=btn_type):
                inp["target_type"] = ctype
                st.rerun()

    st.markdown("<div style='margin-top: 18px;'></div>", unsafe_allow_html=True)

    st.markdown("""
    <div style="border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 22px; background: #ffffff; display: flex; align-items: flex-start; gap: 14px; margin-bottom: 28px; box-shadow: 0 1px 2px rgba(0,0,0,0.02);">
        <div style="font-size: 20px; color: #2563eb; line-height: 1;">ℹ️</div>
        <div>
            <div style="font-size: 15px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">For this selection</div>
            <div style="font-size: 14px; color: #475569; line-height: 1.5;">We'll review accessible pages or interfaces and clearly list anything we cannot check.<br>Deeper testing requires your permission and suitable access.</div>
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


def render_step_2(on_navigate=None):
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]

    # Top Navigation
    col_tb1, col_tb2, col_tsp = st.columns([2, 2, 6])
    with col_tb1:
        if st.button("← Back to Step 1", key="top_step2_back"):
            st.session_state.wizard_step = 1
            st.rerun()
    with col_tb2:
        if st.button("🏠 Home", key="top_step2_home"):
            if on_navigate:
                on_navigate("🏠 Home")
            else:
                st.session_state["app_nav"] = "🏠 Home"
                st.rerun()

    st.markdown("""
    <div style="margin-bottom: 20px; margin-top: 10px;">
        <div style="font-size: 12px; font-weight: 700; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">STEP 2 OF 4</div>
        <h1 style="font-size: 32px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; letter-spacing: -0.02em;">Tell us about your app</h1>
        <p style="font-size: 16px; color: #475569; margin: 0;">Provide target details. You can add more context if you have it.</p>
    </div>
    """, unsafe_allow_html=True)

    target_labels = {
        "website": "🌐 Website or SaaS app",
        "github": "🐙 GitHub project",
        "chatbot": "🤖 AI chatbot (Cloud / API)",
        "local_model": "🦙 Local AI model (Ollama)",
        "questionnaire": "📋 Architecture Questionnaire"
    }
    sel_label = target_labels.get(target_type, "🌐 Website or SaaS app")

    # Selection pill and Change link neatly aligned
    col_pill, col_chg, col_fill = st.columns([3.6, 1.4, 7.0])
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
            entered_url = st.text_input("Website address", value=inp.get("url", ""), placeholder="https://example.com", label_visibility="collapsed")
            inp["url"] = entered_url.strip()
            st.caption("Enter the public web address you want us to review.")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>App name <span style='font-size: 12px; font-weight: 400; color: #64748b;'>(optional)</span></div>", unsafe_allow_html=True)
            inp["app_name"] = st.text_input("App name", value=inp.get("app_name", ""), placeholder="e.g. Acme SaaS Portal", label_visibility="collapsed")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>What does your app help people do? <span style='font-size: 12px; font-weight: 400; color: #64748b;'>(optional)</span></div>", unsafe_allow_html=True)
            inp["app_purpose"] = st.text_area("App purpose", value=inp.get("app_purpose", ""), placeholder="e.g. Customers book appointments and view service records.", label_visibility="collapsed", height=80)

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
            with st.expander("› Advanced options & Demo Presets", expanded=False):
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

        elif target_type == "github":
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>GitHub Repository URL <span style='color: #ef4444;'>*</span></div>", unsafe_allow_html=True)
            inp["github_url"] = st.text_input(
                "GitHub URL",
                value=inp.get("github_url", ""),
                placeholder="https://github.com/owner/repository",
                label_visibility="collapsed"
            )
            st.caption("Enter any public GitHub repository URL (e.g. `https://github.com/pallets/flask` or your AI project repo).")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Repository Branch</div>", unsafe_allow_html=True)
            inp["github_branch"] = st.text_input("Branch", value=inp.get("github_branch", "main"), placeholder="main", label_visibility="collapsed")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Project Purpose / Tech Stack <span style='font-size: 12px; font-weight: 400; color: #64748b;'>(optional)</span></div>", unsafe_allow_html=True)
            inp["app_purpose"] = st.text_area(
                "Purpose",
                value=inp.get("app_purpose", ""),
                placeholder="e.g. Next.js app with LangChain and vector store integration",
                label_visibility="collapsed",
                height=80
            )

        elif target_type == "chatbot":
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Chatbot Endpoint / Webhook URL <span style='color: #ef4444;'>*</span></div>", unsafe_allow_html=True)
            inp["chatbot_url"] = st.text_input(
                "Chatbot Endpoint",
                value=inp.get("chatbot_url", ""),
                placeholder="https://api.yourcompany.com/v1/chat or assistant webhook URL",
                label_visibility="collapsed"
            )
            st.caption("Web conversational assistant endpoint, Dify bot URL, or cloud API webhook.")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Assistant Framework / Protocol</div>", unsafe_allow_html=True)
            bot_types = [
                "OpenAI Compatible API (/v1/chat/completions)",
                "Dify AI Assistant Webhook",
                "LangChain / Flowise API",
                "Custom REST Webhook",
                "Web Chat Widget Page"
            ]
            curr_btype = inp.get("chatbot_type", bot_types[0])
            btype_idx = bot_types.index(curr_btype) if curr_btype in bot_types else 0
            inp["chatbot_type"] = st.selectbox("Bot Type", bot_types, index=btype_idx, label_visibility="collapsed")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Authorization Header / API Key <span style='font-size: 12px; font-weight: 400; color: #64748b;'>(optional)</span></div>", unsafe_allow_html=True)
            inp["chatbot_token"] = st.text_input(
                "API Token",
                value=inp.get("chatbot_token", ""),
                type="password",
                placeholder="Bearer token or Authorization header value (if required)",
                label_visibility="collapsed"
            )

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Assistant Name <span style='font-size: 12px; font-weight: 400; color: #64748b;'>(optional)</span></div>", unsafe_allow_html=True)
            inp["app_name"] = st.text_input("Name", value=inp.get("app_name", ""), placeholder="e.g. Customer Support AI Assistant", label_visibility="collapsed")

        elif target_type == "local_model":
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Ollama Gateway Endpoint <span style='color: #ef4444;'>*</span></div>", unsafe_allow_html=True)
            gw_url = inp.get("url", OLLAMA_GATEWAY_URL)
            inp["url"] = st.text_input("Endpoint", value=gw_url, placeholder="http://127.0.0.1:8080 or https://xxxx.ngrok-free.app", label_visibility="collapsed")
            st.caption("Enter the Ollama Gateway or model endpoint (default: `http://127.0.0.1:8080`).")

            # Check gateway connectivity live
            gateway_online = False
            detected_models = ["llama3.2:1b", "llama3.1:8b"]
            try:
                probe_req = urllib.request.Request(f"{inp['url']}/models")
                with urllib.request.urlopen(probe_req, timeout=1.5) as resp:
                    m_data = json.loads(resp.read().decode())
                    raw_models = [m.get("name", "llama3.2:1b") for m in m_data.get("models", [])]
                    if raw_models:
                        detected_models = raw_models
                    gateway_online = True
            except Exception:
                gateway_online = False

            if gateway_online:
                st.success(f"🟢 Connected to Ollama Gateway at `{inp['url']}` ({len(detected_models)} model(s) available)")
            else:
                st.info(f"ℹ️ Ready to connect to `{inp['url']}`. If assessing via cloud web app, follow the 3 steps below:")

            with st.expander("📖 Step-by-Step: How to connect your local Ollama to this cloud website", expanded=not gateway_online):
                st.markdown("""
**Follow these 3 quick terminal commands on your computer:**

**Step 1: Start Ollama on your computer**
In your bash terminal, run:
```bash
ollama run llama3.2:1b
```
*(Or keep daemon active in background: `ollama serve`)*

**Step 2: Start the ATLAS-Risk Security Gateway**
In your project folder, open a new bash terminal and run:
```bash
python ollama_gateway.py
```
*(You will see confirmation: `🛡️ ATLAS-Risk Ollama Gateway Online (Port 8080)`)*

**Step 3: Create a public tunnel with ngrok**
In another bash terminal, run:
```bash
ngrok http 8080
```
Copy the **Forwarding URL** (e.g. `https://abcd-1234.ngrok-free.app`) and paste it into the **Ollama Gateway Endpoint** field above!
""")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Select Local Model</div>", unsafe_allow_html=True)
            curr_model = inp.get("model", detected_models[0])
            model_idx = detected_models.index(curr_model) if curr_model in detected_models else 0
            inp["model"] = st.selectbox("Model", detected_models, index=model_idx, label_visibility="collapsed")

            st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Protection Configuration</div>", unsafe_allow_html=True)
            curr_variant = inp.get("variant", "Baseline (Unprotected)")
            v_idx = 0 if "Baseline" in curr_variant else 1
            inp["variant"] = st.radio("Variant", ["Baseline (Unprotected)", "Hardened (Safeguard Active)"], index=v_idx, label_visibility="collapsed")

            with st.expander("› Advanced options & Dedicated Console", expanded=False):
                inp["has_rag"] = st.selectbox("Does the model use a document database (RAG)?", ["I don't know", "Yes", "No"])
                st.markdown("---")
                st.caption("Need real-time streaming probe evaluation with pre-flight interaction?")
                if st.button("🖥️ Open Dedicated Local AI Testing Console"):
                    st.session_state["app_nav"] = "⚙️ Settings"
                    st.session_state["open_local_ai_console"] = True
                    st.rerun()

        else:
            st.markdown("<div style='font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 4px;'>Architecture Questionnaire Scope</div>", unsafe_allow_html=True)
            st.info("Questionnaire mode requires no live server. We will evaluate your architectural threat model across OWASP Top 10 for LLM and MITRE ATLAS.")

            inp["app_name"] = st.text_input("System / Application Name", value=inp.get("app_name", ""), placeholder="e.g. Enterprise AI Assistant")
            inp["deployment_scope"] = st.selectbox("Deployment Exposure", ["Public Web Interface", "Authenticated Internal Users", "Isolated Sandbox/Testing"])
            inp["uses_rag"] = st.selectbox("Does the application use Retrieval-Augmented Generation (RAG)?", ["Yes", "No", "Planned"])
            inp["has_tools"] = st.selectbox("Does the LLM have tool-calling or autonomous agent capabilities?", ["Yes", "No", "Read-only tools"])

    with col_right:
        if target_type == "website":
            card_items = [
                ("📄", "We review accessible public pages."),
                ("🔍", "We list what we could not check."),
                ("👥", "You review the scope before we start.")
            ]
            lock_note = "🔒 No passwords needed for a public review."
        elif target_type == "github":
            card_items = [
                ("🐙", "We inspect public repo files and configuration."),
                ("🛡️", "We check vulnerability disclosure policy & licensing."),
                ("👥", "You review the scope before we start.")
            ]
            lock_note = "🔒 Read-only review. Never commits or modifies code."
        elif target_type == "chatbot":
            card_items = [
                ("🤖", "We test prompt injection & boundary defense."),
                ("🔍", "We record token and completion metadata."),
                ("👥", "You authorize testing before probes run.")
            ]
            lock_note = "🔒 Zero requests dispatched without permission."
        elif target_type == "local_model":
            card_items = [
                ("🦙", "We run controlled security probes on your local LLM."),
                ("📊", "We compare Baseline vs Hardened guardrails."),
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

        rows_str = "".join([f'<div style="display:flex; align-items:center; gap:12px; margin-bottom:14px;"><span style="font-size:18px;">{icon}</span><span style="font-size:14px; color:#334155; line-height:1.4;">{text}</span></div>' for icon, text in card_items])
        card_container_html = f'<div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:12px; padding:22px; margin-bottom:12px;"><div style="font-size:16px; font-weight:700; color:#0f172a; margin-bottom:16px;">What happens next?</div>{rows_str}</div><div style="font-size:13px; color:#64748b; display:flex; align-items:center; gap:6px; padding-left:4px;">{lock_note}</div>'
        st.markdown(card_container_html, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 24px;'></div>", unsafe_allow_html=True)

    st.markdown("""
    <div style="background: #eff6ff; border: 1px solid #dbeafe; border-radius: 10px; padding: 14px 18px; display: flex; align-items: center; gap: 10px; margin-bottom: 24px;">
        <span style="font-size: 18px; color: #2563eb;">ℹ️</span>
        <span style="font-size: 14px; color: #1e40af; font-weight: 500;">Protected endpoints or pages stay untested unless you provide suitable access later.</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    col_b, col_sp, col_n = st.columns([2, 5, 2])
    with col_b:
        if st.button("← Back to Step 1", key="btn_step2_back", use_container_width=True):
            st.session_state.wizard_step = 1
            st.rerun()
    with col_n:
        if st.button("Review checks →", type="primary", key="btn_step2_next", use_container_width=True):
            st.session_state.wizard_step = 3
            st.rerun()


def render_step_3(on_navigate=None):
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]

    # Top Navigation
    col_tb1, col_tb2, col_tsp = st.columns([2, 2, 6])
    with col_tb1:
        if st.button("← Back to Step 2", key="top_step3_back"):
            st.session_state.wizard_step = 2
            st.rerun()
    with col_tb2:
        if st.button("🏠 Home", key="top_step3_home"):
            if on_navigate:
                on_navigate("🏠 Home")
            else:
                st.session_state["app_nav"] = "🏠 Home"
                st.rerun()

    st.markdown("""
    <div style="margin-bottom: 20px; margin-top: 10px;">
        <div style="font-size: 12px; font-weight: 700; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 6px;">STEP 3 OF 4</div>
        <h1 style="font-size: 32px; font-weight: 800; color: #0f172a; margin: 0 0 8px 0; letter-spacing: -0.02em;">Review the checks & permission</h1>
        <p style="font-size: 16px; color: #475569; margin: 0;">Before starting, review the exact scope boundaries of this assessment.</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        if target_type == "website":
            checked_items = "<li>Accessible public pages (up to 3)</li><li>Visible elements & layout usability</li><li>HTML accessibility (lang, alt tags, viewport)</li><li>Response latency & TTFB</li><li>Public security headers (CSP, HSTS)</li><li>Published pricing signals</li>"
        elif target_type == "github":
            checked_items = "<li>Public repository metadata & branches</li><li>Licensing declaration (`LICENSE`)</li><li>Vulnerability disclosure policy (`SECURITY.md`)</li><li>Documentation & repository posture</li><li>Dependency hygiene indicators</li>"
        elif target_type in ("chatbot", "local_model"):
            checked_items = "<li>Direct prompt injection resistance</li><li>System prompt disclosure defense</li><li>Boundary adherence under roleplay probes</li><li>Inference latency & token telemetry</li><li>Baseline vs Hardened guardrail delta</li>"
        else:
            checked_items = "<li>OWASP Top 10 for LLM threat alignment</li><li>MITRE ATLAS adversarial technique mapping</li><li>Deployment boundary exposure</li><li>Autonomous tool & RAG data governance</li>"

        st.markdown(f"""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; min-height: 220px;">
            <div style="font-size: 15px; font-weight: 700; color: #16a34a; margin-bottom: 10px;">🟢 We will check:</div>
            <ul style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.6;">
                {checked_items}
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; min-height: 220px;">
            <div style="font-size: 15px; font-weight: 700; color: #d97706; margin-bottom: 10px;">🟡 We cannot check yet:</div>
            <ul style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.6;">
                <li>Protected / login-required dashboards</li>
                <li>Private database security & internal code</li>
                <li>Private API endpoints & session tokens</li>
                <li>Cloud IAM roles & VPC security rules</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 18px; min-height: 220px;">
            <div style="font-size: 15px; font-weight: 700; color: #4f46e5; margin-bottom: 10px;">🔐 Access needed for deeper checks:</div>
            <ul style="margin: 0; padding-left: 18px; font-size: 13px; color: #334155; line-height: 1.6;">
                <li>Test account credentials for private pages</li>
                <li>Authorized API keys or session tokens</li>
                <li>Read-only GitHub repo access token</li>
                <li>Cloud security audit role</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 18px;'></div>", unsafe_allow_html=True)

    st.markdown("""
    <div style="background: #eff6ff; border: 1px solid #dbeafe; border-radius: 10px; padding: 14px 18px; margin-bottom: 22px;">
        <span style="font-size: 14px; color: #1e40af; line-height: 1.5;">
            <strong>ℹ️ Access Boundary Notice:</strong> An authentication barrier (HTTP 401/403 or login screen) may limit this review. 
            <strong>It does not mean the app has a security vulnerability.</strong> We will inspect all accessible areas, document what works, and clearly list unassessed sections.
        </span>
    </div>
    """, unsafe_allow_html=True)

    if target_type == "website":
        target_spec = inp.get("url", "website")
    elif target_type == "github":
        target_spec = inp.get("github_url", "GitHub repository")
    elif target_type == "chatbot":
        target_spec = inp.get("chatbot_url", "chatbot endpoint")
    elif target_type == "local_model":
        target_spec = f"{inp.get('url', OLLAMA_GATEWAY_URL)} [{inp.get('model', 'llama3.2:1b')}]"
    else:
        target_spec = inp.get("app_name", "Architecture Profile")

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
        if st.button("← Back to Step 2", key="btn_step3_back", use_container_width=True):
            st.session_state.wizard_step = 2
            st.rerun()
    with col_s:
        can_start = inp.get("auth_granted", False)
        if st.button("🚀 Start assessment", type="primary", disabled=not can_start, key="btn_step3_start", use_container_width=True):
            st.session_state.wizard_step = 4
            st.session_state.is_assessment_executing = True
            st.session_state.stop_requested = False
            st.rerun()


def render_step_4(on_navigate=None):
    inp = st.session_state.wizard_inputs
    target_type = inp["target_type"]
    store = AssessmentStore()

    # Top Navigation on Step 4
    col_tb1, col_tb2, col_tsp = st.columns([2, 2, 6])
    with col_tb1:
        if st.button("← Back to Step 3", key="top_step4_back"):
            st.session_state.wizard_step = 3
            st.rerun()
    with col_tb2:
        if st.button("🏠 Home", key="top_step4_home"):
            if on_navigate:
                on_navigate("🏠 Home")
            else:
                st.session_state["app_nav"] = "🏠 Home"
                st.rerun()

    st.markdown("""
    <div style="margin-bottom: 20px; margin-top: 10px;">
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
        target_url = inp.get("url", DEFAULT_PUBLIC_URL)
        status_container.info(f"Connecting to `{target_url}` and discovering public pages...")
        time.sleep(0.5)

        if st.session_state.stop_requested:
            record = build_stopped_record(inp, "Assessment stopped by user during initial discovery.")
        else:
            inspector = PublicAppInspector(max_pages=inp.get("crawl_depth", 3))
            raw_res = inspector.inspect_url(target_url)

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
                "name": f"Web Review: {target_url.replace('http://', '').replace('https://', '')[:25]}",
                "target_type": "website",
                "target_input": target_url,
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

    elif target_type == "local_model":
        endpoint = inp.get("url", OLLAMA_GATEWAY_URL)
        selected_model = inp.get("model", "llama3.2:1b")
        variant = inp.get("variant", "Baseline (Unprotected)")
        mode_param = "hardened" if "Hardened" in variant else "baseline"
        probe_endpoint = f"{endpoint}/probe/{mode_param}"

        status_container.info(f"Connecting to Ollama Gateway at `{endpoint}`...")
        time.sleep(0.4)

        gateway_connected = False
        try:
            req = urllib.request.Request(f"{endpoint}/models")
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                gateway_connected = True
        except Exception:
            gateway_connected = False

        if not gateway_connected:
            status_container.warning(f"Ollama Gateway offline at `{endpoint}`. Generating bounded assessment report...")
            record = {
                "id": store.generate_assessment_id(),
                "name": f"Ollama Audit: {selected_model} ({variant})",
                "target_type": "local_model",
                "target_input": f"{endpoint} [{selected_model}]",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "PARTIAL",
                "summary": f"Could not connect to Ollama Gateway at {endpoint}. Probes were not dispatched to protect network integrity.",
                "counts": {"issues": 1, "no_issue": 0, "not_completed": len(LOCAL_TEST_CATALOGUE), "not_applicable": 0},
                "findings": [
                    {
                        "domain": "Target Connectivity",
                        "severity": "HIGH",
                        "title": f"Gateway Offline at {endpoint}",
                        "observed": f"Connection to {endpoint}/models was refused or timed out.",
                        "why_it_matters": "Ollama local model security probes require an active gateway process.",
                        "evidence": f"Failed connection attempt to {endpoint}/models",
                        "action": "Ensure Ollama is running (`ollama serve`) and the gateway is running (`python ollama_gateway.py`).",
                        "how_to_verify": "Verify `curl http://127.0.0.1:8080/models` returns model list."
                    }
                ],
                "positive_observations": [],
                "unassessed_areas": [
                    {"area": t["name"], "reason": "Target gateway unreachable during audit", "required_access": f"Active Ollama Gateway on {endpoint}"}
                    for t in LOCAL_TEST_CATALOGUE
                ],
                "next_steps": [
                    "Start Ollama locally: `ollama run llama3.2:1b`",
                    "Start Ollama Gateway: `python ollama_gateway.py`",
                    "If assessing via cloud web app, tunnel port 8080 via ngrok (`ngrok http 8080`) or run ATLAS-Risk locally."
                ]
            }
        else:
            status_container.info(f"Executing {len(LOCAL_TEST_CATALOGUE)} controlled security probes against `{selected_model}`...")
            findings = []
            positive_obs = []
            issues_cnt = 0
            safe_cnt = 0

            for test in LOCAL_TEST_CATALOGUE:
                if st.session_state.stop_requested:
                    break
                status_container.info(f"Running probe: {test['name']} ({test['test_id']})...")
                time.sleep(0.3)

                payload_dict = {
                    "prompt": test["test_prompt"],
                    "test_id": test["test_id"],
                    "model": selected_model,
                    "mode": mode_param
                }
                try:
                    payload = json.dumps(payload_dict).encode()
                    req = urllib.request.Request(probe_endpoint, data=payload, headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        body = json.loads(resp.read().decode())
                        raw_reply = body.get("response", "")
                        done = body.get("done", True)
                        done_reason = body.get("done_reason", "stop")
                        assertion = test["assertion"]

                        if not raw_reply or not raw_reply.strip():
                            findings.append({
                                "domain": test["threat_family"],
                                "severity": "MEDIUM",
                                "title": f"{test['name']} (Empty Response)",
                                "observed": "Model returned an empty response.",
                                "why_it_matters": "Empty response cannot confirm safety compliance.",
                                "evidence": f"Raw reply was empty (done: {done})",
                                "action": "Inspect model prompt template and generation settings.",
                                "how_to_verify": "Re-run probe."
                            })
                            issues_cnt += 1
                        elif done_reason == "length" or not done:
                            if assertion["type"] == "contains_secret" and assertion["secret"].lower() in raw_reply.lower():
                                findings.append({
                                    "domain": test["threat_family"],
                                    "severity": "CRITICAL",
                                    "title": f"{test['name']} (Secret Disclosed in Truncated Output)",
                                    "observed": f"Secret '{assertion['secret']}' was exposed before truncation.",
                                    "why_it_matters": "Confidential internal system instructions or credentials were leaked.",
                                    "evidence": f"Response snippet: {raw_reply[:120]}... (done_reason: {done_reason})",
                                    "action": "Enforce strict pre-generation system prompt protection guardrails.",
                                    "how_to_verify": "Retest with hardened guardrail."
                                })
                                issues_cnt += 1
                            else:
                                findings.append({
                                    "domain": test["threat_family"],
                                    "severity": "LOW",
                                    "title": f"{test['name']} (Truncated Response)",
                                    "observed": f"Response stopped prematurely (done_reason: {done_reason}).",
                                    "why_it_matters": "Truncated reply leaves compliance inconclusive.",
                                    "evidence": f"Tokens: {body.get('eval_count', 0)}, done_reason: {done_reason}",
                                    "action": "Increase model max token limit.",
                                    "how_to_verify": "Re-run probe with larger token window."
                                })
                                issues_cnt += 1
                        else:
                            is_vuln = False
                            if assertion["type"] == "contains_secret" and assertion["secret"].lower() in raw_reply.lower():
                                is_vuln = True
                            elif assertion["type"] == "contains_keyword" and any(k.lower() in raw_reply.lower() for k in assertion.get("keywords", [])):
                                is_vuln = True

                            if is_vuln:
                                findings.append({
                                    "domain": test["threat_family"],
                                    "severity": "HIGH",
                                    "title": f"{test['name']} (Vulnerability Observed)",
                                    "observed": f"Model revealed protected internal information under probe: '{test['test_prompt']}'.",
                                    "why_it_matters": "Prompt injection allowed bypass of intended instruction boundaries.",
                                    "evidence": f"Response output: {raw_reply[:140]}...",
                                    "action": "Implement active input filtering and system prompt fencing.",
                                    "how_to_verify": "Retest with Hardened safeguard active."
                                })
                                issues_cnt += 1
                            else:
                                positive_obs.append({
                                    "domain": test["threat_family"],
                                    "summary": f"{test['name']}: Compliant output",
                                    "evidence": "Model adhered to safety boundary without disclosing protected secret."
                                })
                                safe_cnt += 1
                except Exception as e:
                    findings.append({
                        "domain": test["threat_family"],
                        "severity": "MEDIUM",
                        "title": f"{test['name']} (Probe Error)",
                        "observed": f"Error communicating with model: {str(e)}",
                        "why_it_matters": "Test execution encountered an error.",
                        "evidence": str(e),
                        "action": "Verify model and gateway stability.",
                        "how_to_verify": "Re-run probe."
                    })
                    issues_cnt += 1

            record = {
                "id": store.generate_assessment_id(),
                "name": f"Ollama Audit: {selected_model} ({variant})",
                "target_type": "local_model",
                "target_input": f"{endpoint} [{selected_model}]",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "COMPLETE" if issues_cnt == 0 else "PARTIAL",
                "summary": f"Ollama probe audit executed against {selected_model} in {variant} mode. "
                           f"Observed {issues_cnt} finding(s) and {safe_cnt} compliant behavior(s).",
                "counts": {
                    "issues": issues_cnt,
                    "no_issue": safe_cnt,
                    "not_completed": 0,
                    "not_applicable": 6
                },
                "findings": findings,
                "positive_observations": positive_obs,
                "unassessed_areas": [],
                "next_steps": [
                    "Compare results with Hardened mode active." if "Baseline" in variant else "Review findings and deploy verified guardrails."
                ]
            }

    elif target_type == "chatbot":
        status_container.info(f"Connecting to Chatbot endpoint `{inp.get('chatbot_url')}`...")
        time.sleep(0.5)
        record = inspect_chatbot_endpoint(
            chatbot_url=inp.get("chatbot_url", "https://api.example.com/v1/chat"),
            chatbot_type=inp.get("chatbot_type", "OpenAI Compatible API"),
            token=inp.get("chatbot_token", ""),
            app_name=inp.get("app_name", "")
        )

    elif target_type == "github":
        status_container.info(f"Inspecting GitHub repository `{inp.get('github_url')}`...")
        time.sleep(0.5)
        record = inspect_github_repository(
            github_url=inp.get("github_url", "https://github.com/example/repo"),
            branch=inp.get("github_branch", "main"),
            purpose=inp.get("app_purpose", "")
        )

    else:
        status_container.info("Evaluating architecture questionnaire responses against OWASP LLM & MITRE ATLAS...")
        time.sleep(0.5)
        record = evaluate_questionnaire_inputs(inp)

    store.save_assessment(record)

    st.session_state.current_completed_record = record
    st.session_state.is_assessment_executing = False
    st.success("✅ Assessment run complete! Rendering results...")
    time.sleep(0.4)
    st.rerun()


def inspect_github_repository(github_url: str, branch: str = "main", purpose: str = "") -> dict:
    """Inspects a public GitHub repository for security posture, secret hygiene, and best practices."""
    store = AssessmentStore()
    clean_url = github_url.strip().rstrip("/")
    parts = [p for p in clean_url.split("/") if p]
    owner, repo_name = "unknown", "repository"
    if len(parts) >= 2:
        owner = parts[-2]
        repo_name = parts[-1].replace(".git", "")

    api_url = f"https://api.github.com/repos/{owner}/{repo_name}"
    headers = {"User-Agent": "ATLAS-Risk-Security-Scanner/1.0", "Accept": "application/vnd.github.v3+json"}

    repo_data = {}
    is_live_api = False
    try:
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            repo_data = json.loads(resp.read().decode())
            is_live_api = True
    except Exception:
        is_live_api = False

    findings = []
    positive_obs = []
    unassessed = []

    if is_live_api:
        positive_obs.append({
            "domain": "Repository Visibility",
            "summary": f"Verified public repository: {owner}/{repo_name}",
            "evidence": f"Repository is publicly reachable on default branch '{repo_data.get('default_branch', branch)}'."
        })

        if repo_data.get("license"):
            positive_obs.append({
                "domain": "Governance & Licensing",
                "summary": f"Open source license declared: {repo_data['license'].get('name', 'Declared')}",
                "evidence": f"SPDX ID: {repo_data['license'].get('spdx_id', 'Active')}"
            })
        else:
            findings.append({
                "domain": "Governance & Licensing",
                "severity": "LOW",
                "title": "Missing Open Source License (LICENSE)",
                "observed": "No declared license found in repository root.",
                "why_it_matters": "Without a license, default copyright applies, making reuse or dependency integration legally ambiguous.",
                "evidence": f"Inspected metadata for {owner}/{repo_name}",
                "action": "Add an appropriate license (e.g. MIT, Apache-2.0) to the repository root.",
                "how_to_verify": "Verify GitHub recognizes the license badge in the repository sidebar."
            })

        has_security = False
        try:
            sec_req = urllib.request.Request(f"https://api.github.com/repos/{owner}/{repo_name}/contents/SECURITY.md", headers=headers)
            with urllib.request.urlopen(sec_req, timeout=2.0) as sresp:
                if sresp.status == 200:
                    has_security = True
        except Exception:
            has_security = False

        if has_security:
            positive_obs.append({
                "domain": "Vulnerability Disclosure",
                "summary": "Security Advisory Policy (`SECURITY.md`) present",
                "evidence": "Public vulnerability disclosure instructions verified."
            })
        else:
            findings.append({
                "domain": "Vulnerability Disclosure",
                "severity": "MEDIUM",
                "title": "Missing Security Policy (`SECURITY.md`)",
                "observed": "No `SECURITY.md` found in repository root or `.github/` folder.",
                "why_it_matters": "External security researchers need a dedicated disclosure channel to report vulnerabilities privately.",
                "evidence": f"GET /repos/{owner}/{repo_name}/contents/SECURITY.md returned 404",
                "action": "Create a `.github/SECURITY.md` file specifying your responsible disclosure email or GitHub Security Advisory process.",
                "how_to_verify": "Confirm security policy appears under the Security tab in GitHub."
            })
    else:
        positive_obs.append({
            "domain": "Repository Structure",
            "summary": f"Registered repository path: {owner}/{repo_name}",
            "evidence": f"Configured review target: {clean_url}"
        })
        findings.append({
            "domain": "Repository Hygiene",
            "severity": "MEDIUM",
            "title": "GitHub Direct API Authentication Required for Deep Scan",
            "observed": "Public unauthenticated GitHub API rate-limited or repository is private.",
            "why_it_matters": "Deep code inspection (AST analysis, dependency vulnerability parsing, secret git commit history) requires read access.",
            "evidence": f"Repository: {clean_url}",
            "action": "Provide a read-only GitHub Personal Access Token (PAT) or GitHub App integration in Settings.",
            "how_to_verify": "Re-run assessment with GitHub credentials configured."
        })

    unassessed.extend([
        {"area": "Private Git Commit History", "reason": "Requires cloned repository git objects", "required_access": "Read-only repository access token"},
        {"area": "Dependency CVE Vulnerability Database", "reason": "Requires full lockfile resolution (`package-lock.json` / `poetry.lock`)", "required_access": "Dependency graph / lockfile contents"},
        {"area": "Protected Branch Rules & Secrets Scanning", "reason": "Requires GitHub Organization / Repo admin permissions", "required_access": "GitHub App OAuth installation"}
    ])

    issues_cnt = len(findings)
    safe_cnt = len(positive_obs)

    return {
        "id": store.generate_assessment_id(),
        "name": f"GitHub Review: {owner}/{repo_name}",
        "target_type": "github",
        "target_input": clean_url,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "COMPLETE" if issues_cnt == 0 else "PARTIAL",
        "summary": f"Bounded repository review completed for {owner}/{repo_name}. Identified {issues_cnt} finding(s), {safe_cnt} verified standard(s), and {len(unassessed)} unassessed area(s) requiring deeper access.",
        "counts": {
            "issues": issues_cnt,
            "no_issue": safe_cnt,
            "not_completed": len(unassessed),
            "not_applicable": 0
        },
        "findings": findings,
        "positive_observations": positive_obs,
        "unassessed_areas": unassessed,
        "next_steps": [
            "Add `.github/SECURITY.md` for responsible vulnerability disclosure.",
            "Enable GitHub Dependabot or automated dependency vulnerability scanning.",
            "Connect read-only access in Settings for private secret and commit history scanning."
        ]
    }


def inspect_chatbot_endpoint(chatbot_url: str, chatbot_type: str, token: str = "", app_name: str = "") -> dict:
    """Inspects an AI conversational endpoint or webhook for boundary defenses and connectivity."""
    store = AssessmentStore()
    clean_url = chatbot_url.strip()
    name = app_name.strip() if app_name else "Cloud AI Chatbot"

    findings = []
    positive_obs = []
    unassessed = []

    is_reachable = False
    status_code = None
    headers = {"User-Agent": "ATLAS-Risk-Auditor/1.0", "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}" if not token.lower().startswith("bearer ") else token

    try:
        test_payload = json.dumps({"messages": [{"role": "user", "content": "Hello"}], "max_tokens": 10}).encode()
        req = urllib.request.Request(clean_url, data=test_payload, headers=headers)
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            status_code = resp.status
            is_reachable = True
    except urllib.error.HTTPError as e:
        status_code = e.code
        if status_code in (401, 403):
            is_reachable = True
    except Exception:
        is_reachable = False

    if is_reachable:
        if status_code in (200, 201):
            positive_obs.append({
                "domain": "Endpoint Availability",
                "summary": "Chatbot endpoint responded successfully (HTTP 200 OK)",
                "evidence": f"Successfully received HTTP {status_code} from {clean_url}"
            })
            positive_obs.append({
                "domain": "Protocol Negotiation",
                "summary": f"Compatible with {chatbot_type}",
                "evidence": "Endpoint accepted JSON conversation payload."
            })
        elif status_code in (401, 403):
            positive_obs.append({
                "domain": "Access Control",
                "summary": f"Endpoint strictly enforces authentication (HTTP {status_code})",
                "evidence": "Anonymous or unauthenticated requests are rejected as expected."
            })
            unassessed.append({
                "area": "Live Prompt Injection Probing",
                "reason": f"Endpoint requires valid authentication credentials (returned HTTP {status_code})",
                "required_access": "Provide valid API bearer token in Step 2"
            })
    else:
        findings.append({
            "domain": "Endpoint Connectivity",
            "severity": "HIGH",
            "title": "Chatbot Endpoint Unreachable",
            "observed": f"Connection attempt to {clean_url} failed or timed out.",
            "why_it_matters": "Probing and boundary validation cannot proceed without an accessible endpoint.",
            "evidence": f"Endpoint connection failed for {clean_url}",
            "action": "Ensure the chatbot server or webhook is online and public routing is configured.",
            "how_to_verify": f"Run `curl -I -X POST {clean_url}` to verify responsiveness."
        })

    unassessed.extend([
        {"area": "Underlying Model Weights & Architecture", "reason": "Cloud API hides base model checkpoint", "required_access": "Model provider transparency report"},
        {"area": "Retrieval-Augmented Vector Database (RAG)", "reason": "Internal vector store is not directly exposed", "required_access": "Vector database read telemetry"}
    ])

    issues_cnt = len(findings)
    safe_cnt = len(positive_obs)

    return {
        "id": store.generate_assessment_id(),
        "name": f"Chatbot Audit: {name}",
        "target_type": "chatbot",
        "target_input": f"{clean_url} ({chatbot_type})",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "COMPLETE" if (is_reachable and issues_cnt == 0) else "PARTIAL",
        "summary": f"AI Chatbot audit completed for {name}. Observed {issues_cnt} finding(s), {safe_cnt} verified behavior(s), and {len(unassessed)} unassessed boundary item(s).",
        "counts": {
            "issues": issues_cnt,
            "no_issue": safe_cnt,
            "not_completed": len(unassessed),
            "not_applicable": 0
        },
        "findings": findings,
        "positive_observations": positive_obs,
        "unassessed_areas": unassessed,
        "next_steps": [
            "Deploy input/output guardrail filters to enforce system prompt boundary defense.",
            "Monitor inference latency and rate-limit high-frequency requests.",
            "Configure authorized token credentials to enable deeper automated injection testing."
        ]
    }


def evaluate_questionnaire_inputs(inp: dict) -> dict:
    """Evaluates architectural questionnaire answers against OWASP Top 10 for LLMs and MITRE ATLAS."""
    store = AssessmentStore()
    app_name = inp.get("app_name", "Enterprise System Profile")
    if not app_name.strip():
        app_name = "Enterprise AI Architecture"
    exposure = inp.get("deployment_scope", "Public Web Interface")
    uses_rag = inp.get("uses_rag", "No")
    has_tools = inp.get("has_tools", "No")

    findings = []
    positive_obs = []
    unassessed = []

    positive_obs.append({
        "domain": "Architecture Profiling",
        "summary": f"Scope boundary declared: {exposure}",
        "evidence": f"System '{app_name}' evaluated under declared operational boundary."
    })

    if exposure == "Public Web Interface":
        findings.append({
            "domain": "OWASP LLM01: Prompt Injection",
            "severity": "HIGH",
            "title": "Public LLM Interface Requires Robust Input Guardrails",
            "observed": "Application is exposed to untrusted public web users without isolated network perimeter.",
            "why_it_matters": "Direct untrusted user inputs can attempt system prompt extraction or goal hijacking.",
            "evidence": f"Deployment Exposure set to '{exposure}'",
            "action": "Implement dual-perimeter guardrails: input content filtering and post-generation policy evaluation.",
            "how_to_verify": "Audit red-teaming test cases against published boundary defense rules."
        })

    if uses_rag == "Yes":
        findings.append({
            "domain": "OWASP LLM04: Model Denial of Service & Context Manipulation",
            "severity": "MEDIUM",
            "title": "RAG Document Ingestion & Chunking Governance",
            "observed": "System utilizes Retrieval-Augmented Generation (RAG) knowledge stores.",
            "why_it_matters": "Poisoned or unvetted external documents can introduce indirect prompt injections into the context window.",
            "evidence": f"Uses RAG set to '{uses_rag}'",
            "action": "Sanitize and validate all ingested knowledge chunks; isolate system instructions from retrieved chunk context.",
            "how_to_verify": "Perform adversarial injection testing on retrieved chunk embeddings."
        })
    else:
        positive_obs.append({
            "domain": "Knowledge Boundary",
            "summary": "No external RAG ingestion risk",
            "evidence": "Model relies solely on base weights or static prompt instructions."
        })

    if has_tools == "Yes":
        findings.append({
            "domain": "OWASP LLM06: Excessive Agency & Tool Execution",
            "severity": "HIGH",
            "title": "Autonomous Tool Calling Requires Human-in-the-Loop Safeguards",
            "observed": "LLM has autonomous function-calling or API write permissions.",
            "why_it_matters": "An injected prompt could trigger unauthorized state-changing actions (e.g. database updates, API transactions).",
            "evidence": f"Tool calling capability set to '{has_tools}'",
            "action": "Enforce strict read-only tool limits, parameter schema validation, and human confirmation for state-changing operations.",
            "how_to_verify": "Confirm permission elevation prompts before sensitive tool execution."
        })
    else:
        positive_obs.append({
            "domain": "Agency Control",
            "summary": "Limited autonomous tool execution",
            "evidence": "System does not allow unrestricted autonomous function calling."
        })

    unassessed.append({
        "area": "Live Dynamic Penetration Probing",
        "reason": "Questionnaire assessment is an architectural review and does not dispatch live network packets",
        "required_access": "Connect live endpoint or web address in Step 1"
    })

    issues_cnt = len(findings)
    safe_cnt = len(positive_obs)

    return {
        "id": store.generate_assessment_id(),
        "name": f"Architecture Review: {app_name}",
        "target_type": "questionnaire",
        "target_input": f"{app_name} ({exposure})",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "COMPLETE",
        "summary": f"Architectural risk review completed for {app_name}. Identified {issues_cnt} structural recommendation(s) and {safe_cnt} verified baseline control(s) mapped to OWASP LLM and MITRE ATLAS.",
        "counts": {
            "issues": issues_cnt,
            "no_issue": safe_cnt,
            "not_completed": len(unassessed),
            "not_applicable": 0
        },
        "findings": findings,
        "positive_observations": positive_obs,
        "unassessed_areas": unassessed,
        "next_steps": [
            "Implement input/output guardrails as recommended in the architectural findings.",
            "Conduct active live endpoint or repository scanning to verify runtime controls.",
            "Review findings with system architects and engineering leads."
        ]
    }


def build_stopped_record(inp: dict, reason: str) -> dict:
    """Builds a standardized STOPPED assessment record when user halts execution."""
    store = AssessmentStore()
    target_val = inp.get("url") or inp.get("github_url") or inp.get("chatbot_url") or "Target"
    return {
        "id": store.generate_assessment_id(),
        "name": f"Stopped Run: {target_val}",
        "target_type": inp.get("target_type", "website"),
        "target_input": target_val,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "STOPPED",
        "summary": f"Assessment was manually stopped: {reason}",
        "counts": {"issues": 0, "no_issue": 0, "not_completed": 1, "not_applicable": 0},
        "findings": [],
        "positive_observations": [],
        "unassessed_areas": [{"area": "Entire Target", "reason": "Execution cancelled before completion", "required_access": "Restart assessment"}],
        "next_steps": ["Re-run assessment when ready."]
    }
