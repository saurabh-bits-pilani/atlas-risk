"""
Home View Component for ATLAS-Risk.
Implements the clean, human-centered design matching the user's specification:
- Brand breadcrumb and Design preview badge
- Hero section with clear headline, CTA buttons, and report mockup graphic
- 3-Step horizontal process flow guide
- 'What can you assess?' cards (Website/SaaS, GitHub project, AI chatbot or model, Questionnaire)
- 'Recent assessments' list with empty state and 'View reports' link
- Ethical verification footer note
"""

import streamlit as st
from typing import Callable, Any
from engines.assessment_store import AssessmentStore


def render_home_page(on_navigate: Callable[[str, Any], None]):
    """
    Renders the modern, clean ATLAS-Risk Home screen.
    on_navigate: callback taking (tab_name, optional_extra_state_dict)
    """
    store = AssessmentStore()
    assessments = store.list_assessments()
    user_assessments = [a for a in assessments if a["id"] != "SAMPLE-HYBRID-001"]

    # Top Header / Breadcrumb row
    st.markdown(
        '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">'
        '<span style="font-size: 13px; color: #64748b; font-weight: 500;">Home</span>'
        '<span style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; background: #eef2ff; color: #4f46e5; border-radius: 9999px; font-size: 12px; font-weight: 600; border: 1px solid #e0e7ff;">'
        '👁️ Design preview</span></div>',
        unsafe_allow_html=True
    )

    # Hero Section
    col_hero_text, col_hero_card = st.columns([1.55, 1])

    with col_hero_text:
        st.markdown(
            '<div style="padding-top: 4px;">'
            '<div style="font-size: 11px; font-weight: 700; letter-spacing: 1.2px; color: #64748b; text-transform: uppercase; margin-bottom: 12px;">APP ASSESSMENT, MADE SIMPLE</div>'
            '<h1 style="font-size: 2.85rem; font-weight: 800; color: #0f172a; line-height: 1.15; margin: 0 0 16px 0; letter-spacing: -0.025em;">Understand your app\'s risks.</h1>'
            '<p style="font-size: 1.125rem; color: #475569; line-height: 1.55; margin: 0 0 28px 0; max-width: 520px;">See what works, what needs attention, and what we could not check.</p>'
            '</div>',
            unsafe_allow_html=True
        )

        col_b1, col_b2, col_b_space = st.columns([1.3, 1.3, 1.4])
        with col_b1:
            if st.button("Start assessment →", type="primary", use_container_width=True, key="home_hero_start_btn"):
                on_navigate("➕ New assessment", {"wizard_step": 1, "target_type": "website"})
        with col_b2:
            if st.button("View sample report", use_container_width=True, key="home_hero_sample_btn"):
                sample = store.get_sample_report()
                on_navigate("📄 Reports", {"opened_report_id": sample["id"]})

    with col_hero_card:
        # Floating Graphic Card with clean single-string HTML
        card_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 22px 24px; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 0 8px 10px -6px rgba(0, 0, 0, 0.03); max-width: 320px; margin: 0 auto; position: relative;">'
            '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;">'
            '<span style="font-size: 14px; font-weight: 700; color: #0f172a;">App assessment</span>'
            '<span style="font-size: 18px;">📄</span></div>'
            '<div style="margin-bottom: 14px;"><div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">'
            '<span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #10b981;"></span>'
            '<span style="font-size: 12px; font-weight: 600; color: #334155;">Observed</span></div>'
            '<div style="height: 5px; background: #e2e8f0; border-radius: 4px; width: 85%; margin-bottom: 4px; margin-left: 18px;"></div>'
            '<div style="height: 5px; background: #f1f5f9; border-radius: 4px; width: 60%; margin-left: 18px;"></div></div>'
            '<div style="margin-bottom: 14px;"><div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">'
            '<span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #f59e0b;"></span>'
            '<span style="font-size: 12px; font-weight: 600; color: #334155;">Needs attention</span></div>'
            '<div style="height: 5px; background: #e2e8f0; border-radius: 4px; width: 75%; margin-bottom: 4px; margin-left: 18px;"></div>'
            '<div style="height: 5px; background: #f1f5f9; border-radius: 4px; width: 45%; margin-left: 18px;"></div></div>'
            '<div><div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">'
            '<span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #94a3b8;"></span>'
            '<span style="font-size: 12px; font-weight: 600; color: #334155;">Not checked</span></div>'
            '<div style="height: 5px; background: #e2e8f0; border-radius: 4px; width: 70%; margin-bottom: 4px; margin-left: 18px;"></div>'
            '<div style="height: 5px; background: #f1f5f9; border-radius: 4px; width: 50%; margin-left: 18px;"></div></div>'
            '</div>'
        )
        st.markdown(card_html, unsafe_allow_html=True)

    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)

    # 3-Step Process Flow Bar
    process_html = (
        '<div style="display: grid; grid-template-columns: 1fr auto 1fr auto 1fr; align-items: center; gap: 14px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 24px; margin-bottom: 36px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">'
        '<div style="display: flex; align-items: center; gap: 12px;"><span style="display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 50%; background: #f1f5f9; color: #475569; font-size: 12px; font-weight: 700;">1</span><span style="font-size: 20px;">💻</span><div><div style="font-size: 13.5px; font-weight: 700; color: #0f172a;">Choose your app</div><div style="font-size: 12px; color: #64748b;">Tell us what you\'d like to assess.</div></div></div>'
        '<div style="color: #cbd5e1; font-size: 18px; user-select: none;">—</div>'
        '<div style="display: flex; align-items: center; gap: 12px;"><span style="display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 50%; background: #f1f5f9; color: #475569; font-size: 12px; font-weight: 700;">2</span><span style="font-size: 20px;">📋</span><div><div style="font-size: 13.5px; font-weight: 700; color: #0f172a;">Review the checks</div><div style="font-size: 12px; color: #64748b;">We run a set of relevant checks.</div></div></div>'
        '<div style="color: #cbd5e1; font-size: 18px; user-select: none;">—</div>'
        '<div style="display: flex; align-items: center; gap: 12px;"><span style="display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 50%; background: #f1f5f9; color: #475569; font-size: 12px; font-weight: 700;">3</span><span style="font-size: 20px;">📄</span><div><div style="font-size: 13.5px; font-weight: 700; color: #0f172a;">Get your report</div><div style="font-size: 12px; color: #64748b;">See what we found, in a clear report.</div></div></div>'
        '</div>'
    )
    st.markdown(process_html, unsafe_allow_html=True)

    # "What can you assess?" Section
    st.markdown('<h2 style="font-size: 1.35rem; font-weight: 700; color: #0f172a; margin: 0 0 16px 0;">What can you assess?</h2>', unsafe_allow_html=True)

    c_card1, c_card2, c_card3 = st.columns(3)

    with c_card1:
        card1_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; min-height: 120px; margin-bottom: 8px;">'
            '<div style="font-size: 24px; margin-bottom: 10px;">🌐</div>'
            '<div style="font-size: 14.5px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">Website or SaaS</div>'
            '<div style="font-size: 12.5px; color: #64748b;">Review publicly accessible pages.</div>'
            '</div>'
        )
        st.markdown(card1_html, unsafe_allow_html=True)
        if st.button("Select Website or SaaS →", key="btn_assess_web", use_container_width=True):
            on_navigate("➕ New assessment", {"wizard_step": 1, "target_type": "website"})

    with c_card2:
        card2_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; min-height: 120px; margin-bottom: 8px;">'
            '<div style="font-size: 24px; margin-bottom: 10px;">🐙</div>'
            '<div style="font-size: 14.5px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">GitHub project</div>'
            '<div style="font-size: 12.5px; color: #64748b;">Inspect available code and configuration.</div>'
            '</div>'
        )
        st.markdown(card2_html, unsafe_allow_html=True)
        if st.button("Select GitHub project →", key="btn_assess_github", use_container_width=True):
            on_navigate("➕ New assessment", {"wizard_step": 1, "target_type": "github"})

    with c_card3:
        card3_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 20px; min-height: 120px; margin-bottom: 8px;">'
            '<div style="font-size: 24px; margin-bottom: 10px;">💬</div>'
            '<div style="font-size: 14.5px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">AI chatbot or model</div>'
            '<div style="font-size: 12.5px; color: #64748b;">Check a supported AI connection.</div>'
            '</div>'
        )
        st.markdown(card3_html, unsafe_allow_html=True)
        if st.button("Select AI chatbot →", key="btn_assess_chatbot", use_container_width=True):
            on_navigate("➕ New assessment", {"wizard_step": 1, "target_type": "chatbot"})

    st.markdown("<div style='margin-top: 6px;'></div>", unsafe_allow_html=True)
    c_q_link, c_q_space = st.columns([2.5, 3])
    with c_q_link:
        if st.button("No connection? Start with a questionnaire →", key="btn_assess_questionnaire"):
            on_navigate("➕ New assessment", {"wizard_step": 1, "target_type": "questionnaire"})

    st.markdown("<div style='height: 32px;'></div>", unsafe_allow_html=True)

    # "Recent assessments" Section
    c_rec_hdr, c_rec_link = st.columns([3, 1])
    with c_rec_hdr:
        st.markdown('<h2 style="font-size: 1.25rem; font-weight: 700; color: #0f172a; margin: 0;">Recent assessments</h2>', unsafe_allow_html=True)
    with c_rec_link:
        if st.button("View reports →", key="btn_home_view_all_reports"):
            on_navigate("📄 Reports", {})

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    if not user_assessments:
        # Empty State matching Image 2
        empty_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 36px 20px; text-align: center; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(0,0,0,0.02);">'
            '<div style="font-size: 28px; margin-bottom: 10px;">📄</div>'
            '<div style="font-size: 15px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">Your first report starts here</div>'
            '<div style="font-size: 13px; color: #64748b; margin-bottom: 14px;">Completed and partial assessments will appear here.</div>'
            '<div style="font-size: 11.5px; color: #94a3b8;">⬇ Download reports as PDF or HTML.</div>'
            '</div>'
        )
        st.markdown(empty_html, unsafe_allow_html=True)
    else:
        # List recent reports
        for rec in user_assessments[:4]:
            with st.container():
                c_info, c_status, c_act = st.columns([3, 1.3, 1.2])
                with c_info:
                    st.markdown(f"**{rec.get('name', 'Assessment')}** (`{rec.get('target_input', 'Target')}`)")
                    st.caption(f"Date: {rec.get('created_at', '')[:19].replace('T', ' ')} UTC | ID: `{rec['id']}`")
                with c_status:
                    stat = rec.get("status", "COMPLETE")
                    stat_icon = "🟢" if stat == "COMPLETE" else ("🟡" if stat == "PARTIAL" else "🔴")
                    st.markdown(f"**{stat_icon} {stat}**")
                    issues_cnt = rec.get("counts", {}).get("issues_observed", rec.get("counts", {}).get("issues", 0))
                    st.caption(f"{issues_cnt} issue(s) observed")
                with c_act:
                    if st.button("Open Report", key=f"open_recent_{rec['id']}", use_container_width=True):
                        on_navigate("📄 Reports", {"opened_report_id": rec["id"]})
                st.markdown("<hr style='margin: 8px 0; border: none; border-top: 1px solid #f1f5f9;'>", unsafe_allow_html=True)

        st.markdown('<div style="font-size: 11.5px; color: #94a3b8; margin-top: 8px;">⬇ Download reports as PDF or HTML.</div>', unsafe_allow_html=True)

    # Ethical Footer Notice
    footer_html = (
        '<div style="display: flex; align-items: center; justify-content: center; gap: 8px; color: #64748b; font-size: 12px; margin-top: 36px; padding-top: 20px; border-top: 1px solid #f1f5f9;">'
        '<span>ⓘ</span><span>We report what we can verify. Anything untested stays clearly marked.</span></div>'
    )
    st.markdown(footer_html, unsafe_allow_html=True)
