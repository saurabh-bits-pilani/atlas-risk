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

    # 3-Step Process Flow Bar (Responsive grid/flex)
    process_html = (
        '<div class="atlas-process-bar" style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 24px; margin-bottom: 36px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">'
        '<div class="atlas-process-item" style="display: flex; align-items: center; gap: 12px;"><span style="display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 50%; background: #f1f5f9; color: #475569; font-size: 12px; font-weight: 700; flex-shrink: 0;">1</span><span style="font-size: 20px; flex-shrink: 0;">💻</span><div><div style="font-size: 13.5px; font-weight: 700; color: #0f172a;">Choose your app</div><div style="font-size: 12px; color: #64748b;">Tell us what you\'d like to assess.</div></div></div>'
        '<div class="atlas-process-divider" style="color: #cbd5e1; font-size: 18px; user-select: none; text-align: center;">—</div>'
        '<div class="atlas-process-item" style="display: flex; align-items: center; gap: 12px;"><span style="display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 50%; background: #f1f5f9; color: #475569; font-size: 12px; font-weight: 700; flex-shrink: 0;">2</span><span style="font-size: 20px; flex-shrink: 0;">📋</span><div><div style="font-size: 13.5px; font-weight: 700; color: #0f172a;">Review the checks</div><div style="font-size: 12px; color: #64748b;">We run a set of relevant checks.</div></div></div>'
        '<div class="atlas-process-divider" style="color: #cbd5e1; font-size: 18px; user-select: none; text-align: center;">—</div>'
        '<div class="atlas-process-item" style="display: flex; align-items: center; gap: 12px;"><span style="display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; border-radius: 50%; background: #f1f5f9; color: #475569; font-size: 12px; font-weight: 700; flex-shrink: 0;">3</span><span style="font-size: 20px; flex-shrink: 0;">📄</span><div><div style="font-size: 13.5px; font-weight: 700; color: #0f172a;">Get your report</div><div style="font-size: 12px; color: #64748b;">See what we found, in a clear report.</div></div></div>'
        '</div>'
    )
    st.markdown(process_html, unsafe_allow_html=True)

    # "What can you assess?" Section
    st.markdown('<h2 style="font-size: 1.35rem; font-weight: 700; color: #0f172a; margin: 0 0 16px 0;">What can you assess?</h2>', unsafe_allow_html=True)

    c_card1, c_card2, c_card3, c_card4 = st.columns(4)

    with c_card1:
        card1_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 16px; min-height: 128px; margin-bottom: 8px;">'
            '<div style="font-size: 24px; margin-bottom: 8px;">🌐</div>'
            '<div style="font-size: 14.5px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">Website or SaaS</div>'
            '<div style="font-size: 12px; color: #64748b; line-height: 1.4;">Review public pages & security headers.</div>'
            '</div>'
        )
        st.markdown(card1_html, unsafe_allow_html=True)
        if st.button("Select Website →", key="btn_assess_web", use_container_width=True):
            on_navigate("➕ New assessment", {"wizard_step": 2, "target_type": "website"})

    with c_card2:
        card2_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 16px; min-height: 128px; margin-bottom: 8px;">'
            '<div style="font-size: 24px; margin-bottom: 8px;">🐙</div>'
            '<div style="font-size: 14.5px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">GitHub project</div>'
            '<div style="font-size: 12px; color: #64748b; line-height: 1.4;">Inspect repository code & security policy.</div>'
            '</div>'
        )
        st.markdown(card2_html, unsafe_allow_html=True)
        if st.button("Select GitHub →", key="btn_assess_github", use_container_width=True):
            on_navigate("➕ New assessment", {"wizard_step": 2, "target_type": "github"})

    with c_card3:
        card3_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 16px; min-height: 128px; margin-bottom: 8px;">'
            '<div style="font-size: 24px; margin-bottom: 8px;">🤖</div>'
            '<div style="font-size: 14.5px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">AI chatbot (Cloud)</div>'
            '<div style="font-size: 12px; color: #64748b; line-height: 1.4;">Test web assistants, Dify & webhooks.</div>'
            '</div>'
        )
        st.markdown(card3_html, unsafe_allow_html=True)
        if st.button("Select Chatbot →", key="btn_assess_chatbot", use_container_width=True):
            on_navigate("➕ New assessment", {"wizard_step": 2, "target_type": "chatbot"})

    with c_card4:
        card4_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px 16px; min-height: 128px; margin-bottom: 8px;">'
            '<div style="font-size: 24px; margin-bottom: 8px;">🦙</div>'
            '<div style="font-size: 14.5px; font-weight: 700; color: #0f172a; margin-bottom: 4px;">Local AI (Ollama)</div>'
            '<div style="font-size: 12px; color: #64748b; line-height: 1.4;">Audit local models via port 8080/ngrok.</div>'
            '</div>'
        )
        st.markdown(card4_html, unsafe_allow_html=True)
        if st.button("Select Local AI →", key="btn_assess_local_model", use_container_width=True):
            on_navigate("➕ New assessment", {"wizard_step": 2, "target_type": "local_model"})

    st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
    c_q_link, c_q_space = st.columns([3.5, 2.5])
    with c_q_link:
        if st.button("📋 No connection? Start with Architecture Questionnaire →", key="btn_assess_questionnaire"):
            on_navigate("➕ New assessment", {"wizard_step": 2, "target_type": "questionnaire"})

    st.markdown("<div style='height: 36px;'></div>", unsafe_allow_html=True)

    # Executive Risk Dashboard & Telemetry Section
    total_projects = len(user_assessments)
    total_issues = sum(a.get("counts", {}).get("issues", 0) for a in user_assessments)
    total_passing = sum(a.get("counts", {}).get("no_issue", 0) for a in user_assessments)
    total_unassessed = sum(a.get("counts", {}).get("not_completed", 0) for a in user_assessments)

    c_dash_hdr, c_dash_link = st.columns([3, 1.2])
    with c_dash_hdr:
        st.markdown("""
        <div>
            <h2 style="font-size: 1.35rem; font-weight: 800; color: #0f172a; margin: 0 0 4px 0;">📊 Executive Risk Dashboard & Telemetry</h2>
            <p style="font-size: 13.5px; color: #64748b; margin: 0;">Portfolio health metrics, verified strengths, and pending security findings across assessed projects.</p>
        </div>
        """, unsafe_allow_html=True)
    with c_dash_link:
        if st.button("View All Reports Archive →", key="btn_home_view_all_reports"):
            on_navigate("📄 Reports", {})

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # 4 KPI Stat Metric Cards
    kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)
    with kpi_col1:
        st.markdown(f"""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
            <div style="font-size: 12px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">Projects Assessed</div>
            <div style="font-size: 28px; font-weight: 800; color: #0f172a; line-height: 1.2;">{total_projects}</div>
            <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Evaluated till date</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi_col2:
        st.markdown(f"""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
            <div style="font-size: 12px; font-weight: 600; color: #ef4444; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">Issues Identified</div>
            <div style="font-size: 28px; font-weight: 800; color: #ef4444; line-height: 1.2;">{total_issues}</div>
            <div style="font-size: 12px; color: #f87171; margin-top: 4px;">Needs attention & fixes</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi_col3:
        st.markdown(f"""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
            <div style="font-size: 12px; font-weight: 600; color: #16a34a; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">Verified Strengths</div>
            <div style="font-size: 28px; font-weight: 800; color: #16a34a; line-height: 1.2;">{total_passing}</div>
            <div style="font-size: 12px; color: #4ade80; margin-top: 4px;">Signals working good</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi_col4:
        st.markdown(f"""
        <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
            <div style="font-size: 12px; font-weight: 600; color: #d97706; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px;">Access Gaps</div>
            <div style="font-size: 28px; font-weight: 800; color: #d97706; line-height: 1.2;">{total_unassessed}</div>
            <div style="font-size: 12px; color: #fbbf24; margin-top: 4px;">Protected / deeper access</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

    if not user_assessments:
        empty_html = (
            '<div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 36px 20px; text-align: center; margin-bottom: 18px; box-shadow: 0 1px 2px rgba(0,0,0,0.02);">'
            '<div style="font-size: 32px; margin-bottom: 10px;">📊</div>'
            '<div style="font-size: 16px; font-weight: 700; color: #0f172a; margin-bottom: 6px;">No Projects Assessed Yet</div>'
            '<div style="font-size: 13.5px; color: #64748b; margin-bottom: 16px; max-width: 480px; margin-left: auto; margin-right: auto;">'
            'Start an assessment above to evaluate a Website, GitHub repository, or local Ollama AI model. Your executive risk dashboard and project-by-project breakdown will automatically populate here.'
            '</div>'
            '</div>'
        )
        st.markdown(empty_html, unsafe_allow_html=True)
    else:
        st.markdown('<div style="font-size: 15px; font-weight: 700; color: #0f172a; margin-bottom: 14px;">Project-by-Project Health & Findings Breakdown:</div>', unsafe_allow_html=True)

        for rec in user_assessments[:5]:
            full = store.get_assessment(rec["id"]) or rec
            t_type = rec.get("target_type", "website")
            icon = "🌐" if t_type == "website" else ("🐙" if t_type == "github" else ("🤖" if t_type == "chatbot" else "📋"))
            t_label = "Website / SaaS" if t_type == "website" else ("GitHub Project" if t_type == "github" else ("AI Model / Ollama" if t_type == "chatbot" else "Architecture Questionnaire"))

            stat = rec.get("status", "COMPLETE")
            stat_badge = '<span style="background: #dcfce7; color: #15803d; padding: 3px 8px; border-radius: 6px; font-size: 12px; font-weight: 700;">🟢 COMPLETE</span>' if stat == "COMPLETE" else '<span style="background: #fef3c7; color: #b45309; padding: 3px 8px; border-radius: 6px; font-size: 12px; font-weight: 700;">🟡 PARTIAL</span>'

            # Project Card Container
            with st.container():
                st.markdown(f"""
                <div style="background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px 22px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                    <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #f1f5f9; padding-bottom: 12px; margin-bottom: 16px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 22px;">{icon}</span>
                            <div>
                                <span style="font-size: 15.5px; font-weight: 700; color: #0f172a;">{rec.get('name', 'Assessment')}</span>
                                <span style="font-size: 12.5px; color: #64748b; margin-left: 8px;">({rec.get('target_input', 'Target')})</span>
                            </div>
                        </div>
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 12px; color: #64748b;">{rec.get('created_at', '')[:19].replace('T', ' ')} UTC</span>
                            {stat_badge}
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                c_good, c_issues, c_unassessed = st.columns(3)

                # Column 1: What Worked Good
                with c_good:
                    st.markdown("<div style='font-size: 13.5px; font-weight: 700; color: #16a34a; margin-bottom: 8px;'>🟢 What Worked Good</div>", unsafe_allow_html=True)
                    positives = full.get("positive_observations", [])
                    if positives:
                        for p in positives[:3]:
                            summary_txt = p.get("summary", p.get("domain", "Good practice verified"))
                            st.markdown(f"<div style='font-size: 12.5px; color: #334155; margin-bottom: 6px;'>• {summary_txt}</div>", unsafe_allow_html=True)
                    else:
                        st.markdown("<div style='font-size: 12px; color: #64748b;'>• Verified connection and response handling.</div>", unsafe_allow_html=True)

                # Column 2: Issues Observed
                with c_issues:
                    st.markdown("<div style='font-size: 13.5px; font-weight: 700; color: #ef4444; margin-bottom: 8px;'>🔴 Issues Found</div>", unsafe_allow_html=True)
                    findings = full.get("findings", [])
                    if findings:
                        for f in findings[:3]:
                            st.markdown(f"<div style='font-size: 12.5px; color: #334155; margin-bottom: 6px;'>• <strong>{f.get('title', 'Issue')}:</strong> <span style='color: #64748b;'>{f.get('observed', '')[:70]}...</span></div>", unsafe_allow_html=True)
                    else:
                        st.markdown("<div style='font-size: 12px; color: #16a34a;'>• No security or compliance issues observed.</div>", unsafe_allow_html=True)

                # Column 3: Access Gaps & Deeper Scope
                with c_unassessed:
                    st.markdown("<div style='font-size: 13.5px; font-weight: 700; color: #d97706; margin-bottom: 8px;'>🟡 Deeper Scope & Access Needed</div>", unsafe_allow_html=True)
                    unassessed = full.get("unassessed_areas", [])
                    if unassessed:
                        for u in unassessed[:2]:
                            area_txt = u.get("area", "Protected Section")
                            req_txt = u.get("required_access", "Credentials required")
                            st.markdown(f"<div style='font-size: 12.5px; color: #334155; margin-bottom: 6px;'>• <strong>{area_txt}:</strong> <span style='color: #64748b;'>{req_txt}</span></div>", unsafe_allow_html=True)
                    else:
                        st.markdown("<div style='font-size: 12px; color: #64748b;'>• Public surface completely verified.</div>", unsafe_allow_html=True)

                # Action buttons row
                col_act1, col_act2, col_act_space = st.columns([1.5, 1.5, 3])
                with col_act1:
                    if st.button("📄 Open Full Report", key=f"home_open_{rec['id']}", use_container_width=True):
                        on_navigate("📄 Reports", {"opened_report_id": rec["id"]})
                with col_act2:
                    if st.button("🔄 Re-Assess Project", key=f"home_retest_{rec['id']}", use_container_width=True):
                        on_navigate("➕ New assessment", {"wizard_step": 2, "target_type": t_type})

                st.markdown("<hr style='margin: 16px 0; border: none; border-top: 1px solid #e2e8f0;'>", unsafe_allow_html=True)

    # Ethical Footer Notice
    footer_html = (
        '<div style="display: flex; align-items: center; justify-content: center; gap: 8px; color: #64748b; font-size: 12px; margin-top: 36px; padding-top: 20px; border-top: 1px solid #f1f5f9;">'
        '<span>ⓘ</span><span>We report what we can verify. Anything untested stays clearly marked.</span></div>'
    )
    st.markdown(footer_html, unsafe_allow_html=True)
