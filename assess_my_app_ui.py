"""
'Assess My App' Public-First Review UI Module for ATLAS-Risk.
Designed for vibe-coded applications:
- Bounded, non-intrusive evaluation of publicly observable pages.
- Does not bypass login/CAPTCHA; treats protected areas as unassessed (never as a vulnerability or blanket failure).
- Produces a categorized report across Usability, Accessibility, Performance, Security/Privacy, and Pricing.
- Supplies actionable, practical code fixes for every issue observed.
- Offers clear instructions on what credentials/access are needed to unlock deeper checks.
"""

import streamlit as st
import json
import os
import re
from datetime import datetime, timezone
from engines.public_app_inspector import PublicAppInspector

DEFAULT_PUBLIC_DEMO = "http://127.0.0.1:8088/public_app"
DEFAULT_HYBRID_DEMO = "http://127.0.0.1:8088/hybrid_app"


def render_assess_my_app_tab():
    st.header("🌐 Assess My App: Public-First Review")
    st.caption("Bounded, non-intrusive review for web applications built through vibe coding (Cursor, Lovable, v0, Bolt, Streamlit).")

    st.info(
        "💡 **Product Principle:** We assess what is publicly observable without credentials. "
        "A login screen or protected area is **not a vulnerability** and does not fail the assessment; "
        "we review all accessible areas, document what works, pinpoint issues with practical code fixes, "
        "and explain the exact access needed for deeper checks."
    )

    # Quick selection presets
    st.markdown("##### 🚀 Quick Demo Presets:")
    col_p1, col_p2, col_p3 = st.columns([1.5, 2, 2.5])
    with col_p1:
        if st.button("🟢 1. Public App Demo"):
            st.session_state["target_app_url_input"] = DEFAULT_PUBLIC_DEMO
    with col_p2:
        if st.button("🔐 2. Hybrid App (With Protected Area)"):
            st.session_state["target_app_url_input"] = DEFAULT_HYBRID_DEMO

    # Target URL Form
    target_url = st.text_input(
        "Public Application URL",
        value=st.session_state.get("target_app_url_input", DEFAULT_PUBLIC_DEMO),
        help="Enter the root URL of your deployed application (e.g., https://my-app.vercel.app or local demo URL)"
    )

    col_opt1, col_opt2 = st.columns([2, 2])
    with col_opt1:
        max_pages = st.slider("Crawl Depth Limit (Max Internal Pages)", min_value=1, max_value=5, value=3)
    with col_opt2:
        st.caption("🔒 **Scope & Access Boundaries:** Passive review only. No credentials required. Login screens or CAPTCHAs will not be bypassed.")

    run_review = st.button("🔍 Run Public App Review", type="primary")

    if run_review and target_url:
        with st.spinner(f"Performing bounded non-intrusive inspection of {target_url}..."):
            inspector = PublicAppInspector(max_pages=max_pages)
            audit_result = inspector.inspect_url(target_url)
            st.session_state["public_app_audit_result"] = audit_result
            st.success("✅ Public review completed successfully!")

    # Display results if present in session state
    if "public_app_audit_result" in st.session_state:
        res = st.session_state["public_app_audit_result"]
        render_audit_results_view(res)


def render_audit_results_view(res: dict):
    pages = res.get("pages_inspected", [])
    unassessed = res.get("unassessed_areas", [])
    verified = res.get("what_we_verified", [])
    positives = res.get("positive_observations", [])
    issues = res.get("issues_observed", [])
    unassessed_topics = res.get("what_could_not_be_assessed", [])
    next_steps = res.get("next_steps_required_access", [])

    st.markdown("---")

    # Executive Status Banner
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%); color: white; padding: 20px 24px; border-radius: 8px; margin-bottom: 20px;">
        <h3 style="color: white; margin: 0 0 6px 0;">📊 Public Review Assessment: <code>{res['target_url']}</code></h3>
        <div style="font-size: 13px; color: #93c5fd;">Inspected At: {res['inspected_at']} | Scope: Bounded Public Discovery (Up to {len(pages)} pages)</div>
    </div>
    """, unsafe_allow_html=True)

    # Top KPI Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Accessible Pages", len(pages))
        st.caption("🟢 Fully reviewed")
    with m2:
        st.metric("Verified Claims", len(verified))
        st.caption("Traceable evidence")
    with m3:
        st.metric("Issues Observed", len(issues))
        st.caption("Actionable code fixes")
    with m4:
        st.metric("Protected / Unassessed", len(unassessed))
        if len(unassessed) > 0:
            st.caption("🔐 Requires test credentials")
        else:
            st.caption("0 blocked areas")

    # If unassessed areas exist, show graceful callout
    if unassessed:
        st.warning(
            f"🔐 **Partial Review Notice:** {len(unassessed)} section(s) require authentication or were protected. "
            "This is **not a vulnerability** or an assessment failure. Accessible pages were fully reviewed below, "
            "and required credentials for the protected areas are listed in Section 4."
        )

    # Multi-Domain Categorized Review Tabs
    st.markdown("### 📂 Categorized Domain Observations")
    tab_usability, tab_a11y, tab_perf, tab_sec, tab_pricing = st.tabs([
        "🖱️ Usability & Visible UI",
        "♿ Accessibility",
        "⚡ Performance",
        "🛡️ Public Security & Privacy",
        "💰 Published Pricing"
    ])

    with tab_usability:
        st.markdown("#### Usability & Visible Functionality")
        for p in pages:
            parsed = p.get("parsed", {})
            st.write(f"**URL:** `{p['url']}` (HTTP {p['http_status']})")
            st.write(f"- **Document Title:** `{parsed.get('title') or 'None detected'}`")
            st.write(f"- **Interactive Elements:** {parsed.get('buttons_count', 0)} button(s), {parsed.get('forms_count', 0)} form(s)")
            if p.get("discovered_links"):
                st.write(f"- **Discovered Same-Origin Links ({len(p['discovered_links'])}):**")
                for lk in p["discovered_links"]:
                    st.caption(f"  • `{lk}`")
            st.markdown("---")

    with tab_a11y:
        st.markdown("#### Accessibility Health")
        for p in pages:
            parsed = p.get("parsed", {})
            st.write(f"**URL:** `{p['url']}`")
            st.write(f"- **Language Declaration:** `{parsed.get('html_lang') or 'Missing'}`")
            st.write(f"- **Mobile Viewport:** `{'Present' if parsed.get('has_meta_viewport') else 'Missing'}`")
            st.write(f"- **Discovered Images:** {parsed.get('images_count', 0)} total")
            if parsed.get("images_missing_alt"):
                st.caption(f"  ⚠️ Images missing alt: `{parsed['images_missing_alt']}`")
            else:
                st.caption("  ✅ All images have valid alt attributes.")
            st.markdown("---")

    with tab_perf:
        st.markdown("#### Basic Performance Measurements")
        st.caption("Test Conditions: Direct HTTP GET from local inspector. Response latencies measured at network boundary.")
        for p in pages:
            st.write(f"**Page:** `{p['url']}`")
            col_ttfb, col_tot, col_sz = st.columns(3)
            with col_ttfb:
                st.metric("Time to First Byte (TTFB)", f"{p['ttfb_ms']} ms")
            with col_tot:
                st.metric("Total Load Latency", f"{p['total_latency_ms']} ms")
            with col_sz:
                st.metric("Payload Size", f"{p['content_length_bytes']} Bytes")
            st.markdown("---")

    with tab_sec:
        st.markdown("#### Publicly Observable Security & Privacy Signals")
        st.caption("Evaluates public HTTP headers and transport security without intrusive attacks.")
        for p in pages:
            headers = p.get("headers", {})
            st.write(f"**Headers on `{p['url']}`:**")
            col_s1, col_s2 = st.columns(2)
            with col_s1:
                st.write(f"• **X-Content-Type-Options:** `{headers.get('X-Content-Type-Options', 'Missing')}`")
                st.write(f"• **X-Frame-Options:** `{headers.get('X-Frame-Options', 'Missing')}`")
            with col_s2:
                st.write(f"• **Referrer-Policy:** `{headers.get('Referrer-Policy', 'Missing')}`")
                st.write(f"• **Content-Security-Policy:** `{headers.get('Content-Security-Policy', 'Missing')}`")
            st.markdown("---")

    with tab_pricing:
        st.markdown("#### Published Pricing Transparency")
        pricing_data = res["categories"]["pricing"]
        if pricing_data["status"] == "DETECTED":
            st.success(f"✅ Published Pricing Structure Detected: `{pricing_data.get('evidence')}`")
        else:
            st.info("ℹ️ **Not assessed — no public pricing table detected.** If this app has commercial plans, link them on the public landing navigation.")

    st.markdown("---")

    # 5 Structured Report Sections
    st.subheader("📋 Comprehensive Review Report")

    with st.expander("✅ 1. What We Could Verify (Traceable Evidence)", expanded=True):
        st.markdown("Every positive verification below is backed by traceable DOM or HTTP network evidence:")
        table_rows = []
        for v in verified:
            table_rows.append({
                "Domain": v["domain"],
                "Item Evaluated": v["item"],
                "Traceable Evidence": v["evidence"],
                "Status": f"🟢 {v['status']}"
            })
        st.table(table_rows)

    with st.expander("🌟 2. Positive Observations", expanded=True):
        for pos in positives:
            st.markdown(f"• **[{pos['area']}]** {pos['observation']}\n  - *Evidence:* `{pos['evidence']}`")

    with st.expander("🛠️ 3. Issues Observed & Practical Fixes", expanded=True):
        if not issues:
            st.success("🎉 Zero public issues detected across inspected pages!")
        else:
            for idx, iss in enumerate(issues, 1):
                st.markdown(f"#### {idx}. [{iss['domain']}] {iss['issue']}")
                st.caption(f"**Evidence:** `{iss['evidence']}`")
                st.markdown(f"**Practical Code Fix:**")
                st.code(iss["fix"], language="javascript" if "header" in iss["fix"].lower() else "html")
                st.markdown("---")

    with st.expander("🔒 4. What We Could Not Assess & Why", expanded=True):
        st.markdown(
            "The following areas were outside the bounded public scope or required authentication. "
            "**These are not failures or vulnerabilities; they represent boundary limits:**"
        )
        for un in unassessed_topics:
            st.markdown(f"• **Area:** `{un['area']}`\n  - *Reason:* {un['reason']}\n  - *Required Access:* **{un['required_access']}**")

    with st.expander("🚀 5. Next Steps & Required Access for Deeper Checks", expanded=True):
        st.markdown("To transition from passive public review to full-spectrum deep testing:")
        for step in next_steps:
            st.markdown(f"• {step}")

    st.markdown("---")

    # Report Export Actions
    st.subheader("📥 Export Review Documentation")
    col_e1, col_e2, col_e3 = st.columns(3)

    # Build Markdown string
    report_md = build_markdown_report(res)

    with col_e1:
        st.download_button(
            "📄 Download Markdown Report (.MD)",
            data=report_md,
            file_name=f"AssessMyApp_{res['origin'].replace('://', '_').replace(':', '_')}.md",
            mime="text/markdown"
        )
    with col_e2:
        st.download_button(
            "📊 Download Evidence Telemetry (.JSON)",
            data=json.dumps(res, indent=2),
            file_name=f"AssessMyApp_Evidence_{res['origin'].replace('://', '_').replace(':', '_')}.json",
            mime="application/json"
        )
    with col_e3:
        try:
            from engines.report_exporter import export_assessment_pdf_and_html
            origin = res.get("origin", "http://localhost")
            rec_id = f"AMA-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
            rec_for_pdf = {
                "id": rec_id,
                "name": f"Assess MyApp: {origin}",
                "model_name": f"Web App: {origin}",
                "model_id": origin,
                "company": "Public Web App",
                "model_company": "Web Application Review",
                "model_tier": "Public-First Review",
                "target_type": "website",
                "target_input": origin,
                "scan_profile": "owasp_core",
                "audit_profile_name": "Public-First Web Audit",
                "audit_profile_tier": "Public-First Review",
                "overall_safety_score": 85 if len(res.get("issues_observed", [])) == 0 else max(40, 100 - len(res.get("issues_observed", [])) * 12),
                "safety_grade": "A" if len(res.get("issues_observed", [])) == 0 else "B",
                "max_severity_found": "HIGH" if any(iss.get("severity") == "HIGH" for iss in res.get("issues_observed", [])) else ("MEDIUM" if res.get("issues_observed") else "LOW"),
                "circuit_breaker_triggered": False,
                "launch_readiness": "CONDITIONAL_APPROVAL" if res.get("issues_observed") else "PRODUCTION_READY",
                "attack_success_rate": round(len(res.get("issues_observed", [])) / max(1, len(res.get("issues_observed", [])) + len(res.get("positive_observations", []))), 2),
                "total_prompts_tested": len(res.get("issues_observed", [])) + len(res.get("positive_observations", [])),
                "total_prompts_planned": len(res.get("issues_observed", [])) + len(res.get("positive_observations", [])),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "status": "PARTIAL" if res.get("unassessed_areas") else "COMPLETE",
                "summary": f"Public review of {origin}: {len(res.get('issues_observed', []))} issue(s), {len(res.get('positive_observations', []))} verified baseline(s).",
                "counts": {
                    "issues": len(res.get("issues_observed", [])),
                    "no_issue": len(res.get("positive_observations", [])),
                    "not_completed": len(res.get("unassessed_areas", [])),
                    "not_applicable": 0
                },
                "findings": [
                    {
                        "domain": iss.get("domain", "General"),
                        "severity": iss.get("severity", "MEDIUM"),
                        "title": iss.get("issue", "Security / Usability Issue"),
                        "observed": iss.get("evidence", ""),
                        "action": iss.get("fix", ""),
                        "evidence": iss.get("evidence", ""),
                        "why_it_matters": "Affects security posture, usability, or browser privacy.",
                        "business_impact": "Exposes web assets to client-side attacks or degraded user trust.",
                        "attack_scenario": f"An attacker attempts cross-origin attacks or directory harvesting against {origin}.",
                        "code_fix": iss.get("fix", ""),
                        "compliance": "OWASP Top 10 Web (A05: Security Misconfiguration) | MITRE ATLAS AML.T0051"
                    }
                    for iss in res.get("issues_observed", [])
                ],
                "positive_observations": res.get("positive_observations", []),
                "unassessed_areas": res.get("what_could_not_be_assessed", []),
                "next_steps": res.get("next_steps_required_access", [])
            }
            pdf_path, _ = export_assessment_pdf_and_html(rec_for_pdf)
            if pdf_path and os.path.exists(pdf_path):
                with open(pdf_path, "rb") as f_pdf:
                    st.download_button(
                        "📕 Download PDF Report (.PDF)",
                        data=f_pdf.read(),
                        file_name=f"AssessMyApp_{res['origin'].replace('://', '_').replace(':', '_')}.pdf",
                        mime="application/pdf",
                        type="primary"
                    )
            else:
                st.caption("📕 PDF report could not be compiled.")
        except Exception as e:
            st.caption(f"📕 PDF generation note: {e}")


def build_markdown_report(res: dict) -> str:
    pages = res.get("pages_inspected", [])
    unassessed = res.get("unassessed_areas", [])
    verified = res.get("what_we_verified", [])
    positives = res.get("positive_observations", [])
    issues = res.get("issues_observed", [])
    unassessed_topics = res.get("what_could_not_be_assessed", [])
    next_steps = res.get("next_steps_required_access", [])

    md = f"""# ATLAS-Risk: 'Assess My App' Public Review Report
**Target URL:** `{res['target_url']}`  
**Inspected At:** `{res['inspected_at']}`  
**Scope:** Bounded Public Review ({len(pages)} pages inspected, {len(unassessed)} protected areas identified)  

## Executive Summary
- **Accessible Pages Inspected:** {len(pages)}
- **Verified Positive Claims:** {len(verified)}
- **Issues Observed:** {len(issues)}
- **Protected / Unassessed Sections:** {len(unassessed)} (Requires credentials; not a failure)

---

## 1. What We Could Verify (Traceable Evidence)
| Domain | Item Evaluated | Traceable Evidence | Status |
| :--- | :--- | :--- | :--- |
"""
    for v in verified:
        md += f"| {v['domain']} | {v['item']} | {v['evidence']} | {v['status']} |\n"

    md += "\n## 2. Positive Observations\n"
    for pos in positives:
        md += f"- **[{pos['area']}]** {pos['observation']} (Evidence: `{pos['evidence']}`)\n"

    md += "\n## 3. Issues Observed & Practical Fixes\n"
    if not issues:
        md += "- Zero public issues detected.\n"
    else:
        for idx, iss in enumerate(issues, 1):
            md += f"### {idx}. [{iss['domain']}] {iss['issue']}\n"
            md += f"- **Evidence:** `{iss['evidence']}`\n"
            md += f"- **Practical Fix:** `{iss['fix']}`\n\n"

    md += "\n## 4. What We Could Not Assess & Why\n"
    for un in unassessed_topics:
        md += f"- **Area:** `{un['area']}`\n"
        md += f"  - *Reason:* {un['reason']}\n"
        md += f"  - *Required Access:* {un['required_access']}\n"

    md += "\n## 5. Next Steps & Required Access for Deeper Checks\n"
    for step in next_steps:
        md += f"- {step}\n"

    return md
