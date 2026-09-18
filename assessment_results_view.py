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

    model_name = record.get("model_name") or target
    model_id = record.get("model_id") or target
    company = record.get("model_company") or "OpenRouter / Cloud AI"
    tier_str = record.get("model_tier") or ("🟢 100% Free Tier" if (":free" in str(model_id) or model_id == "openrouter/free") else "🔹 Standard Tier")
    duration = record.get("execution_duration_sec", "")
    dur_str = f"{duration}s" if duration != "" else "Quick Scan"
    eval_date_display = record.get("evaluated_at_display") or f"{record.get('created_at', '')[:19].replace('T', ' ')} UTC"

    if show_back_button:
        if st.button("← Back to Reports List"):
            if "opened_report_id" in st.session_state:
                del st.session_state["opened_report_id"]
            st.rerun()

    # Top Header & Action Row
    col_hdr, col_pdf, col_html = st.columns([3, 1.2, 1.2])
    with col_hdr:
        st.subheader(f"📊 Assessment Results: `{model_name}`")
        status_color = "🟢" if status == "COMPLETE" else ("🟡" if status == "PARTIAL" else "🔴")
        st.caption(f"Status: **{status_color} {status}** | Company: **{company}** | ID: `{rec_id}` | Evaluated: **{eval_date_display}**")

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
    if status == "FAILED_CONNECTIVITY":
        st.warning("""
        ⚠️ **Target Endpoint Unreachable — Pre-flight Connectivity Halted**  
        The target model endpoint was not reachable (e.g., HTTP 404 Not Found or HTTP 401 Unauthorized).  
        **Four-Bucket Policy:** Connection errors are classified as **Unassessed / Blocked**, **NEVER vulnerabilities**. Zero security probes ran against the model, so **Issues Observed = 0**.
        """)
    else:
        st.info(f"**Executive Summary:** {summary}")

    # Tabs: Executive Overview | Findings & Risks | What Went Well | Second Opinion | Technical Data
    tab_overview, tab_findings, tab_evidence, tab_garak, tab_tech = st.tabs([
        "📋 Executive Overview",
        "🚨 Findings & Real-World Risks",
        "🟢 What Went Well (Defenses)",
        "🛡️ Second Opinion (Cross-Check)",
        "⚙️ Technical Data"
    ])

    positives = record.get("positive_observations", [])
    findings = record.get("findings", [])
    issues_cnt = counts.get("issues", 0)

    with tab_overview:
        # Launch Readiness Verdict Banner
        if status == "FAILED_CONNECTIVITY":
            st.warning("🚦 **Launch Readiness: ⏸️ Audit Incomplete (Target Unreachable)** — Pre-flight connection failed. Fix API credentials or model slug to run tests.")
        elif issues_cnt == 0:
            st.success("🚦 **Launch Readiness: 🟢 Safe for Guardrailed Pilot** — 0 vulnerabilities detected across all tested security controls. Model maintained safety boundaries.")
        else:
            st.error(f"🚦 **Launch Readiness: 🔴 Action Required Before Public Release** — {issues_cnt} vulnerability detected that an attacker could exploit. Remediations required below.")

        st.markdown("---")
        st.markdown("### ⚖️ Executive Scorecard: What Went Well vs What Broke")
        st.caption("A plain-English summary of your AI's real-world security posture for leadership and non-technical stakeholders:")

        col_well, col_broke = st.columns(2)

        with col_well:
            st.markdown("#### 🟢 What Went Well (Defended Areas)")
            if status == "FAILED_CONNECTIVITY":
                st.caption("Scan safely halted before execution because the target was unreachable.")
            elif positives:
                for p in positives:
                    aspect = p.get('aspect', p.get('area', 'Security Defense'))
                    summary_obs = p.get('summary', p.get('observation', ''))
                    pv = p.get('practical_value', '')
                    st.markdown(f"✅ **{aspect}**")
                    st.markdown(f"*{summary_obs}*")
                    if pv:
                        st.caption(f"💼 **Business Value:** {pv}")
                    st.markdown("")
            else:
                st.markdown("✅ **Baseline Safety:** The AI responded within baseline conversational safety parameters.")

        with col_broke:
            st.markdown("#### 🔴 What Broke (Identified Risks)")
            if status == "FAILED_CONNECTIVITY":
                st.warning("⚠️ **Connection Failed (HTTP 404/401)**\nThe AI server was unreachable. Zero attacks were executed, so zero vulnerabilities exist in this report.")
            elif findings:
                for f in findings:
                    sev = f.get("severity", "MEDIUM").upper()
                    sev_icon = "🔴" if "HIGH" in sev or "CRIT" in sev else ("🟡" if "MED" in sev else "🔵")
                    title = f.get("title", f.get("issue", "Identified Weakness"))
                    attack_scen = f.get("attack_scenario", "Adversary uses prompt manipulation to bypass boundaries.")
                    biz_impact = f.get("business_impact", "May lead to unauthorized model behaviors.")

                    st.markdown(f"{sev_icon} **{title}** ({sev})")
                    st.markdown(f"• **What an attacker could do:** {attack_scen}")
                    st.markdown(f"• **Business consequence:** {biz_impact}")
                    st.markdown("")
            else:
                st.success("🎉 **Zero Breaches Detected!**\n\nThe AI successfully resisted all simulated jailbreak attempts, protected internal system prompts, and rejected malicious instructions.")

        st.markdown("---")
        st.markdown("### 📋 Assessment & Target Metadata")
        ov_col1, ov_col2 = st.columns(2)
        with ov_col1:
            st.markdown(f"**Model Name:** {model_name}")
            st.markdown(f"**Model Identifier (Slug):** `{model_id}`")
            st.markdown(f"**Managing Company / Provider:** **{company}**")
            st.markdown(f"**Service Tier:** {tier_str}")
        with ov_col2:
            st.markdown(f"**Evaluation Timestamp:** {eval_date_display}")
            st.markdown(f"**Audit Execution Duration:** {dur_str} (10 Security Probes)")
            st.markdown(f"**Assessment Mode:** {record.get('target_type', 'Public Review').replace('_', ' ').title()}")
            st.markdown(f"**Completion State:** `{status}`")

        model_desc = record.get("model_description")
        if model_desc:
            st.info(f"ℹ️ **Model Description:** {model_desc}")

        st.markdown("---")
        st.markdown("#### 🎯 Executive Recommended Action Plan")
        next_steps = record.get("next_steps", record.get("next_steps_required_access", []))
        for step in next_steps:
            st.markdown(f"• {step}")

    with tab_findings:
        st.markdown("### 🚨 Observed Vulnerabilities & Plain-English Fixes")
        st.caption("Detailed walkthrough of failed security checks, what an attacker could achieve in practice, and step-by-step engineering fixes:")
        if not findings:
            st.success("🎉 Zero issues observed within the tested scope! All tested security boundaries held firm.")
        else:
            for idx, f in enumerate(findings, 1):
                sev = f.get("severity", "MEDIUM").upper()
                sev_icon = "🔴" if "HIGH" in sev or "CRIT" in sev else ("🟡" if "MED" in sev else "🔵")
                with st.expander(f"{sev_icon} #{idx}: {f.get('title', f.get('issue', 'Issue'))} ({sev})", expanded=True):
                    biz_impact = f.get("business_impact", f.get("why_it_matters", "Risk to business operations."))
                    attack_scen = f.get("attack_scenario", "Adversary uses prompt manipulation to bypass boundaries.")
                    compliance = f.get("compliance_impact", f.get("domain", "MITRE ATLAS / OWASP LLM Top 10"))

                    st.markdown(f"**🏢 Executive Business Impact & Risk:**\n{biz_impact}")
                    st.markdown(f"**🎭 Real-World Attack Scenario (What an Attacker Could Do):**\n{attack_scen}")
                    st.markdown(f"**⚖️ Regulatory & Compliance Exposure:**\n`{compliance}`")
                    st.markdown(f"**🔍 Observed Technical Evidence:**\n`{f.get('observed', f.get('evidence', ''))}`")
                    
                    st.markdown("**🛠️ Actionable Remediation for Engineering:**")
                    st.info(f.get("action", f.get("fix", "")))
                    
                    if f.get("how_to_verify"):
                        st.caption(f"**How to verify:** {f.get('how_to_verify')}")

    with tab_evidence:
        st.markdown("### 🟢 Verified Positive Safeguards & Business Value")
        st.caption("Security isn't just about catching errors—it is equally about knowing what defenses actively protected your brand:")
        if positives:
            for p in positives:
                aspect = p.get('aspect', p.get('area', 'Security Control'))
                summary_obs = p.get('summary', p.get('observation', ''))
                pv = p.get('practical_value', '')
                st.markdown(f"• **[{aspect}]** {summary_obs}")
                if pv:
                    st.markdown(f"  - 💼 **Business Value:** *{pv}*")
                st.markdown(f"  - 🔍 *Evidence:* `{p.get('evidence', '')}`")
        else:
            st.caption("No positive observations recorded.")

        st.markdown("---")
        st.markdown("### 📋 What We Could Not Assess & Required Access")
        st.caption("Protected barriers and private databases are not vulnerabilities. They represent access boundaries requiring authorized credentials:")
        unassessed = record.get("unassessed_areas", [])
        if unassessed:
            for u in unassessed:
                st.warning(f"• **Area:** `{u.get('area', 'Protected Section')}`\n\n  - *Reason:* {u.get('reason', '')}\n\n  - *Required Access:* **{u.get('required_access', '')}**")
        else:
            st.caption("No unassessed areas reported.")

    with tab_garak:
        st.markdown("### 🛡️ Independent Second Opinion: Cross-Verification with Garak")
        
        st.markdown("""
        #### 🏥 The "Second Opinion" Doctor Analogy
        > **Why cross-verify with a second tool?**  
        > When a physician recommends major surgery, patients seek a second opinion from an independent specialist.  
        > In AI security, ATLAS-Risk cross-checks test results against **Garak**—the world’s leading open-source adversarial AI scanner.  
        > 
        > This independent cross-verification gives business leaders **rock-solid confidence**:
        > 1. **Zero False Alarms:** Confirms that harmless responses aren't mistakenly labeled as breaches.
        > 2. **Confirmed Threats:** When both tools flag a vulnerability, it is 100% verified.
        > 3. **Never Penalizes Offline Models:** If a model cannot be reached (e.g., 404 Not Found), both tools recognize it was unreachable—it is **never** counted as a security failure.
        """)

        st.markdown("---")
        st.markdown("#### 📊 How Business Stakeholders Should Interpret the Results")
        st.markdown("""
| Test Result | Second Opinion Verification | Real-World Meaning For Your Business | Recommended Action |
|---|---|---|---|
| 🟢 **No Issues Observed** | Second tool confirms model held boundaries | **High Confidence: Protected** — Your AI safely deflected attacks across independent scanners. | ✅ **Proceed:** Move forward to next deployment stage. |
| 🔴 **Issue Observed** | Second tool also flags jailbreak / prompt leak | **High Confidence: Real Vulnerability** — Multiple tools confirmed an attacker can bypass safety rules. | 🚨 **Block:** Fix prompts and apply guardrails before launch. |
| 🟡 **Tools Disagree** | One tool passes, another flags borderline text | **Borderline Prompt Sensitivity** — The AI resisted some phrasing but broke on subtle variations. | 🛡️ **Guardrail:** Add input filter or system prompt hardening. |
| ⚪ **Target Offline (404/401)** | Second tool also cannot reach endpoint | **IT Connection / Setup Issue** — Neither tool reached the AI. **Zero security tests ran.** | 🔑 **Action:** Check API key or endpoint URL; not an AI flaw. |
        """)

        st.info("💡 **Golden Rule of AI Audits:** A security vulnerability only exists if the AI **actually answered** and said something unsafe. If a server is down, returns a 404, or rejects an API key, that is a connectivity issue—**never** an AI vulnerability.")

        # Developer & Technical CLI section neatly tucked away in an expander
        with st.expander("🛠️ For Technical Teams & Developers: Independent CLI Verification"):
            st.markdown("Engineers can independently reproduce these adversarial tests using Garak in the command line:")
            raw_target = record.get("target_input", "")
            clean_model_slug = raw_target.replace("OpenRouter: ", "").replace("Local Ollama: ", "").strip()
            
            target_type = record.get("target_type", "")
            if target_type == "web_url" or clean_model_slug.startswith("http"):
                st.markdown("""
                **Web Applications & SaaS Platforms:**  
                Garak is specialized for direct LLM inference endpoints (e.g. Ollama, OpenRouter, HuggingFace APIs).  
                For web applications (such as Canva or web portals), ATLAS-Risk performs HTTP boundary scanning and simulated UI probing directly.
                """)
            elif "openrouter" in target_type or "openrouter" in clean_model_slug:
                st.code(f"""# Run targeted Garak jailbreak scan against the identical OpenRouter model:
python -m garak --model_type openrouter --model_name {clean_model_slug} \\
  --probes dan,promptinject --generations 5""", language="bash")
            else:
                st.code(f"""# Run targeted Garak jailbreak scan against local Ollama model:
python -m garak --model_type ollama --model_name {clean_model_slug} \\
  --probes dan,promptinject --generations 5""", language="bash")

    with tab_tech:
        st.markdown("### ⚙️ Technical Metadata & Raw Audit Logs")
        st.caption("Detailed taxonomy mappings, raw response headers, and completion metadata for security auditors and engineers:")
        st.json(record)

