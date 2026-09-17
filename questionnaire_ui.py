"""
Interactive Questionnaire & New AI System Assessment UI Module (v0.4.0-dev).
Renders 24-question form across 7 sections, system profile, threat mapping,
active-testing authorization safety gate, execution mode selection (Simulated vs Live Authorized Target),
Live Target Scope Verification, 3 explicit verdict status displays, and post-remediation retest workflow.
"""

import streamlit as st
import json
import os
from typing import Dict, Any, List

from questionnaire import QUESTIONNAIRE_SECTIONS, build_system_profile
from engines.threat_mapper import ThreatMapper
from engines.test_runner import TestRunner
from engines.evaluation_engine import EvaluationEngine
from engines.evidence_evaluator_v04 import EvidenceEvaluatorV04
from engines.baseline_comparator import BaselineComparator
from engines.persistence_engine import PersistenceEngine
from reports.report_v02 import ExperimentReportGenerator


def render_interactive_questionnaire_app():
    st.title("🛡️ ATLAS-Risk v0.4.0-beta: New AI System Assessment")
    st.caption("Interactive Application Security Assessment Workflow (v0.4.0-beta) — Questionnaire → Profile → Threat Applicability → Safety Gate → Active Test → Multi-Attribute Verdicts → Retest")

    mapper = ThreatMapper()

    # Form State Management
    if "form_answers" not in st.session_state:
        st.session_state.form_answers = {}

    # Top Mode Selection Header
    st.markdown("### ⚙️ Select Target Execution Mode")
    exec_mode = st.radio(
        "Execution Assessment Mode",
        [
            "SIMULATED (Static Probe Harness)",
            "LIVE AUTHORIZED TARGET (HTTP REST API)"
        ],
        index=0,
        horizontal=True,
        help="Simulated mode evaluates target responses against reference benchmark vectors. Live Authorized Target sends controlled static probes to your live endpoint."
    )

    if exec_mode == "SIMULATED (Static Probe Harness)":
        st.info("🔬 **Mode Status: SIMULATED (Static Probe Harness)** — Probes execute against reference benchmark target response vectors without sending external network traffic.")
    else:
        st.warning("⚡ **Mode Status: LIVE AUTHORIZED TARGET (HTTP REST API)** — Controlled static probes will target an authorized external endpoint. Scope verification is mandatory.")

    st.markdown("---")
    st.subheader("📋 Step 1: Interactive System Profile Questionnaire")
    st.markdown("Complete the 7-part form below to profile your AI application's architecture, data boundaries, and safeguards.")

    with st.form("interactive_assessment_form"):
        form_values = {}

        for sec in QUESTIONNAIRE_SECTIONS:
            with st.expander(f"{sec['icon']} {sec['title']}", expanded=True):
                cols = st.columns(2)
                for i, q in enumerate(sec["questions"]):
                    col = cols[i % 2]
                    q_id = q["id"]
                    q_type = q["type"]
                    label = q["label"]
                    help_text = q.get("help", "")
                    default_val = q.get("default", "")

                    if q_type == "text":
                        form_values[q_id] = col.text_input(label, value=default_val, help=help_text)
                    elif q_type == "textarea":
                        form_values[q_id] = col.text_area(label, value=default_val, help=help_text)
                    elif q_type == "selectbox":
                        opts = q.get("options", [])
                        idx = opts.index(default_val) if default_val in opts else 0
                        form_values[q_id] = col.selectbox(label, options=opts, index=idx, help=help_text)
                    elif q_type == "radio":
                        opts = q.get("options", [])
                        idx = opts.index(default_val) if default_val in opts else 0
                        form_values[q_id] = col.radio(label, options=opts, index=idx, help=help_text)

        submitted = st.form_submit_button("🔍 Evaluate System Profile & Threat Applicability")

    if submitted or "system_profile" in st.session_state:
        if submitted:
            st.session_state.form_answers = form_values
            st.session_state.system_profile = build_system_profile(form_values)
            # Clear previous assessment results on new profile submission to prevent mixing findings
            for key in ["v04_exp_rec", "v04_eval_metrics", "v04_verdict_records", "v04_verdict_counts", "v04_exec_mode"]:
                if key in st.session_state:
                    del st.session_state[key]

        profile = st.session_state.system_profile
        meta = profile["system_metadata"]
        q_prof = profile["questionnaire_profile"]
        gov = profile["governance_and_safety"]

        st.markdown("---")
        st.subheader(f"📊 Step 2: Generated System Profile — {meta['name']}")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("System Name", meta["name"])
        c2.metric("Exposure", q_prof["q1_target_exposure"])
        c3.metric("Business Impact", meta["business_impact"])
        c4.metric("Active Test Auth", "APPROVED ✅" if gov["active_testing_authorized"] else "UNAUTHORIZED 🛑")

        with st.expander("📄 View Generated System Profile JSON", expanded=False):
            st.json(profile)

        # Threat Applicability Evaluation
        applicability = mapper.evaluate_applicability(q_prof)
        st.subheader("🎯 Step 3: Threat Applicability & OWASP / MITRE ATLAS Mapping")

        app_cols = st.columns(2)
        applicable_threats = [a for a in applicability if a["is_applicable"]]
        non_applicable_threats = [a for a in applicability if not a["is_applicable"]]

        with app_cols[0]:
            st.markdown(f"### 🔴 Applicable Threat Families ({len(applicable_threats)})")
            for a in applicable_threats:
                st.error(
                    f"**{a['threat_family']}** ({a['owasp_code']} / {a['atlas_code']})\n\n"
                    f"• **OWASP Category:** {a['owasp']['name']}\n\n"
                    f"• **MITRE ATLAS:** {a['atlas']['name']}\n\n"
                    f"• **Rationale:** {a['rationale']}"
                )

        with app_cols[1]:
            st.markdown(f"### 🟢 Non-Applicable Threat Vectors ({len(non_applicable_threats)})")
            for a in non_applicable_threats:
                st.success(
                    f"**{a['threat_family']}** ({a['owasp_code']} / {a['atlas_code']})\n\n"
                    f"• **Rationale:** {a['rationale']}"
                )

        st.markdown("---")
        st.subheader("⚠️ Step 4: Active Testing Authorization & Safety Gating")

        is_authorized = gov["active_testing_authorized"]

        if not is_authorized:
            st.warning(
                "🛑 **ACTIVE SAFETY GATE ENGAGED: Unauthorized Active Probing Blocked**\n\n"
                "You selected **'No - Profiling & Analysis Only'** for active testing authorization. "
                "ATLAS-Risk has generated your Threat Applicability Profile and OWASP/MITRE Mappings above, "
                "but active prompt injection and attack execution probes are strictly **BLOCKED** to prevent unauthorized penetration testing."
            )
            
            # Dynamic High-Priority Security Control Recommendations based on applicable threats only
            dynamic_recs = []
            if any(a['threat_family'] in ['Direct Prompt Injection', 'Indirect Prompt Injection', 'Guardrail Bypass'] for a in applicable_threats):
                dynamic_recs.append("1. **Prompt Injection Safeguards:** Implement strict system prompt delimiters and input sanitization.")
            if any(a['threat_family'] == 'System Prompt Leakage' for a in applicable_threats):
                dynamic_recs.append("2. **System Prompt Redaction:** Redact confidential developer prompt instructions.")
            if any(a['threat_family'] == 'Sensitive Information Disclosure' for a in applicable_threats):
                dynamic_recs.append("3. **Sensitive Data Filtering:** Enforce contextual PII redaction and credential masking.")
            if any(a['threat_family'] == 'RAG & Vector Store Risk' for a in applicable_threats):
                dynamic_recs.append("4. **Indirect RAG Context Filtering:** Deploy document-level RBAC and sanitization filters on vector retrieval.")
            if any(a['threat_family'] == 'Excessive Agency & Tool Misuse' for a in applicable_threats):
                dynamic_recs.append("5. **Agent Excessive Agency Guardrails:** Enforce mandatory Human-in-the-Loop approval for write/delete tools.")
            if any(a['threat_family'] == 'Improper Output Handling' for a in applicable_threats):
                dynamic_recs.append("6. **Output Encoding & Sanitization:** Encode output strings before rendering to prevent injection.")
            if any(a['threat_family'] == 'Unbounded Consumption' for a in applicable_threats):
                dynamic_recs.append("7. **Unbounded Consumption Budgeting:** Set hard per-user API rate limits and token spend caps.")

            if not dynamic_recs:
                dynamic_recs = ["1. **Baseline System Monitoring:** Maintain standard logging and security auditing."]

            st.subheader("📋 Recommended Security Controls & Passive Assessment Summary")
            st.info("### High-Priority Security Control Recommendations:\n\n" + "\n".join(dynamic_recs))

            # Downloadable Passive Assessment Report
            passive_md = (
                f"# 🛡️ PASSIVE ASSESSMENT REPORT (v0.4.0-beta)\n\n"
                f"**System Name:** `{meta['name']}`  \n"
                f"**Business Impact:** `{meta['business_impact']}`  \n"
                f"**Target Exposure:** `{q_prof['q1_target_exposure']}`  \n"
                f"**Assessment Status:** `PASSIVE PROFILING ONLY (Active Probing Unauthorized)`\n\n"
                f"---\n\n"
                f"## 🔴 Applicable Threat Families ({len(applicable_threats)})\n"
                + "\n".join([f"- **{a['threat_family']}** ({a['owasp_code']} / {a['atlas_code']}): {a['rationale']}" for a in applicable_threats]) +
                f"\n\n## 🟢 Excluded / Non-Applicable Threat Vectors ({len(non_applicable_threats)})\n"
                + "\n".join([f"- **{a['threat_family']}** ({a['owasp_code']} / {a['atlas_code']}): {a['rationale']}" for a in non_applicable_threats]) +
                f"\n\n---\n\n"
                f"## 📋 Recommended Security Controls\n"
                + "\n".join(dynamic_recs) + "\n"
            )
            st.download_button(
                label="📥 Download PASSIVE ASSESSMENT REPORT (.md)",
                data=passive_md,
                file_name=f"PASSIVE_ASSESSMENT_REPORT_{meta['name'].replace(' ', '_')}.md",
                mime="text/markdown"
            )
        else:
            st.success(
                "✅ **ACTIVE TESTING AUTHORIZED:** Explicit authorization confirmed in system profile questionnaire."
            )

            # Pre-execution Static Probe Preview List
            test_runner = TestRunner()
            app_map_family = {a["threat_family"]: a for a in applicability}
            app_map_owasp = {a["owasp_code"]: a for a in applicability}

            with st.expander("🔍 View Pre-Execution Static Assessment Probe Preview (Audit List)", expanded=False):
                st.markdown(
                    "**Assessment Scope, Resource Limits, & Safety Assurance:**\n\n"
                    "• **Repeats Per Test:** 3 iterations (Simulated Mode) / 1 iteration (Live HTTP Mode)\n\n"
                    "• **Enforced Resource Limits:** 5-second HTTP request timeout limit enforced per live probe execution\n\n"
                    "• **Non-Destructive Safety Assurance:** `TEST-DOS-001` measures system token ceiling caps via standard query prompts without network socket DoS, payload fuzzing, or destructive attacks."
                )
                st.markdown("---")
                st.markdown("The following static, version-controlled probes will be evaluated against applicable threats:")
                for idx, tc in enumerate(test_runner.test_cases, 1):
                    tf = tc.get("threat_family", "")
                    owasp_code = tc.get("expected_owasp", "LLM01")
                    app_info = app_map_family.get(tf) or app_map_owasp.get(owasp_code, {"is_applicable": True})
                    is_app = app_info.get("is_applicable", True)
                    status_str = "🔴 APPLICABLE (Will Execute)" if is_app else "🟢 EXCLUDED (Non-Applicable Vector)"
                    st.markdown(f"**Probe #{idx}:** `{tc['test_id']}` — {tc['name']} ({tc.get('expected_owasp', 'LLM01')} / {tc.get('expected_atlas', 'AML.T0051')}) — **{status_str}**")
                    st.caption(f"Exact Prompt Input Vector: `{tc.get('test_vector_prompt', '')}`")

            # Mode-specific gating UI
            can_execute = False
            live_target_url = ""

            if exec_mode == "LIVE AUTHORIZED TARGET (HTTP REST API)":
                st.markdown("### 🛡️ Live Target Scope Verification Card")
                st.markdown("To prevent unauthorized or destructive testing, confirm all 4 scope prerequisites below:")

                col_chk1, col_chk2 = st.columns(2)
                with col_chk1:
                    chk_auth = st.checkbox("1. Owner Authorization confirmed for target endpoint.")
                    chk_url = st.checkbox("2. Target URL specified & endpoint within approved boundaries.")
                with col_chk2:
                    chk_scope = st.checkbox("3. Probe Scope restricted to controlled static assessment inputs.")
                    chk_fuzz = st.checkbox("4. Static Test Suite confirmed (Zero zero-day/fuzzing/DoS payloads).")

                live_target_url = st.text_input("Active Target Endpoint URL", value=q_prof.get("app_url", "https://api.target.internal/v1/chat"))
                valid_url = bool(live_target_url.strip()) and (live_target_url.strip().startswith("http://") or live_target_url.strip().startswith("https://"))

                if chk_auth and chk_url and chk_scope and chk_fuzz and valid_url:
                    can_execute = True
                    st.success("✅ Scope Verification Complete: Live authorized assessment unlocked.")
                else:
                    if not valid_url:
                        st.warning("⚠️ Invalid Target URL: Please enter a valid HTTP or HTTPS endpoint URL.")
                    else:
                        st.warning("⚠️ Scope Verification Incomplete: Check all 4 boxes above to enable Live Authorized Assessment.")
            else:
                can_execute = True  # Simulated mode auto-unlocked when authorized

            button_label = "⚡ Execute Authorized Live Security Assessment" if exec_mode == "LIVE AUTHORIZED TARGET (HTTP REST API)" else "🚀 Execute Authorized Simulated Security Assessment"

            if can_execute and st.button(button_label):
                with st.spinner("Executing controlled test suite & evaluating multi-attribute evidence..."):
                    exp_id = f"ASSESS-{meta['name'].replace(' ', '-').upper()}-V04"
                    
                    if exec_mode == "LIVE AUTHORIZED TARGET (HTTP REST API)":
                        exp_rec = test_runner.run_live_http_experiment(
                            experiment_id=exp_id,
                            target_id="TARGET-USER-LIVE",
                            target_name=meta['name'],
                            target_endpoint_url=live_target_url,
                            configuration_variant="User Target Configuration",
                            questionnaire_answers=q_prof,
                            applicability_list=applicability,
                            framework_versions=mapper.framework_versions,
                            repeats_per_test=1
                        )
                    else:
                        exp_rec = test_runner.run_experiment(
                            experiment_id=exp_id,
                            target_id="TARGET-USER-ASSESS",
                            target_name=meta['name'],
                            target_type="stochastic_llm",
                            configuration_variant="User Target Configuration",
                            questionnaire_answers=q_prof,
                            applicability_list=applicability,
                            framework_versions=mapper.framework_versions,
                            repeats_per_test=3
                        )

                    # Multi-Attribute Evidence Evaluation (v0.4.0-dev)
                    verdict_records = []
                    v_obs = 0
                    v_no_obs = 0
                    v_inconc = 0

                    for ex in exp_rec.execution_records:
                        tc = next((t for t in test_runner.test_cases if t["test_id"] == ex.test_id), {})
                        
                        target_type_str = "stochastic_llm"
                        if "tool" in ex.test_id.lower() or "agent" in ex.test_id.lower():
                            target_type_str = "agentic_application"
                        elif "rag" in ex.test_id.lower() or "indirect" in ex.test_id.lower():
                            target_type_str = "rag_application"

                        ret_ctx = getattr(ex, "retrieved_context", tc.get("simulated_retrieved_context", ""))
                        tool_tr = getattr(ex, "tool_execution_result", tc.get("simulated_tool_execution_result", ""))

                        verdict, rationale, confidence = EvidenceEvaluatorV04.evaluate_evidence(
                            test_case=tc,
                            raw_response=ex.raw_response,
                            retrieved_context=ret_ctx,
                            tool_execution_result=tool_tr,
                            target_type=target_type_str
                        )

                        if verdict == "VULNERABILITY OBSERVED":
                            v_obs += 1
                        elif verdict == "NO VULNERABILITY OBSERVED":
                            v_no_obs += 1
                        else:
                            v_inconc += 1

                        verdict_records.append({
                            "execution": ex,
                            "verdict": verdict,
                            "rationale": rationale,
                            "confidence": confidence
                        })

                    eval_eng = EvaluationEngine()
                    eval_metrics = eval_eng.evaluate_experiment(exp_rec)

                    st.session_state.v04_exp_rec = exp_rec
                    st.session_state.v04_eval_metrics = eval_metrics
                    st.session_state.v04_verdict_records = verdict_records
                    st.session_state.v04_verdict_counts = {
                        "vulnerability_observed": v_obs,
                        "no_vulnerability_observed": v_no_obs,
                        "inconclusive": v_inconc
                    }
                    st.session_state.v04_exec_mode = exec_mode

            if "v04_exp_rec" in st.session_state and st.session_state.v04_exp_rec:
                exp_rec = st.session_state.v04_exp_rec
                eval_metrics = st.session_state.v04_eval_metrics
                verdict_records = st.session_state.v04_verdict_records
                verdict_counts = st.session_state.v04_verdict_counts
                saved_mode = st.session_state.get("v04_exec_mode", exec_mode)

                st.markdown("---")
                st.subheader("📈 Step 5: Active Testing Assessment Findings & Multi-Attribute Verdicts")

                st.markdown(f"**Execution Mode:** `{saved_mode}`")

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total Executions", eval_metrics["total_executions"])
                m2.metric("🔴 Vulnerabilities Observed", verdict_counts["vulnerability_observed"])
                m3.metric("🟢 Safe / Blocked", verdict_counts["no_vulnerability_observed"])
                m4.metric("⚠️ Inconclusive / Review", verdict_counts["inconclusive"])

                st.subheader("🔎 Multi-Attribute Evidence Evaluation Trace")
                for vr in verdict_records:
                    ex = vr["execution"]
                    v_label = vr["verdict"]
                    rationale = vr["rationale"]
                    conf = vr["confidence"]

                    if v_label == "VULNERABILITY OBSERVED":
                        badge_color = "error"
                        badge_icon = "🔴 VULNERABILITY OBSERVED"
                    elif v_label == "NO VULNERABILITY OBSERVED":
                        badge_color = "success"
                        badge_icon = "🟢 NO VULNERABILITY OBSERVED"
                    else:
                        badge_color = "warning"
                        badge_icon = "⚠️ INCONCLUSIVE / MANUAL REVIEW REQUIRED"

                    with st.expander(f"{badge_icon} — {ex.test_name} ({ex.test_id})", expanded=True):
                        st.markdown(f"**Verdict:** `{v_label}` (Confidence: `{conf*100:.0f}%`)")
                        st.markdown(f"• **Evaluator Rationale:** {rationale}")
                        st.markdown("• **Prompt Input:**")
                        st.code(ex.prompt_input)
                        st.markdown("• **Raw Target Response:**")
                        st.code(ex.raw_response)
                        st.markdown(f"• **Risk Score:** `{ex.computed_risk_score:.4f}` ({ex.severity_rating})")

                # Step 5 Downloadable Report
                report_prefix = "SIMULATED ASSESSMENT REPORT" if "SIMULATED" in saved_mode else "LIVE ASSESSMENT REPORT"
                active_report_md = (
                    f"# 🛡️ {report_prefix} (v0.4.0-beta)\n\n"
                    f"**System Name:** `{meta['name']}` | **Execution Mode:** `{saved_mode}`  \n"
                    f"**Total Executions:** `{eval_metrics['total_executions']}` | **Vulnerabilities Observed:** `{verdict_counts['vulnerability_observed']}`  \n"
                    f"**Safe / Blocked:** `{verdict_counts['no_vulnerability_observed']}` | **Inconclusive / Review:** `{verdict_counts['inconclusive']}`\n\n"
                    f"---\n\n"
                    f"## 📊 Multi-Attribute Findings Summary\n\n"
                    + "\n".join([
                        f"### {vr['verdict']} — {vr['execution'].test_name} ({vr['execution'].test_id})\n"
                        f"- **OWASP / ATLAS:** {vr['execution'].owasp_mapping.get('id', '')} / {vr['execution'].atlas_mapping.get('id', '')}\n"
                        f"- **Rationale:** {vr['rationale']}\n"
                        f"- **Prompt Input:** `{vr['execution'].prompt_input}`\n"
                        f"- **Raw Target Response:** `{vr['execution'].raw_response}`\n"
                        f"- **Risk Score:** `{vr['execution'].computed_risk_score:.4f}` ({vr['execution'].severity_rating})\n"
                        for vr in verdict_records
                    ]) + "\n"
                )
                st.download_button(
                    label=f"📥 Download {report_prefix} (.md)",
                    data=active_report_md,
                    file_name=f"{report_prefix.replace(' ', '_')}_{meta['name'].replace(' ', '_')}.md",
                    mime="text/markdown"
                )

                # Step 6: Retest & Post-Mitigation Verification Workflow
                st.markdown("---")
                st.subheader("🔁 Step 6: Post-Mitigation Verification Workflow")
                
                retest_tabs = st.tabs(["🧪 SIMULATED MITIGATION RETEST", "⚡ LIVE RETEST (Post-Remediation)"])

                with retest_tabs[0]:
                    st.warning(
                        "ℹ️ **SIMULATED MITIGATION RETEST DISCLAIMER:**\n\n"
                        "Simulated mitigation retests evaluate expected safeguard efficacy against reference hardened profiles. "
                        "ATLAS-Risk does **NOT** automatically modify, deploy code patches to, or alter customer live endpoints."
                    )

                    if st.button("🚀 Run Hardened Reference Simulation Retest"):
                        with st.spinner("Evaluating hardened reference configuration..."):
                            hardened_exp = test_runner.run_experiment(
                                experiment_id=f"RETEST-SIM-{meta['name'].replace(' ', '-').upper()}",
                                target_id="TARGET-USER-HARDENED",
                                target_name=f"{meta['name']} (Hardened)",
                                target_type="stochastic_llm",
                                configuration_variant="Hardened Safeguard Configuration",
                                questionnaire_answers=q_prof,
                                applicability_list=applicability,
                                framework_versions=mapper.framework_versions,
                                repeats_per_test=3
                            )
                            hardened_metrics = EvaluationEngine().evaluate_experiment(hardened_exp)
                            st.success(
                                f"✅ **SIMULATED MITIGATION RETEST COMPLETE:**\n\n"
                                f"• Initial Vulnerabilities: {eval_metrics['successful_attacks']}\n\n"
                                f"• Post-Mitigation Vulnerabilities: {hardened_metrics['successful_attacks']}\n\n"
                                f"• Attack Success Rate Delta: {eval_metrics['attack_success_rate']*100:.1f}% ➡️ {hardened_metrics['attack_success_rate']*100:.1f}%"
                            )

                with retest_tabs[1]:
                    st.info(
                        "⚡ **LIVE RETEST (Customer Post-Remediation Verification):**\n\n"
                        "After deploying system prompt guardrails, RAG document filters, or agent authorization checks to your live target endpoint, "
                        "confirm all 4 scope verification checks below to re-assess live posture."
                    )

                    st.markdown("### 🛡️ Live Retest Scope Verification Card")
                    col_rt1, col_rt2 = st.columns(2)
                    with col_rt1:
                        rt_chk1 = st.checkbox("1. Owner Authorization confirmed for remediated target endpoint.")
                        rt_chk2 = st.checkbox("2. Remediated Target URL specified & endpoint within approved boundaries.")
                    with col_rt2:
                        rt_chk3 = st.checkbox("3. Probe Scope restricted to controlled static assessment inputs.")
                        rt_chk4 = st.checkbox("4. Static Test Suite confirmed (Zero zero-day/fuzzing/DoS payloads).")

                    retest_url = st.text_input("Remediated Target Endpoint URL", value=q_prof.get("app_url", "https://api.target.internal/v1/chat-remediated"))
                    valid_retest_url = bool(retest_url.strip()) and (retest_url.strip().startswith("http://") or retest_url.strip().startswith("https://"))

                    can_live_retest = rt_chk1 and rt_chk2 and rt_chk3 and rt_chk4 and valid_retest_url

                    if not can_live_retest:
                        if not valid_retest_url:
                            st.warning("⚠️ Invalid Remediated Target URL: Please enter a valid HTTP or HTTPS endpoint URL.")
                        else:
                            st.warning("⚠️ Scope Verification Incomplete: Check all 4 boxes above to enable Live Authorized Retest.")

                    if st.button("⚡ Execute Live Authorized Retest", disabled=not can_live_retest):
                        with st.spinner("Executing post-remediation live probe suite against target..."):
                            live_retest_exp = test_runner.run_live_http_experiment(
                                experiment_id=f"RETEST-LIVE-{meta['name'].replace(' ', '-').upper()}",
                                target_id="TARGET-USER-LIVE-RETEST",
                                target_name=f"{meta['name']} (Live Retest)",
                                target_endpoint_url=retest_url,
                                configuration_variant="Live Post-Remediation Target",
                                questionnaire_answers=q_prof,
                                applicability_list=applicability,
                                framework_versions=mapper.framework_versions,
                                repeats_per_test=1
                            )
                            retest_metrics = EvaluationEngine().evaluate_experiment(live_retest_exp)
                            st.success(
                                f"✅ **LIVE RETEST COMPLETE on {retest_url}:**\n\n"
                                f"• Verified Post-Remediation Breach Count: {retest_metrics['successful_attacks']}\n\n"
                                f"• Remediated Attack Success Rate: {retest_metrics['attack_success_rate']*100:.1f}%"
                            )
