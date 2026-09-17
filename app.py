"""
Main Streamlit Application Entry Point for ATLAS-Risk.
Supports switching between preserved v0.1 POC and v0.2 Research Experiment Platform.
"""

import streamlit as st
import json
import os
from datetime import datetime, timezone

from app_v01 import render_v01_app
from questionnaire_ui import render_interactive_questionnaire_app
from local_ai_testing_ui import render_local_ai_testing_tab
from executive_report_ui import render_executive_report_tab
from assess_my_app_ui import render_assess_my_app_tab
from engines.threat_mapper import ThreatMapper
from engines.test_runner import TestRunner
from engines.evaluation_engine import EvaluationEngine
from engines.baseline_comparator import BaselineComparator
from reports.report_v02 import ExperimentReportGenerator


st.set_page_config(
    page_title="ATLAS-Risk Security Platform",
    page_icon="🛡️",
    layout="wide"
)


def load_target_configs() -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "data", "target_configs.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f).get("target_configurations", {})


def load_benchmark_ground_truth() -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "data", "benchmark_catalogue.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
        return {
            t["test_id"]: {
                "expected_vulnerable": t.get("expected_vulnerable", True),
                "expected_applicable": t.get("expected_applicable", True)
            }
            for t in data.get("test_cases", [])
        }


def render_v02_research_app():
    st.title("🔬 ATLAS-Risk Research v0.2: Experiment Platform")
    st.caption("Reproducible Experiment Platform for LLM Threat Mapping, Ground-Truth Validation, & ASR Evaluation")

    targets = load_target_configs()
    mapper = ThreatMapper()
    gt_map = load_benchmark_ground_truth()

    # Sidebar Research Config
    st.sidebar.header("⚙️ Experiment Configuration")
    target_key = st.sidebar.selectbox(
        "Target Configuration Variant",
        options=list(targets.keys()),
        format_func=lambda k: f"{targets[k]['name']} ({targets[k]['target_type']})"
    )
    target_cfg = targets[target_key]

    repeats = st.sidebar.slider(
        "Repeats Per Test (N Samples)",
        min_value=1,
        max_value=10,
        value=5 if target_cfg["target_type"] == "stochastic_llm" else 1,
        help="Deterministic benchmarks mark replays as 1 sample. Stochastic LLM targets run N sampling iterations for ASR."
    )

    exp_id = st.sidebar.text_input("Experiment ID", value=f"EXP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📜 Provenance & Disclaimers")
    st.sidebar.info(
        f"• **OWASP Version:** `OWASP LLM Top 10 2025`\n"
        f"• **ATLAS Version:** `MITRE ATLAS v4.0`\n"
        f"• **Scoring Method:** `poc_heuristic_v1` (v1.0.0)\n"
        f"• **Disclaimer:** *POC validation results — not evidence of general system accuracy.*"
    )

    if "current_experiment" not in st.session_state:
        st.session_state.current_experiment = None
    if "eval_metrics" not in st.session_state:
        st.session_state.eval_metrics = None
    if "baseline_comp" not in st.session_state:
        st.session_state.baseline_comp = None

    tabs = st.tabs([
        "🚀 1. Experiment Control",
        "📊 2. Confusion Matrix & Metrics",
        "⚖️ 3. Two-Layer Baseline Comparison",
        "🛡️ 4. Before vs After Mitigation",
        "📥 5. Export Dataset & Telemetry"
    ])

    # Tab 1: Experiment Harness
    with tabs[0]:
        st.subheader("Run Research Experiment")
        c1, c2 = st.columns([2, 3])
        with c1:
            st.markdown(f"**Target ID:** `{target_cfg['target_id']}`")
            st.markdown(f"**Target Name:** `{target_cfg['name']}`")
            st.markdown(f"**Target Type:** `{target_cfg['target_type']}`")
            st.markdown(f"**Hardened Configuration:** `{target_cfg['is_hardened']}`")
            st.write(target_cfg['description'])

        with c2:
            st.markdown("### Target Questionnaire System Profile")
            st.json(target_cfg["questionnaire_profile"])

        st.markdown("---")
        if st.button("▶️ Launch Research Experiment", type="primary"):
            app_list = mapper.evaluate_applicability(target_cfg["questionnaire_profile"])
            runner = TestRunner()
            
            exp = runner.run_experiment(
                experiment_id=exp_id,
                target_id=target_cfg["target_id"],
                target_name=target_cfg["name"],
                target_type=target_cfg["target_type"],
                configuration_variant="Hardened Safeguard" if target_cfg["is_hardened"] else "Vulnerable Baseline",
                questionnaire_answers=target_cfg["questionnaire_profile"],
                applicability_list=app_list,
                framework_versions=mapper.framework_versions,
                repeats_per_test=repeats
            )

            eval_engine = EvaluationEngine()
            eval_metrics = eval_engine.evaluate_experiment(exp)
            baseline_comp = BaselineComparator.compare_baselines(exp, app_list, gt_map)

            st.session_state.current_experiment = exp
            st.session_state.eval_metrics = eval_metrics
            st.session_state.baseline_comp = baseline_comp

            st.success(f"Experiment `{exp_id}` executed successfully! {eval_metrics['total_executions']} total test executions recorded.")

    # Tab 2: Confusion Matrix & Metrics
    with tabs[1]:
        st.subheader("Ground-Truth Benchmark Evaluation Metrics")
        if st.session_state.eval_metrics:
            m = st.session_state.eval_metrics
            
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Total Executions", m["total_executions"])
            c2.metric("Attack Success Rate (ASR)", f"{m['attack_success_rate'] * 100:.1f}%")
            c3.metric("Accuracy", f"{m['accuracy'] * 100:.1f}%")
            c4.metric("Precision", f"{m['precision'] * 100:.1f}%")
            c5.metric("F1 Score", f"{m['f1_score']:.4f}")

            st.markdown("---")
            st.markdown("### 🔲 Confusion Matrix Breakdown")
            col1, col2, col3, col4 = st.columns(4)
            col1.success(f"**True Positives (TP):** `{m['tp']}`")
            col2.info(f"**True Negatives (TN):** `{m['tn']}`")
            col3.warning(f"**False Positives (FP):** `{m['fp']}`")
            col4.error(f"**False Negatives (FN):** `{m['fn']}`")

            st.warning(f"⚠️ **Rigor Disclaimer:** {m['disclaimer']}")
        else:
            st.info("Launch an experiment in Tab 1 to view evaluation metrics.")

    # Tab 3: Two-Layer Baseline Comparison
    with tabs[2]:
        st.subheader("Two-Layer Baseline Comparison")
        if st.session_state.baseline_comp:
            comp = st.session_state.baseline_comp
            l1 = comp["layer_1_applicability_comparison"]
            l2 = comp["layer_2_detection_comparison"]

            st.markdown("### Layer 1: Threat Applicability Comparison")
            st.caption("Evaluates threat applicability prediction without test execution.")
            st.table([
                {
                    "Method": "Method A: Static Checklist (No Context)",
                    "Predicted Applicable": l1["method_a_static_checklist"]["applicable_threats_predicted"],
                    "False Positives": l1["method_a_static_checklist"]["false_positives"],
                    "Applicability Precision": f"{l1['method_a_static_checklist']['precision'] * 100:.1f}%"
                },
                {
                    "Method": "Method B: Questionnaire Context Rules",
                    "Predicted Applicable": l1["method_b_context_rules"]["applicable_threats_predicted"],
                    "False Positives": l1["method_b_context_rules"]["false_positives"],
                    "Applicability Precision": f"{l1['method_b_context_rules']['precision'] * 100:.1f}%"
                },
                {
                    "Method": "Method C: ATLAS-Risk Evidence Mode",
                    "Predicted Applicable": l1["method_c_atlas_risk"]["applicable_threats_predicted"],
                    "False Positives": l1["method_c_atlas_risk"]["false_positives"],
                    "Applicability Precision": f"{l1['method_c_atlas_risk']['precision'] * 100:.1f}%"
                }
            ])

            st.markdown("---")
            st.markdown("### Layer 2: Vulnerability Detection Comparison")
            st.caption("Evaluates empirical vulnerability detection accuracy against ground truth.")
            st.table([
                {
                    "Method": l2["method_a_static"]["name"],
                    "TP": l2["method_a_static"]["tp"], "FP": l2["method_a_static"]["fp"],
                    "FN": l2["method_a_static"]["fn"], "TN": l2["method_a_static"]["tn"],
                    "Precision": f"{l2['method_a_static']['precision'] * 100:.1f}%",
                    "Recall": f"{l2['method_a_static']['recall'] * 100:.1f}%",
                    "F1 Score": l2["method_a_static"]["f1_score"],
                    "Accuracy": f"{l2['method_a_static']['accuracy'] * 100:.1f}%"
                },
                {
                    "Method": l2["method_b_profile_rules"]["name"],
                    "TP": l2["method_b_profile_rules"]["tp"], "FP": l2["method_b_profile_rules"]["fp"],
                    "FN": l2["method_b_profile_rules"]["fn"], "TN": l2["method_b_profile_rules"]["tn"],
                    "Precision": f"{l2['method_b_profile_rules']['precision'] * 100:.1f}%",
                    "Recall": f"{l2['method_b_profile_rules']['recall'] * 100:.1f}%",
                    "F1 Score": l2["method_b_profile_rules"]["f1_score"],
                    "Accuracy": f"{l2['method_b_profile_rules']['accuracy'] * 100:.1f}%"
                },
                {
                    "Method": l2["method_c_atlas_risk"]["name"],
                    "TP": l2["method_c_atlas_risk"]["tp"], "FP": l2["method_c_atlas_risk"]["fp"],
                    "FN": l2["method_c_atlas_risk"]["fn"], "TN": l2["method_c_atlas_risk"]["tn"],
                    "Precision": f"{l2['method_c_atlas_risk']['precision'] * 100:.1f}%",
                    "Recall": f"{l2['method_c_atlas_risk']['recall'] * 100:.1f}%",
                    "F1 Score": l2["method_c_atlas_risk"]["f1_score"],
                    "Accuracy": f"{l2['method_c_atlas_risk']['accuracy'] * 100:.1f}%"
                }
            ])
        else:
            st.info("Launch an experiment in Tab 1 to view baseline comparison metrics.")

    # Tab 4: Before vs After Mitigation
    with tabs[3]:
        st.subheader("Before-vs-After Mitigation Testing Harness")
        st.markdown("Compares **Target A - Vulnerable Configuration** against **Target A - Hardened Configuration**:")

        if st.button("🧪 Run Paired Mitigation Experiment", type="primary"):
            runner = TestRunner()
            eval_engine = EvaluationEngine()

            # 1. Run Vulnerable Target
            v_cfg = targets["TARGET-DONKAI-VULN"]
            v_app = mapper.evaluate_applicability(v_cfg["questionnaire_profile"])
            exp_v = runner.run_experiment(
                experiment_id="EXP-PAIR-VULN",
                target_id=v_cfg["target_id"],
                target_name=v_cfg["name"],
                target_type=v_cfg["target_type"],
                configuration_variant="Vulnerable Baseline",
                questionnaire_answers=v_cfg["questionnaire_profile"],
                applicability_list=v_app,
                framework_versions=mapper.framework_versions,
                repeats_per_test=1
            )
            m_v = eval_engine.evaluate_experiment(exp_v)

            # 2. Run Hardened Target
            h_cfg = targets["TARGET-DONKAI-HARD"]
            h_app = mapper.evaluate_applicability(h_cfg["questionnaire_profile"])
            exp_h = runner.run_experiment(
                experiment_id="EXP-PAIR-HARD",
                target_id=h_cfg["target_id"],
                target_name=h_cfg["name"],
                target_type=h_cfg["target_type"],
                configuration_variant="Hardened Safeguard",
                questionnaire_answers=h_cfg["questionnaire_profile"],
                applicability_list=h_app,
                framework_versions=mapper.framework_versions,
                repeats_per_test=1
            )
            m_h = eval_engine.evaluate_experiment(exp_h)

            c1, c2, c3 = st.columns(3)
            c1.metric("Baseline ASR", f"{m_v['attack_success_rate'] * 100:.1f}%")
            c2.metric("Hardened ASR", f"{m_h['attack_success_rate'] * 100:.1f}%", f"{(m_h['attack_success_rate'] - m_v['attack_success_rate']) * 100:+.1f}% ASR Delta")
            c3.metric("Observed Vulnerability Reduction", f"{m_v['successful_attacks']} → {m_h['successful_attacks']}")

            st.success("Paired mitigation experiment complete!")

    # Tab 5: Dataset & Telemetry Export
    with tabs[4]:
        st.subheader("Research Dataset & Telemetry Export Center")
        if st.session_state.current_experiment:
            exp = st.session_state.current_experiment
            eval_m = st.session_state.eval_metrics
            base_c = st.session_state.baseline_comp

            report_md = ExperimentReportGenerator.generate_research_report(
                experiment=exp,
                eval_metrics=eval_m,
                baseline_comparison=base_c
            )
            csv_data = ExperimentReportGenerator.export_csv_dataset(exp)
            json_data = json.dumps(exp.to_dict(), indent=2)

            col1, col2, col3 = st.columns(3)
            with col1:
                st.download_button(
                    "📊 Export Research Dataset (.CSV)",
                    data=csv_data,
                    file_name=f"Dataset_{exp.experiment_id}.csv",
                    mime="text/csv"
                )
            with col2:
                st.download_button(
                    "📜 Export Evidence Telemetry (.JSON)",
                    data=json_data,
                    file_name=f"Evidence_{exp.experiment_id}.json",
                    mime="application/json"
                )
            with col3:
                st.download_button(
                    "📄 Export Research Report (.MD)",
                    data=report_md,
                    file_name=f"Report_{exp.experiment_id}.md",
                    mime="text/markdown"
                )

            st.markdown("---")
            st.markdown("### Research Report Preview")
            st.markdown(report_md)
        else:
            st.info("Launch an experiment in Tab 1 to enable dataset export.")


def main():
    mode = st.sidebar.radio(
        "Application Platform Mode",
        [
            "🌐 Assess My App (Public Review)",
            "📊 Executive Management Report",
            "🖥️ Local AI Testing (Ollama Live Model)",
            "🛡️ New AI System Assessment Mode (v0.4.0-beta)",
            "🔬 Research / Benchmark Mode (v0.3.0 Freeze)",
            "📜 v0.1 POC Baseline Mode"
        ]
    )
    st.sidebar.markdown("---")

    if "Assess My App" in mode:
        render_assess_my_app_tab()
    elif "Executive Management Report" in mode:
        render_executive_report_tab()
    elif "Local AI Testing" in mode:
        render_local_ai_testing_tab()
    elif "v0.4.0" in mode or "New AI System Assessment" in mode:
        render_interactive_questionnaire_app()
    elif "Research" in mode or "v0.2" in mode or "v0.3" in mode:
        render_v02_research_app()
    else:
        render_v01_app()


if __name__ == "__main__":
    main()
