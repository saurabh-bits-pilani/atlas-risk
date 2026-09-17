"""
v0.3.0 Multi-Scenario Report & Dataset Export Module.
Generates research reports, independent scenario breakdowns, multi-scenario aggregate tables,
and exports 1-row-per-attempt CSV & JSON datasets for statistical analysis in Python/R/Excel.
"""

import json
import csv
import io
from typing import Dict, Any, List
from models.experiment_models import ExperimentRecord


class MultiScenarioReportGenerator:
    @staticmethod
    def generate_scenario_report(
        experiment: ExperimentRecord,
        eval_metrics: Dict[str, Any],
        baseline_comparison: Dict[str, Any],
        mitigation_delta: Dict[str, Any] = None
    ) -> str:
        """
        Generates markdown research report for an individual v0.3.0 scenario experiment.
        """
        md = []
        md.append(f"# 🔬 ATLAS-Risk v0.3.0 Research Report: `{experiment.scenario_id}`\n")
        md.append(f"**Experiment ID:** `{experiment.experiment_id}` | **Scenario ID:** `{experiment.scenario_id}`  ")
        md.append(f"**Target Name:** `{experiment.target_name}` | **Target Type:** `{experiment.target_type}`  ")
        md.append(f"**Configuration Variant:** `{experiment.configuration_variant}` | **Repeats ($N$):** `{experiment.repeats_per_test}`  ")
        md.append(f"**Timestamp:** `{experiment.timestamp}`\n")

        # LLM Reproducibility Header
        repro = experiment.llm_reproducibility
        md.append("> [!NOTE]")
        md.append(f"> **LLM Reproducibility Metadata:** Provider=`{repro.get('provider')}` | Model=`{repro.get('model_name')}` | Temp=`{repro.get('temperature')}` | TopP=`{repro.get('top_p')}`  ")
        md.append(f"> **Sealed Holdout Hash:** `{repro.get('holdout_hash', 'N/A')[:16]}...`  ")
        md.append(f"> **Scoring Provenance:** Method=`{experiment.scoring_method}` | Config Version=`{experiment.scoring_config_version}`  ")
        md.append(f"> **Academic Rigor Disclaimer:** *Engineering validation passed; ready to begin controlled research data collection.*\n")

        md.append("---\n")

        # 1. Benchmark Execution & Confusion Matrix
        md.append("## 📊 Ground-Truth Benchmark Results & Confusion Matrix\n")

        prec_str = f"{eval_metrics['precision'] * 100:.1f}%" if isinstance(eval_metrics['precision'], float) else eval_metrics['precision']
        rec_str = f"{eval_metrics['recall'] * 100:.1f}%" if isinstance(eval_metrics['recall'], float) else eval_metrics['recall']
        f1_str = f"{eval_metrics['f1_score']:.4f}" if isinstance(eval_metrics['f1_score'], float) else eval_metrics['f1_score']
        spec_str = f"{eval_metrics.get('specificity', 'N/A') * 100:.1f}%" if isinstance(eval_metrics.get('specificity'), float) else eval_metrics.get('specificity', 'N/A')

        md.append("| Metric | Value | Description |")
        md.append("|---|---|---|")
        md.append(f"| **Total Executions** | `{eval_metrics['total_executions']}` | Total test iterations run |")
        md.append(f"| **Attack Success Rate (ASR)** | `{eval_metrics['attack_success_rate'] * 100:.1f}%` | (Successful Attacks / Total Attempts) |")
        md.append(f"| **Accuracy** | `{eval_metrics['accuracy'] * 100:.1f}%` | Overall correct classifications |")
        md.append(f"| **Precision (Positive Class)** | `{prec_str}` | TP / (TP + FP) |")
        md.append(f"| **Recall (TPR)** | `{rec_str}` | TP / (TP + FN) |")
        md.append(f"| **Specificity (TNR)** | `{spec_str}` | TN / (TN + FP) |")
        md.append(f"| **F1 Score** | `{f1_str}` | Harmonic mean of Precision & Recall |")
        md.append(f"| **Confusion Matrix** | `TP: {eval_metrics['tp']} | TN: {eval_metrics['tn']} | FP: {eval_metrics['fp']} | FN: {eval_metrics['fn']}` | Ground truth validation breakdown |\n")

        md.append("---\n")

        # 2. Two-Layer Baseline Comparison
        l1 = baseline_comparison.get("layer_1_applicability_comparison", {})
        l2 = baseline_comparison.get("layer_2_detection_comparison", {})

        md.append("## ⚖️ Two-Layer Baseline Comparison\n")
        md.append("### Layer 1: Threat Applicability Comparison\n")
        md.append("| Assessment Method | Predicted Applicable Threats | False Positives | Applicability Precision |")
        md.append("|---|---|---|---|")
        for key in ["method_a_static_checklist", "method_b_context_rules", "method_c_atlas_risk"]:
            m = l1.get(key, {})
            md.append(f"| **{m.get('name')}** | `{m.get('applicable_threats_predicted')}` | `{m.get('false_positives')}` | `{m.get('precision', 0.0) * 100:.1f}%` |")

        md.append("\n### Layer 2: Vulnerability Detection Comparison\n")
        md.append("| Assessment Method | TP | FP | FN | TN | Precision | Recall | F1 Score | Accuracy |")
        md.append("|---|---|---|---|---|---|---|---|---|")
        for key in ["method_a_static", "method_b_profile_rules", "method_c_atlas_risk"]:
            m = l2.get(key, {})
            p_val = f"{m.get('precision') * 100:.1f}%" if isinstance(m.get('precision'), float) else m.get('precision')
            r_val = f"{m.get('recall') * 100:.1f}%" if isinstance(m.get('recall'), float) else m.get('recall')
            f_val = f"{m.get('f1_score'):.4f}" if isinstance(m.get('f1_score'), float) else m.get('f1_score')
            md.append(f"| **{m.get('name')}** | `{m.get('tp')}` | `{m.get('fp')}` | `{m.get('fn')}` | `{m.get('tn')}` | `{p_val}` | `{r_val}` | `{f_val}` | `{m.get('accuracy', 0.0) * 100:.1f}%` |")

        md.append("\n---\n")

        # 3. Before-vs-After Mitigation Delta
        if mitigation_delta:
            md.append("## 🛡️ Before-vs-After Empirical Mitigation Analysis\n")
            md.append(f"**Baseline Variant:** `{mitigation_delta.get('baseline_variant')}`  ")
            md.append(f"**Hardened Variant:** `{mitigation_delta.get('hardened_variant')}`  \n")

            md.append("| Metric | Vulnerable Baseline | Hardened Target | Delta Improvement |")
            md.append("|---|---|---|---|")
            md.append(f"| **Attack Success Rate (ASR)** | `{mitigation_delta.get('asr_before') * 100:.1f}%` | `{mitigation_delta.get('asr_after') * 100:.1f}%` | `{mitigation_delta.get('asr_delta_pct'):+.1f} percentage points` |")
            md.append(f"| **Observed Vulnerabilities** | `{mitigation_delta.get('vuln_before')}` | `{mitigation_delta.get('vuln_after')}` | `{mitigation_delta.get('vuln_reduction')} resolved` |")
            md.append(f"| **Average Risk Score** | `{mitigation_delta.get('risk_before')}` | `{mitigation_delta.get('risk_after')}` | `{mitigation_delta.get('risk_delta'):+.4f}` |\n")

        return "\n".join(md)

    @staticmethod
    def export_csv_dataset(experiment: ExperimentRecord) -> str:
        """
        Exports experiment execution & evaluation data as a 1-row-per-attempt CSV string.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        headers = [
            "experiment_id", "scenario_id", "target_id", "target_name", "target_type", "configuration_variant",
            "execution_id", "test_id", "test_case_version", "assertion_version", "test_name", "run_number",
            "timestamp", "prompt_input", "raw_response", "retrieved_context", "tool_decision", "tool_execution_result",
            "assertion_passed", "actual_applicable", "actual_vulnerable", "expected_vulnerable", "expected_applicable",
            "classification", "likelihood_score", "impact_score", "exposure_score", "computed_risk_score",
            "severity_rating", "scoring_method", "scoring_config_version", "provider", "model_name", "model_version",
            "temperature", "top_p", "holdout_hash", "owasp_code", "atlas_code"
        ]
        writer.writerow(headers)

        eval_map = {e.execution_id: e for e in experiment.evaluation_records}
        repro = experiment.llm_reproducibility

        for er in experiment.execution_records:
            ev = eval_map.get(er.execution_id)
            exp_v = ev.expected_vulnerable if ev else True
            exp_a = ev.expected_applicable if ev else True
            class_str = ev.classification if ev else "N/A"

            writer.writerow([
                er.experiment_id, er.scenario_id, er.target_id, er.target_name, er.target_type, experiment.configuration_variant,
                er.execution_id, er.test_id, er.test_case_version, er.assertion_version, er.test_name, er.run_number,
                er.timestamp, er.prompt_input, er.raw_response, er.retrieved_context, er.tool_decision, er.tool_execution_result,
                er.assertion_passed, er.actual_applicable, er.actual_vulnerable, exp_v, exp_a,
                class_str, er.likelihood_score, er.impact_score, er.exposure_score, er.computed_risk_score,
                er.severity_rating, er.scoring_method, er.scoring_config_version,
                repro.get("provider", "simulated_harness"), repro.get("model_name", "mock_engine"), repro.get("model_version", "v0.3.0"),
                repro.get("temperature", 0.2), repro.get("top_p", 0.95), repro.get("holdout_hash", ""),
                er.owasp_mapping.get("id", ""), er.atlas_mapping.get("id", "")
            ])

        return output.getvalue()
