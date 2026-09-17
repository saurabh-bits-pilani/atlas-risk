"""
v0.2 Research Experiment Report & Dataset Export Module.
Generates research reports, 2-layer baseline comparisons, before/after mitigation deltas,
and formats 1-row-per-attempt CSV & JSON datasets for statistical analysis.
"""

import json
import csv
import io
from typing import Dict, Any, List
from models.experiment_models import ExperimentRecord


class ExperimentReportGenerator:
    @staticmethod
    def generate_research_report(
        experiment: ExperimentRecord,
        eval_metrics: Dict[str, Any],
        baseline_comparison: Dict[str, Any],
        mitigation_delta: Dict[str, Any] = None
    ) -> str:
        """
        Generates markdown research report for v0.2 platform.
        """
        md = []
        md.append(f"# 🔬 ATLAS-Risk Research Experiment Report\n")
        md.append(f"**Experiment ID:** `{experiment.experiment_id}` | **Target ID:** `{experiment.target_id}`  ")
        md.append(f"**Target Name:** `{experiment.target_name}` | **Target Type:** `{experiment.target_type}`  ")
        md.append(f"**Configuration Variant:** `{experiment.configuration_variant}` | **Repeats per Test:** `{experiment.repeats_per_test}`  ")
        md.append(f"**Timestamp:** `{experiment.timestamp}`\n")

        # Provenance Header
        md.append("> [!NOTE]")
        md.append(f"> **Framework Versions:** `{experiment.framework_versions.get('owasp')}` | `{experiment.framework_versions.get('atlas')}`  ")
        md.append(f"> **Scoring Provenance:** Method=`{experiment.scoring_method}` | Config Version=`{experiment.scoring_config_version}`  ")
        md.append(f"> **Academic Rigor Disclaimer:** *{eval_metrics.get('disclaimer', 'POC validation results.')}*\n")

        md.append("---\n")

        # 1. Benchmark Execution & Confusion Matrix
        prec_str = f"{eval_metrics['precision'] * 100:.1f}%" if isinstance(eval_metrics['precision'], float) else eval_metrics['precision']
        rec_str = f"{eval_metrics['recall'] * 100:.1f}%" if isinstance(eval_metrics['recall'], float) else eval_metrics['recall']
        f1_str = f"{eval_metrics['f1_score']:.4f}" if isinstance(eval_metrics['f1_score'], float) else eval_metrics['f1_score']
        spec_str = f"{eval_metrics.get('specificity', 'N/A') * 100:.1f}%" if isinstance(eval_metrics.get('specificity'), float) else eval_metrics.get('specificity', 'N/A')

        md.append("## 📊 Ground-Truth Benchmark Results & Confusion Matrix\n")
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
        md.append("### Layer 1: Threat Applicability Comparison")
        md.append("Compares predicted threat applicability against ground-truth applicable threat categories:\n")
        
        md.append("| Assessment Method | Predicted Applicable Threats | False Positives | Applicability Precision |")
        md.append("|---|---|---|---|")
        for key in ["method_a_static_checklist", "method_b_context_rules", "method_c_atlas_risk"]:
            m = l1.get(key, {})
            md.append(f"| **{m.get('name')}** | `{m.get('applicable_threats_predicted')}` | `{m.get('false_positives')}` | `{m.get('precision', 0.0) * 100:.1f}%` |")

        md.append("\n### Layer 2: Vulnerability Detection Comparison")
        md.append("Compares empirical vulnerability detection against ground-truth vulnerable benchmarks:\n")

        md.append("| Assessment Method | TP | FP | FN | TN | Precision | Recall | F1 Score | Accuracy |")
        md.append("|---|---|---|---|---|---|---|---|---|")
        for key in ["method_a_static", "method_b_profile_rules", "method_c_atlas_risk"]:
            m = l2.get(key, {})
            md.append(f"| **{m.get('name')}** | `{m.get('tp')}` | `{m.get('fp')}` | `{m.get('fn')}` | `{m.get('tn')}` | `{m.get('precision', 0.0) * 100:.1f}%` | `{m.get('recall', 0.0) * 100:.1f}%` | `{m.get('f1_score', 0.0):.4f}` | `{m.get('accuracy', 0.0) * 100:.1f}%` |")

        md.append("\n---\n")

        # 3. Before-vs-After Mitigation Delta (if available)
        if mitigation_delta:
            md.append("## 🛡️ Before-vs-After Mitigation Testing\n")
            md.append(f"**Baseline Configuration:** `{mitigation_delta.get('baseline_variant')}`  ")
            md.append(f"**Hardened Configuration:** `{mitigation_delta.get('hardened_variant')}`  \n")

            md.append("| Evaluation Parameter | Vulnerable Baseline | Hardened Target | Delta Improvement |")
            md.append("|---|---|---|---|")
            md.append(f"| **Attack Success Rate (ASR)** | `{mitigation_delta.get('asr_before') * 100:.1f}%` | `{mitigation_delta.get('asr_after') * 100:.1f}%` | `{mitigation_delta.get('asr_delta_pct'):+.1f}%` |")
            md.append(f"| **Observed Vulnerabilities** | `{mitigation_delta.get('vuln_before')}` | `{mitigation_delta.get('vuln_after')}` | `{mitigation_delta.get('vuln_reduction')} resolved` |")
            md.append(f"| **Average Risk Score** | `{mitigation_delta.get('risk_before')}` | `{mitigation_delta.get('risk_after')}` | `{mitigation_delta.get('risk_delta'):+.4f}` |\n")

        md.append("---\n")

        # 4. Detailed Test Execution Log
        md.append("## 📜 Test Execution Telemetry Log\n")
        md.append("| Exec ID | Test ID | Version | Target Type | Prompt Input | Assertion Result | Observed Vulnerable | Severity |")
        md.append("|---|---|---|---|---|---|---|---|")
        for er in experiment.execution_records:
            pass_str = "Breach" if er.assertion_passed else "Safeguard"
            vuln_str = "🚨 Yes" if er.actual_vulnerable else "🛡️ No"
            md.append(f"| `{er.execution_id}` | `{er.test_id}` | `{er.test_case_version}` | `{er.target_type}` | `{er.prompt_input[:30]}...` | `{pass_str}` | {vuln_str} | `{er.severity_rating}` |")

        return "\n".join(md)

    @staticmethod
    def export_csv_dataset(experiment: ExperimentRecord) -> str:
        """
        Exports experiment execution & evaluation data as a 1-row-per-attempt CSV string.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        headers = [
            "experiment_id", "target_id", "target_name", "target_type", "configuration_variant",
            "execution_id", "test_id", "test_case_version", "test_name", "run_number",
            "timestamp", "prompt_input", "raw_response", "assertion_passed",
            "actual_applicable", "actual_vulnerable", "expected_vulnerable", "expected_applicable",
            "classification", "likelihood_score", "impact_score", "exposure_score",
            "computed_risk_score", "severity_rating", "scoring_method", "scoring_config_version",
            "owasp_code", "atlas_code", "owasp_provenance_verified", "atlas_provenance_verified"
        ]
        writer.writerow(headers)

        eval_map = {e.execution_id: e for e in experiment.evaluation_records}

        for er in experiment.execution_records:
            ev = eval_map.get(er.execution_id)
            exp_v = ev.expected_vulnerable if ev else True
            exp_a = ev.expected_applicable if ev else True
            class_str = ev.classification if ev else "N/A"

            owasp_prov = er.owasp_mapping.get("provenance", {}).get("verified_flag", True)
            atlas_prov = er.atlas_mapping.get("provenance", {}).get("verified_flag", True)

            writer.writerow([
                er.experiment_id, er.target_id, er.target_name, er.target_type, experiment.configuration_variant,
                er.execution_id, er.test_id, er.test_case_version, er.test_name, er.run_number,
                er.timestamp, er.prompt_input, er.raw_response, er.assertion_passed,
                er.actual_applicable, er.actual_vulnerable, exp_v, exp_a,
                class_str, er.likelihood_score, er.impact_score, er.exposure_score,
                er.computed_risk_score, er.severity_rating, er.scoring_method, er.scoring_config_version,
                er.owasp_mapping.get("id", ""), er.atlas_mapping.get("id", ""), owasp_prov, atlas_prov
            ])

        return output.getvalue()
