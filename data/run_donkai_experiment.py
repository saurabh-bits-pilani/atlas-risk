"""
DonkAI Benchmark Validation Experiment Execution Script for ATLAS-Risk v0.2.0.
Executes the approved Experimental Protocol across Target A (Vulnerable Baseline) and Target A (Hardened Safeguard),
logs persistent experiment runs to data/runs/, calculates confusion matrix & 2-layer baselines,
and exports 1-row-per-attempt CSV & JSON datasets.
"""

import os
import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engines.threat_mapper import ThreatMapper
from engines.test_runner import TestRunner
from engines.evaluation_engine import EvaluationEngine
from engines.baseline_comparator import BaselineComparator
from engines.persistence_engine import PersistenceEngine
from reports.report_v02 import ExperimentReportGenerator


def run_donkai_protocol():
    print("==================================================================")
    print("🔬 Executing DonkAI Experimental Protocol (ATLAS-Risk v0.2.0)")
    print("==================================================================")

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_configs_path = os.path.join(base_dir, "data", "target_configs.json")
    catalogue_path = os.path.join(base_dir, "data", "benchmark_catalogue.json")

    with open(target_configs_path, "r", encoding="utf-8") as f:
        target_configs = json.load(f)["target_configurations"]

    with open(catalogue_path, "r", encoding="utf-8") as f:
        test_cases = json.load(f)["test_cases"]

    gt_map = {
        t["test_id"]: {
            "expected_vulnerable": t.get("expected_vulnerable", True),
            "expected_applicable": t.get("expected_applicable", True)
        }
        for t in test_cases
    }

    mapper = ThreatMapper()
    runner = TestRunner(catalogue_path=catalogue_path)
    eval_engine = EvaluationEngine(catalogue_path=catalogue_path)
    persistence = PersistenceEngine()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # ------------------------------------------------------------------
    # RUN 1: Target A — Vulnerable Baseline (N = 5 Repeats)
    # ------------------------------------------------------------------
    vuln_cfg = target_configs["TARGET-DONKAI-VULN"]
    vuln_app = mapper.evaluate_applicability(vuln_cfg["questionnaire_profile"])

    exp_vuln = runner.run_experiment(
        experiment_id=f"EXP-DONK-VULN-{timestamp}",
        target_id=vuln_cfg["target_id"],
        target_name=vuln_cfg["name"],
        target_type=vuln_cfg["target_type"],
        configuration_variant="Vulnerable Baseline",
        questionnaire_answers=vuln_cfg["questionnaire_profile"],
        applicability_list=vuln_app,
        framework_versions=mapper.framework_versions,
        repeats_per_test=5
    )

    metrics_vuln = eval_engine.evaluate_experiment(exp_vuln)
    comp_vuln = BaselineComparator.compare_baselines(exp_vuln, vuln_app, gt_map)
    persistence.save_experiment(exp_vuln)
    csv_vuln = ExperimentReportGenerator.export_csv_dataset(exp_vuln)

    csv_vuln_path = os.path.join(base_dir, "data", f"Dataset_DONKAI_VULN_{timestamp}.csv")
    with open(csv_vuln_path, "w", encoding="utf-8") as f:
        f.write(csv_vuln)

    print(f"\n✅ Run 1 Complete: Vulnerable Baseline ({metrics_vuln['total_executions']} executions)")
    print(f"   • Attack Success Rate (ASR): {metrics_vuln['attack_success_rate'] * 100:.1f}%")
    print(f"   • Accuracy: {metrics_vuln['accuracy'] * 100:.1f}% | Precision: {metrics_vuln['precision'] * 100:.1f}% | Recall: {metrics_vuln['recall'] * 100:.1f}% | F1: {metrics_vuln['f1_score']:.4f}")
    print(f"   • Confusion Matrix: TP={metrics_vuln['tp']} | TN={metrics_vuln['tn']} | FP={metrics_vuln['fp']} | FN={metrics_vuln['fn']}")
    print(f"   • Saved: data/runs/{exp_vuln.experiment_id}.json & {os.path.basename(csv_vuln_path)}")

    # ------------------------------------------------------------------
    # RUN 2: Target A — Hardened Safeguard (N = 5 Repeats)
    # ------------------------------------------------------------------
    hard_cfg = target_configs["TARGET-DONKAI-HARD"]
    hard_app = mapper.evaluate_applicability(hard_cfg["questionnaire_profile"])

    exp_hard = runner.run_experiment(
        experiment_id=f"EXP-DONK-HARD-{timestamp}",
        target_id=hard_cfg["target_id"],
        target_name=hard_cfg["name"],
        target_type=hard_cfg["target_type"],
        configuration_variant="Hardened Safeguard",
        questionnaire_answers=hard_cfg["questionnaire_profile"],
        applicability_list=hard_app,
        framework_versions=mapper.framework_versions,
        repeats_per_test=5
    )

    metrics_hard = eval_engine.evaluate_experiment(exp_hard)
    comp_hard = BaselineComparator.compare_baselines(exp_hard, hard_app, gt_map)
    persistence.save_experiment(exp_hard)
    csv_hard = ExperimentReportGenerator.export_csv_dataset(exp_hard)

    csv_hard_path = os.path.join(base_dir, "data", f"Dataset_DONKAI_HARD_{timestamp}.csv")
    with open(csv_hard_path, "w", encoding="utf-8") as f:
        f.write(csv_hard)

    print(f"\n✅ Run 2 Complete: Hardened Safeguard ({metrics_hard['total_executions']} executions)")
    print(f"   • Attack Success Rate (ASR): {metrics_hard['attack_success_rate'] * 100:.1f}%")
    prec_str = f"{metrics_hard['precision'] * 100:.1f}%" if isinstance(metrics_hard['precision'], float) else metrics_hard['precision']
    rec_str = f"{metrics_hard['recall'] * 100:.1f}%" if isinstance(metrics_hard['recall'], float) else metrics_hard['recall']
    f1_str = f"{metrics_hard['f1_score']:.4f}" if isinstance(metrics_hard['f1_score'], float) else metrics_hard['f1_score']
    spec_str = f"{metrics_hard.get('specificity', 'N/A') * 100:.1f}%" if isinstance(metrics_hard.get('specificity'), float) else metrics_hard.get('specificity', 'N/A')

    print(f"   • Accuracy: {metrics_hard['accuracy'] * 100:.1f}% | Precision (Pos): {prec_str} | Recall: {rec_str} | Specificity (TNR): {spec_str} | F1: {f1_str}")
    print(f"   • Confusion Matrix: TP={metrics_hard['tp']} | TN={metrics_hard['tn']} | FP={metrics_hard['fp']} | FN={metrics_hard['fn']}")
    print(f"   • Saved: data/runs/{exp_hard.experiment_id}.json & {os.path.basename(csv_hard_path)}")

    # ------------------------------------------------------------------
    # BEFORE-VS-AFTER MITIGATION DELTA ANALYSIS
    # ------------------------------------------------------------------
    avg_risk_v = round(sum(r.computed_risk_score for r in exp_vuln.execution_records) / len(exp_vuln.execution_records), 4)
    avg_risk_h = round(sum(r.computed_risk_score for r in exp_hard.execution_records) / len(exp_hard.execution_records), 4)

    mitigation_delta = {
        "baseline_variant": "Target A - Vulnerable Baseline",
        "hardened_variant": "Target A - Hardened Safeguard",
        "asr_before": metrics_vuln['attack_success_rate'],
        "asr_after": metrics_hard['attack_success_rate'],
        "asr_delta_pct": (metrics_hard['attack_success_rate'] - metrics_vuln['attack_success_rate']) * 100,
        "vuln_before": metrics_vuln['successful_attacks'],
        "vuln_after": metrics_hard['successful_attacks'],
        "vuln_reduction": metrics_vuln['successful_attacks'] - metrics_hard['successful_attacks'],
        "risk_before": avg_risk_v,
        "risk_after": avg_risk_h,
        "risk_delta": avg_risk_h - avg_risk_v
    }

    report_md = ExperimentReportGenerator.generate_research_report(
        experiment=exp_vuln,
        eval_metrics=metrics_vuln,
        baseline_comparison=comp_vuln,
        mitigation_delta=mitigation_delta
    )

    report_path = os.path.join(base_dir, "data", f"DonkAI_Experiment_Report_{timestamp}.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    print("\n==================================================================")
    print(f"📊 BEFORE-VS-AFTER MITIGATION RESULTS")
    print("==================================================================")
    print(f"• Baseline ASR: {mitigation_delta['asr_before']*100:.1f}%  ──>  Hardened ASR: {mitigation_delta['asr_after']*100:.1f}% ({mitigation_delta['asr_delta_pct']:+.1f}% Delta)")
    print(f"• Observed Vulnerabilities: {mitigation_delta['vuln_before']}  ──>  {mitigation_delta['vuln_after']} ({mitigation_delta['vuln_reduction']} vulnerabilities resolved)")
    print(f"• Average Risk Score: {mitigation_delta['risk_before']}  ──>  {mitigation_delta['risk_after']} ({mitigation_delta['risk_delta']:+.4f} Risk Delta)")
    print(f"• Research Report Exported: {os.path.basename(report_path)}")
    print("==================================================================")


if __name__ == "__main__":
    run_donkai_protocol()
