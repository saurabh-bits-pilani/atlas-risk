"""
Master Execution Script for ATLAS-Risk v0.3.0 Multi-Scenario Experiments.
Executes Scenarios B through G, freezes v0.3.0 engine, and executes sealed Scenario H (Holdout Set).
Logs persistent experiment runs to data/runs/, calculates confusion matrices & 2-layer baselines,
and exports 1-row-per-attempt CSV & JSON datasets.
"""

import os
import sys
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engines.threat_mapper import ThreatMapper
from engines.multi_scenario_runner import MultiScenarioRunner
from engines.evaluation_engine import EvaluationEngine
from engines.baseline_comparator import BaselineComparator
from engines.persistence_engine import PersistenceEngine
from reports.report_v03 import MultiScenarioReportGenerator


def run_v03_multi_scenario_experiments():
    print("==================================================================")
    print("🔬 ATLAS-Risk v0.3.0 — Multi-Scenario Experiment Execution")
    print("==================================================================")

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_configs_path = os.path.join(base_dir, "data", "target_configs_v03.json")
    multi_cat_path = os.path.join(base_dir, "data", "multi_scenario_catalogue.json")
    holdout_cat_path = os.path.join(base_dir, "data", "holdout_catalogue_v1.json")

    with open(target_configs_path, "r", encoding="utf-8") as f:
        target_configs = json.load(f)["target_configurations"]

    with open(multi_cat_path, "r", encoding="utf-8") as f:
        multi_cases = json.load(f)["test_cases"]

    with open(holdout_cat_path, "r", encoding="utf-8") as f:
        holdout_cases = json.load(f)["test_cases"]

    mapper = ThreatMapper()
    runner = MultiScenarioRunner(catalogue_path=multi_cat_path)
    persistence = PersistenceEngine()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    scenarios_to_run = [
        {"scenario_id": "SCEN-B", "vuln_target": "TARGET-CHATBOT-VULN", "hard_target": "TARGET-CHATBOT-HARD", "repeats": 5},
        {"scenario_id": "SCEN-C", "vuln_target": "TARGET-RAG-VULN", "hard_target": "TARGET-RAG-HARD", "repeats": 5},
        {"scenario_id": "SCEN-D", "vuln_target": "TARGET-AGENT-VULN", "hard_target": "TARGET-AGENT-HARD", "repeats": 5},
        {"scenario_id": "SCEN-E", "vuln_target": "TARGET-CMPD-VULN", "hard_target": "TARGET-CMPD-HARD", "repeats": 5},
        {"scenario_id": "SCEN-F", "vuln_target": None, "hard_target": "TARGET-NEG-HARD", "repeats": 5},
        {"scenario_id": "SCEN-G", "vuln_target": "TARGET-DONKAI-VULN", "hard_target": "TARGET-DONKAI-HARD", "repeats": 1}
    ]

    all_scenario_metrics = {}

    # ------------------------------------------------------------------
    # PHASE 1: Scenarios B through G Execution (Development & Architecture Validation)
    # ------------------------------------------------------------------
    print("\n--- Phase 1: Scenarios B through G Execution ---")
    for sc in scenarios_to_run:
        sc_id = sc["scenario_id"]
        sc_cases = [tc for tc in multi_cases if tc.get("scenario_id") == sc_id]
        eval_eng = EvaluationEngine(catalogue_path=multi_cat_path)
        gt_map = {t["test_id"]: t for t in sc_cases}

        # Run Vulnerable Variant if applicable
        if sc["vuln_target"]:
            v_cfg = target_configs[sc["vuln_target"]]
            v_app = mapper.evaluate_applicability(v_cfg["questionnaire_profile"])
            exp_v = runner.run_scenario_experiment(
                experiment_id=f"EXP-{sc_id}-VULN-{timestamp}",
                scenario_id=sc_id,
                target_id=v_cfg["target_id"],
                target_name=v_cfg["name"],
                target_type=v_cfg["target_type"],
                configuration_variant="Vulnerable Baseline",
                questionnaire_answers=v_cfg["questionnaire_profile"],
                applicability_list=v_app,
                framework_versions=mapper.framework_versions,
                repeats_per_test=sc["repeats"],
                custom_test_cases=sc_cases
            )
            m_v = eval_eng.evaluate_experiment(exp_v)
            comp_v = BaselineComparator.compare_baselines(exp_v, v_app, gt_map)
            persistence.save_experiment(exp_v)

        # Run Hardened Variant
        h_cfg = target_configs[sc["hard_target"]]
        h_app = mapper.evaluate_applicability(h_cfg["questionnaire_profile"])
        exp_h = runner.run_scenario_experiment(
            experiment_id=f"EXP-{sc_id}-HARD-{timestamp}",
            scenario_id=sc_id,
            target_id=h_cfg["target_id"],
            target_name=h_cfg["name"],
            target_type=h_cfg["target_type"],
            configuration_variant="Hardened Safeguard",
            questionnaire_answers=h_cfg["questionnaire_profile"],
            applicability_list=h_app,
            framework_versions=mapper.framework_versions,
            repeats_per_test=sc["repeats"],
            custom_test_cases=sc_cases
        )
        m_h = eval_eng.evaluate_experiment(exp_h)
        comp_h = BaselineComparator.compare_baselines(exp_h, h_app, gt_map)
        persistence.save_experiment(exp_h)

        # Print Scenario Summary
        if sc["vuln_target"]:
            asr_v = f"{m_v['attack_success_rate']*100:.1f}%"
            asr_h = f"{m_h['attack_success_rate']*100:.1f}%"
            print(f"✅ {sc_id} Complete: ASR Before={asr_v} -> ASR After={asr_h} | Vuln Execs={m_v['total_executions']}, Hard Execs={m_h['total_executions']}")
        else:
            asr_h = f"{m_h['attack_success_rate']*100:.1f}%"
            print(f"✅ {sc_id} Complete: Hardened ASR={asr_h} | Execs={m_h['total_executions']} (Negative Control)")

        all_scenario_metrics[sc_id] = {"hardened_metrics": m_h}

    # ------------------------------------------------------------------
    # ENGINE FREEZE NOTICE
    # ------------------------------------------------------------------
    print("\n==================================================================")
    print("🔒 FREEZING ENGINE: ATLAS-Risk v0.3.0 Engine Sealed for Holdout Evaluation")
    print("==================================================================")

    # ------------------------------------------------------------------
    # PHASE 2: Scenario H — Sealed Unseen Holdout Execution
    # ------------------------------------------------------------------
    print("\n--- Phase 2: Scenario H (Sealed Unseen Holdout Set) Execution ---")
    eval_eng_holdout = EvaluationEngine(catalogue_path=holdout_cat_path)
    gt_map_holdout = {t["test_id"]: t for t in holdout_cases}

    # Run Holdout Vulnerable
    h_v_cfg = target_configs["TARGET-HOLDOUT-VULN"]
    h_v_app = mapper.evaluate_applicability(h_v_cfg["questionnaire_profile"])
    exp_h_v = runner.run_scenario_experiment(
        experiment_id=f"EXP-SCEN-H-VULN-{timestamp}",
        scenario_id="SCEN-H",
        target_id=h_v_cfg["target_id"],
        target_name=h_v_cfg["name"],
        target_type=h_v_cfg["target_type"],
        configuration_variant="Vulnerable Baseline",
        questionnaire_answers=h_v_cfg["questionnaire_profile"],
        applicability_list=h_v_app,
        framework_versions=mapper.framework_versions,
        repeats_per_test=5,
        custom_test_cases=holdout_cases
    )
    m_h_v = eval_eng_holdout.evaluate_experiment(exp_h_v)
    comp_h_v = BaselineComparator.compare_baselines(exp_h_v, h_v_app, gt_map_holdout)
    persistence.save_experiment(exp_h_v)

    # Run Holdout Hardened
    h_h_cfg = target_configs["TARGET-HOLDOUT-HARD"]
    h_h_app = mapper.evaluate_applicability(h_h_cfg["questionnaire_profile"])
    exp_h_h = runner.run_scenario_experiment(
        experiment_id=f"EXP-SCEN-H-HARD-{timestamp}",
        scenario_id="SCEN-H",
        target_id=h_h_cfg["target_id"],
        target_name=h_h_cfg["name"],
        target_type=h_h_cfg["target_type"],
        configuration_variant="Hardened Safeguard",
        questionnaire_answers=h_h_cfg["questionnaire_profile"],
        applicability_list=h_h_app,
        framework_versions=mapper.framework_versions,
        repeats_per_test=5,
        custom_test_cases=holdout_cases
    )
    m_h_h = eval_eng_holdout.evaluate_experiment(exp_h_h)
    comp_h_h = BaselineComparator.compare_baselines(exp_h_h, h_h_app, gt_map_holdout)
    persistence.save_experiment(exp_h_h)

    csv_holdout_v = MultiScenarioReportGenerator.export_csv_dataset(exp_h_v)
    csv_holdout_h = MultiScenarioReportGenerator.export_csv_dataset(exp_h_h)

    csv_v_path = os.path.join(base_dir, "data", f"Dataset_HOLDOUT_VULN_{timestamp}.csv")
    csv_h_path = os.path.join(base_dir, "data", f"Dataset_HOLDOUT_HARD_{timestamp}.csv")
    with open(csv_v_path, "w", encoding="utf-8") as f:
        f.write(csv_holdout_v)
    with open(csv_h_path, "w", encoding="utf-8") as f:
        f.write(csv_holdout_h)

    print(f"✅ Scenario H Complete: Unseen Holdout Baseline ASR={m_h_v['attack_success_rate']*100:.1f}% -> Hardened ASR={m_h_h['attack_success_rate']*100:.1f}%")
    print(f"   • Holdout Vulnerable Matrix: TP={m_h_v['tp']} | TN={m_h_v['tn']} | FP={m_h_v['fp']} | FN={m_h_v['fn']} | Accuracy={m_h_v['accuracy']*100:.1f}%")
    print(f"   • Holdout Hardened Matrix: TP={m_h_h['tp']} | TN={m_h_h['tn']} | FP={m_h_h['fp']} | FN={m_h_h['fn']} | Accuracy={m_h_h['accuracy']*100:.1f}%")
    print(f"   • Saved: {os.path.basename(csv_v_path)} & {os.path.basename(csv_h_path)}")

    print("\n==================================================================")
    print("🎉 MULTI-SCENARIO EXPERIMENTS COMPLETE")
    print("==================================================================")


if __name__ == "__main__":
    run_v03_multi_scenario_experiments()
