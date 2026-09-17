"""
Unit tests for ATLAS-Risk v0.2 Research Experiment Platform.
Verifies zero ground truth leakage, ExecutionRecord/EvaluationRecord separation,
2-layer baseline comparisons, mapping/scoring provenance, target_type handling, and CSV export.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engines.threat_mapper import ThreatMapper
from engines.risk_engine import RiskEngine
from engines.test_runner import TestRunner
from engines.evaluation_engine import EvaluationEngine
from engines.baseline_comparator import BaselineComparator
from reports.report_v02 import ExperimentReportGenerator


def test_v02_execution_record_zero_ground_truth_leakage():
    mapper = ThreatMapper()
    runner = TestRunner()

    answers = {
        "q1_target_exposure": "Public Web Interface",
        "q2_system_prompt": "Yes - Confidential/Proprietary Instructions",
        "q3_untrusted_input": "Yes - Ingests external unvetted documents/web text",
        "q4_rag_usage": "Yes - Multi-tenant RAG without document filter controls",
        "q5_sensitive_data": "High - Contains credentials or sensitive customer PII",
        "q6_tool_calling": "Yes - Destructive/Write access (Database updates, APIs, command execution)",
        "q7_agency_autonomy": "Fully Autonomous (Zero human-in-the-loop)",
        "q8_output_validation": "No - Directly executed or rendered",
        "q9_rate_limiting": "No limits",
        "q10_guardrails": "None"
    }

    app_list = mapper.evaluate_applicability(answers)

    exp = runner.run_experiment(
        experiment_id="EXP-TEST-001",
        target_id="TARGET-DONKAI-VULN",
        target_name="DonkAI Vulnerable",
        target_type="deterministic_benchmark",
        configuration_variant="Vulnerable Baseline",
        questionnaire_answers=answers,
        applicability_list=app_list,
        framework_versions=mapper.framework_versions,
        repeats_per_test=1
    )

    assert len(exp.execution_records) >= 12

    # STRICT ASSERTION: Zero ground-truth fields inside ExecutionRecord instances
    for exec_rec in exp.execution_records:
        rec_dict = exec_rec.to_dict()
        assert "expected_vulnerable" not in rec_dict
        assert "expected_applicable" not in rec_dict
        assert hasattr(exec_rec, "test_case_version")
        assert exec_rec.scoring_method == "poc_heuristic_v1"
        assert exec_rec.scoring_config_version == "1.0.0"
        assert "provenance" in exec_rec.owasp_mapping
        assert "provenance" in exec_rec.atlas_mapping
        assert exec_rec.owasp_mapping["provenance"]["verified_flag"] is True

    print("✅ test_v02_execution_record_zero_ground_truth_leakage passed!")


def test_v02_decoupled_evaluation_engine_metrics():
    mapper = ThreatMapper()
    runner = TestRunner()
    eval_engine = EvaluationEngine()

    answers = {
        "q1_target_exposure": "Public Web Interface",
        "q2_system_prompt": "Yes - Confidential/Proprietary Instructions",
        "q3_untrusted_input": "Yes - Ingests external unvetted documents/web text",
        "q4_rag_usage": "Yes - Multi-tenant RAG without document filter controls",
        "q5_sensitive_data": "High - Contains credentials or sensitive customer PII",
        "q6_tool_calling": "Yes - Destructive/Write access (Database updates, APIs, command execution)",
        "q7_agency_autonomy": "Fully Autonomous (Zero human-in-the-loop)",
        "q8_output_validation": "No - Directly executed or rendered",
        "q9_rate_limiting": "No limits",
        "q10_guardrails": "None"
    }
    app_list = mapper.evaluate_applicability(answers)

    exp = runner.run_experiment(
        experiment_id="EXP-TEST-002",
        target_id="TARGET-DONKAI-VULN",
        target_name="DonkAI Vulnerable",
        target_type="stochastic_llm",
        configuration_variant="Vulnerable Baseline",
        questionnaire_answers=answers,
        applicability_list=app_list,
        framework_versions=mapper.framework_versions,
        repeats_per_test=3
    )

    eval_metrics = eval_engine.evaluate_experiment(exp)

    assert len(exp.evaluation_records) == len(exp.execution_records)
    assert "attack_success_rate" in eval_metrics
    assert "accuracy" in eval_metrics
    assert "precision" in eval_metrics
    assert "recall" in eval_metrics
    assert "f1_score" in eval_metrics
    assert eval_metrics["tp"] + eval_metrics["tn"] + eval_metrics["fp"] + eval_metrics["fn"] == len(exp.evaluation_records)

    print("✅ test_v02_decoupled_evaluation_engine_metrics passed!")


def test_v02_two_layer_baseline_comparison():
    mapper = ThreatMapper()
    runner = TestRunner()

    answers = {
        "q1_target_exposure": "Public Web Interface",
        "q2_system_prompt": "Yes - Confidential/Proprietary Instructions",
        "q3_untrusted_input": "Yes - Ingests external unvetted documents/web text",
        "q4_rag_usage": "Yes - Multi-tenant RAG without document filter controls",
        "q5_sensitive_data": "High - Contains credentials or sensitive customer PII",
        "q6_tool_calling": "Yes - Destructive/Write access (Database updates, APIs, command execution)",
        "q7_agency_autonomy": "Fully Autonomous (Zero human-in-the-loop)",
        "q8_output_validation": "No - Directly executed or rendered",
        "q9_rate_limiting": "No limits",
        "q10_guardrails": "None"
    }
    app_list = mapper.evaluate_applicability(answers)

    exp = runner.run_experiment(
        experiment_id="EXP-TEST-003",
        target_id="TARGET-DONKAI-VULN",
        target_name="DonkAI Vulnerable",
        target_type="deterministic_benchmark",
        configuration_variant="Vulnerable Baseline",
        questionnaire_answers=answers,
        applicability_list=app_list,
        framework_versions=mapper.framework_versions,
        repeats_per_test=1
    )

    gt_map = {
        t["test_id"]: {
            "expected_vulnerable": t.get("expected_vulnerable", True),
            "expected_applicable": t.get("expected_applicable", True)
        }
        for t in runner.test_cases
    }

    comp = BaselineComparator.compare_baselines(exp, app_list, gt_map)

    assert "layer_1_applicability_comparison" in comp
    assert "layer_2_detection_comparison" in comp
    assert "method_a_static_checklist" in comp["layer_1_applicability_comparison"]
    assert "method_c_atlas_risk" in comp["layer_2_detection_comparison"]

    print("✅ test_v02_two_layer_baseline_comparison passed!")


def test_v02_csv_dataset_export():
    mapper = ThreatMapper()
    runner = TestRunner()
    eval_engine = EvaluationEngine()

    answers = {
        "q1_target_exposure": "Public Web Interface",
        "q2_system_prompt": "Yes - Confidential/Proprietary Instructions",
        "q3_untrusted_input": "Yes - Ingests external unvetted documents/web text",
        "q4_rag_usage": "No RAG",
        "q5_sensitive_data": "Low/None - Public data only",
        "q6_tool_calling": "No tool execution",
        "q7_agency_autonomy": "N/A - No tools",
        "q8_output_validation": "Yes - Strict schema validation and sanitization",
        "q9_rate_limiting": "Strict user authentication & budget limits",
        "q10_guardrails": "Comprehensive ML guardrail framework"
    }
    app_list = mapper.evaluate_applicability(answers)

    exp = runner.run_experiment(
        experiment_id="EXP-TEST-004",
        target_id="TARGET-DONKAI-HARD",
        target_name="DonkAI Hardened",
        target_type="deterministic_benchmark",
        configuration_variant="Hardened Safeguard",
        questionnaire_answers=answers,
        applicability_list=app_list,
        framework_versions=mapper.framework_versions,
        repeats_per_test=1
    )
    eval_engine.evaluate_experiment(exp)

    csv_data = ExperimentReportGenerator.export_csv_dataset(exp)
    assert "experiment_id" in csv_data
    assert "scoring_method" in csv_data
    assert "test_case_version" in csv_data
    assert "target_type" in csv_data
    assert "poc_heuristic_v1" in csv_data

    print("✅ test_v02_csv_dataset_export passed!")
